package vpn

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sync"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

var profileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

const (
	maximumProfilesPerOwner = 8
	maximumStoredProfiles   = 64
	redactedPlan            = "[REDACTED VPN RESOLUTION PLAN]"
)

// RotationState is a safe, non-secret summary. Every resolution attempt first
// invalidates the previous plan. An unsafe or failed result requires rotation.
type RotationState string

const (
	RotationNotImported      RotationState = "not_imported"
	RotationResolutionNeeded RotationState = "resolution_required"
	RotationCurrent          RotationState = "current"
	RotationRequired         RotationState = "rotation_required"
)

// Status contains no owner, endpoint, key, address, DNS value, source path or
// time. Generation is an opaque same-owner concurrency token.
type Status struct {
	SchemaVersion int           `json:"schema_version"`
	Present       bool          `json:"present"`
	Generation    uint64        `json:"generation"`
	Rotation      RotationState `json:"rotation"`
	Code          string        `json:"code"`
	Remediation   string        `json:"remediation"`
	Profile       *Inspection   `json:"profile,omitempty"`
}

// ResolutionPlan is a sealed opaque handle. The package-private concrete value
// is bound to one store entry, owner, profile name, generation, resolution
// epoch, exact endpoint set and port.
type ResolutionPlan interface {
	privateResolutionPlan()
}

// ResolvedProfile is a short-lived view supplied only after a plan is proven
// current. Host firewall planning must iterate Endpoints and guest delivery
// must call WithGuestConfig on this same view.
type ResolvedProfile interface {
	Endpoints(context.Context, func(netip.Addr, uint16) error) error
	WithGuestConfig(context.Context, func(context.Context, io.Reader) error) error
	privateResolvedProfile()
}

type resolutionPlan struct {
	owner      uint32
	name       string
	generation uint64
	epoch      uint64
	endpoints  []resolvedEndpoint
}

func (resolutionPlan) privateResolutionPlan() {}
func (resolutionPlan) String() string         { return redactedPlan }
func (resolutionPlan) GoString() string       { return redactedPlan }
func (resolutionPlan) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedPlan))
}
func (resolutionPlan) MarshalJSON() ([]byte, error)   { return nil, secret.ErrSerialization }
func (resolutionPlan) MarshalText() ([]byte, error)   { return nil, secret.ErrSerialization }
func (resolutionPlan) MarshalBinary() ([]byte, error) { return nil, secret.ErrSerialization }
func (resolutionPlan) GobEncode() ([]byte, error)     { return nil, secret.ErrSerialization }
func (resolutionPlan) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

type resolvedProfile struct {
	plan    *resolutionPlan
	profile Profile
}

func (resolvedProfile) privateResolvedProfile() {}
func (resolvedProfile) String() string          { return redactedPlan }
func (resolvedProfile) GoString() string        { return redactedPlan }
func (resolvedProfile) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedPlan))
}
func (resolvedProfile) MarshalJSON() ([]byte, error)   { return nil, secret.ErrSerialization }
func (resolvedProfile) MarshalText() ([]byte, error)   { return nil, secret.ErrSerialization }
func (resolvedProfile) MarshalBinary() ([]byte, error) { return nil, secret.ErrSerialization }
func (resolvedProfile) GobEncode() ([]byte, error)     { return nil, secret.ErrSerialization }
func (resolvedProfile) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

func (view resolvedProfile) Endpoints(ctx context.Context, fn func(netip.Addr, uint16) error) error {
	if ctx == nil || fn == nil || view.plan == nil {
		return ErrCallbackRequired
	}
	for _, endpoint := range view.plan.endpoints {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(endpoint.address, endpoint.port); err != nil {
			return err
		}
	}
	return nil
}

func (view resolvedProfile) WithGuestConfig(ctx context.Context, fn func(context.Context, io.Reader) error) error {
	if view.plan == nil || len(view.plan.endpoints) == 0 {
		return profileNotReady()
	}
	// Resolution is sorted, so the same deterministic first endpoint is used
	// for guest configuration while the firewall allows exactly the full set.
	return view.profile.withResolvedConfig(ctx, view.plan.endpoints[0], fn)
}

type profileKey struct {
	owner uint32
	name  string
}

type storedProfile struct {
	profile    Profile
	generation uint64
	epoch      uint64
	rotation   RotationState
	plan       *resolutionPlan
}

// MemoryStore is the only v1 profile store. It has no file path, persistence,
// marshaling or restore API. Close is the daemon-restart cleanup boundary.
type MemoryStore struct {
	mu       sync.Mutex
	profiles map[profileKey]*storedProfile
	next     uint64
	closed   bool
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{profiles: make(map[profileKey]*storedProfile)}
}

// Import parses protected source bytes and atomically replaces one owner's
// named profile. The source remains caller-owned. Replacement invalidates the
// prior plan and destroys the prior key.
func (s *MemoryStore) Import(owner uint32, name string, source *secret.Bytes) (Status, error) {
	if !profileNamePattern.MatchString(name) || source == nil {
		return Status{}, invalidProfile()
	}
	if s == nil {
		return Status{}, storeClosed()
	}
	parsed, err := ParseSecret(source)
	if err != nil {
		return Status{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		parsed.Destroy()
		return Status{}, storeClosed()
	}
	key := profileKey{owner: owner, name: name}
	if _, replacing := s.profiles[key]; !replacing {
		if len(s.profiles) >= maximumStoredProfiles || s.ownerCount(owner) >= maximumProfilesPerOwner {
			parsed.Destroy()
			return Status{}, profileLimit()
		}
	}
	s.next++
	if s.next == 0 {
		parsed.Destroy()
		return Status{}, storeClosed()
	}
	old := s.profiles[key]
	entry := &storedProfile{profile: parsed, generation: s.next, rotation: RotationResolutionNeeded}
	s.profiles[key] = entry
	if old != nil {
		old.plan = nil
		old.profile.Destroy()
	}
	return statusFor(entry), nil
}

// Resolve invalidates the previous plan before DNS and performs DNS without
// holding the store lock. Import, remove and close therefore remain available
// even if an injected resolver violates its context contract. Production uses
// net.Resolver, whose LookupNetIP honors the ten-second context ceiling.
func (s *MemoryStore) Resolve(ctx context.Context, owner uint32, name string, resolver *EndpointResolver) (ResolutionPlan, Status, error) {
	if !profileNamePattern.MatchString(name) {
		return nil, Status{}, profileNotFound()
	}
	if s == nil {
		return nil, Status{}, storeClosed()
	}
	key := profileKey{owner: owner, name: name}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, Status{}, storeClosed()
	}
	entry := s.profiles[key]
	if entry == nil {
		s.mu.Unlock()
		return nil, missingStatus(), profileNotFound()
	}
	entry.epoch++
	if entry.epoch == 0 {
		s.mu.Unlock()
		return nil, Status{}, storeClosed()
	}
	entry.plan = nil
	entry.rotation = RotationResolutionNeeded
	profileSnapshot := entry.profile
	generation, epoch := entry.generation, entry.epoch
	s.mu.Unlock()

	var endpoints []resolvedEndpoint
	var resolveErr error
	if resolver == nil {
		resolveErr = endpointUnresolved()
	} else {
		endpoints, resolveErr = resolver.resolve(ctx, profileSnapshot)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, missingStatus(), storeClosed()
	}
	current := s.profiles[key]
	if current == nil {
		return nil, missingStatus(), profileNotFound()
	}
	if current != entry || current.generation != generation || current.epoch != epoch {
		return nil, statusFor(current), profileRotated()
	}
	if resolveErr != nil {
		if ctx != nil && ctx.Err() != nil {
			current.rotation = RotationResolutionNeeded
		} else {
			current.rotation = RotationRequired
		}
		return nil, statusFor(current), resolveErr
	}
	plan := &resolutionPlan{
		owner: owner, name: name, generation: generation, epoch: epoch,
		endpoints: append([]resolvedEndpoint(nil), endpoints...),
	}
	current.plan = plan
	current.rotation = RotationCurrent
	return plan, statusFor(current), nil
}

// UsePlan serializes one bounded firewall/guest-plan consumer against
// re-resolution, rotation, removal and close. The opaque handle must be the
// exact pointer currently installed for this owner and name.
func (s *MemoryStore) UsePlan(ctx context.Context, owner uint32, name string, plan ResolutionPlan, fn func(ResolvedProfile) error) error {
	if ctx == nil || fn == nil {
		return ErrCallbackRequired
	}
	if !profileNamePattern.MatchString(name) || s == nil {
		return profileNotFound()
	}
	concrete, ok := plan.(*resolutionPlan)
	if !ok || concrete == nil {
		return profileRotated()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return storeClosed()
	}
	entry := s.profiles[profileKey{owner: owner, name: name}]
	if entry == nil {
		return profileNotFound()
	}
	if entry.plan != concrete || concrete.owner != owner || concrete.name != name ||
		concrete.generation != entry.generation || concrete.epoch != entry.epoch || entry.rotation != RotationCurrent {
		return profileRotated()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(resolvedProfile{plan: concrete, profile: entry.profile})
}

func (s *MemoryStore) Inspect(owner uint32, name string) Status {
	if s == nil || !profileNamePattern.MatchString(name) {
		return missingStatus()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return missingStatus()
	}
	return statusFor(s.profiles[profileKey{owner: owner, name: name}])
}

func (s *MemoryStore) Remove(owner uint32, name string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := profileKey{owner: owner, name: name}
	entry := s.profiles[key]
	delete(s.profiles, key)
	if entry != nil {
		entry.plan = nil
		entry.profile.Destroy()
	}
}

func (s *MemoryStore) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	for key, entry := range s.profiles {
		entry.plan = nil
		entry.profile.Destroy()
		delete(s.profiles, key)
	}
	s.closed = true
}

func (s *MemoryStore) ownerCount(owner uint32) int {
	count := 0
	for key := range s.profiles {
		if key.owner == owner {
			count++
		}
	}
	return count
}

func statusFor(entry *storedProfile) Status {
	if entry == nil {
		return missingStatus()
	}
	inspection, err := entry.profile.Inspect()
	if err != nil {
		return missingStatus()
	}
	status := Status{SchemaVersion: 1, Present: true, Generation: entry.generation, Rotation: entry.rotation, Profile: &inspection}
	switch entry.rotation {
	case RotationCurrent:
		status.Code = "VPN_PROFILE_CURRENT"
		status.Remediation = "No profile rotation is currently required."
	case RotationRequired:
		status.Code = "VPN_PROFILE_ROTATION_REQUIRED"
		status.Remediation = "Generate and import a current Proton WireGuard profile before starting a networked role."
	default:
		status.Code = "VPN_ENDPOINT_CHECK_REQUIRED"
		status.Remediation = "Run the bounded trusted-host endpoint check before starting a networked role."
	}
	return status
}

func missingStatus() Status {
	return Status{SchemaVersion: 1, Rotation: RotationNotImported, Code: "VPN_PROFILE_NOT_IMPORTED", Remediation: "Import a current Proton WireGuard profile before starting a networked role."}
}

var (
	_ ResolutionPlan  = (*resolutionPlan)(nil)
	_ ResolvedProfile = resolvedProfile{}
	_ fmt.Formatter   = resolutionPlan{}
	_ json.Marshaler  = resolutionPlan{}
	_ xml.Marshaler   = resolutionPlan{}
)
