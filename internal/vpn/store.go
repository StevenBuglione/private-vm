package vpn

import (
	"context"
	"io"
	"regexp"
	"sync"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

var profileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

const maximumStoredProfiles = 8

// RotationState is a safe, non-secret summary. A newly imported profile must
// be resolved before use; any unsafe or failed later resolution requires a new
// profile instead of weakening the endpoint policy.
type RotationState string

const (
	RotationNotImported      RotationState = "not_imported"
	RotationResolutionNeeded RotationState = "resolution_required"
	RotationCurrent          RotationState = "current"
	RotationRequired         RotationState = "rotation_required"
)

// Status contains no endpoint, key, address, DNS value, source path or time.
type Status struct {
	SchemaVersion int           `json:"schema_version"`
	Present       bool          `json:"present"`
	Generation    uint64        `json:"generation"`
	Rotation      RotationState `json:"rotation"`
	Code          string        `json:"code"`
	Remediation   string        `json:"remediation"`
	Profile       *Inspection   `json:"profile,omitempty"`
}

type storedProfile struct {
	profile    *Profile
	generation uint64
	rotation   RotationState
}

// MemoryStore is the only v1 profile store. It has no file path, persistence,
// marshaling or restore API. Close is the daemon-restart cleanup boundary.
type MemoryStore struct {
	mu       sync.Mutex
	profiles map[string]*storedProfile
	next     uint64
	closed   bool
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{profiles: make(map[string]*storedProfile)}
}

// Import parses protected source bytes and atomically replaces the named
// profile. The source remains caller-owned. Replacement destroys the prior key.
func (s *MemoryStore) Import(name string, source *secret.Bytes) (Status, error) {
	if !profileNamePattern.MatchString(name) || source == nil {
		return Status{}, invalidProfile()
	}
	if s == nil {
		return Status{}, storeClosed()
	}
	profile, err := ParseSecret(source)
	if err != nil {
		return Status{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		profile.Destroy()
		return Status{}, storeClosed()
	}
	if _, replacing := s.profiles[name]; !replacing && len(s.profiles) >= maximumStoredProfiles {
		profile.Destroy()
		return Status{}, profileLimit()
	}
	s.next++
	if s.next == 0 {
		profile.Destroy()
		return Status{}, storeClosed()
	}
	old := s.profiles[name]
	entry := &storedProfile{profile: profile, generation: s.next, rotation: RotationResolutionNeeded}
	s.profiles[name] = entry
	if old != nil {
		old.profile.Destroy()
	}
	return statusFor(entry), nil
}

// Resolve performs the bounded trusted-host resolution while serializing it
// against profile replacement/removal, then updates the safe rotation status.
func (s *MemoryStore) Resolve(ctx context.Context, name string, resolver *EndpointResolver) ([]ResolvedEndpoint, Status, error) {
	if !profileNamePattern.MatchString(name) {
		return nil, Status{}, profileNotFound()
	}
	if s == nil {
		return nil, Status{}, storeClosed()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, Status{}, storeClosed()
	}
	entry := s.profiles[name]
	if entry == nil {
		return nil, missingStatus(), profileNotFound()
	}
	resolved, err := resolver.Resolve(ctx, entry.profile)
	if err != nil {
		if ctx == nil || ctx.Err() == nil {
			entry.rotation = RotationRequired
		}
		return nil, statusFor(entry), err
	}
	entry.rotation = RotationCurrent
	return resolved, statusFor(entry), nil
}

// WithResolvedConfig uses the currently stored generation without allowing a
// concurrent rotate/remove operation to invalidate it halfway through delivery.
func (s *MemoryStore) WithResolvedConfig(ctx context.Context, name string, generation uint64, endpoint ResolvedEndpoint, fn func(context.Context, io.Reader) error) error {
	if !profileNamePattern.MatchString(name) {
		return profileNotFound()
	}
	if s == nil {
		return storeClosed()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return storeClosed()
	}
	entry := s.profiles[name]
	if entry == nil {
		return profileNotFound()
	}
	if entry.generation != generation {
		return profileRotated()
	}
	if entry.rotation != RotationCurrent {
		return profileNotReady()
	}
	return entry.profile.WithResolvedConfig(ctx, endpoint, fn)
}

// Inspect returns a schema-versioned, redacted status and performs no DNS or
// other network activity.
func (s *MemoryStore) Inspect(name string) Status {
	if s == nil || !profileNamePattern.MatchString(name) {
		return missingStatus()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return missingStatus()
	}
	return statusFor(s.profiles[name])
}

// Remove is idempotent and destroys the removed key before returning.
func (s *MemoryStore) Remove(name string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.profiles[name]
	delete(s.profiles, name)
	if entry != nil {
		entry.profile.Destroy()
	}
}

// Close is idempotent and models daemon shutdown/restart: every imported key is
// destroyed and no profile can be restored.
func (s *MemoryStore) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	for name, entry := range s.profiles {
		entry.profile.Destroy()
		delete(s.profiles, name)
	}
	s.closed = true
}

func statusFor(entry *storedProfile) Status {
	if entry == nil {
		return missingStatus()
	}
	inspection, err := entry.profile.Inspect()
	if err != nil {
		return missingStatus()
	}
	status := Status{
		SchemaVersion: 1,
		Present:       true,
		Generation:    entry.generation,
		Rotation:      entry.rotation,
		Profile:       &inspection,
	}
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
	return Status{
		SchemaVersion: 1,
		Rotation:      RotationNotImported,
		Code:          "VPN_PROFILE_NOT_IMPORTED",
		Remediation:   "Import a current Proton WireGuard profile before starting a networked role.",
	}
}
