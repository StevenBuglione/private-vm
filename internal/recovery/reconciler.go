// Package recovery owns conservative daemon-startup reconciliation.
//
// The reconciler never discovers or removes resources by pathname alone. A
// trusted backend enumerates candidates, records a stable identity fingerprint,
// revalidates private-vm ownership before every mutation, and proves both the
// individual artifact and the complete session resource set absent afterward.
package recovery

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/StevenBuglione/private-vm/internal/session"
)

const (
	defaultMaxCandidates = 4096
	// Reserve one failure slot for the final immutable-base audit so the closed
	// report can represent one failure per session without truncation.
	defaultMaxSessions = 255
)

// Kind is a closed daemon-owned resource class. The order below is a security
// contract: users of this package cannot supply an arbitrary cleanup priority.
type Kind string

const (
	KindQEMUProcess Kind = "qemu_process"
	KindCgroup      Kind = "cgroup"
	KindQMPSocket   Kind = "qmp_socket"
	KindSPICESocket Kind = "spice_socket"
	KindVSOCKCID    Kind = "vsock_cid"
	KindTAP         Kind = "tap"
	KindVeth        Kind = "veth"
	KindNetNS       Kind = "network_namespace"
	KindNFTables    Kind = "nftables"
	KindUSBClaim    Kind = "usb_claim"
	KindMount       Kind = "outer_mount"
	KindMapper      Kind = "device_mapper"
	KindLoop        Kind = "loop_device"
	KindCiphertext  Kind = "ciphertext"
	KindRuntimePath Kind = "runtime_path"
)

var cleanupOrder = []Kind{
	KindQEMUProcess,
	KindCgroup,
	KindQMPSocket,
	KindSPICESocket,
	KindVSOCKCID,
	KindTAP,
	KindVeth,
	KindNetNS,
	KindNFTables,
	KindUSBClaim,
	KindMount,
	KindMapper,
	KindLoop,
	KindCiphertext,
	KindRuntimePath,
}

var (
	fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	knownKind          = make(map[Kind]int, len(cleanupOrder))
	ErrIncomplete      = errors.New("startup recovery incomplete")
	ErrActiveOwner     = errors.New("session has a current registry owner")
)

func init() {
	for priority, kind := range cleanupOrder {
		knownKind[kind] = priority
	}
}

// Origin records which trusted inventory boundary found an artifact. It is
// never copied into the public recovery report.
type Origin string

const (
	OriginVolatileRecord Origin = "volatile_record"
	OriginKernel         Origin = "kernel_inventory"
	OriginScratch        Origin = "scratch_inventory"
)

// Identity is non-secret exact-object evidence produced by Backend.Inventory.
// Fingerprint is a SHA-256 over a backend-specific closed identity tuple (for
// example device/inode/owner/mode, or PID/start-time/executable/cgroup). The
// backend must recompute and compare that tuple in RevalidateOwned.
type Identity struct {
	Fingerprint string
	OwnerUID    uint32
	OwnerGID    uint32
}

// Candidate is an internal inventory entry. Locator may be a kernel object
// name or daemon-derived absolute path; it is intentionally absent from Report.
type Candidate struct {
	SessionID string
	Kind      Kind
	Origin    Origin
	Locator   string
	Identity  Identity
}

// Backend is the only boundary permitted to inspect or mutate host resources.
// Implementations must use typed operations, never shell interpolation. Cleanup
// is idempotent. RevalidateOwned must compare the complete current identity to
// Candidate.Identity immediately before a mutation.
type Backend interface {
	Inventory(context.Context) ([]Candidate, error)
	RevalidateOwned(context.Context, Candidate) error
	Cleanup(context.Context, Candidate) error
	AuditAbsent(context.Context, Candidate) error
	AuditSessionAbsent(context.Context, string) error
}

// RecoveryClaim excludes a session from ordinary registry admission for the
// complete recovery attempt.
type RecoveryClaim interface {
	Release()
}

// Registry atomically rejects a currently owned session and otherwise grants a
// recovery claim. A production startup must not admit new sessions until Run
// returns successfully.
type Registry interface {
	ClaimRecovery(context.Context, string) (RecoveryClaim, error)
}

type KeyState string

const (
	KeyUnavailable KeyState = "unavailable"
	KeyPresent     KeyState = "present"
	KeyUnknown     KeyState = "unknown"
)

// KeyEvidence proves that no recoverable private-vm key source survived the
// previous daemon. An open device-mapper target may still hold its kernel key;
// that target is closed before ciphertext deletion by the normal cleanup order.
type KeyEvidence interface {
	State(context.Context, string) (KeyState, error)
}

// BaseImageSeal is a bounded aggregate over all immutable base image identities.
// It contains no paths and cannot identify session content.
type BaseImageSeal struct {
	Count       uint32
	Fingerprint string
}

// BaseImageAuditor proves recovery did not alter immutable base images.
type BaseImageAuditor interface {
	Snapshot(context.Context) (BaseImageSeal, error)
	Verify(context.Context, BaseImageSeal) error
}

type Config struct {
	DaemonUID        uint32
	InventoryTimeout time.Duration
	StepTimeout      time.Duration
	SessionTimeout   time.Duration
	MaxCandidates    int
	MaxSessions      int
}

type Reconciler struct {
	backend  Backend
	registry Registry
	keys     KeyEvidence
	bases    BaseImageAuditor
	config   Config
}

func New(backend Backend, registry Registry, keys KeyEvidence, bases BaseImageAuditor, config Config) (*Reconciler, error) {
	if backend == nil || registry == nil || keys == nil || bases == nil {
		return nil, errors.New("recovery backend, registry, key evidence, and base-image auditor are required")
	}
	if config.InventoryTimeout <= 0 || config.InventoryTimeout > 30*time.Second ||
		config.StepTimeout <= 0 || config.StepTimeout > 30*time.Second ||
		config.SessionTimeout < config.StepTimeout || config.SessionTimeout > 5*time.Minute {
		return nil, errors.New("recovery timeouts are outside supported bounds")
	}
	if config.MaxCandidates == 0 {
		config.MaxCandidates = defaultMaxCandidates
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = defaultMaxSessions
	}
	if config.MaxCandidates < 1 || config.MaxCandidates > defaultMaxCandidates ||
		config.MaxSessions < 1 || config.MaxSessions > defaultMaxSessions {
		return nil, errors.New("recovery inventory limits are outside supported bounds")
	}
	return &Reconciler{backend: backend, registry: registry, keys: keys, bases: bases, config: config}, nil
}

// Run executes sequentially and owns no detached goroutine. A failed dependent
// step stops that session but does not prevent another independently claimed
// session from converging. Any failure leaves the overall result incomplete.
func (r *Reconciler) Run(ctx context.Context) (Report, error) {
	report := newReport()
	seal, err := r.snapshotBases(ctx)
	if err != nil {
		report.addFailure(classifyFailure(err, "RECOVERY_BASE_IMAGE_AUDIT_FAILED", "Immutable base-image identity could not be captured before recovery."))
		return report.finish(), incompleteError(err)
	}

	candidates, err := r.inventory(ctx)
	if err != nil {
		report.addFailure(classifyFailure(err, "RECOVERY_INVENTORY_FAILED", "The private-vm orphan inventory could not be completed."))
		r.verifyBasesAfterFailure(seal, &report)
		return report.finish(), incompleteError(err)
	}
	if len(candidates) > r.config.MaxCandidates {
		err = errors.New("candidate limit exceeded")
		report.addFailure(newFailure("RECOVERY_INVENTORY_LIMIT", "The private-vm orphan inventory exceeded its fixed bound."))
		r.verifyBasesAfterFailure(seal, &report)
		return report.finish(), incompleteError(err)
	}

	grouped, groupErr := r.validateAndGroup(candidates, &report)
	if groupErr != nil {
		r.verifyBasesAfterFailure(seal, &report)
		return report.finish(), incompleteError(groupErr)
	}
	report.SessionsDiscovered = len(grouped)
	if len(grouped) > r.config.MaxSessions {
		err = errors.New("session limit exceeded")
		report.addFailure(newFailure("RECOVERY_INVENTORY_LIMIT", "The private-vm orphan session inventory exceeded its fixed bound."))
		r.verifyBasesAfterFailure(seal, &report)
		return report.finish(), incompleteError(err)
	}

	ids := sortedSessionIDs(grouped)
	var runErrors []error
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			report.addFailure(classifyFailure(err, "RECOVERY_CANCELED", "Startup recovery was canceled before all sessions were audited."))
			runErrors = append(runErrors, err)
			break
		}
		if err := r.recoverSession(ctx, id, grouped[id], &report); err != nil {
			runErrors = append(runErrors, err)
		}
	}

	if err := r.verifyBases(seal); err != nil {
		report.addFailure(classifyFailure(err, "RECOVERY_BASE_IMAGE_CHANGED", "Immutable base-image identity changed during recovery."))
		runErrors = append(runErrors, err)
	} else {
		report.BaseImagesVerified = true
	}
	report = report.finish()
	if len(runErrors) != 0 || len(report.Failures) != 0 {
		return report, incompleteError(errors.Join(runErrors...))
	}
	return report, nil
}

func (r *Reconciler) recoverSession(parent context.Context, id string, candidates []Candidate, report *Report) error {
	sessionCtx, cancelSession := context.WithTimeout(parent, r.config.SessionTimeout)
	defer cancelSession()

	claim, err := withResultTimeout(sessionCtx, r.config.StepTimeout, func(ctx context.Context) (RecoveryClaim, error) {
		return r.registry.ClaimRecovery(ctx, id)
	})
	if err != nil || claim == nil {
		if err == nil {
			err = errors.New("registry returned a nil recovery claim")
		}
		report.addFailure(classifyFailure(err, "RECOVERY_REGISTRY_CONFLICT", "An orphan could not be excluded from the live session registry."))
		return err
	}
	defer claim.Release()

	if hasStorage(candidates) {
		state, stateErr := withResultTimeout(sessionCtx, r.config.StepTimeout, func(ctx context.Context) (KeyState, error) {
			return r.keys.State(ctx, id)
		})
		if stateErr != nil {
			report.addFailure(classifyFailure(stateErr, "RECOVERY_KEY_STATE_UNKNOWN", "Volatile session-key loss could not be verified."))
			return stateErr
		}
		if state != KeyUnavailable {
			err := errors.New("volatile session key is not proven unavailable")
			report.addFailure(newFailure("RECOVERY_KEY_STATE_UNKNOWN", "Volatile session-key loss could not be verified."))
			return err
		}
		report.KeyLossVerifiedSessions++
	}

	// Pin the entire discovered ownership set before the first mutation. A
	// replacement or unverifiable later resource therefore causes zero cleanup
	// for this session.
	for _, candidate := range candidates {
		if err := r.revalidate(sessionCtx, candidate); err != nil {
			report.addFailure(withKind(classifyFailure(err, "RECOVERY_IDENTITY_REJECTED", "An orphan identity or private-vm ownership proof was rejected."), candidate.Kind))
			return err
		}
	}

	sortCandidates(candidates)
	for _, candidate := range candidates {
		if err := r.revalidate(sessionCtx, candidate); err != nil {
			report.addFailure(withKind(classifyFailure(err, "RECOVERY_IDENTITY_CHANGED", "An orphan identity changed immediately before cleanup."), candidate.Kind))
			return err
		}
		if err := withTimeout(sessionCtx, r.config.StepTimeout, func(ctx context.Context) error {
			return r.backend.Cleanup(ctx, candidate)
		}); err != nil {
			report.addFailure(withKind(classifyFailure(err, "RECOVERY_CLEANUP_FAILED", "An owned orphan could not be removed."), candidate.Kind))
			return err
		}
		if err := withTimeout(sessionCtx, r.config.StepTimeout, func(ctx context.Context) error {
			return r.backend.AuditAbsent(ctx, candidate)
		}); err != nil {
			report.addFailure(withKind(classifyFailure(err, "RECOVERY_ABSENCE_UNPROVEN", "An owned orphan could not be proven absent."), candidate.Kind))
			return err
		}
		report.ArtifactsRecovered.add(candidate.Kind)
	}
	if err := withTimeout(sessionCtx, r.config.StepTimeout, func(ctx context.Context) error {
		return r.backend.AuditSessionAbsent(ctx, id)
	}); err != nil {
		report.addFailure(classifyFailure(err, "RECOVERY_SESSION_ABSENCE_UNPROVEN", "The complete session resource set could not be proven absent."))
		return err
	}
	report.SessionsRecovered++
	return nil
}

func (r *Reconciler) validateAndGroup(candidates []Candidate, report *Report) (map[string][]Candidate, error) {
	grouped := make(map[string][]Candidate)
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if err := validateCandidate(candidate, r.config.DaemonUID); err != nil {
			report.addFailure(withKind(classifyFailure(err, "RECOVERY_IDENTITY_REJECTED", "An orphan inventory entry failed its closed identity contract."), candidate.Kind))
			return nil, err
		}
		key := candidate.SessionID + "\x00" + string(candidate.Kind) + "\x00" + candidate.Locator
		if _, exists := seen[key]; exists {
			err := errors.New("duplicate recovery artifact")
			report.addFailure(withKind(newFailure("RECOVERY_INVENTORY_DUPLICATE", "The orphan inventory contained a duplicate object."), candidate.Kind))
			return nil, err
		}
		seen[key] = struct{}{}
		grouped[candidate.SessionID] = append(grouped[candidate.SessionID], candidate)
		report.ArtifactsDiscovered.add(candidate.Kind)
	}
	return grouped, nil
}

func validateCandidate(candidate Candidate, daemonUID uint32) error {
	if err := session.ValidateID(candidate.SessionID); err != nil {
		return errors.New("invalid recovery session identity")
	}
	if _, ok := knownKind[candidate.Kind]; !ok {
		return errors.New("unknown recovery artifact kind")
	}
	switch candidate.Origin {
	case OriginVolatileRecord, OriginKernel, OriginScratch:
	default:
		return errors.New("unknown recovery inventory origin")
	}
	if len(candidate.Locator) == 0 || len(candidate.Locator) > 512 || strings.TrimSpace(candidate.Locator) != candidate.Locator || strings.IndexFunc(candidate.Locator, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("invalid recovery artifact locator")
	}
	if candidate.Identity.OwnerUID != daemonUID || !fingerprintPattern.MatchString(candidate.Identity.Fingerprint) {
		return errors.New("invalid recovery ownership identity")
	}
	return nil
}

func (r *Reconciler) inventory(ctx context.Context) ([]Candidate, error) {
	return withResultTimeout(ctx, r.config.InventoryTimeout, r.backend.Inventory)
}

func (r *Reconciler) revalidate(ctx context.Context, candidate Candidate) error {
	return withTimeout(ctx, r.config.StepTimeout, func(step context.Context) error {
		return r.backend.RevalidateOwned(step, candidate)
	})
}

func (r *Reconciler) snapshotBases(ctx context.Context) (BaseImageSeal, error) {
	seal, err := withResultTimeout(ctx, r.config.StepTimeout, r.bases.Snapshot)
	if err != nil {
		return BaseImageSeal{}, err
	}
	if seal.Count == 0 || seal.Count > uint32(r.config.MaxCandidates) || !fingerprintPattern.MatchString(seal.Fingerprint) {
		return BaseImageSeal{}, errors.New("invalid immutable base-image seal")
	}
	return seal, nil
}

func (r *Reconciler) verifyBases(seal BaseImageSeal) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.StepTimeout)
	defer cancel()
	return r.bases.Verify(ctx, seal)
}

func (r *Reconciler) verifyBasesAfterFailure(seal BaseImageSeal, report *Report) {
	if err := r.verifyBases(seal); err != nil {
		report.addFailure(classifyFailure(err, "RECOVERY_BASE_IMAGE_CHANGED", "Immutable base-image identity changed during recovery."))
		return
	}
	report.BaseImagesVerified = true
}

func sortedSessionIDs(grouped map[string][]Candidate) []string {
	ids := make([]string, 0, len(grouped))
	for id := range grouped {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func sortCandidates(candidates []Candidate) {
	sort.Slice(candidates, func(i, j int) bool {
		left, right := knownKind[candidates[i].Kind], knownKind[candidates[j].Kind]
		if left != right {
			return left < right
		}
		return candidates[i].Locator < candidates[j].Locator
	})
}

func hasStorage(candidates []Candidate) bool {
	for _, candidate := range candidates {
		switch candidate.Kind {
		case KindMount, KindMapper, KindLoop, KindCiphertext:
			return true
		}
	}
	return false
}

func withTimeout(parent context.Context, maximum time.Duration, operation func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(parent, maximum)
	defer cancel()
	return operation(ctx)
}

func withResultTimeout[T any](parent context.Context, maximum time.Duration, operation func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(parent, maximum)
	defer cancel()
	return operation(ctx)
}

// Error is deliberately safe under all ordinary formatting verbs. The wrapped
// cause is retained only for trusted errors.Is/errors.As classification.
type Error struct{ cause error }

func incompleteError(cause error) error { return &Error{cause: errors.Join(ErrIncomplete, cause)} }

func (e *Error) Error() string {
	return "ORPHAN_CLEANUP_FAILED: one or more owned resources could not be proven absent; preserve volatile recovery evidence and retry cleanup"
}

func (e *Error) GoString() string               { return e.Error() }
func (e *Error) Unwrap() error                  { return e.cause }
func (e *Error) Format(state fmt.State, _ rune) { _, _ = fmt.Fprint(state, e.Error()) }
