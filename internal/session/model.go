package session

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

const (
	maxSessionEvents    = 4096
	cleanupEventReserve = 3
)

type Role string

const (
	RoleWorkstation Role = "workstation"
	RoleDownloader  Role = "downloader"
	RoleScanner     Role = "scanner"
	RoleExporter    Role = "exporter"
)

// LaunchPlan is the closed, non-secret result of daemon-side selector and
// resource validation. It is retained only by the owning daemon process and is
// never added to the volatile session journal: a restarted daemon must recover
// resources, not resume a prior guest launch.
type LaunchPlan struct {
	Role         Role
	ImageBundle  string
	PolicyName   string
	VCPUs        uint32
	MemoryBytes  uint64
	RootBytes    uint64
	ScratchBytes uint64
}

// Phase is the top-level lifecycle from docs/05-state-machines.md. Role-specific
// workflow states are tracked separately and may advance only through the
// closed, role-specific transition tables below.
type Phase string

const (
	PhaseCreated        Phase = "CREATED"
	PhasePreflighted    Phase = "PREFLIGHTED"
	PhaseImagesVerified Phase = "IMAGES_VERIFIED"
	PhaseStorageReady   Phase = "STORAGE_READY"
	PhaseActive         Phase = "ACTIVE"
	PhaseStopping       Phase = "STOPPING"
	PhaseAborting       Phase = "ABORTING"
	PhaseDestroying     Phase = "DESTROYING"
	PhaseDestroyed      Phase = "DESTROYED"
)

var lifecycleTransitions = map[Phase]map[Phase]bool{
	PhaseCreated:        {PhasePreflighted: true, PhaseAborting: true},
	PhasePreflighted:    {PhaseImagesVerified: true, PhaseAborting: true},
	PhaseImagesVerified: {PhaseStorageReady: true, PhaseAborting: true},
	PhaseStorageReady:   {PhaseActive: true, PhaseAborting: true},
	PhaseActive:         {PhaseStopping: true, PhaseAborting: true},
	PhaseStopping:       {PhaseDestroying: true, PhaseAborting: true},
	PhaseAborting:       {PhaseDestroying: true},
	PhaseDestroying:     {PhaseDestroyed: true},
}

var lifecycleEvents = map[Phase]struct {
	code    string
	message string
}{
	PhasePreflighted:    {"SESSION_PREFLIGHTED", "Host preflight completed."},
	PhaseImagesVerified: {"SESSION_IMAGES_VERIFIED", "Guest image verification completed."},
	PhaseStorageReady:   {"SESSION_STORAGE_READY", "Session storage is ready."},
	PhaseActive:         {"SESSION_ACTIVE", "The session is active."},
	PhaseStopping:       {"SESSION_STOPPING", "A protected stop was requested."},
	PhaseAborting:       {"SESSION_ABORTING", "Session cleanup was requested."},
	PhaseDestroying:     {"SESSION_DESTROYING", "Owned resources are being released."},
	PhaseDestroyed:      {"SESSION_DESTROYED", "The resource absence audit completed."},
}

var workflowTransitions = map[Role]map[string]map[string]bool{
	RoleWorkstation: workstationWorkflow(),
	RoleDownloader:  downloaderWorkflow(),
	RoleScanner:     scannerWorkflow(),
	RoleExporter: linearWorkflow(
		"PLANNED", "USB_IDENTIFIED", "USB_CLAIMED", "EXPORTER_BOOTING",
		"GUEST_AUTHENTICATED", "NO_NETWORK_VERIFIED", "USB_ATTACHED",
		"DESTINATION_PREPARED", "STREAMING", "STREAM_COMPLETE", "FLUSHED",
		"POST_WRITE_VERIFIED", "USB_UNMOUNTED", "USB_DETACHED", "EXPORTER_STOPPED",
	),
}

var eventCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

var (
	ErrInvalidTransition       = errors.New("invalid session transition")
	ErrInvalidWorkflow         = errors.New("invalid role workflow transition")
	ErrUnauthorized            = errors.New("session owner mismatch")
	ErrNotFound                = errors.New("session not found")
	ErrQuotaExceeded           = errors.New("session quota exceeded")
	ErrCleanupIncomplete       = errors.New("session cleanup incomplete")
	ErrEventLimit              = errors.New("session event limit reached")
	ErrEventCursor             = errors.New("invalid session event cursor")
	ErrSubscriberSlow          = errors.New("session event subscriber is too slow")
	ErrDuplicateResource       = errors.New("duplicate session resource")
	ErrResourceRegistrationEnd = errors.New("session no longer accepts resources")
	ErrManagerShuttingDown     = errors.New("session manager is shutting down")
)

type Event struct {
	Sequence      uint64    `json:"sequence"`
	Code          string    `json:"code"`
	Phase         Phase     `json:"phase"`
	WorkflowState string    `json:"workflow_state,omitempty"`
	Message       string    `json:"message"`
	Time          time.Time `json:"time"`
}

type Snapshot struct {
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"id"`
	OwnerUID      uint32    `json:"owner_uid"`
	Role          Role      `json:"role"`
	Phase         Phase     `json:"phase"`
	WorkflowState string    `json:"workflow_state,omitempty"`
	Sequence      uint64    `json:"sequence"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Events        []Event   `json:"events"`
}

// Session has no exported mutation method. A Manager actor is the sole
// production transition owner; the mutex permits concurrent read-only snapshots.
type Session struct {
	mu            sync.RWMutex
	id            string
	ownerUID      uint32
	role          Role
	phase         Phase
	workflowState string
	sequence      uint64
	createdAt     time.Time
	updatedAt     time.Time
	events        []Event
}

func newOwned(id string, ownerUID uint32, role Role, now time.Time) (*Session, error) {
	if err := ValidateRole(role); err != nil {
		return nil, err
	}
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, errors.New("session creation time is required")
	}
	now = now.UTC()
	s := &Session{
		id: id, ownerUID: ownerUID, role: role, phase: PhaseCreated,
		sequence: 1, createdAt: now, updatedAt: now,
	}
	s.events = []Event{{
		Sequence: 1, Code: "SESSION_CREATED", Phase: PhaseCreated,
		Message: "Session record created.", Time: now,
	}}
	return s, nil
}

func ValidateRole(role Role) error {
	switch role {
	case RoleWorkstation, RoleDownloader, RoleScanner, RoleExporter:
		return nil
	default:
		return fmt.Errorf("unknown role %q", role)
	}
}

func validPhase(phase Phase) bool {
	switch phase {
	case PhaseCreated, PhasePreflighted, PhaseImagesVerified, PhaseStorageReady,
		PhaseActive, PhaseStopping, PhaseAborting, PhaseDestroying, PhaseDestroyed:
		return true
	default:
		return false
	}
}

func (s *Session) transitionLifecycle(to Phase, cleanupOwned bool, now time.Time) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !lifecycleTransitions[s.phase][to] {
		return Event{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, s.phase, to)
	}
	if !cleanupOwned && (to == PhaseDestroying || to == PhaseDestroyed) {
		return Event{}, fmt.Errorf("%w: %s is cleanup-owned", ErrInvalidTransition, to)
	}
	if err := s.requireEventRoom(cleanupOwned); err != nil {
		return Event{}, err
	}
	detail, ok := lifecycleEvents[to]
	if !ok {
		return Event{}, fmt.Errorf("%w: no event for %s", ErrInvalidTransition, to)
	}
	s.phase = to
	return s.appendEventLocked(detail.code, detail.message, now), nil
}

func (s *Session) transitionWorkflow(to string, now time.Time) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == PhaseStopping || s.phase == PhaseAborting || s.phase == PhaseDestroying || s.phase == PhaseDestroyed {
		return Event{}, fmt.Errorf("%w: lifecycle phase %s", ErrInvalidWorkflow, s.phase)
	}
	if !workflowTransitions[s.role][s.workflowState][to] {
		return Event{}, fmt.Errorf("%w: %s %q -> %q", ErrInvalidWorkflow, s.role, s.workflowState, to)
	}
	if err := s.requireEventRoom(false); err != nil {
		return Event{}, err
	}
	s.workflowState = to
	return s.appendEventLocked("WORKFLOW_STATE_CHANGED", "Role workflow advanced.", now), nil
}

func (s *Session) appendEventLocked(code, message string, now time.Time) Event {
	now = now.UTC()
	s.sequence++
	s.updatedAt = now
	event := Event{
		Sequence: s.sequence, Code: code, Phase: s.phase,
		WorkflowState: s.workflowState, Message: message, Time: now,
	}
	s.events = append(s.events, event)
	return event
}

func (s *Session) requireEventRoom(cleanupOwned bool) error {
	limit := maxSessionEvents - cleanupEventReserve
	if cleanupOwned {
		limit = maxSessionEvents
	}
	if len(s.events) >= limit {
		return ErrEventLimit
	}
	return nil
}

func (s *Session) restore(snapshot Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phase = snapshot.Phase
	s.workflowState = snapshot.WorkflowState
	s.sequence = snapshot.Sequence
	s.updatedAt = snapshot.UpdatedAt
	s.events = append([]Event(nil), snapshot.Events...)
}

func (s *Session) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Snapshot{
		SchemaVersion: 1,
		ID:            s.id, OwnerUID: s.ownerUID, Role: s.role, Phase: s.phase,
		WorkflowState: s.workflowState, Sequence: s.sequence,
		CreatedAt: s.createdAt, UpdatedAt: s.updatedAt,
		Events: append([]Event(nil), s.events...),
	}
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.SchemaVersion != 1 {
		return errors.New("unsupported volatile session schema version")
	}
	if err := ValidateID(snapshot.ID); err != nil {
		return err
	}
	if err := ValidateRole(snapshot.Role); err != nil {
		return err
	}
	if !validPhase(snapshot.Phase) {
		return errors.New("invalid volatile session phase")
	}
	if snapshot.CreatedAt.IsZero() || snapshot.UpdatedAt.Before(snapshot.CreatedAt) {
		return errors.New("invalid volatile session timestamps")
	}
	if len(snapshot.Events) == 0 || len(snapshot.Events) > maxSessionEvents {
		return errors.New("invalid volatile session event count")
	}

	first := snapshot.Events[0]
	if first.Sequence != 1 || first.Code != "SESSION_CREATED" || first.Phase != PhaseCreated ||
		first.WorkflowState != "" || first.Message != "Session record created." ||
		!first.Time.Equal(snapshot.CreatedAt) {
		return errors.New("volatile session journal has an invalid creation event")
	}

	currentPhase := PhaseCreated
	currentWorkflow := ""
	previousTime := first.Time
	for index, event := range snapshot.Events {
		expected := uint64(index + 1)
		if event.Sequence != expected {
			return errors.New("invalid volatile session event sequence")
		}
		if err := validateEvent(event.Code, event.Message); err != nil {
			return err
		}
		if event.Time.Before(previousTime) || event.Time.After(snapshot.UpdatedAt) {
			return errors.New("invalid volatile session event timestamp")
		}
		if index == 0 {
			continue
		}

		switch event.Code {
		case "WORKFLOW_STATE_CHANGED":
			if event.Phase != currentPhase ||
				!workflowTransitions[snapshot.Role][currentWorkflow][event.WorkflowState] {
				return errors.New("invalid volatile workflow event transition")
			}
			if currentPhase == PhaseStopping || currentPhase == PhaseAborting ||
				currentPhase == PhaseDestroying || currentPhase == PhaseDestroyed {
				return errors.New("volatile workflow event occurs after cleanup started")
			}
			currentWorkflow = event.WorkflowState
		default:
			detail, ok := lifecycleEvents[event.Phase]
			if !ok || event.Code != detail.code || event.Message != detail.message ||
				event.WorkflowState != currentWorkflow ||
				!lifecycleTransitions[currentPhase][event.Phase] {
				return errors.New("invalid volatile lifecycle event transition")
			}
			currentPhase = event.Phase
		}
		previousTime = event.Time
	}
	last := snapshot.Events[len(snapshot.Events)-1]
	if snapshot.Sequence != last.Sequence || snapshot.Phase != currentPhase ||
		snapshot.WorkflowState != currentWorkflow || !snapshot.UpdatedAt.Equal(last.Time) {
		return errors.New("volatile session snapshot does not match its final event")
	}
	return nil
}

func validateEvent(code, message string) error {
	if !eventCodePattern.MatchString(code) {
		return errors.New("event code must be a stable uppercase identifier")
	}
	expected, ok := safeEventMessages()[code]
	if !ok || message != expected {
		return errors.New("event message is not from the safe event catalog")
	}
	return nil
}

func safeEventMessages() map[string]string {
	result := map[string]string{
		"SESSION_CREATED":        "Session record created.",
		"WORKFLOW_STATE_CHANGED": "Role workflow advanced.",
	}
	for _, detail := range lifecycleEvents {
		result[detail.code] = detail.message
	}
	return result
}

func linearWorkflow(states ...string) map[string]map[string]bool {
	result := make(map[string]map[string]bool, len(states))
	from := ""
	for _, state := range states {
		result[from] = map[string]bool{state: true}
		from = state
	}
	return result
}

func workstationWorkflow() map[string]map[string]bool {
	result := linearWorkflow(
		"PLANNED", "IMAGE_READY", "STORAGE_READY", "NETWORK_READY", "VM_BOOTING",
		"GUEST_AUTHENTICATED", "VPN_CONFIGURED", "VPN_VERIFIED", "DISPLAY_READY",
		"WORKING", "EXPORT_REQUIRED", "STOP_REQUESTED", "OUTPUT_VERIFIED",
		"VM_STOPPED", "SESSION_DESTROYED",
	)
	result["WORKING"] = map[string]bool{"EXPORT_REQUIRED": true, "CLEAN": true}
	result["CLEAN"] = map[string]bool{"STOP_REQUESTED": true}
	return result
}

func scannerWorkflow() map[string]map[string]bool {
	result := linearWorkflow(
		"UPDATE_VM_BOOTING", "DEFINITIONS_UPDATING", "DEFINITIONS_VERIFIED",
		"UPDATE_VM_STOPPED", "SCAN_VM_BOOTING_OFFLINE", "OFFLINE_VERIFIED",
		"QUARANTINE_ATTACHED_READ_ONLY", "INVENTORY_COMPLETE", "MALWARE_SCAN_COMPLETE",
		"RECONSTRUCTION_COMPLETE", "REPORT_COMPLETE", "POLICY_APPROVED", "SCAN_VM_STOPPED",
	)
	result["REPORT_COMPLETE"] = map[string]bool{"POLICY_APPROVED": true, "POLICY_REJECTED": true}
	result["POLICY_REJECTED"] = map[string]bool{"SCAN_VM_STOPPED": true}
	return result
}

func downloaderWorkflow() map[string]map[string]bool {
	result := linearWorkflow(
		"PLANNED", "SCANNER_UPDATE_PREPARED", "DOWNLOADER_BOOTING", "GUEST_AUTHENTICATED",
		"VPN_CONFIGURED", "VPN_VERIFIED", "METADATA_FETCHING", "METADATA_READY",
		"FILE_SELECTION_REQUIRED", "CAPACITY_VERIFIED", "DOWNLOADING", "DOWNLOAD_COMPLETE",
		"DOWNLOADER_STOPPED", "QUARANTINE_SEALED",
	)
	result["DOWNLOADING"] = map[string]bool{"DOWNLOAD_PAUSED": true, "DOWNLOAD_COMPLETE": true}
	result["DOWNLOAD_PAUSED"] = map[string]bool{"DOWNLOADING": true, "DOWNLOAD_COMPLETE": true}
	return result
}
