package session

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

type Role string

const (
	RoleWorkstation Role = "workstation"
	RoleDownloader  Role = "downloader"
	RoleScanner     Role = "scanner"
	RoleExporter    Role = "exporter"
)

// Phase is the top-level lifecycle from docs/05-state-machines.md. Role-specific
// workflow states are carried separately as safe event codes.
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

var transitions = map[Phase]map[Phase]bool{
	PhaseCreated:        {PhasePreflighted: true, PhaseAborting: true},
	PhasePreflighted:    {PhaseImagesVerified: true, PhaseAborting: true},
	PhaseImagesVerified: {PhaseStorageReady: true, PhaseAborting: true},
	PhaseStorageReady:   {PhaseActive: true, PhaseAborting: true},
	PhaseActive:         {PhaseStopping: true, PhaseAborting: true},
	PhaseStopping:       {PhaseDestroying: true, PhaseAborting: true},
	PhaseAborting:       {PhaseDestroying: true},
	PhaseDestroying:     {PhaseDestroyed: true},
}

var eventCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

var (
	ErrInvalidTransition = errors.New("invalid session transition")
	ErrUnauthorized      = errors.New("session owner mismatch")
	ErrNotFound          = errors.New("session not found")
	ErrQuotaExceeded     = errors.New("session quota exceeded")
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

func New(id string, role Role) (*Session, error) {
	return NewOwned(id, 0, role, time.Now().UTC())
}

func NewOwned(id string, ownerUID uint32, role Role, now time.Time) (*Session, error) {
	if err := ValidateRole(role); err != nil {
		return nil, err
	}
	if id == "" {
		return nil, errors.New("session id is required")
	}
	if now.IsZero() {
		return nil, errors.New("session creation time is required")
	}
	now = now.UTC()
	s := &Session{
		id:        id,
		ownerUID:  ownerUID,
		role:      role,
		phase:     PhaseCreated,
		sequence:  1,
		createdAt: now,
		updatedAt: now,
	}
	s.events = []Event{{Sequence: 1, Code: "SESSION_CREATED", Phase: PhaseCreated, Message: "Session record created.", Time: now}}
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

// Transition is retained for small unit-level state-machine use. The daemon
// uses Manager.Transition so mutations are serialized by the session owner.
func (s *Session) Transition(to Phase) error {
	return s.transition(to, string(to), "Session lifecycle advanced.", "", time.Now().UTC())
}

func (s *Session) transition(to Phase, code, message, workflowState string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !transitions[s.phase][to] {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, s.phase, to)
	}
	if err := validateEvent(code, message, workflowState); err != nil {
		return err
	}
	s.phase = to
	s.workflowState = workflowState
	s.sequence++
	s.updatedAt = now.UTC()
	s.events = appendBounded(s.events, Event{
		Sequence: s.sequence, Code: code, Phase: to, WorkflowState: workflowState,
		Message: message, Time: s.updatedAt,
	})
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
		ID:            s.id,
		OwnerUID:      s.ownerUID,
		Role:          s.role,
		Phase:         s.phase,
		WorkflowState: s.workflowState,
		Sequence:      s.sequence,
		CreatedAt:     s.createdAt,
		UpdatedAt:     s.updatedAt,
		Events:        append([]Event(nil), s.events...),
	}
}

func validateEvent(code, message, workflowState string) error {
	if !eventCodePattern.MatchString(code) {
		return errors.New("event code must be a stable uppercase identifier")
	}
	if len(message) == 0 || len(message) > 256 {
		return errors.New("event message must be between 1 and 256 bytes")
	}
	if len(workflowState) > 64 || (workflowState != "" && !eventCodePattern.MatchString(workflowState)) {
		return errors.New("workflow state must be empty or a stable uppercase identifier")
	}
	return nil
}

func appendBounded(events []Event, event Event) []Event {
	const maxEvents = 256
	if len(events) == maxEvents {
		copy(events, events[1:])
		events[len(events)-1] = event
		return events
	}
	return append(events, event)
}
