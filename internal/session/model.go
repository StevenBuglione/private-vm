package session

import (
	"fmt"
	"sync"
)

type Role string

const (
	RoleWorkstation Role = "workstation"
	RoleDownloader  Role = "downloader"
	RoleScanner     Role = "scanner"
	RoleExporter    Role = "exporter"
)

type Phase string

const (
	PhaseCreated   Phase = "created"
	PhasePlanned   Phase = "planned"
	PhaseBooting   Phase = "booting"
	PhaseReady     Phase = "ready"
	PhaseRunning   Phase = "running"
	PhaseStopping  Phase = "stopping"
	PhaseSucceeded Phase = "succeeded"
	PhaseRejected  Phase = "rejected"
	PhaseAborting  Phase = "aborting"
	PhaseDestroyed Phase = "destroyed"
	PhaseFailed    Phase = "failed"
)

var transitions = map[Phase]map[Phase]bool{
	PhaseCreated:   {PhasePlanned: true, PhaseAborting: true},
	PhasePlanned:   {PhaseBooting: true, PhaseAborting: true},
	PhaseBooting:   {PhaseReady: true, PhaseFailed: true, PhaseAborting: true},
	PhaseReady:     {PhaseRunning: true, PhaseStopping: true, PhaseAborting: true},
	PhaseRunning:   {PhaseStopping: true, PhaseSucceeded: true, PhaseRejected: true, PhaseFailed: true, PhaseAborting: true},
	PhaseStopping:  {PhaseSucceeded: true, PhaseDestroyed: true, PhaseFailed: true},
	PhaseSucceeded: {PhaseDestroyed: true},
	PhaseRejected:  {PhaseDestroyed: true},
	PhaseFailed:    {PhaseAborting: true, PhaseDestroyed: true},
	PhaseAborting:  {PhaseDestroyed: true},
}

type Session struct {
	mu    sync.Mutex
	ID    string `json:"id"`
	Role  Role   `json:"role"`
	Phase Phase  `json:"phase"`
}

func New(id string, role Role) (*Session, error) {
	switch role {
	case RoleWorkstation, RoleDownloader, RoleScanner, RoleExporter:
	default:
		return nil, fmt.Errorf("unknown role %q", role)
	}
	if id == "" {
		return nil, fmt.Errorf("session id is required")
	}
	return &Session{ID: id, Role: role, Phase: PhaseCreated}, nil
}

func (s *Session) Transition(to Phase) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !transitions[s.Phase][to] {
		return fmt.Errorf("invalid transition %s -> %s", s.Phase, to)
	}
	s.Phase = to
	return nil
}
