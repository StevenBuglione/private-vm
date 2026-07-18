package session

import "testing"

func TestSessionTransitions(t *testing.T) {
	s, err := New("test", RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(PhasePlanned); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(PhaseDestroyed); err == nil {
		t.Fatal("expected invalid transition")
	}
}
