package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestSessionTransitionsMatchDocumentedLifecycle(t *testing.T) {
	s, err := New("test", RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []Phase{PhasePreflighted, PhaseImagesVerified, PhaseStorageReady, PhaseActive, PhaseStopping, PhaseDestroying, PhaseDestroyed} {
		if err := s.Transition(phase); err != nil {
			t.Fatalf("transition to %s: %v", phase, err)
		}
	}
	if err := s.Transition(PhaseActive); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected invalid transition, got %v", err)
	}
}

func TestManagerOwnershipQuotaAndVolatileRecord(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(store, 1)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Create(1000, RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(1000, RoleDownloader); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected quota error, got %v", err)
	}
	if _, err := manager.Get(snapshot.ID, 1001); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected owner rejection, got %v", err)
	}
	info, err := os.Stat(filepath.Join(store.Root(), snapshot.ID))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("session directory mode is %o", info.Mode().Perm())
	}
}

func TestManagerSerializesTransitionsAndRetriesCleanup(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(store, 4)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Create(1000, RoleScanner)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, transition := range []struct {
		phase Phase
		code  string
	}{
		{PhasePreflighted, "HOST_PREFLIGHT_PASSED"},
		{PhaseImagesVerified, "IMAGES_VERIFIED"},
		{PhaseStorageReady, "STORAGE_READY"},
		{PhaseActive, "SCAN_VM_ACTIVE"},
	} {
		if _, err := manager.Transition(ctx, snapshot.ID, 1000, transition.phase, transition.code, "Safe transition event.", transition.code); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int32
	if err := manager.RegisterCleanup(ctx, snapshot.ID, 1000, "test-resource", func(context.Context) error {
		if calls.Add(1) == 1 {
			return errors.New("injected cleanup failure")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Cleanup(ctx, snapshot.ID, 1000); err == nil {
		t.Fatal("expected injected cleanup failure")
	}
	final, err := manager.Cleanup(ctx, snapshot.ID, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if final.Phase != PhaseDestroyed || calls.Load() != 2 {
		t.Fatalf("unexpected cleanup result: phase=%s calls=%d", final.Phase, calls.Load())
	}
	if _, err := os.Stat(filepath.Join(store.Root(), snapshot.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("volatile record remains after cleanup: %v", err)
	}
	repeated, err := manager.Cleanup(ctx, snapshot.ID, 1000)
	if err != nil || repeated.Phase != PhaseDestroyed {
		t.Fatalf("repeated cleanup was not idempotent: snapshot=%v err=%v", repeated, err)
	}
}
