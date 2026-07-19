package qemu

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/session"
)

func TestRuntimeAllocationQMPFailureTriggersSessionCleanup(t *testing.T) {
	runtimeRoot := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(runtimeRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	store, err := session.NewStore(runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(store, session.DefaultMaxSessionsPerOwner)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Create(1000, session.RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	spec := validSpec(t)
	spec.SessionID = snapshot.ID
	cgroups := &fakeCgroupFactory{}
	launcher, err := NewLauncher(cgroups)
	if err != nil {
		t.Fatal(err)
	}
	launcher.commandBuilder = fakeQEMUCommand("qmp-disconnect-stays")
	launcher.qmpWait = 2 * time.Second
	launcher.graceWait = 20 * time.Millisecond
	launcher.termWait = 100 * time.Millisecond
	capability, err := os.CreateTemp(t.TempDir(), "capability")
	if err != nil {
		t.Fatal(err)
	}
	defer capability.Close()
	lease := &fakeRuntimeImageLease{}
	lease.active.Store(true)
	allocation := RuntimeAllocation(manager, launcher, 1000, spec, capability, func() (RuntimeImageLease, error) {
		return lease, nil
	})
	if err := manager.AcquireResource(t.Context(), snapshot.ID, 1000, "qemu-runtime", allocation); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		current, getErr := manager.Get(snapshot.ID, 1000)
		if getErr == nil && current.Phase == session.PhaseDestroyed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("QMP failure did not drive session cleanup: snapshot=%+v err=%v", current, getErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lease.active.Load() {
		t.Fatal("session cleanup left the verified image lease active")
	}
	if !cgroups.cleaned.Load() {
		t.Fatal("session cleanup left the QEMU cgroup active")
	}
}

type fakeRuntimeImageLease struct {
	active atomic.Bool
}

func (l *fakeRuntimeImageLease) Destroy() error {
	l.active.Store(false)
	return nil
}

func (l *fakeRuntimeImageLease) Audit() error {
	if l.active.Load() {
		return context.Canceled
	}
	return nil
}
