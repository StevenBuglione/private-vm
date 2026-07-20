package torrent

import (
	"context"
	"errors"
	"testing"
)

type fakeQuarantineBackend struct {
	mounted       bool
	formatted     int
	mounts        int
	prepared      int
	syncs         int
	unmounts      int
	audits        int
	closed        int
	failPrepare   bool
	failUnmount   bool
	cancelPrepare context.CancelFunc
}

func (backend *fakeQuarantineBackend) Mounted(context.Context) (bool, error) {
	return backend.mounted, nil
}
func (backend *fakeQuarantineBackend) PrepareFilesystem(context.Context) error {
	backend.formatted++
	return nil
}
func (backend *fakeQuarantineBackend) Mount(context.Context) error {
	backend.mounts++
	backend.mounted = true
	return nil
}
func (backend *fakeQuarantineBackend) PrepareDirectories(context.Context) error {
	backend.prepared++
	if backend.cancelPrepare != nil {
		backend.cancelPrepare()
	}
	if backend.failPrepare {
		return errors.New("fixture prepare failure")
	}
	return nil
}
func (backend *fakeQuarantineBackend) Sync(context.Context) error { backend.syncs++; return nil }
func (backend *fakeQuarantineBackend) Unmount(context.Context) error {
	backend.unmounts++
	if backend.failUnmount {
		return errors.New("fixture unmount failure")
	}
	backend.mounted = false
	return nil
}
func (backend *fakeQuarantineBackend) AuditAbsent(context.Context) error {
	backend.audits++
	if backend.mounted {
		return errors.New("fixture still mounted")
	}
	return nil
}
func (*fakeQuarantineBackend) CapacityBytes() (uint64, error) { return 8 << 30, nil }
func (backend *fakeQuarantineBackend) Close() error           { backend.closed++; return nil }

func TestQuarantineOwnerPreparesSyncsAndCleansIdempotently(t *testing.T) {
	backend := &fakeQuarantineBackend{}
	owner, err := newQuarantineOwner(backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Prepare(t.Context()); err != nil {
		t.Fatal(err)
	}
	if capacity, err := owner.CapacityBytes(t.Context()); err != nil || capacity != 8<<30 {
		t.Fatalf("capacity=%d err=%v", capacity, err)
	}
	if err := owner.SyncAndUnmount(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := owner.SyncAndUnmount(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if backend.formatted != 1 || backend.mounts != 1 || backend.prepared != 1 || backend.syncs != 1 || backend.unmounts != 1 || backend.audits != 3 || backend.closed != 1 {
		t.Fatalf("quarantine lifecycle = %+v", backend)
	}
}

func TestQuarantineOwnerCancellationAfterMountOwnsCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := &fakeQuarantineBackend{cancelPrepare: cancel}
	owner, err := newQuarantineOwner(backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Prepare(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Prepare cancellation = %v", err)
	}
	if backend.mounted || backend.unmounts != 1 || backend.audits != 1 {
		t.Fatalf("cancellation cleanup = %+v", backend)
	}
}

func TestQuarantineOwnerRetainsPreparationCleanupForRetry(t *testing.T) {
	backend := &fakeQuarantineBackend{failPrepare: true, failUnmount: true}
	owner, err := newQuarantineOwner(backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Prepare(t.Context()); err == nil || !owner.mounted {
		t.Fatalf("failed preparation lost cleanup ownership: err=%v mounted=%t", err, owner.mounted)
	}
	backend.failUnmount = false
	if err := owner.Close(t.Context()); err != nil {
		t.Fatalf("cleanup retry = %v", err)
	}
	if backend.mounted || backend.closed != 1 {
		t.Fatalf("cleanup retry state = %+v", backend)
	}
}

func TestQuarantineOwnerRetainsFailedUnmountForRetry(t *testing.T) {
	backend := &fakeQuarantineBackend{mounted: true, failUnmount: true}
	owner, _ := newQuarantineOwner(backend)
	if err := owner.Prepare(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := owner.SyncAndUnmount(t.Context()); err == nil {
		t.Fatal("failed unmount passed")
	}
	backend.failUnmount = false
	if err := owner.SyncAndUnmount(t.Context()); err != nil {
		t.Fatalf("retry unmount = %v", err)
	}
}
