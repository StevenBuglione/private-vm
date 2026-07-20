package torrent

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

type quarantineBackend interface {
	Mounted(context.Context) (bool, error)
	PrepareFilesystem(context.Context) error
	Mount(context.Context) error
	PrepareDirectories(context.Context) error
	Sync(context.Context) error
	Unmount(context.Context) error
	AuditAbsent(context.Context) error
	CapacityBytes() (uint64, error)
	Close() error
}

func (owner *QuarantineOwner) CapacityBytes(ctx context.Context) (uint64, error) {
	if owner == nil || ctx == nil {
		return 0, invalidRequest()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || !owner.mounted {
		return 0, invalidRequest()
	}
	capacity, err := owner.backend.CapacityBytes()
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return capacity, nil
}

// QuarantineOwner is the one guest-side mount/format/teardown owner. Its
// Linux backend can address only the fixed virtio-quarantine device and mount.
type QuarantineOwner struct {
	mu      sync.Mutex
	backend quarantineBackend
	mounted bool
	closed  bool
}

func newQuarantineOwner(backend quarantineBackend) (*QuarantineOwner, error) {
	if nilLikeQuarantine(backend) {
		return nil, invalidRequest()
	}
	return &QuarantineOwner{backend: backend}, nil
}

func (owner *QuarantineOwner) Prepare(ctx context.Context) error {
	if owner == nil || ctx == nil {
		return invalidRequest()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return invalidRequest()
	}
	if owner.mounted {
		return nil
	}
	mounted, err := owner.backend.Mounted(ctx)
	if err != nil {
		return errors.New("quarantine mount evidence unavailable")
	}
	if !mounted {
		if err := owner.backend.PrepareFilesystem(ctx); err != nil {
			return errors.New("quarantine filesystem preparation failed")
		}
		if err := owner.backend.Mount(ctx); err != nil {
			return fmt.Errorf("quarantine mount failed: %w", err)
		}
	}
	owner.mounted = true
	if err := owner.backend.PrepareDirectories(ctx); err != nil || ctx.Err() != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		unmountErr := owner.backend.Unmount(cleanupCtx)
		auditErr := owner.backend.AuditAbsent(cleanupCtx)
		cancel()
		if unmountErr != nil || auditErr != nil {
			// Preserve ownership so Close can retry instead of losing a live
			// guest mount after a partially failed preparation.
			owner.mounted = true
			return errors.New("quarantine preparation cleanup incomplete")
		}
		owner.mounted = false
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("quarantine directory preparation failed")
	}
	return nil
}

func (owner *QuarantineOwner) SyncAndUnmount(ctx context.Context) error {
	if owner == nil || ctx == nil {
		return invalidRequest()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if !owner.mounted {
		return owner.backend.AuditAbsent(ctx)
	}
	if err := owner.backend.Sync(ctx); err != nil {
		return errors.New("quarantine sync failed")
	}
	if err := owner.backend.Unmount(ctx); err != nil {
		return errors.New("quarantine unmount failed")
	}
	if err := owner.backend.AuditAbsent(ctx); err != nil {
		return errors.New("quarantine absence audit failed")
	}
	owner.mounted = false
	return nil
}

func (owner *QuarantineOwner) Close(ctx context.Context) error {
	if owner == nil {
		return nil
	}
	if err := owner.SyncAndUnmount(ctx); err != nil {
		return err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return nil
	}
	if err := owner.backend.Close(); err != nil {
		return errors.New("quarantine device close failed")
	}
	owner.closed = true
	return nil
}

func nilLikeQuarantine(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ Quarantine = (*QuarantineOwner)(nil)
