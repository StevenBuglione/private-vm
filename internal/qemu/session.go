package qemu

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/StevenBuglione/private-vm/internal/session"
)

type RuntimeImageLease interface {
	Destroy() error
	Audit() error
}

type runtimeResource struct {
	process *Process
	images  RuntimeImageLease
}

// RuntimeAllocation binds the verified image lease, QEMU launch and process
// supervision to one session-actor allocation. A QMP loss or spontaneous QEMU
// death requests daemon-owned session cleanup without relying on the client.
func RuntimeAllocation(
	manager *session.Manager,
	launcher *Launcher,
	ownerUID uint32,
	spec Spec,
	capability *os.File,
	activateImages func() (RuntimeImageLease, error),
) session.AllocateFunc {
	return func(ctx context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		if manager == nil || launcher == nil || capability == nil || activateImages == nil {
			return nil, nil, errors.New("QEMU runtime allocation contract is incomplete")
		}
		snapshot, err := manager.Get(spec.SessionID, ownerUID)
		if err != nil || snapshot.Role != spec.Role {
			return nil, nil, errors.New("QEMU launch session identity or role does not match")
		}
		images, err := activateImages()
		if err != nil {
			if images != nil {
				return imageLeaseContract(images, err)
			}
			return nil, nil, errors.New("verified QEMU image lease could not be acquired")
		}
		if images == nil {
			return nil, nil, errors.New("verified QEMU image lease could not be acquired")
		}
		process, err := launcher.Launch(ctx, spec, capability)
		if err != nil {
			cleanupErr := images.Destroy()
			auditErr := images.Audit()
			if cleanupErr != nil || auditErr != nil {
				return imageLeaseContract(images, errors.Join(err, cleanupErr, auditErr))
			}
			return nil, nil, errors.Join(err, cleanupErr, auditErr)
		}
		resource := &runtimeResource{process: process, images: images}
		go func() {
			if err := process.Wait(context.Background()); err == nil {
				return
			}
			cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, _ = manager.Cleanup(cleanupContext, spec.SessionID, 0)
			cancel()
		}()
		return resource.Destroy, resource.Audit, nil
	}
}

func imageLeaseContract(images RuntimeImageLease, cause error) (session.CleanupFunc, session.AuditFunc, error) {
	return func(context.Context) error { return images.Destroy() },
		func(context.Context) error { return images.Audit() }, cause
}

func (r *runtimeResource) Destroy(ctx context.Context) error {
	if r == nil || r.process == nil || r.images == nil {
		return errors.New("QEMU runtime resource is invalid")
	}
	processErr := r.process.Cleanup(ctx)
	imageErr := r.images.Destroy()
	return errors.Join(processErr, imageErr)
}

func (r *runtimeResource) Audit(ctx context.Context) error {
	if r == nil || r.process == nil || r.images == nil {
		return errors.New("QEMU runtime resource is invalid")
	}
	return errors.Join(r.process.Audit(ctx), r.images.Audit())
}
