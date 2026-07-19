package storage

import (
	"context"
	"errors"

	"github.com/StevenBuglione/private-vm/internal/session"
)

// CapacityAllocation reserves the immutable host-capacity snapshot through the
// same actor boundary as all other session resources. The returned plan is
// available only after AcquireResource succeeds.
func CapacityAllocation(pool *CapacityPool, sessionID string, request CapacityRequest, selected *CapacityPlan) session.AllocateFunc {
	return func(context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		if pool == nil || selected == nil {
			return nil, nil, errors.New("capacity pool and plan destination are required")
		}
		reservation, err := pool.Reserve(sessionID, request)
		if err != nil {
			return nil, nil, err
		}
		*selected = reservation.Plan()
		return reservation.Destroy, reservation.Audit, nil
	}
}

// OverlayAllocation binds overlay creation and its absence audit into the
// session actor's atomic allocation/cleanup-registration boundary.
func OverlayAllocation(manager OverlayManager, outerDirectory, basePath, name string) session.AllocateFunc {
	return func(ctx context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		handle, err := manager.Create(ctx, outerDirectory, basePath, name)
		if err != nil {
			return nil, nil, err
		}
		return handle.Destroy, handle.Audit, nil
	}
}

func TmpfsAllocation(manager *TmpfsManager, sessionID string, capacityBytes uint64) session.AllocateFunc {
	return func(ctx context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		if manager == nil {
			return nil, nil, errors.New("tmpfs manager is required")
		}
		handle, err := manager.Create(ctx, sessionID, capacityBytes)
		if err != nil {
			if handle != nil {
				return handle.Destroy, handle.Audit, err
			}
			return nil, nil, err
		}
		return handle.Destroy, handle.Audit, nil
	}
}

func LUKSAllocation(manager *LUKSManager, sessionID string, sizeBytes uint64) session.AllocateFunc {
	return func(ctx context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		if manager == nil {
			return nil, nil, errors.New("LUKS manager is required")
		}
		handle, err := manager.Create(ctx, sessionID, sizeBytes)
		if err != nil {
			if handle != nil {
				return handle.Destroy, handle.Audit, err
			}
			return nil, nil, err
		}
		return handle.Destroy, handle.Audit, nil
	}
}
