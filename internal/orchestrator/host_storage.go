package orchestrator

import (
	"context"
	"errors"
	"sync"

	"github.com/StevenBuglione/private-vm/internal/image"
	"github.com/StevenBuglione/private-vm/internal/qemu"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/storage"
)

type outerStorage interface {
	OuterPath() string
	CreateOpaqueFile(string, uint64) (string, error)
	Destroy(context.Context) error
	Audit(context.Context) error
}

// StorageStack composes capacity reservation, one bounded tmpfs or encrypted
// LUKS outer filesystem, a fresh root overlay and downloader quarantine bytes.
// It never mounts a guest or quarantine filesystem on the host.
type StorageStack struct {
	Capacity        *storage.CapacityPool
	Tmpfs           *storage.TmpfsManager
	LUKS            *storage.LUKSManager
	Overlays        storage.OverlayManager
	SmallScratchMax uint64
}

func (stack StorageStack) Allocate(ctx context.Context, snapshot session.Snapshot, plan session.LaunchPlan, verified image.RuntimeImage) (HostStorage, error) {
	if stack.Capacity == nil || stack.Tmpfs == nil || stack.LUKS == nil || stack.Overlays.Registry == nil ||
		session.ValidateID(snapshot.ID) != nil || snapshot.Role != plan.Role || verified.Entry.ImagePath == "" {
		return nil, ErrHostStorageUnavailable
	}
	expectedWrites, ok := addStorageBytes(plan.RootBytes, plan.ScratchBytes)
	if !ok || expectedWrites == 0 {
		return nil, ErrHostStorageUnavailable
	}
	request := storage.CapacityRequest{
		GuestRAMBytes: plan.MemoryBytes, ExpectedWritesBytes: expectedWrites,
		SmallScratchMax: stack.SmallScratchMax,
	}
	reservation, err := stack.Capacity.Reserve(snapshot.ID, request)
	if err != nil {
		return nil, err
	}
	resource := &hostStorageResource{reservation: reservation}
	fail := func(cause error) (HostStorage, error) {
		if cleanupErr := resource.Cleanup(context.Background()); cleanupErr != nil {
			return resource, errors.Join(cause, cleanupErr)
		}
		return nil, cause
	}

	capacityPlan := reservation.Plan()
	switch capacityPlan.Mode {
	case storage.ScratchModeRAM:
		handle, createErr := stack.Tmpfs.Create(ctx, snapshot.ID, capacityPlan.ReservedBytes)
		if handle != nil {
			resource.outer = handle
		}
		if createErr != nil {
			return fail(createErr)
		}
	case storage.ScratchModeLUKS:
		handle, createErr := stack.LUKS.Create(ctx, snapshot.ID, capacityPlan.ReservedBytes)
		if handle != nil {
			resource.outer = handle
		}
		if createErr != nil {
			return fail(createErr)
		}
	default:
		return fail(ErrHostStorageUnavailable)
	}
	if resource.outer == nil {
		return fail(ErrHostStorageUnavailable)
	}

	overlay, err := stack.Overlays.Create(ctx, resource.outer.OuterPath(), verified.Entry.ImagePath, rootOverlayName(snapshot.Role))
	if err != nil {
		return fail(err)
	}
	resource.overlay = overlay
	if snapshot.Role == session.RoleDownloader {
		if plan.ScratchBytes == 0 {
			return fail(ErrHostStorageUnavailable)
		}
		quarantine, err := resource.outer.CreateOpaqueFile("quarantine.raw", plan.ScratchBytes)
		if err != nil {
			return fail(err)
		}
		resource.quarantine = quarantine
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return resource, nil
}

type hostStorageResource struct {
	mu sync.Mutex

	reservation *storage.CapacityReservation
	outer       outerStorage
	overlay     *storage.OverlayHandle
	quarantine  string

	overlayClean     bool
	outerClean       bool
	reservationClean bool
}

func (resource *hostStorageResource) RootPath() string {
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.overlay == nil || resource.overlayClean {
		return ""
	}
	return resource.overlay.Path()
}

func (resource *hostStorageResource) QuarantinePath() string {
	resource.mu.Lock()
	defer resource.mu.Unlock()
	return resource.quarantine
}

func (resource *hostStorageResource) ActivateImages() (qemu.RuntimeImageLease, error) {
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.overlay == nil || resource.overlayClean || resource.outerClean {
		return nil, ErrHostStorageUnavailable
	}
	return resource.overlay.Activate()
}

func (resource *hostStorageResource) Cleanup(ctx context.Context) error {
	if resource == nil {
		return nil
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if !resource.overlayClean && resource.overlay != nil {
		if err := resource.overlay.Destroy(ctx); err != nil {
			return err
		}
		resource.overlayClean = true
		resource.quarantine = ""
	} else if resource.overlay == nil {
		resource.overlayClean = true
	}
	if !resource.outerClean && resource.outer != nil {
		if err := resource.outer.Destroy(ctx); err != nil {
			return err
		}
		resource.outerClean = true
	} else if resource.outer == nil {
		resource.outerClean = true
	}
	if !resource.reservationClean && resource.reservation != nil {
		if err := resource.reservation.Destroy(ctx); err != nil {
			return err
		}
		resource.reservationClean = true
	} else if resource.reservation == nil {
		resource.reservationClean = true
	}
	return nil
}

func (resource *hostStorageResource) Audit(ctx context.Context) error {
	if resource == nil {
		return ErrHostStorageUnavailable
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	var audits []error
	if !resource.overlayClean || (resource.overlay != nil && resource.overlay.Audit(ctx) != nil) {
		audits = append(audits, errors.New("root overlay remains active"))
	}
	if !resource.outerClean || (resource.outer != nil && resource.outer.Audit(ctx) != nil) {
		audits = append(audits, errors.New("outer session storage remains active"))
	}
	if !resource.reservationClean || (resource.reservation != nil && resource.reservation.Audit(ctx) != nil) {
		audits = append(audits, errors.New("capacity reservation remains active"))
	}
	return errors.Join(audits...)
}

func rootOverlayName(role session.Role) string {
	switch role {
	case session.RoleWorkstation:
		return "root-workstation.qcow2"
	case session.RoleDownloader:
		return "root-downloader.qcow2"
	case session.RoleScanner:
		return "root-scanner.qcow2"
	case session.RoleExporter:
		return "root-exporter.qcow2"
	default:
		return ""
	}
}

func addStorageBytes(left, right uint64) (uint64, bool) {
	result := left + right
	return result, result >= left
}

var _ HostStorageAllocator = StorageStack{}
