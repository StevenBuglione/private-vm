package orchestrator

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/image"
	"github.com/StevenBuglione/private-vm/internal/qemu"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/torrent"
)

var (
	ErrHostPlanUnavailable    = errors.New("validated host role plan unavailable")
	ErrHostRoleUnavailable    = errors.New("host role is not implemented by the production runtime")
	ErrHostImageUnavailable   = errors.New("verified host role image unavailable")
	ErrHostStorageUnavailable = errors.New("host role storage unavailable")
	ErrHostRuntimeUnavailable = errors.New("host role runtime unavailable")
)

type HostImageSelector interface {
	Select(context.Context, session.Snapshot, session.LaunchPlan) (image.RuntimeImage, error)
}

type HostStorage interface {
	RootPath() string
	QuarantinePath() string
	ActivateImages() (qemu.RuntimeImageLease, error)
	Cleanup(context.Context) error
	Audit(context.Context) error
}

type HostStorageAllocator interface {
	Allocate(context.Context, session.Snapshot, session.LaunchPlan, image.RuntimeImage) (HostStorage, error)
}

type HostRuntimeRequest struct {
	Snapshot session.Snapshot
	Plan     session.LaunchPlan
	Image    image.RuntimeImage
	Storage  HostStorage
}

type HostRuntime interface {
	Stop(context.Context, bool) error
	Audit(context.Context) error
	WorkspaceState(context.Context) (string, error)
	Torrent() (TorrentRelay, error)
}

type HostRuntimeStarter interface {
	Start(context.Context, HostRuntimeRequest) (HostRuntime, error)
}

type HostRuntimePreparer interface {
	Prepare(context.Context, session.Snapshot, session.LaunchPlan) error
	Forget(string)
}

// TorrentRelay is the exact downloader guest surface exposed back to the
// daemon. It contains no generic gRPC client, qBittorrent URL, path, token,
// VSOCK CID, QEMU argument or host device selector.
type TorrentRelay interface {
	Add(context.Context, torrent.InputKind, io.Reader) (*privatevmv1.TorrentMetadata, error)
	Metadata(context.Context) (*privatevmv1.TorrentMetadata, error)
	Select(context.Context, []uint32) (*privatevmv1.TorrentMetadata, error)
	Start(context.Context, func(*privatevmv1.TorrentEvent) error) error
	Pause(context.Context) (*privatevmv1.TorrentStatus, error)
	Status(context.Context) (*privatevmv1.TorrentStatus, error)
	Seal(context.Context) (*privatevmv1.TorrentStatus, error)
}

type hostRoleState struct {
	plan    session.LaunchPlan
	image   image.RuntimeImage
	storage HostStorage
	runtime HostRuntime
}

// HostRoles is the daemon's production workstation/downloader owner. Each map
// entry is born through PlanAllocation inside the session actor and is removed
// by that actor's final reverse-order cleanup step.
type HostRoles struct {
	mu sync.Mutex

	PreflightCheck func(context.Context, session.Snapshot, session.LaunchPlan) error
	Images         HostImageSelector
	Storage        HostStorageAllocator
	Runtime        HostRuntimeStarter
	states         map[string]*hostRoleState
}

func NewHostRoles(images HostImageSelector, storage HostStorageAllocator, runtime HostRuntimeStarter) (*HostRoles, error) {
	if nilLikeHost(images) || nilLikeHost(storage) || nilLikeHost(runtime) {
		return nil, errors.New("host role composition is incomplete")
	}
	return &HostRoles{Images: images, Storage: storage, Runtime: runtime, states: make(map[string]*hostRoleState)}, nil
}

func (roles *HostRoles) PlanAllocation(snapshot session.Snapshot, plan session.LaunchPlan) session.AllocateFunc {
	return func(context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		if roles == nil || session.ValidateID(snapshot.ID) != nil || snapshot.Role != plan.Role ||
			plan.VCPUs == 0 || plan.MemoryBytes == 0 || plan.RootBytes == 0 {
			return nil, nil, ErrHostPlanUnavailable
		}
		roles.mu.Lock()
		if roles.states == nil || roles.states[snapshot.ID] != nil {
			roles.mu.Unlock()
			return nil, nil, ErrHostPlanUnavailable
		}
		state := &hostRoleState{plan: plan}
		roles.states[snapshot.ID] = state
		roles.mu.Unlock()
		cleanup := func(context.Context) error {
			roles.mu.Lock()
			current := roles.states[snapshot.ID]
			if current == nil {
				roles.mu.Unlock()
				return nil
			}
			if current != state || current.runtime != nil || current.storage != nil {
				roles.mu.Unlock()
				return ErrHostPlanUnavailable
			}
			delete(roles.states, snapshot.ID)
			roles.mu.Unlock()
			if preparer, ok := roles.Runtime.(HostRuntimePreparer); ok {
				preparer.Forget(snapshot.ID)
			}
			return nil
		}
		audit := func(context.Context) error {
			roles.mu.Lock()
			defer roles.mu.Unlock()
			if roles.states[snapshot.ID] != nil {
				return ErrHostPlanUnavailable
			}
			return nil
		}
		return cleanup, audit, nil
	}
}

func (roles *HostRoles) Preflight(ctx context.Context, snapshot session.Snapshot) error {
	state, err := roles.state(snapshot)
	if err != nil {
		return err
	}
	if snapshot.Role != session.RoleWorkstation && snapshot.Role != session.RoleDownloader {
		return ErrHostRoleUnavailable
	}
	if roles.PreflightCheck != nil {
		if err := roles.PreflightCheck(ctx, snapshot, state.plan); err != nil {
			return err
		}
	}
	if preparer, ok := roles.Runtime.(HostRuntimePreparer); ok {
		return preparer.Prepare(ctx, snapshot, state.plan)
	}
	return nil
}

func (roles *HostRoles) VerifyImages(ctx context.Context, snapshot session.Snapshot) error {
	state, err := roles.state(snapshot)
	if err != nil {
		return err
	}
	selected, err := roles.Images.Select(ctx, snapshot, state.plan)
	if err != nil {
		return errors.Join(ErrHostImageUnavailable, err)
	}
	if selected.Entry.ImagePath == "" || selected.ManifestDigest == "" || selected.ImageDigest == "" || selected.SourceCommit == "" || selected.VirtualSizeBytes == 0 ||
		state.plan.RootBytes > selected.VirtualSizeBytes {
		return ErrHostImageUnavailable
	}
	roles.mu.Lock()
	defer roles.mu.Unlock()
	if roles.states[snapshot.ID] != state || state.image.ManifestDigest != "" {
		return ErrHostImageUnavailable
	}
	state.image = selected
	return nil
}

func (roles *HostRoles) StorageAllocation(snapshot session.Snapshot) session.AllocateFunc {
	return func(ctx context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		state, err := roles.state(snapshot)
		if err != nil {
			return nil, nil, ErrHostImageUnavailable
		}
		roles.mu.Lock()
		selected := state.image
		roles.mu.Unlock()
		if selected.ManifestDigest == "" {
			return nil, nil, ErrHostImageUnavailable
		}
		resource, allocationErr := roles.Storage.Allocate(ctx, snapshot, state.plan, selected)
		if resource == nil {
			return nil, nil, errors.Join(ErrHostStorageUnavailable, allocationErr)
		}
		roles.mu.Lock()
		if roles.states[snapshot.ID] != state || state.storage != nil {
			roles.mu.Unlock()
			cleanupErr := resource.Cleanup(context.Background())
			return nil, nil, errors.Join(ErrHostStorageUnavailable, allocationErr, cleanupErr)
		}
		state.storage = resource
		roles.mu.Unlock()
		cleanup := func(cleanupCtx context.Context) error {
			if err := resource.Cleanup(cleanupCtx); err != nil {
				return err
			}
			roles.mu.Lock()
			if roles.states[snapshot.ID] == state && state.storage == resource {
				state.storage = nil
			}
			roles.mu.Unlock()
			return nil
		}
		audit := func(auditCtx context.Context) error { return resource.Audit(auditCtx) }
		if allocationErr != nil {
			return cleanup, audit, errors.Join(ErrHostStorageUnavailable, allocationErr)
		}
		return cleanup, audit, nil
	}
}

func (roles *HostRoles) RuntimeAllocation(snapshot session.Snapshot) session.AllocateFunc {
	return func(ctx context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		state, err := roles.state(snapshot)
		if err != nil {
			return nil, nil, ErrHostStorageUnavailable
		}
		roles.mu.Lock()
		storageResource := state.storage
		selected := state.image
		plan := state.plan
		roles.mu.Unlock()
		if storageResource == nil || selected.ManifestDigest == "" {
			return nil, nil, ErrHostStorageUnavailable
		}
		resource, allocationErr := roles.Runtime.Start(ctx, HostRuntimeRequest{Snapshot: snapshot, Plan: plan, Image: selected, Storage: storageResource})
		if resource == nil {
			return nil, nil, errors.Join(ErrHostRuntimeUnavailable, allocationErr)
		}
		roles.mu.Lock()
		if roles.states[snapshot.ID] != state || state.runtime != nil {
			roles.mu.Unlock()
			cleanupErr := resource.Stop(context.Background(), true)
			return nil, nil, errors.Join(ErrHostRuntimeUnavailable, allocationErr, cleanupErr)
		}
		state.runtime = resource
		roles.mu.Unlock()
		cleanup := func(cleanupCtx context.Context) error {
			if err := resource.Stop(cleanupCtx, true); err != nil {
				return err
			}
			roles.mu.Lock()
			if roles.states[snapshot.ID] == state && state.runtime == resource {
				state.runtime = nil
			}
			roles.mu.Unlock()
			return nil
		}
		audit := func(auditCtx context.Context) error { return resource.Audit(auditCtx) }
		if allocationErr != nil {
			return cleanup, audit, errors.Join(ErrHostRuntimeUnavailable, allocationErr)
		}
		return cleanup, audit, nil
	}
}

func (roles *HostRoles) WorkspaceState(ctx context.Context, snapshot session.Snapshot) (string, error) {
	state, err := roles.state(snapshot)
	if err != nil || snapshot.Role != session.RoleWorkstation {
		return "", ErrHostRuntimeUnavailable
	}
	roles.mu.Lock()
	runtimeResource := state.runtime
	roles.mu.Unlock()
	if runtimeResource == nil {
		return "", ErrHostRuntimeUnavailable
	}
	return runtimeResource.WorkspaceState(ctx)
}

func (roles *HostRoles) Add(ctx context.Context, snapshot session.Snapshot, kind torrent.InputKind, reader io.Reader) (*privatevmv1.TorrentMetadata, error) {
	relay, err := roles.torrent(snapshot)
	if err != nil {
		return nil, err
	}
	return relay.Add(ctx, kind, reader)
}

func (roles *HostRoles) Metadata(ctx context.Context, snapshot session.Snapshot) (*privatevmv1.TorrentMetadata, error) {
	relay, err := roles.torrent(snapshot)
	if err != nil {
		return nil, err
	}
	return relay.Metadata(ctx)
}

func (roles *HostRoles) Select(ctx context.Context, snapshot session.Snapshot, indexes []uint32) (*privatevmv1.TorrentMetadata, error) {
	relay, err := roles.torrent(snapshot)
	if err != nil {
		return nil, err
	}
	return relay.Select(ctx, append([]uint32(nil), indexes...))
}

func (roles *HostRoles) Start(ctx context.Context, snapshot session.Snapshot, emit func(*privatevmv1.TorrentEvent) error) error {
	relay, err := roles.torrent(snapshot)
	if err != nil {
		return err
	}
	return relay.Start(ctx, emit)
}

func (roles *HostRoles) Pause(ctx context.Context, snapshot session.Snapshot) (*privatevmv1.TorrentStatus, error) {
	relay, err := roles.torrent(snapshot)
	if err != nil {
		return nil, err
	}
	return relay.Pause(ctx)
}

func (roles *HostRoles) Status(ctx context.Context, snapshot session.Snapshot) (*privatevmv1.TorrentStatus, error) {
	relay, err := roles.torrent(snapshot)
	if err != nil {
		return nil, err
	}
	return relay.Status(ctx)
}

func (roles *HostRoles) SealAndDestroy(ctx context.Context, snapshot session.Snapshot) (*privatevmv1.TorrentStatus, error) {
	state, err := roles.state(snapshot)
	if err != nil {
		return nil, ErrHostRuntimeUnavailable
	}
	roles.mu.Lock()
	runtimeResource := state.runtime
	roles.mu.Unlock()
	if runtimeResource == nil {
		return nil, ErrHostRuntimeUnavailable
	}
	relay, err := runtimeResource.Torrent()
	if err != nil {
		return nil, err
	}
	status, err := relay.Seal(ctx)
	if err != nil {
		return nil, err
	}
	if err := runtimeResource.Stop(ctx, true); err != nil {
		return nil, errors.Join(torrent.ErrCleanupIncomplete, err)
	}
	if err := runtimeResource.Audit(ctx); err != nil {
		return nil, errors.Join(torrent.ErrCleanupIncomplete, err)
	}
	return status, nil
}

func (roles *HostRoles) torrent(snapshot session.Snapshot) (TorrentRelay, error) {
	state, err := roles.state(snapshot)
	if err != nil || snapshot.Role != session.RoleDownloader {
		return nil, ErrHostRuntimeUnavailable
	}
	roles.mu.Lock()
	runtimeResource := state.runtime
	roles.mu.Unlock()
	if runtimeResource == nil {
		return nil, ErrHostRuntimeUnavailable
	}
	return runtimeResource.Torrent()
}

func (roles *HostRoles) state(snapshot session.Snapshot) (*hostRoleState, error) {
	if roles == nil || session.ValidateID(snapshot.ID) != nil {
		return nil, ErrHostPlanUnavailable
	}
	roles.mu.Lock()
	defer roles.mu.Unlock()
	state := roles.states[snapshot.ID]
	if state == nil || state.plan.Role != snapshot.Role {
		return nil, ErrHostPlanUnavailable
	}
	return state, nil
}

func nilLikeHost(value any) bool {
	if value == nil {
		return true
	}
	reflection := reflect.ValueOf(value)
	switch reflection.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflection.IsNil()
	default:
		return false
	}
}
