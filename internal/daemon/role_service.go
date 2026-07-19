package daemon

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc/codes"
)

// RoleOrchestrator is the narrow semantic boundary between the privileged RPC
// service and role-specific runtime composition. Each returned allocation is
// registered with the session actor before the next lifecycle gate is
// published, so cancellation can never create an unowned resource window.
type RoleOrchestrator interface {
	Preflight(context.Context, session.Snapshot) error
	VerifyImages(context.Context, session.Snapshot) error
	StorageAllocation(session.Snapshot) session.AllocateFunc
	RuntimeAllocation(session.Snapshot) session.AllocateFunc
	WorkspaceState(context.Context, session.Snapshot) (string, error)
}

type roleOperationSet struct {
	locks sync.Map
}

var roleOperationInitialization sync.Mutex

func (s *Service) roleOperation(id string) *sync.Mutex {
	roleOperationInitialization.Lock()
	if s.roleOperations == nil {
		s.roleOperations = &roleOperationSet{}
	}
	operations := s.roleOperations
	roleOperationInitialization.Unlock()
	value, _ := operations.locks.LoadOrStore(id, &sync.Mutex{})
	return value.(*sync.Mutex)
}

var workstationStartedStates = []string{
	"PLANNED",
	"IMAGE_READY",
	"STORAGE_READY",
	"NETWORK_READY",
	"VM_BOOTING",
	"GUEST_AUTHENTICATED",
	"VPN_CONFIGURED",
	"VPN_VERIFIED",
	"DISPLAY_READY",
	"WORKING",
}

var downloaderStartedStates = []string{
	"PLANNED",
	"SCANNER_UPDATE_PREPARED",
	"DOWNLOADER_BOOTING",
	"GUEST_AUTHENTICATED",
	"VPN_CONFIGURED",
	"VPN_VERIFIED",
}

func (s *Service) startRole(ctx context.Context, id string, ownerUID uint32) (*session.Snapshot, error) {
	snapshot, err := s.Sessions.Get(id, ownerUID)
	if err != nil {
		return nil, err
	}
	if snapshot.Phase != session.PhaseCreated {
		return nil, session.ErrInvalidTransition
	}
	startupStates := roleStartupStates(snapshot.Role)
	if len(startupStates) > 0 {
		snapshot, err = s.Sessions.TransitionWorkflow(ctx, id, ownerUID, startupStates[0])
		if err != nil {
			return nil, s.failedStart(id, ownerUID, err)
		}
	}
	if err := s.Roles.Preflight(ctx, snapshot); err != nil {
		return nil, s.failedStart(id, ownerUID, err)
	}
	snapshot, err = s.Sessions.Transition(ctx, id, ownerUID, session.PhasePreflighted)
	if err != nil {
		return nil, s.failedStart(id, ownerUID, err)
	}
	if err := s.Roles.VerifyImages(ctx, snapshot); err != nil {
		return nil, s.failedStart(id, ownerUID, err)
	}
	snapshot, err = s.Sessions.Transition(ctx, id, ownerUID, session.PhaseImagesVerified)
	if err != nil {
		return nil, s.failedStart(id, ownerUID, err)
	}
	if len(startupStates) > 1 {
		if snapshot, err = s.Sessions.TransitionWorkflow(ctx, id, ownerUID, startupStates[1]); err != nil {
			return nil, s.failedStart(id, ownerUID, err)
		}
	}
	storage := s.Roles.StorageAllocation(snapshot)
	if storage == nil {
		return nil, s.failedStart(id, ownerUID, errors.New("storage allocation is unavailable"))
	}
	if err := s.Sessions.AcquireResource(ctx, id, ownerUID, "session-storage", storage); err != nil {
		return nil, s.failedStart(id, ownerUID, err)
	}
	snapshot, err = s.Sessions.Transition(ctx, id, ownerUID, session.PhaseStorageReady)
	if err != nil {
		return nil, s.failedStart(id, ownerUID, err)
	}
	if len(startupStates) > 2 {
		if snapshot, err = s.Sessions.TransitionWorkflow(ctx, id, ownerUID, startupStates[2]); err != nil {
			return nil, s.failedStart(id, ownerUID, err)
		}
	}
	runtime := s.Roles.RuntimeAllocation(snapshot)
	if runtime == nil {
		return nil, s.failedStart(id, ownerUID, errors.New("role runtime allocation is unavailable"))
	}
	if err := s.Sessions.AcquireResource(ctx, id, ownerUID, "role-runtime", runtime); err != nil {
		return nil, s.failedStart(id, ownerUID, err)
	}
	snapshot, err = s.Sessions.Transition(ctx, id, ownerUID, session.PhaseActive)
	if err != nil {
		return nil, s.failedStart(id, ownerUID, err)
	}
	if len(startupStates) > 3 {
		for _, state := range startupStates[3:] {
			snapshot, err = s.Sessions.TransitionWorkflow(ctx, id, ownerUID, state)
			if err != nil {
				return nil, s.failedStart(id, ownerUID, err)
			}
		}
	}
	return &snapshot, nil
}

func roleStartupStates(role session.Role) []string {
	switch role {
	case session.RoleWorkstation:
		return workstationStartedStates
	case session.RoleDownloader:
		return downloaderStartedStates
	default:
		return nil
	}
}

func (s *Service) failedStart(id string, ownerUID uint32, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, cleanupErr := s.Sessions.Cleanup(cleanupCtx, id, ownerUID)
	cancel()
	if cleanupErr != nil {
		return session.ErrCleanupIncomplete
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	return errRoleStart
}

var errRoleStart = errors.New("role start failed")

func roleStartRPCError(err error) error {
	if errors.Is(err, errRoleStart) {
		return rpcError(codes.FailedPrecondition, "ROLE_START_FAILED", "The role did not pass every required startup gate.", "Inspect the redacted session events, correct the blocking condition, and start a new session.", false)
	}
	return sessionError(err)
}

func validateWorkspaceStop(state string, requireClean, discard bool) error {
	if discard {
		return nil
	}
	switch state {
	case "CLEAN":
		return nil
	case "READY":
		if !requireClean {
			return nil
		}
	}
	return rpcError(codes.FailedPrecondition, "WORKSPACE_DIRTY", "The workstation has unexported, changed, or unverifiable output.", "Export and verify every current output, or explicitly choose the destructive discard option.", false)
}
