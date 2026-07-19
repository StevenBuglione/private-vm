package daemon

import (
	"context"
	"errors"
	"io"
	"regexp"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var workspaceOutputIDPattern = regexp.MustCompile(`^output-[0-9a-f]{32}$`)

// WorkspaceOrchestrator is the daemon's exact workstation boundary. It cannot
// represent a host path, arbitrary guest RPC, VSOCK endpoint, token or command.
type WorkspaceOrchestrator interface {
	WorkspaceInventory(context.Context, session.Snapshot) (*privatevmv1.WorkspaceState, error)
	ImportWorkspace(context.Context, session.Snapshot, *privatevmv1.TransferBegin, func() (*privatevmv1.TransferFrame, error)) (*privatevmv1.TransferReceipt, error)
	ExportWorkspace(context.Context, session.Snapshot, string, func(*privatevmv1.TransferFrame) error) (*privatevmv1.TransferReceipt, error)
	VerifyWorkspaceExport(context.Context, session.Snapshot, string, *privatevmv1.Hash, *privatevmv1.Hash) (*privatevmv1.WorkspaceState, error)
}

func (s *Service) GetWorkspaceState(ctx context.Context, request *privatevmv1.HostWorkspaceStateRequest) (*privatevmv1.WorkspaceState, error) {
	if request == nil {
		return nil, workspaceRequestError()
	}
	identity, snapshot, roles, err := s.workstationSession(ctx, request.GetContext())
	if err != nil {
		return nil, err
	}
	lock := s.roleOperation(snapshot.ID)
	lock.Lock()
	defer lock.Unlock()
	state, err := roles.WorkspaceInventory(ctx, snapshot)
	if err != nil {
		return nil, workspaceServiceError(err)
	}
	if !validWorkspaceState(state) {
		return nil, workspaceServiceError(errors.New("invalid workspace state"))
	}
	_ = identity
	return state, nil
}

func (s *Service) ImportWorkspaceFile(stream privatevmv1.PrivateVMDaemonService_ImportWorkspaceFileServer) error {
	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return workspaceBeginError()
		}
		return workspaceServiceError(err)
	}
	begin := first.GetBegin()
	if begin == nil {
		clearWorkspaceFrame(first)
		return workspaceBeginError()
	}
	ctx, err := requestContextWithMetadata(stream.Context(), begin.GetContext(), true)
	if err != nil {
		return err
	}
	_, snapshot, roles, err := s.workstationSession(ctx, begin.GetContext())
	if err != nil {
		return err
	}
	lock := s.roleOperation(snapshot.ID)
	lock.Lock()
	defer lock.Unlock()
	receipt, err := roles.ImportWorkspace(ctx, snapshot, begin, stream.Recv)
	if err != nil {
		return workspaceServiceError(err)
	}
	if receipt == nil {
		return workspaceServiceError(errors.New("missing transfer receipt"))
	}
	return stream.SendAndClose(receipt)
}

func (s *Service) ExportWorkspaceFile(request *privatevmv1.ExportWorkspaceRequest, stream privatevmv1.PrivateVMDaemonService_ExportWorkspaceFileServer) error {
	ctx, err := requestContextWithMetadata(stream.Context(), request.GetContext(), true)
	if err != nil {
		return err
	}
	if !workspaceOutputIDPattern.MatchString(request.GetOutputId()) {
		return workspaceRequestError()
	}
	_, snapshot, roles, err := s.workstationSession(ctx, request.GetContext())
	if err != nil {
		return err
	}
	lock := s.roleOperation(snapshot.ID)
	lock.Lock()
	defer lock.Unlock()
	_, err = roles.ExportWorkspace(ctx, snapshot, request.GetOutputId(), stream.Send)
	return workspaceServiceError(err)
}

func (s *Service) VerifyWorkspaceExport(ctx context.Context, request *privatevmv1.VerifyWorkspaceExportRequest) (*privatevmv1.WorkspaceState, error) {
	if request == nil || !workspaceOutputIDPattern.MatchString(request.GetOutputId()) || !validWorkspaceDigest(request.GetDaemonDigest()) || !validWorkspaceDigest(request.GetReceiverDigest()) {
		return nil, workspaceRequestError()
	}
	_, snapshot, roles, err := s.workstationSession(ctx, request.GetContext())
	if err != nil {
		return nil, err
	}
	lock := s.roleOperation(snapshot.ID)
	lock.Lock()
	defer lock.Unlock()
	state, err := roles.VerifyWorkspaceExport(ctx, snapshot, request.GetOutputId(), request.GetDaemonDigest(), request.GetReceiverDigest())
	if err != nil {
		return nil, workspaceServiceError(err)
	}
	if !validWorkspaceState(state) {
		return nil, workspaceServiceError(errors.New("invalid workspace state"))
	}
	return state, nil
}

func (s *Service) workstationSession(ctx context.Context, request *privatevmv1.RequestContext) (PeerIdentity, session.Snapshot, WorkspaceOrchestrator, error) {
	if err := validateRequestContext(request, true); err != nil {
		return PeerIdentity{}, session.Snapshot{}, nil, err
	}
	roles, ok := s.Roles.(WorkspaceOrchestrator)
	if !ok || roles == nil || s.Sessions == nil {
		return PeerIdentity{}, session.Snapshot{}, nil, unimplemented("Authenticated workstation relay")
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return PeerIdentity{}, session.Snapshot{}, nil, sessionError(err)
	}
	snapshot, err := s.Sessions.Get(request.GetSessionId(), identity.UID)
	if err != nil {
		return PeerIdentity{}, session.Snapshot{}, nil, sessionError(err)
	}
	if snapshot.Role != session.RoleWorkstation || snapshot.Phase != session.PhaseActive {
		return PeerIdentity{}, session.Snapshot{}, nil, rpcError(codes.FailedPrecondition, "WORKSPACE_UNREACHABLE", "The selected session is not an active workstation.", "Select one active owned workstation and retry.", false)
	}
	return identity, snapshot, roles, nil
}

func validWorkspaceState(value *privatevmv1.WorkspaceState) bool {
	if value == nil || len(value.GetEntries()) > 1024 {
		return false
	}
	switch value.GetState() {
	case "CLEAN", "READY", "UNEXPORTED", "CHANGED":
	default:
		return false
	}
	for _, entry := range value.GetEntries() {
		if entry == nil || !workspaceOutputIDPattern.MatchString(entry.GetOutputId()) || entry.GetSizeBytes() > 8<<30 || (entry.GetExported() && entry.GetChangedSinceExport()) {
			return false
		}
	}
	return true
}

func validWorkspaceDigest(value *privatevmv1.Hash) bool {
	return value != nil && value.GetAlgorithm() == "sha256" && len(value.GetValue()) == 32
}

func clearWorkspaceFrame(frame *privatevmv1.TransferFrame) {
	if frame != nil && frame.GetChunk() != nil {
		clear(frame.GetChunk().Data)
	}
}

func workspaceBeginError() error {
	return rpcError(codes.InvalidArgument, "TRANSFER_BEGIN_REQUIRED", "The first transfer frame must be TransferBegin.", "Start the stream with one bounded single-file descriptor.", false)
}

func workspaceRequestError() error {
	return rpcError(codes.InvalidArgument, "WORKSPACE_REQUEST_INVALID", "The workspace request is malformed.", "Refresh the workspace state and use one current opaque output identifier.", false)
}

func workspaceServiceError(err error) error {
	if err == nil {
		return nil
	}
	if status.Code(err) != codes.Unknown {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return sessionError(err)
	}
	return rpcError(codes.FailedPrecondition, "WORKSPACE_TRANSFER_FAILED", "The workspace transfer did not complete every integrity check.", "Keep the workstation active, refresh its state, and retry the complete bounded transfer.", false)
}
