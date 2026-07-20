package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"sync/atomic"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var workspaceOutputIDPattern = regexp.MustCompile(`^output-[0-9a-f]{32}$`)

const workspaceDestinationAbortTimeout = 30 * time.Second

// WorkspaceOrchestrator is the daemon's exact workstation boundary. It cannot
// represent a host path, arbitrary guest RPC, VSOCK endpoint, token or command.
type WorkspaceOrchestrator interface {
	WorkspaceInventory(context.Context, session.Snapshot) (*privatevmv1.WorkspaceState, error)
	ImportWorkspace(context.Context, session.Snapshot, *privatevmv1.TransferBegin, func() (*privatevmv1.TransferFrame, error)) (*privatevmv1.TransferReceipt, error)
	ExportWorkspace(context.Context, session.Snapshot, string, func(*privatevmv1.TransferFrame) error) (*privatevmv1.TransferReceipt, error)
	VerifyWorkspaceExport(context.Context, session.Snapshot, string, *privatevmv1.Hash, *privatevmv1.Hash) (*privatevmv1.WorkspaceState, error)
}

// WorkspaceDestinationPlan contains only semantic, already-authorized
// selectors. In particular it cannot represent a host path, mount point,
// device node, guest command or QEMU argument.
type WorkspaceDestinationPlan struct {
	OwnerUID      uint32
	SourceSession string
	OutputID      string
	Destination   privatevmv1.WorkspaceExportDestination
}

// WorkspaceDestinationSource is the one-shot, bounded workstation source a
// destination transaction may consume. The returned receipt is the daemon
// relay's independently calculated receipt, not the final receiver's receipt.
type WorkspaceDestinationSource func(context.Context, func(*privatevmv1.TransferFrame) error) (*privatevmv1.TransferReceipt, error)

// WorkspaceDestinationReceipt is deliberately smaller than an exporter
// implementation. The digest must be calculated by re-reading durable bytes;
// all destination resources must be cleaned before CleanupComplete is true.
type WorkspaceDestinationReceipt struct {
	ReceiverDigest  *privatevmv1.Hash
	Persisted       bool
	Reread          bool
	CleanupComplete bool
}

// WorkspaceDestinationProvider prepares one typed destination transaction.
// Prepare must fail before consuming source bytes when the destination is not
// ready. Implementations may not expose host storage paths through this API.
type WorkspaceDestinationProvider interface {
	Prepare(context.Context, WorkspaceDestinationPlan) (WorkspaceDestinationTransaction, error)
}

// WorkspaceDestinationTransaction owns destination cleanup. Receive must call
// source exactly once and return only after persistence, independent re-read,
// and normal cleanup. Abort is idempotent, bounded by its context, and remains
// safe after Receive committed the destination.
type WorkspaceDestinationTransaction interface {
	Receive(context.Context, WorkspaceDestinationSource) (WorkspaceDestinationReceipt, error)
	Abort(context.Context) error
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

// ExportWorkspaceToDestination performs the complete workstation -> declared
// destination transaction inside the daemon. The CLI supplies no path and
// never receives file bytes or hashes.
func (s *Service) ExportWorkspaceToDestination(ctx context.Context, request *privatevmv1.ExportWorkspaceToDestinationRequest) (_ *privatevmv1.WorkspaceState, resultErr error) {
	if request == nil || !workspaceOutputIDPattern.MatchString(request.GetOutputId()) {
		return nil, workspaceRequestError()
	}
	if request.GetDestination() == privatevmv1.WorkspaceExportDestination_WORKSPACE_EXPORT_DESTINATION_ENCRYPTED_BUNDLE {
		return nil, unimplemented("Encrypted workspace bundle destination")
	}
	if request.GetDestination() != privatevmv1.WorkspaceExportDestination_WORKSPACE_EXPORT_DESTINATION_USB {
		return nil, workspaceDestinationUnavailableError()
	}
	identity, snapshot, roles, err := s.workstationSession(ctx, request.GetContext())
	if err != nil {
		return nil, err
	}
	lock := s.roleOperation(snapshot.ID)
	lock.Lock()
	defer lock.Unlock()

	inventory, err := roles.WorkspaceInventory(ctx, snapshot)
	if err != nil {
		return nil, workspaceServiceError(err)
	}
	if !validWorkspaceState(inventory) || !workspaceOutputRequiresExport(inventory, request.GetOutputId()) {
		return nil, workspaceSelectionError()
	}
	if s.WorkspaceDestinations == nil {
		return nil, workspaceDestinationUnavailableError()
	}
	transaction, err := s.WorkspaceDestinations.Prepare(ctx, WorkspaceDestinationPlan{
		OwnerUID: identity.UID, SourceSession: snapshot.ID, OutputID: request.GetOutputId(), Destination: request.GetDestination(),
	})
	if err != nil || transaction == nil {
		return nil, workspaceDestinationServiceError(err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		abortCtx, cancel := context.WithTimeout(context.Background(), workspaceDestinationAbortTimeout)
		defer cancel()
		if abortErr := transaction.Abort(abortCtx); abortErr != nil {
			resultErr = workspaceDestinationCleanupError()
		}
	}()

	var sourceCalls atomic.Uint32
	var relayReceipt *privatevmv1.TransferReceipt
	source := func(sourceCtx context.Context, send func(*privatevmv1.TransferFrame) error) (*privatevmv1.TransferReceipt, error) {
		if sourceCalls.Add(1) != 1 || send == nil {
			return nil, errors.New("destination requested an invalid source operation")
		}
		receipt, exportErr := roles.ExportWorkspace(sourceCtx, snapshot, request.GetOutputId(), send)
		relayReceipt = receipt
		return receipt, exportErr
	}
	destinationReceipt, err := transaction.Receive(ctx, source)
	if err != nil {
		return nil, workspaceDestinationServiceError(err)
	}
	if sourceCalls.Load() != 1 || !validWorkspaceTransferReceipt(relayReceipt, request.GetOutputId()) ||
		!destinationReceipt.Persisted || !destinationReceipt.Reread || !destinationReceipt.CleanupComplete ||
		!validWorkspaceDigest(destinationReceipt.ReceiverDigest) || !workspaceDigestsEqual(relayReceipt.GetReceiverDigest(), destinationReceipt.ReceiverDigest) {
		return nil, workspaceDestinationServiceError(errors.New("destination receipt did not match the daemon relay"))
	}
	verified, err := roles.VerifyWorkspaceExport(ctx, snapshot, request.GetOutputId(), relayReceipt.GetReceiverDigest(), destinationReceipt.ReceiverDigest)
	if err != nil {
		return nil, workspaceServiceError(err)
	}
	if !validWorkspaceState(verified) || !workspaceOutputIsCurrent(verified, request.GetOutputId()) {
		return nil, workspaceServiceError(errors.New("invalid verified workspace state"))
	}
	committed = true
	return verified, nil
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

func validWorkspaceTransferReceipt(value *privatevmv1.TransferReceipt, outputID string) bool {
	if value == nil || value.GetTransferId() != outputID || !validWorkspaceDigest(value.GetReceiverDigest()) {
		return false
	}
	descriptor := value.GetDescriptor_()
	return descriptor != nil && descriptor.GetSizeBytes() <= 8<<30 && validWorkspaceDigest(descriptor.GetDigest()) && workspaceDigestsEqual(descriptor.GetDigest(), value.GetReceiverDigest())
}

func workspaceDigestsEqual(left, right *privatevmv1.Hash) bool {
	return validWorkspaceDigest(left) && validWorkspaceDigest(right) && bytes.Equal(left.GetValue(), right.GetValue())
}

func workspaceOutputRequiresExport(state *privatevmv1.WorkspaceState, outputID string) bool {
	for _, entry := range state.GetEntries() {
		if entry.GetOutputId() == outputID {
			return !entry.GetExported() || entry.GetChangedSinceExport()
		}
	}
	return false
}

func workspaceOutputIsCurrent(state *privatevmv1.WorkspaceState, outputID string) bool {
	for _, entry := range state.GetEntries() {
		if entry.GetOutputId() == outputID {
			return entry.GetExported() && !entry.GetChangedSinceExport()
		}
	}
	return false
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

func workspaceSelectionError() error {
	return rpcError(codes.FailedPrecondition, "WORKSPACE_SELECTION_REQUIRED", "The selected workspace result is absent or does not require export.", "Refresh the workspace state and select one exact unexported or changed output.", false)
}

func workspaceDestinationUnavailableError() error {
	return rpcError(codes.FailedPrecondition, "WORKSPACE_DESTINATION_UNAVAILABLE", "The selected protected workspace destination is unavailable.", "Prepare the exact supported destination and retry without discarding the workstation.", true)
}

func workspaceDestinationServiceError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return sessionError(err)
	}
	return rpcError(codes.FailedPrecondition, "WORKSPACE_DESTINATION_FAILED", "The protected destination did not persist and independently verify the complete result.", "Keep the workstation active, prepare the destination, and retry the complete export.", true)
}

func workspaceDestinationCleanupError() error {
	return rpcError(codes.Internal, "WORKSPACE_DESTINATION_CLEANUP_INCOMPLETE", "The incomplete destination transaction could not be fully cleaned.", "Do not retry or detach hardware until an administrator completes recovery.", true)
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
