package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"github.com/StevenBuglione/private-vm/internal/transfer"
	"google.golang.org/grpc"
)

const maximumWorkspaceFileBytes = uint64(8 << 30)

const maximumWorkspaceFrames = maximumWorkspaceFileBytes/transfer.DefaultMaxChunk + 2

// WorkspaceExportDestination is the narrow destination boundary used by the
// USB exporter and encrypted-bundle adapters. Support must be checked before
// the guest transfer starts, and Open must return a receiver that independently
// persists and re-reads the received bytes when Commit is called.
type WorkspaceExportDestination interface {
	Supports(destination string) bool
	Open(context.Context, string, transfer.Header) (WorkspaceExportWriter, error)
}

// WorkspaceExportWriter accepts one bounded file. Abort must be idempotent and
// remove an incomplete destination. Commit fsyncs/re-reads the destination and
// returns its independent SHA-256 digest; it must not expose a host path.
// Abort is a no-op after a successful commit.
type WorkspaceExportWriter interface {
	io.Writer
	Commit(context.Context) ([sha256.Size]byte, error)
	Abort() error
}

func (invoker *ProductionInvoker) invokeWorkspace(ctx context.Context, id CommandID, intent Intent) (Result, error) {
	connection, client, err := invoker.client()
	if err != nil {
		return Result{}, err
	}
	defer connection.Close()
	requestID, err := invoker.nextRequestID()
	if err != nil {
		return Result{}, workspaceInternalError()
	}

	switch id {
	case CommandWorkspaceImport:
		request, ok := intent.(WorkspacePathIntent)
		if !ok || request.Path == "" {
			return Result{}, workspaceRequestError()
		}
		current, err := invoker.resolveSession(ctx, client, requestID, request.SessionID, true)
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		if current.GetPhase() != privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE {
			return Result{}, workspaceUnavailableError()
		}
		if err := invoker.importWorkspaceSource(ctx, client, requestID, current.GetId(), request.Path); err != nil {
			return Result{}, err
		}
		return invoker.workspaceState(ctx, client, requestID, current.GetId())
	case CommandWorkspaceInbox, CommandWorkspaceList:
		request, ok := intent.(SessionIntent)
		if !ok {
			return Result{}, workspaceRequestError()
		}
		current, err := invoker.resolveSession(ctx, client, requestID, request.SessionID, true)
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		return invoker.workspaceState(ctx, client, requestID, current.GetId())
	case CommandWorkspaceExport:
		request, ok := intent.(WorkspaceExportIntent)
		if !ok || request.Destination == "" || request.OutputID == "" {
			return Result{}, workspaceRequestError()
		}
		current, err := invoker.resolveSession(ctx, client, requestID, request.SessionID, true)
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		return invoker.exportWorkspace(ctx, client, requestID, current.GetId(), request.OutputID, request.Destination)
	case CommandWorkspaceVerify:
		request, ok := intent.(WorkspaceVerifyIntent)
		if !ok || request.Last == (request.ExportID != "") {
			return Result{}, workspaceRequestError()
		}
		current, err := invoker.resolveSession(ctx, client, requestID, request.SessionID, true)
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		state, err := invoker.getWorkspaceState(ctx, client, requestID, current.GetId())
		if err != nil {
			return Result{}, err
		}
		if !workspaceExportIsCurrent(state, request) {
			return Result{}, workspaceVerificationError()
		}
		return workspaceStateResult(state)
	case CommandWorkspaceDiscard:
		request, ok := intent.(WorkspaceDiscardIntent)
		if !ok || !request.All {
			return Result{}, workspaceRequestError()
		}
		current, err := invoker.resolveSession(ctx, client, requestID, request.SessionID, true)
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		stopped, err := client.StopRole(ctx, &privatevmv1.StopRoleRequest{Context: sessionRequestContext(requestID, current.GetId()), DiscardUnexported: true})
		return sessionResult(stopped, err)
	default:
		return failClosedInvoker{}.Invoke(ctx, id, intent)
	}
}

func (invoker *ProductionInvoker) importWorkspaceSource(ctx context.Context, client privatevmv1.PrivateVMDaemonServiceClient, requestID, sessionID, path string) error {
	source, err := transfer.OpenSource(ctx, path, maximumWorkspaceFileBytes)
	if err != nil {
		return apperror.Wrap("IMPORT_PATH_UNSAFE", exitcode.Transfer, "The trusted import source is not one stable bounded regular file.", "Select one directly referenced regular file without symbolic-link path components and retry.", err)
	}
	defer source.Close()
	transferID, err := newWorkspaceTransferID()
	if err != nil {
		return workspaceInternalError()
	}
	header := source.Header()
	stream, err := client.ImportWorkspaceFile(ctx, grpc.MaxCallSendMsgSize(transfer.DefaultMaxChunk+4096), grpc.MaxCallRecvMsgSize(64<<10))
	if err != nil {
		return daemonRPCError(err)
	}
	begin := &privatevmv1.TransferBegin{
		Context: sessionRequestContext(requestID, sessionID), TransferId: transferID,
		Descriptor_: &privatevmv1.FileDescriptor{LogicalName: header.Name, SizeBytes: header.Size, DetectedMime: header.MediaType, Digest: workspaceHash(header.SHA256)},
	}
	if err := stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: begin}}); err != nil {
		return daemonRPCError(err)
	}
	if err := source.Stream(ctx, func(sequence uint64, data []byte) error {
		return stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Sequence: sequence, Data: data}}})
	}); err != nil {
		return apperror.Wrap("TRANSFER_INCOMPLETE", exitcode.Transfer, "The trusted import changed or stopped before verification.", "Keep the source unchanged and retry the complete import.", err)
	}
	if err := stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{TotalSize: header.Size, Digest: workspaceHash(header.SHA256)}}}); err != nil {
		return daemonRPCError(err)
	}
	receipt, err := stream.CloseAndRecv()
	if err != nil {
		return daemonRPCError(err)
	}
	if receipt == nil || receipt.GetTransferId() != transferID || !workspaceHashEqual(receipt.GetReceiverDigest(), header.SHA256) || receipt.GetDescriptor_().GetSizeBytes() != header.Size || receipt.GetDescriptor_().GetLogicalName() != header.Name {
		return apperror.New("TRANSFER_HASH_MISMATCH", exitcode.Transfer, "The workstation import receipt did not match the trusted source.", "Do not use the partial result; retry the complete import after checking the active session.")
	}
	return nil
}

func (invoker *ProductionInvoker) workspaceState(ctx context.Context, client privatevmv1.PrivateVMDaemonServiceClient, requestID, sessionID string) (Result, error) {
	state, err := invoker.getWorkspaceState(ctx, client, requestID, sessionID)
	if err != nil {
		return Result{}, err
	}
	return workspaceStateResult(state)
}

func (invoker *ProductionInvoker) getWorkspaceState(ctx context.Context, client privatevmv1.PrivateVMDaemonServiceClient, requestID, sessionID string) (*privatevmv1.WorkspaceState, error) {
	state, err := client.GetWorkspaceState(ctx, &privatevmv1.HostWorkspaceStateRequest{Context: sessionRequestContext(requestID, sessionID)})
	if err != nil {
		return nil, daemonRPCError(err)
	}
	if state == nil || len(state.GetEntries()) > 1024 {
		return nil, workspaceInternalError()
	}
	return state, nil
}

func workspaceStateResult(state *privatevmv1.WorkspaceState) (Result, error) {
	if state == nil || len(state.GetEntries()) > 1024 {
		return Result{}, workspaceInternalError()
	}
	payload := WorkspaceStatusPayload{SchemaVersion: 1, State: state.GetState(), FileCount: uint32(len(state.GetEntries()))}
	for _, entry := range state.GetEntries() {
		if entry == nil {
			return Result{}, workspaceInternalError()
		}
		if entry.GetChangedSinceExport() {
			payload.ChangedCount++
		}
		if entry.GetExported() {
			payload.ExportedCount++
		} else {
			payload.UnexportedCount++
		}
	}
	return Result{Code: CodeWorkspaceStatus, Data: payload}, nil
}

func (invoker *ProductionInvoker) exportWorkspace(ctx context.Context, client privatevmv1.PrivateVMDaemonServiceClient, requestID, sessionID, requestedOutputID, destination string) (Result, error) {
	adapter := invoker.workspaceDestination
	if adapter == nil || !adapter.Supports(destination) {
		return Result{}, workspaceDestinationError()
	}
	state, err := invoker.getWorkspaceState(ctx, client, requestID, sessionID)
	if err != nil {
		return Result{}, err
	}
	outputID, err := selectWorkspaceExport(state, requestedOutputID)
	if err != nil {
		return Result{}, err
	}
	stream, err := client.ExportWorkspaceFile(ctx, &privatevmv1.ExportWorkspaceRequest{Context: sessionRequestContext(requestID, sessionID), OutputId: outputID}, grpc.MaxCallRecvMsgSize(transfer.DefaultMaxChunk+4096))
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	first, err := stream.Recv()
	if err != nil || first.GetBegin() == nil || first.GetBegin().GetTransferId() != outputID || first.GetBegin().GetContext() != nil {
		return Result{}, workspaceTransferError(err)
	}
	header, err := workspaceTransferHeader(first.GetBegin().GetDescriptor_())
	if err != nil {
		return Result{}, err
	}
	writer, err := adapter.Open(ctx, destination, header)
	if err != nil || writer == nil {
		return Result{}, workspaceDestinationWrap(err)
	}
	receiverDigest, err := receiveWorkspaceExport(ctx, stream, writer, header)
	if err != nil {
		return Result{}, err
	}
	verified, err := client.VerifyWorkspaceExport(ctx, &privatevmv1.VerifyWorkspaceExportRequest{
		Context: sessionRequestContext(requestID, sessionID), OutputId: outputID,
		DaemonDigest: workspaceHash(header.SHA256), ReceiverDigest: workspaceHash(receiverDigest),
	})
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	return workspaceStateResult(verified)
}

func receiveWorkspaceExport(ctx context.Context, stream privatevmv1.PrivateVMDaemonService_ExportWorkspaceFileClient, writer WorkspaceExportWriter, header transfer.Header) (digest [sha256.Size]byte, resultErr error) {
	defer func() {
		if err := writer.Abort(); err != nil {
			resultErr = workspaceDestinationWrap(errors.Join(resultErr, err))
		}
	}()
	receiver, err := transfer.NewReceiver(header, maximumWorkspaceFileBytes, writer)
	if err != nil {
		return digest, workspaceTransferError(err)
	}
	var offset, sequence uint64
	finished := false
	for frameCount := uint64(1); frameCount < maximumWorkspaceFrames; frameCount++ {
		frame, receiveErr := stream.Recv()
		if receiveErr != nil || frame == nil {
			return digest, workspaceTransferError(receiveErr)
		}
		if chunk := frame.GetChunk(); chunk != nil {
			if chunk.GetSequence() != sequence || receiver.WriteChunk(offset, chunk.GetData()) != nil {
				clear(chunk.Data)
				return digest, workspaceTransferError(nil)
			}
			offset += uint64(len(chunk.GetData()))
			sequence++
			clear(chunk.Data)
			continue
		}
		end := frame.GetEnd()
		if end == nil || end.GetTotalSize() != header.Size || !workspaceHashEqual(end.GetDigest(), header.SHA256) || receiver.Finish() != nil {
			return digest, workspaceTransferError(nil)
		}
		finished = true
		break
	}
	if !finished {
		return digest, workspaceTransferError(nil)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		return digest, workspaceTransferError(err)
	}
	digest, err = writer.Commit(ctx)
	if err != nil || digest != header.SHA256 {
		return digest, workspaceDestinationWrap(err)
	}
	return digest, nil
}

func workspaceTransferHeader(descriptor *privatevmv1.FileDescriptor) (transfer.Header, error) {
	if descriptor == nil || descriptor.GetDigest() == nil || descriptor.GetDigest().GetAlgorithm() != "sha256" || len(descriptor.GetDigest().GetValue()) != sha256.Size {
		return transfer.Header{}, workspaceTransferError(nil)
	}
	var digest [sha256.Size]byte
	copy(digest[:], descriptor.GetDigest().GetValue())
	header := transfer.Header{Name: descriptor.GetLogicalName(), Size: descriptor.GetSizeBytes(), SHA256: digest, MediaType: descriptor.GetDetectedMime()}
	if err := header.Validate(maximumWorkspaceFileBytes); err != nil {
		return transfer.Header{}, workspaceTransferError(err)
	}
	return header, nil
}

func selectWorkspaceExport(state *privatevmv1.WorkspaceState, requestedOutputID string) (string, error) {
	for _, entry := range state.GetEntries() {
		if entry == nil || entry.GetOutputId() != requestedOutputID {
			continue
		}
		if entry.GetExported() && !entry.GetChangedSinceExport() {
			return "", workspaceSelectionError()
		}
		return requestedOutputID, nil
	}
	return "", workspaceSelectionError()
}

func workspaceExportIsCurrent(state *privatevmv1.WorkspaceState, request WorkspaceVerifyIntent) bool {
	matched := 0
	for _, entry := range state.GetEntries() {
		if entry == nil || !entry.GetExported() || entry.GetChangedSinceExport() {
			continue
		}
		if request.ExportID != "" && entry.GetOutputId() != request.ExportID {
			continue
		}
		matched++
	}
	return matched == 1
}

func newWorkspaceTransferID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "transfer-" + hex.EncodeToString(value[:]), nil
}

func workspaceHash(value [sha256.Size]byte) *privatevmv1.Hash {
	return &privatevmv1.Hash{Algorithm: "sha256", Value: append([]byte(nil), value[:]...)}
}

func workspaceHashEqual(value *privatevmv1.Hash, expected [sha256.Size]byte) bool {
	if value == nil || value.GetAlgorithm() != "sha256" || len(value.GetValue()) != sha256.Size {
		return false
	}
	var mismatch byte
	for index := range expected {
		mismatch |= expected[index] ^ value.GetValue()[index]
	}
	return mismatch == 0
}

func workspaceRequestError() error {
	return apperror.New("WORKSPACE_REQUEST_INVALID", exitcode.Transfer, "The workspace request contract is invalid.", "Use one documented workspace command and an active workstation selector.")
}

func workspaceUnavailableError() error {
	return apperror.New("WORKSPACE_UNREACHABLE", exitcode.Transfer, "The selected workstation is not active.", "Start or select one active workstation and retry.")
}

func workspaceInternalError() error {
	return apperror.New("INTERNAL_ERROR", exitcode.Internal, "The workspace result could not be represented safely.", "Retry once; if the error persists, export a redacted diagnostic bundle.")
}

func workspaceSelectionError() error {
	return apperror.New("WORKSPACE_SELECTION_REQUIRED", exitcode.Transfer, "The selected workspace result is absent or does not require export.", "Refresh the guest workspace and choose one exact current result that is unexported or changed.")
}

func workspaceDestinationError() error {
	return apperror.New("WORKSPACE_DESTINATION_UNAVAILABLE", exitcode.Transfer, "The selected protected export destination is not available.", "Prepare and claim the exact supported destination, then retry the complete export.")
}

func workspaceDestinationWrap(err error) error {
	return apperror.Wrap("WORKSPACE_DESTINATION_FAILED", exitcode.Transfer, "The protected destination did not persist and independently verify the complete result.", "Do not discard the workstation; prepare the destination and retry the complete export.", err)
}

func workspaceTransferError(err error) error {
	return apperror.Wrap("WORKSPACE_TRANSFER_FAILED", exitcode.Transfer, "The workspace transfer did not complete every bounded integrity check.", "Keep the workstation active and retry the complete export.", err)
}

func workspaceVerificationError() error {
	return apperror.New("EXPORT_VERIFICATION_FAILED", exitcode.Transfer, "The selected export is absent, stale, changed, or ambiguous.", "Keep the workstation active and repeat a complete protected export before discarding it.")
}
