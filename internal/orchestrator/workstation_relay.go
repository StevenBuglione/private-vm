package orchestrator

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/transfer"
)

const maximumWorkspaceFrames = 8194

var (
	ErrWorkstationUnavailable = errors.New("workstation relay is unavailable")
	ErrWorkspaceTransfer      = errors.New("workspace transfer failed verification")
)

// WorkspaceImport is a pull-based, single-file input. Receive remains owned by
// the authenticated daemon stream; the host runtime has no host path or generic
// guest client and cannot enumerate the caller's filesystem. Close, when set,
// cancels the upstream stream after the synchronous import returns.
type WorkspaceImport struct {
	Begin   *privatevmv1.TransferBegin
	Receive func() (*privatevmv1.TransferFrame, error)
	Close   func()
}

// WorkspaceExport is a push-based, single-output sink. OutputID is the opaque
// identity returned by the workstation and Send receives bounded verified
// frames only.
type WorkspaceExport struct {
	OutputID string
	Send     func(*privatevmv1.TransferFrame) error
}

// WorkstationRelay is the complete typed workstation guest surface retained by
// the host role owner. It intentionally has no dialer, path, token, command or
// arbitrary guest RPC escape hatch.
type WorkstationRelay interface {
	State(context.Context) (*privatevmv1.WorkspaceState, error)
	Import(context.Context, WorkspaceImport) (*privatevmv1.TransferReceipt, error)
	Export(context.Context, WorkspaceExport) (*privatevmv1.TransferReceipt, error)
	Verify(context.Context, string, *privatevmv1.Hash, *privatevmv1.Hash) (*privatevmv1.WorkspaceState, error)
}

// ScannerApprovedWorkspaceSource is intentionally sealed to this package. The
// scanner host orchestrator may implement it only after authenticating a
// complete approved report and binding one reconstructed output stream. Other
// packages cannot turn an arbitrary import into a scanner promotion.
type ScannerApprovedWorkspaceSource interface {
	approvedWorkspaceImport(context.Context) (WorkspaceImport, error)
	privateVMScannerApproval()
}

type hostWorkstationRuntime interface {
	Workstation() (WorkstationRelay, error)
}

func (roles *HostRoles) WorkspaceInventory(ctx context.Context, snapshot session.Snapshot) (*privatevmv1.WorkspaceState, error) {
	relay, err := roles.workstation(snapshot)
	if err != nil {
		return nil, err
	}
	return relay.State(ctx)
}

func (roles *HostRoles) ImportWorkspace(ctx context.Context, snapshot session.Snapshot, begin *privatevmv1.TransferBegin, receive func() (*privatevmv1.TransferFrame, error)) (*privatevmv1.TransferReceipt, error) {
	relay, err := roles.workstation(snapshot)
	if err != nil {
		return nil, err
	}
	return relay.Import(ctx, WorkspaceImport{Begin: begin, Receive: receive})
}

func (roles *HostRoles) ExportWorkspace(ctx context.Context, snapshot session.Snapshot, outputID string, send func(*privatevmv1.TransferFrame) error) (*privatevmv1.TransferReceipt, error) {
	relay, err := roles.workstation(snapshot)
	if err != nil {
		return nil, err
	}
	return relay.Export(ctx, WorkspaceExport{OutputID: outputID, Send: send})
}

func (roles *HostRoles) VerifyWorkspaceExport(ctx context.Context, snapshot session.Snapshot, outputID string, daemonDigest, receiverDigest *privatevmv1.Hash) (*privatevmv1.WorkspaceState, error) {
	relay, err := roles.workstation(snapshot)
	if err != nil {
		return nil, err
	}
	return relay.Verify(ctx, outputID, daemonDigest, receiverDigest)
}

func (roles *HostRoles) PromoteApprovedWorkspace(ctx context.Context, snapshot session.Snapshot, source ScannerApprovedWorkspaceSource) (*privatevmv1.TransferReceipt, error) {
	if source == nil {
		return nil, ErrWorkstationUnavailable
	}
	relay, err := roles.workstation(snapshot)
	if err != nil {
		return nil, err
	}
	request, err := source.approvedWorkspaceImport(ctx)
	if err != nil {
		return nil, err
	}
	if request.Close != nil {
		defer request.Close()
	}
	return relay.Import(ctx, request)
}

func (roles *HostRoles) workstation(snapshot session.Snapshot) (WorkstationRelay, error) {
	state, err := roles.state(snapshot)
	if err != nil || snapshot.Role != session.RoleWorkstation {
		return nil, ErrWorkstationUnavailable
	}
	roles.mu.Lock()
	runtimeResource := state.runtime
	roles.mu.Unlock()
	workstation, ok := runtimeResource.(hostWorkstationRuntime)
	if !ok || workstation == nil {
		return nil, ErrWorkstationUnavailable
	}
	return workstation.Workstation()
}

func (runtime *NetworkedRuntime) Workstation() (WorkstationRelay, error) {
	if runtime == nil || runtime.role != session.RoleWorkstation {
		return nil, ErrWorkstationUnavailable
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.processStopped || runtime.guestClosed || runtime.guest == nil {
		return nil, ErrWorkstationUnavailable
	}
	relay, ok := runtime.guest.(WorkstationRelay)
	if !ok || relay == nil {
		return nil, ErrWorkstationUnavailable
	}
	return relay, nil
}

func (resource *hostRuntimeResource) Workstation() (WorkstationRelay, error) {
	if resource == nil {
		return nil, ErrWorkstationUnavailable
	}
	resource.mu.Lock()
	networked := resource.networked
	resource.mu.Unlock()
	if networked == nil {
		return nil, ErrWorkstationUnavailable
	}
	return networked.Workstation()
}

func (connection *vsockGuestConnection) State(ctx context.Context) (*privatevmv1.WorkspaceState, error) {
	if connection == nil || connection.role != session.RoleWorkstation {
		return nil, ErrWorkstationUnavailable
	}
	request, err := connection.guestContext()
	if err != nil {
		return nil, err
	}
	return connection.workstation.ListExportFiles(ctx, &privatevmv1.WorkspaceStateRequest{Context: request})
}

func (connection *vsockGuestConnection) Import(ctx context.Context, request WorkspaceImport) (*privatevmv1.TransferReceipt, error) {
	if connection == nil || connection.role != session.RoleWorkstation || request.Begin == nil || request.Receive == nil {
		return nil, ErrWorkspaceTransfer
	}
	header, err := relayHeader(request.Begin.GetDescriptor_())
	if err != nil || request.Begin.GetTransferId() == "" {
		return nil, ErrWorkspaceTransfer
	}
	guestContext, err := connection.guestContext()
	if err != nil {
		return nil, err
	}
	stream, err := connection.workstation.ImportFile(ctx)
	if err != nil {
		return nil, err
	}
	begin := &privatevmv1.TransferBegin{Context: guestContext.GetContext(), TransferId: request.Begin.GetTransferId(), Descriptor_: cloneDescriptor(request.Begin.GetDescriptor_())}
	if err := stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: begin}}); err != nil {
		return nil, err
	}
	receiver, _ := transfer.NewReceiver(header, header.Size, io.Discard)
	var offset, sequence uint64
	for count := 0; count < maximumWorkspaceFrames; count++ {
		frame, receiveErr := request.Receive()
		if receiveErr != nil || frame == nil {
			return nil, errors.Join(ErrWorkspaceTransfer, receiveErr)
		}
		if chunk := frame.GetChunk(); chunk != nil {
			if chunk.GetSequence() != sequence || receiver.WriteChunk(offset, chunk.GetData()) != nil {
				clear(chunk.Data)
				return nil, ErrWorkspaceTransfer
			}
			offset += uint64(len(chunk.GetData()))
			sequence++
			if err := stream.Send(frame); err != nil {
				clear(chunk.Data)
				return nil, err
			}
			clear(chunk.Data)
			continue
		}
		end := frame.GetEnd()
		if end == nil || end.GetTotalSize() != header.Size || !sameProtoHash(end.GetDigest(), header.SHA256) || receiver.Finish() != nil {
			return nil, ErrWorkspaceTransfer
		}
		if err := stream.Send(frame); err != nil {
			return nil, err
		}
		receipt, err := stream.CloseAndRecv()
		if err != nil || !validReceipt(receipt, request.Begin.GetTransferId(), header) {
			return nil, errors.Join(ErrWorkspaceTransfer, err)
		}
		return receipt, nil
	}
	return nil, ErrWorkspaceTransfer
}

func (connection *vsockGuestConnection) Export(ctx context.Context, request WorkspaceExport) (*privatevmv1.TransferReceipt, error) {
	if connection == nil || connection.role != session.RoleWorkstation || request.OutputID == "" || request.Send == nil {
		return nil, ErrWorkspaceTransfer
	}
	guestContext, err := connection.guestContext()
	if err != nil {
		return nil, err
	}
	stream, err := connection.workstation.ExportFile(ctx, &privatevmv1.GuestExportFileRequest{Context: guestContext, OutputId: request.OutputID})
	if err != nil {
		return nil, err
	}
	first, err := stream.Recv()
	if err != nil || first.GetBegin() == nil || first.GetBegin().GetContext() != nil || first.GetBegin().GetTransferId() != request.OutputID {
		return nil, errors.Join(ErrWorkspaceTransfer, err)
	}
	header, err := relayHeader(first.GetBegin().GetDescriptor_())
	if err != nil || request.Send(first) != nil {
		return nil, ErrWorkspaceTransfer
	}
	receiver, _ := transfer.NewReceiver(header, header.Size, io.Discard)
	var offset, sequence uint64
	for count := 1; count < maximumWorkspaceFrames; count++ {
		frame, receiveErr := stream.Recv()
		if receiveErr != nil || frame == nil {
			return nil, errors.Join(ErrWorkspaceTransfer, receiveErr)
		}
		if chunk := frame.GetChunk(); chunk != nil {
			if chunk.GetSequence() != sequence || receiver.WriteChunk(offset, chunk.GetData()) != nil {
				clear(chunk.Data)
				return nil, ErrWorkspaceTransfer
			}
			offset += uint64(len(chunk.GetData()))
			sequence++
			if err := request.Send(frame); err != nil {
				clear(chunk.Data)
				return nil, err
			}
			clear(chunk.Data)
			continue
		}
		end := frame.GetEnd()
		if end == nil || end.GetTotalSize() != header.Size || !sameProtoHash(end.GetDigest(), header.SHA256) || receiver.Finish() != nil {
			return nil, ErrWorkspaceTransfer
		}
		if err := request.Send(frame); err != nil {
			return nil, err
		}
		connection.mu.Lock()
		if connection.workspaceExports == nil {
			connection.workspaceExports = make(map[string][32]byte)
		}
		connection.workspaceExports[request.OutputID] = header.SHA256
		connection.mu.Unlock()
		return &privatevmv1.TransferReceipt{TransferId: request.OutputID, Descriptor_: cloneDescriptor(first.GetBegin().GetDescriptor_()), ReceiverDigest: protoSHA256(header.SHA256)}, nil
	}
	return nil, ErrWorkspaceTransfer
}

func (connection *vsockGuestConnection) Verify(ctx context.Context, outputID string, daemonDigest, receiverDigest *privatevmv1.Hash) (*privatevmv1.WorkspaceState, error) {
	if connection == nil || connection.role != session.RoleWorkstation || outputID == "" || !equalProtoHashes(daemonDigest, receiverDigest) {
		return nil, ErrWorkspaceTransfer
	}
	connection.mu.Lock()
	pending, ok := connection.workspaceExports[outputID]
	connection.mu.Unlock()
	if !ok || !sameProtoHash(daemonDigest, pending) {
		return nil, ErrWorkspaceTransfer
	}
	request, err := connection.guestContext()
	if err != nil {
		return nil, err
	}
	state, err := connection.workstation.MarkExportVerified(ctx, &privatevmv1.MarkExportVerifiedRequest{Context: request, OutputId: outputID, Digest: cloneHash(receiverDigest)})
	if err == nil {
		connection.mu.Lock()
		delete(connection.workspaceExports, outputID)
		connection.mu.Unlock()
	}
	return state, err
}

func relayHeader(descriptor *privatevmv1.FileDescriptor) (transfer.Header, error) {
	if descriptor == nil || descriptor.GetDigest() == nil || descriptor.GetDigest().GetAlgorithm() != "sha256" || len(descriptor.GetDigest().GetValue()) != sha256.Size {
		return transfer.Header{}, ErrWorkspaceTransfer
	}
	var digest [sha256.Size]byte
	copy(digest[:], descriptor.GetDigest().GetValue())
	header := transfer.Header{Name: descriptor.GetLogicalName(), Size: descriptor.GetSizeBytes(), SHA256: digest, MediaType: descriptor.GetDetectedMime()}
	if err := header.Validate(8 << 30); err != nil {
		return transfer.Header{}, ErrWorkspaceTransfer
	}
	return header, nil
}

func validReceipt(receipt *privatevmv1.TransferReceipt, id string, header transfer.Header) bool {
	if receipt == nil || receipt.GetTransferId() != id || !sameProtoHash(receipt.GetReceiverDigest(), header.SHA256) {
		return false
	}
	received, err := relayHeader(receipt.GetDescriptor_())
	return err == nil && received == header
}

func sameProtoHash(value *privatevmv1.Hash, expected [sha256.Size]byte) bool {
	return value != nil && value.GetAlgorithm() == "sha256" && len(value.GetValue()) == sha256.Size && equalBytes(value.GetValue(), expected[:])
}

func equalProtoHashes(left, right *privatevmv1.Hash) bool {
	return left != nil && right != nil && left.GetAlgorithm() == "sha256" && right.GetAlgorithm() == "sha256" && len(left.GetValue()) == sha256.Size && equalBytes(left.GetValue(), right.GetValue())
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var mismatch byte
	for index := range left {
		mismatch |= left[index] ^ right[index]
	}
	return mismatch == 0
}

func cloneDescriptor(value *privatevmv1.FileDescriptor) *privatevmv1.FileDescriptor {
	if value == nil {
		return nil
	}
	return &privatevmv1.FileDescriptor{LogicalName: value.GetLogicalName(), SizeBytes: value.GetSizeBytes(), DetectedMime: value.GetDetectedMime(), Digest: cloneHash(value.GetDigest())}
}

func cloneHash(value *privatevmv1.Hash) *privatevmv1.Hash {
	if value == nil {
		return nil
	}
	return &privatevmv1.Hash{Algorithm: value.GetAlgorithm(), Value: append([]byte(nil), value.GetValue()...)}
}

func protoSHA256(value [sha256.Size]byte) *privatevmv1.Hash {
	return &privatevmv1.Hash{Algorithm: "sha256", Value: append([]byte(nil), value[:]...)}
}

var _ WorkstationRelay = (*vsockGuestConnection)(nil)
