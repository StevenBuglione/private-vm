package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/transfer"
)

type workspaceInvokerDaemon struct {
	*fakeSessionDaemon
	received    []byte
	mismatch    bool
	state       *privatevmv1.WorkspaceState
	exportCalls int
	verified    bool
}

func (daemon *workspaceInvokerDaemon) ImportWorkspaceFile(stream privatevmv1.PrivateVMDaemonService_ImportWorkspaceFileServer) error {
	first, err := stream.Recv()
	if err != nil || first.GetBegin() == nil {
		return io.ErrUnexpectedEOF
	}
	begin := first.GetBegin()
	for {
		frame, err := stream.Recv()
		if err != nil {
			return err
		}
		if chunk := frame.GetChunk(); chunk != nil {
			daemon.received = append(daemon.received, chunk.GetData()...)
			continue
		}
		if frame.GetEnd() == nil {
			return io.ErrUnexpectedEOF
		}
		digest := begin.GetDescriptor_().GetDigest()
		if daemon.mismatch {
			digest = &privatevmv1.Hash{Algorithm: "sha256", Value: bytes.Repeat([]byte{0xff}, sha256.Size)}
		}
		return stream.SendAndClose(&privatevmv1.TransferReceipt{TransferId: begin.GetTransferId(), Descriptor_: begin.GetDescriptor_(), ReceiverDigest: digest})
	}
}

func (daemon *workspaceInvokerDaemon) GetWorkspaceState(context.Context, *privatevmv1.HostWorkspaceStateRequest) (*privatevmv1.WorkspaceState, error) {
	if daemon.state != nil {
		return daemon.state, nil
	}
	return &privatevmv1.WorkspaceState{State: "UNEXPORTED", Entries: []*privatevmv1.WorkspaceEntry{{OutputId: "output-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SizeBytes: 4}}}, nil
}

func (daemon *workspaceInvokerDaemon) ExportWorkspaceFile(request *privatevmv1.ExportWorkspaceRequest, stream privatevmv1.PrivateVMDaemonService_ExportWorkspaceFileServer) error {
	daemon.exportCalls++
	data := []byte("safe")
	digest := sha256.Sum256(data)
	descriptor := &privatevmv1.FileDescriptor{LogicalName: "result.txt", SizeBytes: uint64(len(data)), Digest: workspaceHash(digest)}
	if err := stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{TransferId: request.GetOutputId(), Descriptor_: descriptor}}}); err != nil {
		return err
	}
	if err := stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Sequence: 0, Data: data}}}); err != nil {
		return err
	}
	return stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{TotalSize: uint64(len(data)), Digest: workspaceHash(digest)}}})
}

func (daemon *workspaceInvokerDaemon) VerifyWorkspaceExport(_ context.Context, request *privatevmv1.VerifyWorkspaceExportRequest) (*privatevmv1.WorkspaceState, error) {
	digest := sha256.Sum256([]byte("safe"))
	if !workspaceHashEqual(request.GetDaemonDigest(), digest) || !workspaceHashEqual(request.GetReceiverDigest(), digest) {
		return nil, io.ErrUnexpectedEOF
	}
	daemon.verified = true
	return &privatevmv1.WorkspaceState{State: "READY", Entries: []*privatevmv1.WorkspaceEntry{{OutputId: request.GetOutputId(), SizeBytes: 4, Exported: true}}}, nil
}

type workspaceTestDestination struct {
	supported bool
	opened    bool
	writer    *workspaceTestWriter
}

func (destination *workspaceTestDestination) Supports(value string) bool {
	return destination.supported && value == "usb"
}

func (destination *workspaceTestDestination) Open(_ context.Context, _ string, _ transfer.Header) (WorkspaceExportWriter, error) {
	destination.opened = true
	destination.writer = &workspaceTestWriter{}
	return destination.writer, nil
}

type workspaceTestWriter struct {
	bytes.Buffer
	committed bool
	aborted   bool
}

func (writer *workspaceTestWriter) Commit(context.Context) ([sha256.Size]byte, error) {
	writer.committed = true
	return sha256.Sum256(writer.Bytes()), nil
}

func (writer *workspaceTestWriter) Abort() error {
	writer.aborted = true
	return nil
}

func TestProductionWorkspaceInvokerStreamsOneStableFileAndReturnsAggregateState(t *testing.T) {
	service := &workspaceInvokerDaemon{fakeSessionDaemon: newFakeSessionDaemon()}
	service.session.Phase = privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE
	socket, stop := startSessionInvokerDaemon(t, service)
	defer stop()
	path := filepath.Join(t.TempDir(), "trusted.txt")
	if err := os.WriteFile(path, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	invoker := &ProductionInvoker{socketPath: socket, requestID: func() (string, error) { return "request-workspace-1234", nil }}
	result, err := invoker.Invoke(t.Context(), CommandWorkspaceImport, WorkspacePathIntent{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := result.Data.(WorkspaceStatusPayload)
	if !ok || result.Code != CodeWorkspaceStatus || payload.State != "UNEXPORTED" || payload.FileCount != 1 || string(service.received) != "safe" {
		t.Fatalf("result = %#v, bytes=%q", result, service.received)
	}
}

func TestProductionWorkspaceInvokerRejectsReceiptMismatchAndSymlink(t *testing.T) {
	service := &workspaceInvokerDaemon{fakeSessionDaemon: newFakeSessionDaemon(), mismatch: true}
	service.session.Phase = privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE
	socket, stop := startSessionInvokerDaemon(t, service)
	defer stop()
	directory := t.TempDir()
	path := filepath.Join(directory, "trusted.txt")
	if err := os.WriteFile(path, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	invoker := &ProductionInvoker{socketPath: socket, requestID: func() (string, error) { return "request-workspace-1234", nil }}
	if _, err := invoker.Invoke(t.Context(), CommandWorkspaceImport, WorkspacePathIntent{Path: path}); err == nil {
		t.Fatal("mismatched guest receipt was accepted")
	}
	link := filepath.Join(directory, "link.txt")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := invoker.Invoke(t.Context(), CommandWorkspaceImport, WorkspacePathIntent{Path: link}); err == nil {
		t.Fatal("symbolic-link import was accepted")
	}
}

func TestProductionWorkspaceExportPersistsAndVerifiesBeforeMarkingReady(t *testing.T) {
	service := &workspaceInvokerDaemon{fakeSessionDaemon: newFakeSessionDaemon()}
	service.session.Phase = privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE
	socket, stop := startSessionInvokerDaemon(t, service)
	defer stop()
	destination := &workspaceTestDestination{supported: true}
	invoker := &ProductionInvoker{
		socketPath: socket, requestID: func() (string, error) { return "request-export-1234", nil },
		workspaceDestination: destination,
	}
	result, err := invoker.Invoke(t.Context(), CommandWorkspaceExport, WorkspaceExportIntent{Destination: "usb", OutputID: "output-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := result.Data.(WorkspaceStatusPayload)
	if !ok || payload.State != "READY" || payload.ExportedCount != 1 || !service.verified || !destination.opened || !destination.writer.committed || destination.writer.String() != "safe" {
		t.Fatalf("result = %#v, service=%#v, destination=%#v", result, service, destination)
	}
}

func TestProductionWorkspaceExportFailsBeforeGuestStreamWithoutDestination(t *testing.T) {
	service := &workspaceInvokerDaemon{fakeSessionDaemon: newFakeSessionDaemon()}
	service.session.Phase = privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE
	socket, stop := startSessionInvokerDaemon(t, service)
	defer stop()
	invoker := &ProductionInvoker{socketPath: socket, requestID: func() (string, error) { return "request-export-1234", nil }}
	if _, err := invoker.Invoke(t.Context(), CommandWorkspaceExport, WorkspaceExportIntent{Destination: "usb", OutputID: "output-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err == nil {
		t.Fatal("missing destination was accepted")
	}
	if service.exportCalls != 0 {
		t.Fatalf("guest export calls = %d", service.exportCalls)
	}
}

func TestProductionWorkspaceVerifyRequiresOneCurrentReceipt(t *testing.T) {
	outputID := "output-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	service := &workspaceInvokerDaemon{fakeSessionDaemon: newFakeSessionDaemon(), state: &privatevmv1.WorkspaceState{
		State: "READY", Entries: []*privatevmv1.WorkspaceEntry{{OutputId: outputID, SizeBytes: 4, Exported: true}},
	}}
	service.session.Phase = privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE
	socket, stop := startSessionInvokerDaemon(t, service)
	defer stop()
	invoker := &ProductionInvoker{socketPath: socket, requestID: func() (string, error) { return "request-verify-1234", nil }}
	if _, err := invoker.Invoke(t.Context(), CommandWorkspaceVerify, WorkspaceVerifyIntent{ExportID: outputID}); err != nil {
		t.Fatal(err)
	}
	service.state.Entries[0].ChangedSinceExport = true
	service.state.Entries[0].Exported = false
	service.state.State = "CHANGED"
	if _, err := invoker.Invoke(t.Context(), CommandWorkspaceVerify, WorkspaceVerifyIntent{ExportID: outputID}); err == nil {
		t.Fatal("changed export receipt was accepted")
	}
}

func TestProductionDesktopConnectUsesResolvedOwnedSession(t *testing.T) {
	service := newFakeSessionDaemon()
	service.session.Phase = privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE
	socket, stop := startSessionInvokerDaemon(t, service)
	defer stop()
	seen := ""
	invoker := &ProductionInvoker{
		socketPath: socket, requestID: func() (string, error) { return "request-display-1234", nil },
		viewer: func(_ context.Context, sessionID string) error { seen = sessionID; return nil },
	}
	if _, err := invoker.Invoke(t.Context(), CommandDesktopConnect, SessionIntent{}); err != nil {
		t.Fatal(err)
	}
	if seen != cliSessionID {
		t.Fatalf("viewer session = %q", seen)
	}
}
