package orchestrator

import (
	"context"
	"crypto/sha256"
	"io"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc"
)

type strictRelayWorkstationClient struct {
	privatevmv1.WorkstationGuestServiceClient
	importStream *strictRelayImportStream
	exportStream *strictRelayExportStream
}

func (client *strictRelayWorkstationClient) ImportFile(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[privatevmv1.TransferFrame, privatevmv1.TransferReceipt], error) {
	return client.importStream, nil
}

func (client *strictRelayWorkstationClient) ExportFile(context.Context, *privatevmv1.GuestExportFileRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[privatevmv1.TransferFrame], error) {
	return client.exportStream, nil
}

type strictRelayImportStream struct {
	grpc.ClientStreamingClient[privatevmv1.TransferFrame, privatevmv1.TransferReceipt]
	receipt *privatevmv1.TransferReceipt
	types   []string
	chunks  [][]byte
	closed  bool
}

func (stream *strictRelayImportStream) Send(frame *privatevmv1.TransferFrame) error {
	switch {
	case frame.GetBegin() != nil:
		stream.types = append(stream.types, "begin")
	case frame.GetChunk() != nil:
		stream.types = append(stream.types, "chunk")
		stream.chunks = append(stream.chunks, append([]byte(nil), frame.GetChunk().GetData()...))
	case frame.GetEnd() != nil:
		stream.types = append(stream.types, "end")
	}
	return nil
}

func (stream *strictRelayImportStream) CloseAndRecv() (*privatevmv1.TransferReceipt, error) {
	stream.closed = true
	return stream.receipt, nil
}

type strictRelayExportStream struct {
	grpc.ServerStreamingClient[privatevmv1.TransferFrame]
	frames []*privatevmv1.TransferFrame
	index  int
}

func (stream *strictRelayExportStream) Recv() (*privatevmv1.TransferFrame, error) {
	if stream.index >= len(stream.frames) {
		return nil, io.EOF
	}
	frame := stream.frames[stream.index]
	stream.index++
	return frame, nil
}

func strictRelayFixture(payload []byte) (*privatevmv1.TransferBegin, []*privatevmv1.TransferFrame) {
	digest := sha256.Sum256(payload)
	descriptor := &privatevmv1.FileDescriptor{
		LogicalName: "approved.bin",
		SizeBytes:   uint64(len(payload)),
		Digest:      protoSHA256(digest),
	}
	begin := &privatevmv1.TransferBegin{TransferId: "transfer-bounded", Descriptor_: descriptor}
	frames := []*privatevmv1.TransferFrame{
		{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Sequence: 0, Data: append([]byte(nil), payload...)}}},
		{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{TotalSize: uint64(len(payload)), Digest: protoSHA256(digest)}}},
	}
	return begin, frames
}

func strictRelayConnection(client privatevmv1.WorkstationGuestServiceClient) *vsockGuestConnection {
	return &vsockGuestConnection{
		role:             session.RoleWorkstation,
		expected:         guest.HandshakeExpectation{SessionID: hostRoleSessionID},
		workstation:      client,
		workspaceExports: make(map[string][32]byte),
	}
}

func frameReceiver(frames []*privatevmv1.TransferFrame) func() (*privatevmv1.TransferFrame, error) {
	index := 0
	return func() (*privatevmv1.TransferFrame, error) {
		if index >= len(frames) {
			return nil, io.EOF
		}
		frame := frames[index]
		index++
		return frame, nil
	}
}

func TestWorkstationRelayImportRequiresImmediateEOFBeforeGuestCommit(t *testing.T) {
	payload := []byte("bounded import")
	begin, frames := strictRelayFixture(payload)
	trailing := &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Sequence: 1, Data: []byte("trailing")}}}
	frames = append(frames, trailing)
	guestStream := &strictRelayImportStream{receipt: &privatevmv1.TransferReceipt{
		TransferId: begin.GetTransferId(), Descriptor_: cloneDescriptor(begin.GetDescriptor_()), ReceiverDigest: cloneHash(begin.GetDescriptor_().GetDigest()),
	}}
	connection := strictRelayConnection(&strictRelayWorkstationClient{importStream: guestStream})

	if _, err := connection.Import(t.Context(), WorkspaceImport{Begin: begin, Receive: frameReceiver(frames)}); err == nil {
		t.Fatal("Import accepted a frame after End")
	}
	if guestStream.closed {
		t.Fatal("guest import was committed before the daemon proved terminal EOF")
	}
	if len(guestStream.types) != 2 || guestStream.types[0] != "begin" || guestStream.types[1] != "chunk" {
		t.Fatalf("guest frames before rejection = %v, want [begin chunk]", guestStream.types)
	}
	if !allZeroRelayData(trailing.GetChunk().GetData()) {
		t.Fatal("rejected trailing bytes were not cleared")
	}
}

func TestWorkstationRelayImportCommitsAfterImmediateEOF(t *testing.T) {
	payload := []byte("bounded import")
	begin, frames := strictRelayFixture(payload)
	guestStream := &strictRelayImportStream{receipt: &privatevmv1.TransferReceipt{
		TransferId: begin.GetTransferId(), Descriptor_: cloneDescriptor(begin.GetDescriptor_()), ReceiverDigest: cloneHash(begin.GetDescriptor_().GetDigest()),
	}}
	connection := strictRelayConnection(&strictRelayWorkstationClient{importStream: guestStream})

	receipt, err := connection.Import(t.Context(), WorkspaceImport{Begin: begin, Receive: frameReceiver(frames)})
	if err != nil {
		t.Fatal(err)
	}
	if !guestStream.closed || receipt.GetTransferId() != begin.GetTransferId() {
		t.Fatalf("committed=%v receipt=%#v", guestStream.closed, receipt)
	}
	if len(guestStream.types) != 3 || guestStream.types[2] != "end" {
		t.Fatalf("guest frames = %v, want [begin chunk end]", guestStream.types)
	}
	if len(guestStream.chunks) != 1 || string(guestStream.chunks[0]) != string(payload) {
		t.Fatalf("guest chunks = %q", guestStream.chunks)
	}
}

func TestWorkstationRelayExportRequiresImmediateEOFBeforeReceiverCommit(t *testing.T) {
	payload := []byte("bounded export")
	begin, frames := strictRelayFixture(payload)
	begin.TransferId = "output-bounded"
	guestFrames := append([]*privatevmv1.TransferFrame{{Frame: &privatevmv1.TransferFrame_Begin{Begin: begin}}}, frames...)
	trailing := &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Sequence: 1, Data: []byte("trailing")}}}
	guestFrames = append(guestFrames, trailing)
	connection := strictRelayConnection(&strictRelayWorkstationClient{exportStream: &strictRelayExportStream{frames: guestFrames}})
	received := make([]string, 0, 3)

	_, err := connection.Export(t.Context(), WorkspaceExport{OutputID: begin.GetTransferId(), Send: func(frame *privatevmv1.TransferFrame) error {
		switch {
		case frame.GetBegin() != nil:
			received = append(received, "begin")
		case frame.GetChunk() != nil:
			received = append(received, "chunk")
		case frame.GetEnd() != nil:
			received = append(received, "end")
		}
		return nil
	}})
	if err == nil {
		t.Fatal("Export accepted a frame after End")
	}
	if len(received) != 2 || received[0] != "begin" || received[1] != "chunk" {
		t.Fatalf("receiver frames before rejection = %v, want [begin chunk]", received)
	}
	if !allZeroRelayData(trailing.GetChunk().GetData()) {
		t.Fatal("rejected trailing bytes were not cleared")
	}
	if _, ok := connection.workspaceExports[begin.GetTransferId()]; ok {
		t.Fatal("export was recorded before the daemon proved terminal EOF")
	}
}

func allZeroRelayData(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}
