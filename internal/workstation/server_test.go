package workstation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"google.golang.org/grpc"
)

func TestImportFileSuccessAndFailureCleanup(t *testing.T) {
	server, root := testServer(t)
	data := []byte("trusted input")
	digest := sha256.Sum256(data)
	stream := &importStream{ctx: t.Context(), frames: []*privatevmv1.TransferFrame{
		beginFrame("transfer-12345678", "input.txt", data, digest),
		chunkFrame(0, data), endFrame(data, digest),
	}}
	if err := server.ImportFile(stream); err != nil {
		t.Fatal(err)
	}
	if stream.receipt == nil || stream.receipt.GetReceiverDigest().GetAlgorithm() != "sha256" {
		t.Fatalf("receipt = %#v", stream.receipt)
	}
	got, err := os.ReadFile(filepath.Join(root, "Inbox", "input.txt"))
	if err != nil || string(got) != string(data) {
		t.Fatalf("imported data = %q, %v", got, err)
	}

	bad := digest
	bad[0] ^= 0xff
	failed := &importStream{ctx: t.Context(), frames: []*privatevmv1.TransferFrame{
		beginFrame("transfer-abcdefgh", "failed.txt", data, digest),
		chunkFrame(0, data), endFrame(data, bad),
	}}
	if err := server.ImportFile(failed); err == nil {
		t.Fatal("digest mismatch was accepted")
	}
	if _, err := os.Stat(filepath.Join(root, "Inbox", "failed.txt")); !os.IsNotExist(err) {
		t.Fatalf("failed target remains: %v", err)
	}
	partials, _ := filepath.Glob(filepath.Join(root, "Inbox", ".*.partial"))
	if len(partials) != 0 {
		t.Fatalf("partial imports remain: %v", partials)
	}
}

func TestImportRejectsTraversal(t *testing.T) {
	server, _ := testServer(t)
	data := []byte("x")
	digest := sha256.Sum256(data)
	stream := &importStream{ctx: t.Context(), frames: []*privatevmv1.TransferFrame{beginFrame("transfer-12345678", "../escape", data, digest)}}
	if err := server.ImportFile(stream); err == nil {
		t.Fatal("traversal name was accepted")
	}
}

func TestImportFailureCancellationTimeoutAndFramingRemoveAllArtifacts(t *testing.T) {
	data := []byte("trusted input")
	digest := sha256.Sum256(data)
	maximum := bytes.Repeat([]byte{'x'}, 1<<20)
	oversized := bytes.Repeat([]byte{'x'}, 1+(1<<20))
	for _, test := range []struct {
		name   string
		stream func(context.Context) *importStream
	}{
		{name: "zero-chunk", stream: func(ctx context.Context) *importStream {
			return &importStream{ctx: ctx, frames: []*privatevmv1.TransferFrame{beginFrame("transfer-zero", "zero.txt", data, digest), chunkFrame(0, nil), endFrame(data, digest)}}
		}},
		{name: "oversized-chunk", stream: func(ctx context.Context) *importStream {
			return &importStream{ctx: ctx, frames: []*privatevmv1.TransferFrame{beginFrame("transfer-oversized", "oversized.txt", maximum, sha256.Sum256(maximum)), chunkFrame(0, oversized)}}
		}},
		{name: "trailing-frame", stream: func(ctx context.Context) *importStream {
			return &importStream{ctx: ctx, frames: []*privatevmv1.TransferFrame{beginFrame("transfer-trailing", "trailing.txt", data, digest), chunkFrame(0, data), endFrame(data, digest), chunkFrame(1, []byte("extra"))}}
		}},
		{name: "cancellation", stream: func(ctx context.Context) *importStream {
			canceled, cancel := context.WithCancel(ctx)
			return &importStream{ctx: canceled, frames: []*privatevmv1.TransferFrame{beginFrame("transfer-canceled", "canceled.txt", data, digest), chunkFrame(0, data)}, beforeRecv: func(index int) {
				if index == 1 {
					cancel()
				}
			}}
		}},
		{name: "deadline", stream: func(ctx context.Context) *importStream {
			expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
			t.Cleanup(cancel)
			return &importStream{ctx: expired, frames: []*privatevmv1.TransferFrame{beginFrame("transfer-timeout", "timeout.txt", data, digest), chunkFrame(0, data)}}
		}},
		{name: "receipt-failure", stream: func(ctx context.Context) *importStream {
			return &importStream{ctx: ctx, sendErr: errors.New("injected receipt failure"), frames: []*privatevmv1.TransferFrame{beginFrame("transfer-receipt", "receipt.txt", data, digest), chunkFrame(0, data), endFrame(data, digest)}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, root := testServer(t)
			if err := server.ImportFile(test.stream(t.Context())); err == nil {
				t.Fatal("invalid import returned success")
			}
			assertNoImportArtifacts(t, filepath.Join(root, "Inbox"))
		})
	}
}

func TestImportFrameLimitRemovesPartial(t *testing.T) {
	server, root := testServer(t)
	data := bytes.Repeat([]byte{'x'}, int(maxWorkspaceFrames))
	digest := sha256.Sum256(data)
	frames := make([]*privatevmv1.TransferFrame, 0, int(maxWorkspaceFrames))
	frames = append(frames, beginFrame("transfer-frame-limit", "limited.bin", data, digest))
	for sequence := uint64(0); sequence < maxWorkspaceFrames-1; sequence++ {
		frames = append(frames, chunkFrame(sequence, []byte{'x'}))
	}
	if err := server.ImportFile(&importStream{ctx: t.Context(), frames: frames}); err == nil {
		t.Fatal("frame limit returned success")
	}
	assertNoImportArtifacts(t, filepath.Join(root, "Inbox"))
}

func TestImportInboxReplacementFailsAndCleansPinnedDirectory(t *testing.T) {
	server, root := testServer(t)
	data := []byte("trusted input")
	digest := sha256.Sum256(data)
	inbox := filepath.Join(root, "Inbox")
	moved := filepath.Join(root, "Inbox-moved")
	stream := &importStream{ctx: t.Context(), frames: []*privatevmv1.TransferFrame{
		beginFrame("transfer-replaced", "replaced.txt", data, digest), chunkFrame(0, data), endFrame(data, digest),
	}, beforeRecv: func(index int) {
		if index != 1 {
			return
		}
		if err := os.Rename(inbox, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(inbox, 0o700); err != nil {
			t.Fatal(err)
		}
	}}
	if err := server.ImportFile(stream); err == nil {
		t.Fatal("replaced Inbox returned success")
	}
	assertNoImportArtifacts(t, inbox)
	assertNoImportArtifacts(t, moved)
}

func TestWorkspaceExportVerificationAndChangeDetection(t *testing.T) {
	server, root := testServer(t)
	path := filepath.Join(root, "Export", "result.bin")
	data := []byte("approved output")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := server.GetWorkspaceState(t.Context(), &privatevmv1.WorkspaceStateRequest{})
	if err != nil || state.GetState() != "UNEXPORTED" || len(state.GetEntries()) != 1 {
		t.Fatalf("initial state = %#v, %v", state, err)
	}
	outputID := state.GetEntries()[0].GetOutputId()
	export := &exportStream{ctx: t.Context()}
	if err := server.ExportFile(&privatevmv1.GuestExportFileRequest{OutputId: outputID}, export); err != nil {
		t.Fatal(err)
	}
	if len(export.frames) < 3 || export.frames[0].GetBegin().GetDescriptor_().GetLogicalName() != "result.bin" {
		t.Fatalf("export frames = %#v", export.frames)
	}
	digest := sha256.Sum256(data)
	state, err = server.MarkExportVerified(t.Context(), &privatevmv1.MarkExportVerifiedRequest{OutputId: outputID, Digest: protoHash(digest)})
	if err != nil || state.GetState() != "READY" || !state.GetEntries()[0].GetExported() {
		t.Fatalf("verified state = %#v, %v", state, err)
	}
	if err := os.WriteFile(path, []byte("changed output"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err = server.GetWorkspaceState(t.Context(), &privatevmv1.WorkspaceStateRequest{})
	if err != nil || state.GetState() != "CHANGED" || !state.GetEntries()[0].GetChangedSinceExport() {
		t.Fatalf("changed state = %#v, %v", state, err)
	}
}

func TestWorkspaceRejectsLinks(t *testing.T) {
	server, root := testServer(t)
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "Export", "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := server.ListExportFiles(t.Context(), &privatevmv1.WorkspaceStateRequest{}); err == nil {
		t.Fatal("symbolic link was accepted")
	}
}

func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"Inbox", "Export"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	server, err := New(Config{Root: root, MaxFileBytes: 1 << 20, MaxWorkspaceBytes: 2 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return server, root
}

func assertNoImportArtifacts(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("import artifacts remain in %s: %+v", directory, entries)
	}
}

func beginFrame(id, name string, data []byte, digest [sha256.Size]byte) *privatevmv1.TransferFrame {
	return &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{TransferId: id,
		Descriptor_: &privatevmv1.FileDescriptor{LogicalName: name, SizeBytes: uint64(len(data)), Digest: protoHash(digest)}}}}
}

func chunkFrame(sequence uint64, data []byte) *privatevmv1.TransferFrame {
	return &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Sequence: sequence, Data: append([]byte(nil), data...)}}}
}

func endFrame(data []byte, digest [sha256.Size]byte) *privatevmv1.TransferFrame {
	return &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{TotalSize: uint64(len(data)), Digest: protoHash(digest)}}}
}

type importStream struct {
	grpc.ServerStream
	ctx        context.Context
	frames     []*privatevmv1.TransferFrame
	receipt    *privatevmv1.TransferReceipt
	sendErr    error
	beforeRecv func(int)
	received   int
}

func (stream *importStream) Context() context.Context { return stream.ctx }
func (stream *importStream) Recv() (*privatevmv1.TransferFrame, error) {
	if stream.beforeRecv != nil {
		stream.beforeRecv(stream.received)
	}
	stream.received++
	if len(stream.frames) == 0 {
		return nil, io.EOF
	}
	frame := stream.frames[0]
	stream.frames = stream.frames[1:]
	return frame, nil
}
func (stream *importStream) SendAndClose(receipt *privatevmv1.TransferReceipt) error {
	stream.receipt = receipt
	return stream.sendErr
}

type exportStream struct {
	grpc.ServerStream
	ctx    context.Context
	frames []*privatevmv1.TransferFrame
}

func (stream *exportStream) Context() context.Context { return stream.ctx }
func (stream *exportStream) Send(frame *privatevmv1.TransferFrame) error {
	stream.frames = append(stream.frames, frame)
	return nil
}
