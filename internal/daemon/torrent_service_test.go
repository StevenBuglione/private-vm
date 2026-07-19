package daemon

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/torrent"
	"google.golang.org/grpc/codes"
)

type fakeTorrentOrchestrator struct {
	input    []byte
	addErr   error
	state    string
	selected []uint32
}

func (orchestrator *fakeTorrentOrchestrator) Add(_ context.Context, _ session.Snapshot, _ torrent.InputKind, reader io.Reader) (*privatevmv1.TorrentMetadata, error) {
	value, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	orchestrator.input = append([]byte(nil), value...)
	clear(value)
	if orchestrator.addErr != nil {
		return nil, orchestrator.addErr
	}
	orchestrator.state = "FILE_SELECTION_REQUIRED"
	return torrentTestMetadata(false), nil
}

func (orchestrator *fakeTorrentOrchestrator) Metadata(context.Context, session.Snapshot) (*privatevmv1.TorrentMetadata, error) {
	return torrentTestMetadata(orchestrator.state == "CAPACITY_VERIFIED"), nil
}

func (orchestrator *fakeTorrentOrchestrator) Select(_ context.Context, _ session.Snapshot, indexes []uint32) (*privatevmv1.TorrentMetadata, error) {
	orchestrator.selected = append([]uint32(nil), indexes...)
	orchestrator.state = "CAPACITY_VERIFIED"
	return torrentTestMetadata(true), nil
}

func (orchestrator *fakeTorrentOrchestrator) Start(_ context.Context, _ session.Snapshot, emit func(*privatevmv1.TorrentEvent) error) error {
	orchestrator.state = "DOWNLOADING"
	for _, completed := range []uint64{32, 64} {
		if err := emit(&privatevmv1.TorrentEvent{Progress: &privatevmv1.Progress{Operation: "torrent-download", Completed: completed, Total: 64, Unit: "bytes"}, Complete: completed == 64}); err != nil {
			orchestrator.state = "DOWNLOAD_PAUSED"
			return err
		}
	}
	orchestrator.state = "DOWNLOAD_COMPLETE"
	return nil
}

func (orchestrator *fakeTorrentOrchestrator) Pause(context.Context, session.Snapshot) (*privatevmv1.TorrentStatus, error) {
	orchestrator.state = "DOWNLOAD_PAUSED"
	return torrentTestStatus(orchestrator.state, 32), nil
}

func (orchestrator *fakeTorrentOrchestrator) Status(context.Context, session.Snapshot) (*privatevmv1.TorrentStatus, error) {
	completed := uint64(0)
	if orchestrator.state == "DOWNLOAD_COMPLETE" || orchestrator.state == "QUARANTINE_SEALED" {
		completed = 64
	}
	return torrentTestStatus(orchestrator.state, completed), nil
}

func (orchestrator *fakeTorrentOrchestrator) SealAndDestroy(context.Context, session.Snapshot) (*privatevmv1.TorrentStatus, error) {
	orchestrator.state = "QUARANTINE_SEALED"
	return torrentTestStatus(orchestrator.state, 64), nil
}

func TestTorrentRPCSuccessOwnsEveryWorkflowTransition(t *testing.T) {
	server, socket, _ := newUnstartedTestServer(t, 0)
	orchestrator := &fakeTorrentOrchestrator{}
	server.options.Service.Torrents = orchestrator
	snapshot := activeDownloaderSession(t, server.options.Service.Sessions, nil)
	done := startTestServer(t, server)
	connection, client := dialTestDaemon(t, socket)
	defer connection.Close()

	fixture := syntheticHostMagnet()
	stream, err := client.AddTorrent(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(hostTorrentBegin(snapshot.ID, privatevmv1.TorrentInputKind_TORRENT_INPUT_KIND_MAGNET)); err != nil {
		t.Fatal(err)
	}
	chunk := append([]byte(nil), fixture...)
	if err := stream.Send(hostTorrentChunk(chunk)); err != nil {
		t.Fatal(err)
	}
	clear(chunk)
	metadata, err := stream.CloseAndRecv()
	if err != nil || !metadata.GetPayloadPaused() || !slices.Equal(orchestrator.input, fixture) {
		t.Fatalf("add metadata=%+v err=%v", metadata, err)
	}
	clear(fixture)
	clear(orchestrator.input)

	context := validRequestContext(snapshot.ID)
	selected, err := client.SelectTorrentFiles(t.Context(), &privatevmv1.HostSelectTorrentFilesRequest{Context: context, Indexes: []uint32{0}})
	if err != nil || selected.GetSelectedSizeBytes() != 64 || !slices.Equal(orchestrator.selected, []uint32{0}) {
		t.Fatalf("selection=%+v err=%v", selected, err)
	}
	download, err := client.StartTorrentDownload(t.Context(), &privatevmv1.TorrentControlRequest{Context: context})
	if err != nil {
		t.Fatal(err)
	}
	events := 0
	for {
		_, err := download.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		events++
	}
	if events != 2 {
		t.Fatalf("download events = %d", events)
	}
	sealed, err := client.SealTorrentQuarantine(t.Context(), &privatevmv1.TorrentControlRequest{Context: context})
	if err != nil || sealed.GetState() != "QUARANTINE_SEALED" {
		t.Fatalf("seal=%+v err=%v", sealed, err)
	}
	current, err := server.options.Service.Sessions.Get(snapshot.ID, snapshot.OwnerUID)
	if err != nil || current.WorkflowState != "QUARANTINE_SEALED" || current.Phase != session.PhaseActive {
		t.Fatalf("final session=%+v err=%v", current, err)
	}
	stopTestServer(t, server, done)
}

func TestTorrentRPCFailureCancellationTimeoutAndCleanup(t *testing.T) {
	for _, test := range []struct {
		name       string
		operation  error
		cleanupErr bool
		grpcCode   codes.Code
		code       string
	}{
		{name: "failure", operation: torrent.ErrUnsafeMetadata, grpcCode: codes.FailedPrecondition, code: "TORRENT_METADATA_UNSAFE"},
		{name: "cancellation", operation: context.Canceled, grpcCode: codes.Canceled, code: "REQUEST_CANCELED"},
		{name: "timeout", operation: context.DeadlineExceeded, grpcCode: codes.DeadlineExceeded, code: "REQUEST_TIMEOUT"},
		{name: "cleanup", operation: torrent.ErrUnsafeMetadata, cleanupErr: true, grpcCode: codes.FailedPrecondition, code: "CLEANUP_INCOMPLETE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, socket, _ := newUnstartedTestServer(t, 0)
			server.options.Service.Torrents = &fakeTorrentOrchestrator{addErr: test.operation}
			var cleanupFailure error
			if test.cleanupErr {
				cleanupFailure = errors.New("injected absence failure")
			}
			snapshot := activeDownloaderSession(t, server.options.Service.Sessions, cleanupFailure)
			done := startTestServer(t, server)
			connection, client := dialTestDaemon(t, socket)
			stream, err := client.AddTorrent(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := stream.Send(hostTorrentBegin(snapshot.ID, privatevmv1.TorrentInputKind_TORRENT_INPUT_KIND_MAGNET)); err != nil {
				t.Fatal(err)
			}
			if err := stream.Send(hostTorrentChunk(syntheticHostMagnet())); err != nil {
				t.Fatal(err)
			}
			_, err = stream.CloseAndRecv()
			assertRPCError(t, err, test.grpcCode, test.code)
			current, getErr := server.options.Service.Sessions.Get(snapshot.ID, snapshot.OwnerUID)
			if getErr != nil {
				t.Fatal(getErr)
			}
			if test.cleanupErr {
				if current.Phase != session.PhaseDestroying {
					t.Fatalf("cleanup failure phase=%s", current.Phase)
				}
			} else if current.Phase != session.PhaseDestroyed {
				t.Fatalf("failed operation phase=%s", current.Phase)
			}
			_ = connection.Close()
			stopTestServer(t, server, done)
		})
	}
}

func syntheticHostMagnet() []byte {
	// Assemble the parser fixture at runtime so the repository never contains a
	// magnet-shaped identifier that could be mistaken for a user-supplied URI.
	return []byte("magnet:" + "?xt=urn:" + "btih:" + "0123456789abcdef0123456789abcdef01234567")
}

func activeDownloaderSession(t *testing.T, manager *session.Manager, cleanupFailure error) session.Snapshot {
	t.Helper()
	snapshot, err := manager.Create(uint32(os.Geteuid()), session.RoleDownloader)
	if err != nil {
		t.Fatal(err)
	}
	if cleanupFailure != nil {
		err = manager.AcquireResource(t.Context(), snapshot.ID, snapshot.OwnerUID, "failure-fixture", func(context.Context) (session.CleanupFunc, session.AuditFunc, error) {
			return func(context.Context) error { return cleanupFailure }, func(context.Context) error { return cleanupFailure }, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, state := range downloaderStartedStates {
		snapshot, err = manager.TransitionWorkflow(t.Context(), snapshot.ID, snapshot.OwnerUID, state)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, phase := range []session.Phase{session.PhasePreflighted, session.PhaseImagesVerified, session.PhaseStorageReady, session.PhaseActive} {
		snapshot, err = manager.Transition(t.Context(), snapshot.ID, snapshot.OwnerUID, phase)
		if err != nil {
			t.Fatal(err)
		}
	}
	return snapshot
}

func torrentTestMetadata(selected bool) *privatevmv1.TorrentMetadata {
	return &privatevmv1.TorrentMetadata{
		DisplayName: "private fixture", PayloadPaused: true, SelectedSizeBytes: map[bool]uint64{false: 0, true: 64}[selected],
		Files: []*privatevmv1.TorrentFile{{Index: 0, DisplayPath: "private.bin", SizeBytes: 64, Selected: selected}},
	}
}

func torrentTestStatus(state string, completed uint64) *privatevmv1.TorrentStatus {
	return &privatevmv1.TorrentStatus{
		State: state, Progress: &privatevmv1.Progress{Operation: "torrent-download", Completed: completed, Total: 64, Unit: "bytes"},
		Diagnostics: []*privatevmv1.Diagnostic{{Code: "TORRENT_" + state, Summary: "The torrent state changed.", Remediation: "Continue only from the documented next state."}},
	}
}

func hostTorrentBegin(id string, kind privatevmv1.TorrentInputKind) *privatevmv1.HostTorrentInputFrame {
	return &privatevmv1.HostTorrentInputFrame{Frame: &privatevmv1.HostTorrentInputFrame_Begin{Begin: &privatevmv1.HostTorrentInputBegin{Context: validRequestContext(id), Kind: kind}}}
}

func hostTorrentChunk(value []byte) *privatevmv1.HostTorrentInputFrame {
	return &privatevmv1.HostTorrentInputFrame{Frame: &privatevmv1.HostTorrentInputFrame_Chunk{Chunk: &privatevmv1.HostTorrentChunk{Data: value}}}
}
