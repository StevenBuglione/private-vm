package guest

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/torrent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const guestTorrentHash = "0123456789abcdef0123456789abcdef01234567"
const guestMagnetPrefix = "magnet:?" + "xt=urn:btih:"

func TestDownloaderTorrentRPCBoundsClearsAndCompletesWorkflow(t *testing.T) {
	backend := &guestTorrentBackend{}
	controller, err := torrent.NewController(backend, guestQuarantine{}, torrent.Config{
		SafePolicy: true, MetadataTimeout: time.Second, PollInterval: time.Millisecond, StallTimeout: time.Second,
		Budget: torrent.CapacityBudget{
			QuarantineAvailableBytes: 8 << 30, ScanAvailableBytes: 8 << 30, ReconstructionAvailable: 8 << 30,
			DestinationAvailable: 8 << 30, RootOverlayBudgetBytes: 1 << 30, ArchiveExpansionBytes: 1 << 30,
			ReconstructionBytes: 128 << 20, MaximumSelectedBytes: 1 << 30,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := &DownloaderVPNServer{torrentController: controller}
	raw := []byte(guestMagnetPrefix + guestTorrentHash)
	frame := &privatevmv1.TorrentInputFrame{
		Context: helloRequest(session.RoleDownloader, APIMajor, APIMinor).GetContext(), Final: true,
		Frame: &privatevmv1.TorrentInputFrame_MagnetChunk{MagnetChunk: raw},
	}
	stream := &torrentAddStream{ctx: t.Context(), frames: []*privatevmv1.TorrentInputFrame{frame}}
	if err := handler.AddTorrent(stream); err != nil {
		t.Fatal(err)
	}
	if frame.Frame != nil || !allZeroGuestBytes(raw) || stream.response == nil || !stream.response.GetPayloadPaused() || len(stream.response.GetFiles()) != 1 {
		t.Fatalf("add response=%+v frameReachable=%t cleared=%t", stream.response, frame.Frame != nil, allZeroGuestBytes(raw))
	}
	requestContext := helloRequest(session.RoleDownloader, APIMajor, APIMinor).GetContext()
	selected, err := handler.SelectTorrentFiles(t.Context(), &privatevmv1.SelectTorrentFilesRequest{Context: requestContext, Indexes: []uint32{0}})
	if err != nil || selected.GetSelectedSizeBytes() != 128<<20 {
		t.Fatalf("selection=%+v err=%v", selected, err)
	}
	download := &torrentDownloadStream{ctx: t.Context()}
	if err := handler.StartDownload(&privatevmv1.TorrentRequest{Context: requestContext}, download); err != nil {
		t.Fatal(err)
	}
	if len(download.events) != 2 || !download.events[1].GetComplete() {
		t.Fatalf("events = %+v", download.events)
	}
	if _, err := handler.SealQuarantine(t.Context(), &privatevmv1.TorrentRequest{Context: requestContext}); err != nil || !backend.shutdown {
		t.Fatalf("seal err=%v shutdown=%t", err, backend.shutdown)
	}
}

func TestDownloaderTorrentRPCRejectsOversizedAndMissingFinalFrames(t *testing.T) {
	handler := &DownloaderVPNServer{torrentController: guestTorrentController(t, &guestTorrentBackend{})}
	for name, frame := range map[string]*privatevmv1.TorrentInputFrame{
		"oversized": {Context: helloRequest(session.RoleDownloader, APIMajor, APIMinor).GetContext(), Final: true, Frame: &privatevmv1.TorrentInputFrame_MagnetChunk{MagnetChunk: make([]byte, maximumTorrentChunkBytes+1)}},
		"not final": {Context: helloRequest(session.RoleDownloader, APIMajor, APIMinor).GetContext(), Frame: &privatevmv1.TorrentInputFrame_MagnetChunk{MagnetChunk: []byte(guestMagnetPrefix + guestTorrentHash)}},
	} {
		t.Run(name, func(t *testing.T) {
			stream := &torrentAddStream{ctx: t.Context(), frames: []*privatevmv1.TorrentInputFrame{frame}}
			err := handler.AddTorrent(stream)
			grpcStatus, ok := status.FromError(err)
			if !ok || grpcStatus.Code() != codes.InvalidArgument || torrentRPCReason(grpcStatus) == "" || torrentRPCReason(grpcStatus) == "INTERNAL_ERROR" {
				t.Fatalf("invalid stream error = %v", err)
			}
		})
	}
}

func torrentRPCReason(value *status.Status) string {
	for _, detail := range value.Details() {
		if info, ok := detail.(*privatevmv1.ErrorDetail); ok {
			return info.GetCode()
		}
	}
	return ""
}

func guestTorrentController(t *testing.T, backend *guestTorrentBackend) *torrent.Controller {
	t.Helper()
	controller, err := torrent.NewController(backend, guestQuarantine{}, torrent.Config{
		SafePolicy: true, MetadataTimeout: time.Second, PollInterval: time.Millisecond, StallTimeout: time.Second,
		Budget: torrent.CapacityBudget{QuarantineAvailableBytes: 8 << 30, ScanAvailableBytes: 8 << 30, ReconstructionAvailable: 8 << 30, DestinationAvailable: 8 << 30, RootOverlayBudgetBytes: 1 << 30, ArchiveExpansionBytes: 1 << 30, ReconstructionBytes: 128 << 20, MaximumSelectedBytes: 1 << 30},
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

type guestTorrentBackend struct {
	statuses []torrent.ClientStatus
	shutdown bool
}

func (*guestTorrentBackend) AddPaused(context.Context, *torrent.Input) (torrent.Handle, error) {
	return torrent.NewHandle(guestTorrentHash)
}
func (*guestTorrentBackend) Metadata(context.Context, torrent.Handle) (torrent.RawMetadata, error) {
	return torrent.RawMetadata{Available: true, DisplayName: "fixture", Files: []torrent.RawFile{{Index: 0, Path: "document.pdf", Size: 128 << 20}}}, nil
}
func (*guestTorrentBackend) SetSelection(context.Context, torrent.Handle, []uint32, uint32) error {
	return nil
}
func (backend *guestTorrentBackend) Start(context.Context, torrent.Handle) error {
	backend.statuses = []torrent.ClientStatus{{State: torrent.ClientRunning, CompletedBytes: 64 << 20, TotalBytes: 128 << 20}, {State: torrent.ClientComplete, CompletedBytes: 128 << 20, TotalBytes: 128 << 20}}
	return nil
}
func (*guestTorrentBackend) Pause(context.Context, torrent.Handle) error { return nil }
func (backend *guestTorrentBackend) Status(context.Context, torrent.Handle) (torrent.ClientStatus, error) {
	if len(backend.statuses) == 0 {
		return torrent.ClientStatus{}, errors.New("fixture exhausted")
	}
	value := backend.statuses[0]
	backend.statuses = backend.statuses[1:]
	return value, nil
}
func (*guestTorrentBackend) VerifyCompleted(context.Context, torrent.Handle, torrent.Metadata) ([]torrent.FileDigest, error) {
	return []torrent.FileDigest{{Path: "document.pdf", SizeBytes: 128 << 20, SourceIndex: 0, SHA256: [32]byte{1}}}, nil
}
func (backend *guestTorrentBackend) Shutdown(context.Context) error {
	backend.shutdown = true
	return nil
}

type guestQuarantine struct{}

func (guestQuarantine) SyncAndUnmount(context.Context) error { return nil }

type torrentAddStream struct {
	ctx      context.Context
	frames   []*privatevmv1.TorrentInputFrame
	response *privatevmv1.TorrentMetadata
}

func (stream *torrentAddStream) Recv() (*privatevmv1.TorrentInputFrame, error) {
	if len(stream.frames) == 0 {
		return nil, io.EOF
	}
	value := stream.frames[0]
	stream.frames = stream.frames[1:]
	return value, nil
}
func (stream *torrentAddStream) SendAndClose(response *privatevmv1.TorrentMetadata) error {
	stream.response = response
	return nil
}
func (stream *torrentAddStream) SetHeader(metadata.MD) error  { return nil }
func (stream *torrentAddStream) SendHeader(metadata.MD) error { return nil }
func (stream *torrentAddStream) SetTrailer(metadata.MD)       {}
func (stream *torrentAddStream) Context() context.Context     { return stream.ctx }
func (stream *torrentAddStream) SendMsg(any) error            { return nil }
func (stream *torrentAddStream) RecvMsg(any) error            { return nil }

type torrentDownloadStream struct {
	ctx    context.Context
	events []*privatevmv1.TorrentEvent
}

func (stream *torrentDownloadStream) Send(event *privatevmv1.TorrentEvent) error {
	stream.events = append(stream.events, event)
	return nil
}
func (stream *torrentDownloadStream) SetHeader(metadata.MD) error  { return nil }
func (stream *torrentDownloadStream) SendHeader(metadata.MD) error { return nil }
func (stream *torrentDownloadStream) SetTrailer(metadata.MD)       {}
func (stream *torrentDownloadStream) Context() context.Context     { return stream.ctx }
func (stream *torrentDownloadStream) SendMsg(any) error            { return nil }
func (stream *torrentDownloadStream) RecvMsg(any) error            { return nil }
