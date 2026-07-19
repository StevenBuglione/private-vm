package orchestrator

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/torrent"
	"google.golang.org/protobuf/proto"
)

type recordingTorrentSender struct {
	frames []*privatevmv1.TorrentInputFrame
	err    error
}

func (sender *recordingTorrentSender) Send(frame *privatevmv1.TorrentInputFrame) error {
	if sender.err != nil {
		return sender.err
	}
	sender.frames = append(sender.frames, proto.Clone(frame).(*privatevmv1.TorrentInputFrame))
	return nil
}

func TestSendTorrentInputFramesBoundedInputAndContextOnce(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, (16<<10)+37)
	request := &privatevmv1.GuestContext{Context: &privatevmv1.RequestContext{SessionId: hostRoleSessionID}}
	sender := &recordingTorrentSender{}
	if err := sendTorrentInput(sender, request, torrent.InputMetainfo, bytes.NewReader(payload), len(payload)); err != nil {
		t.Fatal(err)
	}
	if len(sender.frames) != 2 || sender.frames[0].GetContext() == nil || sender.frames[1].GetContext() != nil ||
		sender.frames[0].GetFinal() || !sender.frames[1].GetFinal() {
		t.Fatalf("unexpected frame envelope: %+v", sender.frames)
	}
	combined := append(append([]byte(nil), sender.frames[0].GetTorrentChunk()...), sender.frames[1].GetTorrentChunk()...)
	if !bytes.Equal(combined, payload) {
		t.Fatal("framed payload changed")
	}
}

func TestSendTorrentInputRejectsEmptyOversizeAndSendFailure(t *testing.T) {
	request := &privatevmv1.GuestContext{}
	if err := sendTorrentInput(&recordingTorrentSender{}, request, torrent.InputMagnet, bytes.NewReader(nil), 32); !errors.Is(err, torrent.ErrInvalidInput) {
		t.Fatalf("empty input error = %v", err)
	}
	if err := sendTorrentInput(&recordingTorrentSender{}, request, torrent.InputMagnet, bytes.NewReader(bytes.Repeat([]byte{'x'}, 33)), 32); !errors.Is(err, torrent.ErrInputTooLarge) {
		t.Fatalf("oversize error = %v", err)
	}
	want := errors.New("send failed")
	if err := sendTorrentInput(&recordingTorrentSender{err: want}, request, torrent.InputMagnet, bytes.NewReader([]byte("magnet:?xt=fixture")), 64); !errors.Is(err, want) {
		t.Fatalf("send error = %v", err)
	}
}

func TestRuntimeSocketDirectoriesCleanupIsIdempotent(t *testing.T) {
	runtimeRoot := t.TempDir()
	parent := filepath.Join(runtimeRoot, hostRoleSessionID)
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	directories, err := createRuntimeSocketDirectories(runtimeRoot, hostRoleSessionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := directories.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := directories.Cleanup(); err != nil {
		t.Fatalf("repeated cleanup = %v", err)
	}
	if err := directories.Audit(); err != nil {
		t.Fatal(err)
	}
}
