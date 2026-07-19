package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/torrent"
)

const cliTorrentHash = "0123456789abcdef0123456789abcdef01234567"
const cliMagnetPrefix = "magnet:?" + "xt=urn:btih:"

type recordingTorrentSubmitter struct {
	kind  torrent.InputKind
	value []byte
	calls int
	err   error
}

func (submitter *recordingTorrentSubmitter) Submit(_ context.Context, kind torrent.InputKind, reader io.Reader) (Result, error) {
	submitter.calls++
	submitter.kind = kind
	value, err := io.ReadAll(reader)
	if err != nil {
		return Result{}, err
	}
	submitter.value = append([]byte(nil), value...)
	clear(value)
	if submitter.err != nil {
		return Result{}, submitter.err
	}
	return Result{Code: CodeAcknowledged, Data: AcknowledgementPayload{Message: "Torrent input accepted into volatile planning."}}, nil
}

func TestTorrentInvokerReadsHiddenTerminalAndDestroysSource(t *testing.T) {
	fixture := []byte(cliMagnetPrefix + cliTorrentHash)
	source, err := secret.New(fixture)
	if err != nil {
		t.Fatal(err)
	}
	submitter := &recordingTorrentSubmitter{}
	var prompt bytes.Buffer
	invoker := &ProductionInvoker{
		prompt: &prompt, torrents: submitter,
		readInput: func(_ context.Context, request ValueRequest) (*secret.Bytes, error) {
			if request.Source != InputSourceTerminal || request.MaxBytes != torrent.MaximumMagnetBytes {
				t.Fatalf("terminal request = %+v", request)
			}
			return source, nil
		},
	}
	result, err := invoker.Invoke(t.Context(), CommandTorrentAdd, TorrentInputIntent{MagnetTTY: true})
	if err != nil || result.Code != CodeAcknowledged || submitter.kind != torrent.InputMagnet || !bytes.Equal(submitter.value, fixture) {
		t.Fatalf("submit result=%+v err=%v submitter=%+v", result, err, submitter)
	}
	if prompt.String() != "Magnet URI: " {
		t.Fatalf("prompt = %q", prompt.String())
	}
	if _, err := source.Equal(fixture); !errors.Is(err, secret.ErrDestroyed) {
		t.Fatalf("source was not destroyed: %v", err)
	}
	clear(fixture)
	clear(submitter.value)
}

func TestTorrentInvokerStreamsFileAndClosesEveryOutcome(t *testing.T) {
	fixture := []byte("d4:infode")
	stream := &trackingTorrentStream{Reader: bytes.NewReader(fixture)}
	submitter := &recordingTorrentSubmitter{err: context.Canceled}
	invoker := &ProductionInvoker{
		torrents: submitter,
		readStream: func(_ context.Context, request StreamRequest) (io.ReadCloser, error) {
			if request.Source != InputSourceFile || request.Path != "/private/input.torrent" || request.MaxBytes != torrent.MaximumMetainfoBytes || request.RequireOwnerOnly {
				t.Fatalf("file request = %+v", request)
			}
			return stream, nil
		},
	}
	_, err := invoker.Invoke(t.Context(), CommandTorrentAdd, TorrentInputIntent{TorrentFile: "/private/input.torrent"})
	if apperror.From(err).Code != "OPERATION_CANCELLED" || !stream.closed || submitter.kind != torrent.InputMetainfo || !bytes.Equal(submitter.value, fixture) {
		t.Fatalf("file submit err=%v stream=%+v submitter=%+v", err, stream, submitter)
	}
	clear(submitter.value)
}

func TestTorrentInvokerRejectsMalformedMagnetBeforeTransport(t *testing.T) {
	source, err := secret.New([]byte("magnet:?dn=missing-topic"))
	if err != nil {
		t.Fatal(err)
	}
	submitter := &recordingTorrentSubmitter{}
	invoker := &ProductionInvoker{torrents: submitter, readInput: func(context.Context, ValueRequest) (*secret.Bytes, error) { return source, nil }}
	_, err = invoker.Invoke(t.Context(), CommandTorrentAdd, TorrentInputIntent{MagnetStdin: true})
	if application := apperror.From(err); application.Code != "TORRENT_INPUT_INVALID" || submitter.calls != 0 || strings.Contains(application.Error()+application.Remediation, "missing-topic") {
		t.Fatalf("malformed result=%+v calls=%d", application, submitter.calls)
	}
}

type trackingTorrentStream struct {
	io.Reader
	closed bool
}

func (stream *trackingTorrentStream) Close() error { stream.closed = true; return nil }
