package cli

import (
	"context"
	"errors"
	"io"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"github.com/StevenBuglione/private-vm/internal/torrent"
)

// TorrentSubmitter is the synchronous host-orchestrator handoff. The caller
// owns reader lifetime; implementations must consume it before returning and
// may not retain it. The production orchestrator supplies the authenticated
// daemon/guest stream rather than exposing VSOCK to the CLI.
type TorrentSubmitter interface {
	Submit(context.Context, torrent.InputKind, io.Reader) (Result, error)
}

func (invoker *ProductionInvoker) submitTorrent(ctx context.Context, request TorrentInputIntent) (Result, error) {
	if invoker == nil || invoker.torrents == nil {
		return Result{}, apperror.New("NOT_IMPLEMENTED", exitcode.Runtime, "The authenticated torrent orchestrator is not installed.", "Start a verified downloader session through private-vmd before submitting torrent input.")
	}
	readInput := invoker.readInput
	if readInput == nil {
		readInput = SensitiveInput
	}
	readStream := invoker.readStream
	if readStream == nil {
		readStream = SensitiveStream
	}
	switch {
	case request.MagnetTTY || request.MagnetStdin:
		source := InputSourceTerminal
		if request.MagnetStdin {
			source = InputSourceStdin
		}
		if request.MagnetTTY {
			if _, err := io.WriteString(invoker.prompt, "Magnet URI: "); err != nil {
				return Result{}, torrentInputError(ErrInputUnavailable)
			}
		}
		value, err := readInput(ctx, ValueRequest{Source: source, Stdin: invoker.stdin, MaxBytes: torrent.MaximumMagnetBytes})
		if err != nil {
			return Result{}, torrentInputError(err)
		}
		defer value.Destroy()
		var result Result
		err = value.WithReader(func(reader io.Reader) error {
			raw, readErr := io.ReadAll(io.LimitReader(reader, torrent.MaximumMagnetBytes+1))
			defer clear(raw)
			if readErr != nil {
				return readErr
			}
			input, parseErr := torrent.NewInput(torrent.InputMagnet, raw)
			if parseErr != nil {
				return parseErr
			}
			defer input.Destroy()
			return input.WithReader(ctx, func(_ context.Context, protected io.Reader) error {
				result, parseErr = invoker.torrents.Submit(ctx, torrent.InputMagnet, protected)
				return parseErr
			})
		})
		if err != nil {
			return Result{}, torrentInputError(err)
		}
		return result, nil
	case request.TorrentFile != "":
		stream, err := readStream(ctx, StreamRequest{Source: InputSourceFile, Path: request.TorrentFile, MaxBytes: torrent.MaximumMetainfoBytes})
		if err != nil {
			return Result{}, torrentInputError(err)
		}
		result, submitErr := invoker.torrents.Submit(ctx, torrent.InputMetainfo, stream)
		closeErr := stream.Close()
		if submitErr != nil {
			return Result{}, torrentInputError(submitErr)
		}
		if closeErr != nil {
			return Result{}, torrentInputError(closeErr)
		}
		return result, nil
	default:
		return Result{}, invalidTorrentIntent()
	}
}

func torrentInputError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return contextError(err)
	case errors.Is(err, torrent.ErrInputTooLarge), errors.Is(err, ErrInputTooLarge):
		return apperror.New("TORRENT_INPUT_TOO_LARGE", exitcode.Torrent, "The torrent input exceeds its fixed size limit.", "Use a magnet no larger than 8 KiB or a .torrent file no larger than 16 MiB.")
	case errors.Is(err, torrent.ErrInvalidInput), errors.Is(err, ErrInputEmpty):
		return apperror.New("TORRENT_INPUT_INVALID", exitcode.Torrent, "The bounded torrent input is malformed.", "Supply one valid magnet through hidden terminal input or stdin, or one regular .torrent file.")
	case errors.Is(err, ErrUnsafeInputFile):
		return apperror.New("TORRENT_SOURCE_UNSAFE", exitcode.Torrent, "The .torrent source file is unsafe.", "Use a regular local file without symlinks or remote-filesystem indirection.")
	default:
		var application *apperror.Error
		if errors.As(err, &application) {
			return application
		}
		return apperror.New("TORRENT_INPUT_READ_FAILED", exitcode.Torrent, "The torrent input could not be read or transferred safely.", "Retry with bounded hidden terminal input, standard input, or one readable regular .torrent file.")
	}
}

func invalidTorrentIntent() error {
	return apperror.New("TORRENT_REQUEST_INVALID", exitcode.Torrent, "The torrent input request contract is invalid.", "Use exactly one documented secure torrent input source.")
}
