package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

// InputSource identifies an explicit source of sensitive input. Callers must
// not infer a source from whether standard input happens to be a terminal.
type InputSource uint8

const (
	InputSourceTerminal InputSource = iota + 1
	InputSourceStdin
	InputSourceFile
)

const defaultTerminalPath = "/dev/tty"

const (
	// MaximumSensitiveValueBytes bounds values copied into protected volatile
	// secret storage. Memory locking is best effort.
	MaximumSensitiveValueBytes int64 = 1 << 20
	// MaximumSensitiveStreamBytes bounds streamed credential or metadata input.
	MaximumSensitiveStreamBytes int64 = 64 << 20
)

var (
	ErrInvalidInputRequest = errors.New("sensitive input request is invalid")
	ErrInputUnavailable    = errors.New("sensitive input is unavailable")
	ErrInputRead           = errors.New("sensitive input could not be read")
	ErrInputEmpty          = errors.New("sensitive input is empty")
	ErrInputTooLarge       = errors.New("sensitive input exceeds the configured limit")
	ErrUnsafeInputFile     = errors.New("sensitive input file does not meet security requirements")
	processStdinLease      = make(chan struct{}, 1)
	inputFDClose           = closeInputFD
)

// InputOpener is an injection seam for opening /dev/tty and sensitive files.
// The flags are operating-system flags and the returned file is owned by the
// input implementation when the source is a terminal or file.
type InputOpener func(name string, flag int, perm fs.FileMode) (*os.File, error)

// ValueRequest describes one bounded sensitive value. Terminal and stdin
// values have one final LF or CRLF removed. File values are returned exactly.
type ValueRequest struct {
	Source InputSource

	// Stdin defaults to os.Stdin and is never closed by SensitiveInput.
	Stdin io.Reader
	// Path is required for InputSourceFile. It is never included in errors.
	Path string
	// TerminalPath defaults to /dev/tty.
	TerminalPath string
	// Open defaults to the platform's no-follow, close-on-exec opener.
	Open InputOpener

	MaxBytes int64
	Timeout  time.Duration

	// RequireOwnerOnly requires a regular file owned by the effective caller
	// with no group/world permissions and no executable permission bits.
	RequireOwnerOnly bool
}

// StreamRequest describes one bounded stdin or regular-file stream. Streams
// do not remove line endings. Terminal streams are intentionally unsupported;
// terminal secrets are values and must use SensitiveInput.
type StreamRequest struct {
	Source InputSource
	Stdin  io.Reader
	Path   string
	Open   InputOpener

	MaxBytes int64
	Timeout  time.Duration

	RequireOwnerOnly bool
}

// SensitiveInput reads one bounded secret and transfers ownership to a
// secret.Bytes. Temporary plaintext buffers are zeroed before return.
func SensitiveInput(ctx context.Context, request ValueRequest) (result *secret.Bytes, resultErr error) {
	if ctx == nil || request.MaxBytes <= 0 || request.MaxBytes > MaximumSensitiveValueBytes || request.Timeout < 0 {
		return nil, ErrInvalidInputRequest
	}

	ctx, cancel := requestContext(ctx, request.Timeout)
	defer cancel()

	if request.Source == InputSourceTerminal {
		value, err := readTerminalValue(ctx, request)
		if err != nil {
			return nil, err
		}
		return newSecret(value)
	}

	streamMaximum := request.MaxBytes
	if request.Source == InputSourceStdin {
		// A line-oriented stdin value may carry LF or CRLF delimiters. They do
		// not count against the value limit, matching terminal input semantics.
		if streamMaximum > int64(^uint64(0)>>1)-2 {
			return nil, ErrInvalidInputRequest
		}
		streamMaximum += 2
	}
	stream, err := SensitiveStream(ctx, StreamRequest{
		Source:           request.Source,
		Stdin:            request.Stdin,
		Path:             request.Path,
		Open:             request.Open,
		MaxBytes:         streamMaximum,
		RequireOwnerOnly: request.RequireOwnerOnly,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := stream.Close(); closeErr != nil {
			if result != nil {
				result.Destroy()
			}
			result = nil
			resultErr = ErrInputRead
		}
	}()

	value, err := readAllSensitive(ctx, stream, streamMaximum)
	if err != nil {
		zero(value)
		return nil, err
	}
	if request.Source == InputSourceStdin {
		value = trimOneLineEnding(value)
	}
	if int64(len(value)) > request.MaxBytes {
		zero(value)
		return nil, ErrInputTooLarge
	}
	return newSecret(value)
}

// SensitiveStream opens a bounded sensitive stream. The caller must close the
// result. Files are closed by Close; caller-owned stdin is deliberately not.
// Reads after MaxBytes return ErrInputTooLarge rather than silently truncating.
func SensitiveStream(ctx context.Context, request StreamRequest) (io.ReadCloser, error) {
	if ctx == nil || request.MaxBytes <= 0 || request.MaxBytes > MaximumSensitiveStreamBytes || request.Timeout < 0 || request.Source == InputSourceTerminal {
		return nil, ErrInvalidInputRequest
	}

	ctx, cancel := requestContext(ctx, request.Timeout)
	var (
		reader       io.Reader
		closer       io.Closer
		releaseLease func()
	)

	switch request.Source {
	case InputSourceStdin:
		callerProvided := request.Stdin != nil
		reader = request.Stdin
		if reader == nil {
			reader = os.Stdin
		}
		if file, ok := reader.(*os.File); ok {
			// A caller-owned os.File may already have Go runtime-poller state
			// (including an unreadable deadline). Duplicating, polling, or
			// closing that descriptor can disturb the caller's state on Linux.
			// The process stdin descriptor is the sole supported file case.
			if callerProvided && file != os.Stdin {
				cancel()
				return nil, ErrInputUnavailable
			}
			select {
			case processStdinLease <- struct{}{}:
				releaseLease = func() { <-processStdinLease }
			case <-ctx.Done():
				cancel()
				return nil, ctx.Err()
			}
			fd, originalFlags, err := duplicateInputFD(file)
			if err != nil {
				releaseLease()
				cancel()
				return nil, err
			}
			owned := &ownedInputFD{fd: fd, originalFlags: originalFlags}
			reader, closer = owned, owned
		}
	case InputSourceFile:
		if request.Path == "" {
			cancel()
			return nil, ErrInvalidInputRequest
		}
		file, err := openSensitiveFileContext(ctx, request.Path, request.Open, request.RequireOwnerOnly)
		if err != nil {
			cancel()
			return nil, err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			cancel()
			return nil, ErrInputRead
		}
		if info.Size() < 0 || info.Size() > request.MaxBytes {
			_ = file.Close()
			cancel()
			return nil, ErrInputTooLarge
		}
		reader, closer = regularFileReader{file: file}, file
	default:
		cancel()
		return nil, ErrInvalidInputRequest
	}

	return &sensitiveStream{
		ctx:       ctx,
		cancel:    cancel,
		reader:    reader,
		closer:    closer,
		release:   releaseLease,
		remaining: request.MaxBytes,
	}, nil
}

type sensitiveStream struct {
	readMu    sync.Mutex
	stateMu   sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	reader    io.Reader
	closer    io.Closer
	release   func()
	remaining int64
	probe     [1]byte
	closed    bool
	oversize  bool
}

// regularFileReader marks an already-opened, regular, size-checked file. It is
// the only production reader permitted to use a synchronous read when the OS
// cannot attach a deadline to a regular file descriptor.
type regularFileReader struct {
	file *os.File
}

func (reader regularFileReader) Read(value []byte) (int, error) {
	return reader.file.Read(value)
}

func (reader regularFileReader) ReadContext(ctx context.Context, value []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		// POSIX regular-file reads have no portable cancellation guarantee.
		// Refuse a timed request instead of detaching an uninterruptible read.
		return 0, ErrInputUnavailable
	}
	n, err := reader.file.Read(value)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	return n, err
}

func (s *sensitiveStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.stateMu.Lock()
	if s.closed {
		s.stateMu.Unlock()
		return 0, os.ErrClosed
	}
	s.stateMu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if s.oversize {
		return 0, ErrInputTooLarge
	}
	if s.remaining == 0 {
		n, err := readWithContext(s.ctx, s.reader, s.probe[:])
		zero(s.probe[:])
		if n > 0 {
			s.oversize = true
			return 0, ErrInputTooLarge
		}
		if err == nil {
			return 0, ErrInputRead
		}
		if errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		return 0, redactReadError(err)
	}

	if int64(len(p)) > s.remaining {
		p = p[:s.remaining]
	}
	n, err := readWithContext(s.ctx, s.reader, p)
	s.remaining -= int64(n)
	if err == nil && n == 0 {
		return 0, ErrInputRead
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return n, redactReadError(err)
	}
	return n, err
}

func (s *sensitiveStream) Close() error {
	s.stateMu.Lock()
	if s.closed {
		s.stateMu.Unlock()
		return nil
	}
	s.closed = true
	cancel := s.cancel
	closer := s.closer
	s.closer = nil
	release := s.release
	s.release = nil
	s.stateMu.Unlock()
	cancel()
	if release != nil {
		defer release()
	}

	// os.File protects an in-flight operation with its own descriptor
	// references, so closing it first is the only available interruption for a
	// regular-file read. Raw duplicated descriptors must instead wait until the
	// bounded poll reader has observed cancellation, preventing FD-number reuse.
	var closeErr error
	if _, raw := closer.(*ownedInputFD); closer != nil && !raw {
		closeErr = closer.Close()
		closer = nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	zero(s.probe[:])
	if closer != nil {
		if err := closer.Close(); err != nil {
			closeErr = err
		}
	}
	if closeErr != nil {
		return ErrInputRead
	}
	return nil
}

func requestContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout > 0 {
		return context.WithTimeout(parent, timeout)
	}
	return context.WithCancel(parent)
}

func readAllSensitive(ctx context.Context, reader io.Reader, maximum int64) ([]byte, error) {
	value := make([]byte, 0, int(maximum))
	buffer := make([]byte, 32*1024)
	defer zero(buffer)

	for {
		if err := ctx.Err(); err != nil {
			return value, err
		}
		n, err := reader.Read(buffer)
		if n > 0 {
			value = append(value, buffer[:n]...)
			zero(buffer[:n])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return value, err
		}
	}
	if int64(len(value)) > maximum {
		return value, ErrInputTooLarge
	}
	return value, nil
}

func readWithContext(ctx context.Context, reader io.Reader, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	if contextual, ok := reader.(interface {
		ReadContext(context.Context, []byte) (int, error)
	}); ok {
		n, err := contextual.ReadContext(ctx, p)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return n, ctxErr
		}
		return n, err
	}

	if !isBoundedSynchronousReader(reader) {
		return 0, ErrInputUnavailable
	}
	return readSynchronous(ctx, reader, p)
}

type boundedSynchronousReader interface {
	boundedSynchronousRead()
}

// ownedInputFD is a raw duplicated descriptor. It deliberately avoids wrapping
// the duplicate in os.File: registering and closing two Go poll descriptors for
// one Linux pipe can disturb deadlines configured on the caller's os.File.
type ownedInputFD struct {
	fd            int
	originalFlags int
	closeOnce     sync.Once
	closeErr      error
}

func (reader *ownedInputFD) Read(value []byte) (int, error) {
	return readInputFDContext(context.Background(), reader.fd, value)
}

func (reader *ownedInputFD) ReadContext(ctx context.Context, value []byte) (int, error) {
	return readInputFDContext(ctx, reader.fd, value)
}

func (reader *ownedInputFD) Close() error {
	reader.closeOnce.Do(func() {
		reader.closeErr = inputFDClose(reader.fd, reader.originalFlags)
	})
	return reader.closeErr
}

func openSensitiveFileContext(ctx context.Context, path string, opener InputOpener, requireOwnerOnly bool) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		// openat2 can block in the kernel and has no cancellation API. Reject a
		// deadline-bearing file request before touching the supplied path.
		return nil, ErrInputUnavailable
	}
	file, err := openSensitiveFile(path, opener, requireOwnerOnly)
	if ctxErr := ctx.Err(); ctxErr != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, ctxErr
	}
	return file, err
}

func isBoundedSynchronousReader(reader io.Reader) bool {
	if _, ok := reader.(boundedSynchronousReader); ok {
		return true
	}
	switch reader.(type) {
	case *bytes.Reader, *strings.Reader:
		return true
	default:
		return false
	}
}

func readSynchronous(ctx context.Context, reader io.Reader, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := reader.Read(p)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	return n, err
}

func redactReadError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrInputRead
}

func newSecret(value []byte) (*secret.Bytes, error) {
	defer zero(value)
	if len(value) == 0 {
		return nil, ErrInputEmpty
	}
	result, err := secret.New(value)
	if err != nil {
		return nil, ErrInputRead
	}
	return result, nil
}

func trimOneLineEnding(value []byte) []byte {
	if len(value) > 0 && value[len(value)-1] == '\n' {
		value = value[:len(value)-1]
		if len(value) > 0 && value[len(value)-1] == '\r' {
			value = value[:len(value)-1]
		}
	}
	return value
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}
