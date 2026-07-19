package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSensitiveInputFromStdin(t *testing.T) {
	input := []byte("magnet:?xt=example\r\n")
	value, err := SensitiveInput(context.Background(), ValueRequest{
		Source:   InputSourceStdin,
		Stdin:    bytes.NewReader(input),
		MaxBytes: int64(len(input) - 2),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer value.Destroy()

	if value.String() != "[REDACTED]" {
		t.Fatal("sensitive value did not redact its string form")
	}
	actual, err := readProtectedValue(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(actual)
	if string(actual) != "magnet:?xt=example" {
		t.Fatal("unexpected protected value")
	}
}

func TestSensitiveInputRejectsEmptyAndOversizeStdin(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		maximum int64
		want    error
	}{
		{name: "empty", input: "\n", maximum: 8, want: ErrInputEmpty},
		{name: "oversize", input: "secret-value\n", maximum: 6, want: ErrInputTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := SensitiveInput(context.Background(), ValueRequest{
				Source: InputSourceStdin, Stdin: strings.NewReader(test.input), MaxBytes: test.maximum,
			})
			if value != nil {
				value.Destroy()
				t.Fatal("unexpected sensitive value")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestSensitiveInputCancellationAndTimeout(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := SensitiveInput(ctx, ValueRequest{
			Source: InputSourceStdin, Stdin: strings.NewReader("secret"), MaxBytes: 32,
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want cancellation", err)
		}
	})

	t.Run("timeout interrupts pipe", func(t *testing.T) {
		reader := newBlockingContextReader()
		started := time.Now()
		_, err := SensitiveInput(context.Background(), ValueRequest{
			Source: InputSourceStdin, Stdin: reader, MaxBytes: 32, Timeout: 30 * time.Millisecond,
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v, want deadline exceeded", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("timeout was not bounded: %v", elapsed)
		}
	})
}

func TestSensitiveInputRejectsLateContextualReaderSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := contextualReaderFunc(func(_ context.Context, value []byte) (int, error) {
		copy(value, "late-secret")
		cancel()
		return len("late-secret"), nil
	})
	secretValue, err := SensitiveInput(ctx, ValueRequest{
		Source: InputSourceStdin, Stdin: reader, MaxBytes: 32,
	})
	if secretValue != nil {
		secretValue.Destroy()
		t.Fatal("late reader success produced a secret")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}

func TestSensitiveInputFilePreservesBytesAndRequiresOwnerOnlyMode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "vpn.conf")
	content := []byte("private-key-material\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	value, err := SensitiveInput(context.Background(), ValueRequest{
		Source: InputSourceFile, Path: path, MaxBytes: 1024, RequireOwnerOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer value.Destroy()
	actual, err := readProtectedValue(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(actual)
	if !bytes.Equal(actual, content) {
		t.Fatal("file value was modified")
	}
}

type protectedReader interface {
	WithReader(func(io.Reader) error) error
}

func readProtectedValue(value protectedReader) ([]byte, error) {
	var result []byte
	err := value.WithReader(func(reader io.Reader) error {
		read, readErr := io.ReadAll(reader)
		if readErr != nil {
			return readErr
		}
		result = read
		return nil
	})
	return result, err
}

func TestSensitiveInputFileRejectsSymlinkUnsafeModeAndNonRegular(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "credential-with-sensitive-name")
	if err := os.WriteFile(target, []byte("private-key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "credential-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	unsafe := filepath.Join(directory, "unsafe")
	if err := os.WriteFile(unsafe, []byte("private-key-material"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		path   string
		strict bool
		want   error
	}{
		{name: "symlink", path: link, want: ErrInputUnavailable},
		{name: "unsafe mode", path: unsafe, strict: true, want: ErrUnsafeInputFile},
		{name: "directory", path: directory, want: ErrUnsafeInputFile},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := SensitiveInput(context.Background(), ValueRequest{
				Source: InputSourceFile, Path: test.path, MaxBytes: 1024, RequireOwnerOnly: test.strict,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			message := err.Error()
			for _, forbidden := range []string{test.path, target, "private-key-material"} {
				if strings.Contains(message, forbidden) {
					t.Fatalf("error exposed sensitive data: %q", message)
				}
			}
		})
	}
}

func TestSensitiveInputRedactsReaderErrors(t *testing.T) {
	sensitiveError := "read /private/credential: private-key-material"
	_, err := SensitiveInput(context.Background(), ValueRequest{
		Source: InputSourceStdin,
		Stdin: readerFunc(func([]byte) (int, error) {
			return 0, errors.New(sensitiveError)
		}),
		MaxBytes: 1024,
	})
	if !errors.Is(err, ErrInputRead) {
		t.Fatalf("got %v, want redacted read error", err)
	}
	if strings.Contains(err.Error(), sensitiveError) || strings.Contains(err.Error(), "private-key-material") {
		t.Fatalf("error exposed sensitive data: %q", err)
	}
}

func TestSensitiveStreamBoundAndCloseOwnership(t *testing.T) {
	t.Run("oversize", func(t *testing.T) {
		stream, err := SensitiveStream(context.Background(), StreamRequest{
			Source: InputSourceStdin, Stdin: strings.NewReader("12345"), MaxBytes: 4,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		value, err := io.ReadAll(stream)
		zero(value)
		if !errors.Is(err, ErrInputTooLarge) {
			t.Fatalf("got %v, want oversize error", err)
		}
	})

	t.Run("stdin remains open", func(t *testing.T) {
		source := &trackingReader{Reader: strings.NewReader("value")}
		stream, err := SensitiveStream(context.Background(), StreamRequest{
			Source: InputSourceStdin, Stdin: source, MaxBytes: 8,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		if source.closed {
			t.Fatal("caller-owned stdin was closed")
		}
	})

	t.Run("file closes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "input")
		if err := os.WriteFile(path, []byte("value"), 0o600); err != nil {
			t.Fatal(err)
		}
		var opened *os.File
		stream, err := SensitiveStream(context.Background(), StreamRequest{
			Source: InputSourceFile, Path: path, MaxBytes: 8,
			Open: func(name string, flag int, perm fs.FileMode) (*os.File, error) {
				file, openErr := os.OpenFile(name, flag, perm)
				opened = file
				return file, openErr
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := opened.Read(make([]byte, 1)); err == nil {
			t.Fatal("owned file remained open")
		}
	})
}

func TestSensitiveRequestsRejectInvalidBoundsAndTerminalStream(t *testing.T) {
	if _, err := SensitiveInput(context.Background(), ValueRequest{Source: InputSourceStdin}); !errors.Is(err, ErrInvalidInputRequest) {
		t.Fatalf("got %v, want invalid request", err)
	}
	if _, err := SensitiveStream(context.Background(), StreamRequest{Source: InputSourceTerminal, MaxBytes: 8}); !errors.Is(err, ErrInvalidInputRequest) {
		t.Fatalf("got %v, want invalid terminal stream request", err)
	}
	if _, err := SensitiveInput(context.Background(), ValueRequest{Source: InputSourceStdin, MaxBytes: MaximumSensitiveValueBytes + 1}); !errors.Is(err, ErrInvalidInputRequest) {
		t.Fatalf("got %v, want bounded value request", err)
	}
	if _, err := SensitiveStream(context.Background(), StreamRequest{Source: InputSourceStdin, MaxBytes: MaximumSensitiveStreamBytes + 1}); !errors.Is(err, ErrInvalidInputRequest) {
		t.Fatalf("got %v, want bounded stream request", err)
	}
}

type readerFunc func([]byte) (int, error)

func (function readerFunc) Read(value []byte) (int, error) { return function(value) }

type contextualReaderFunc func(context.Context, []byte) (int, error)

func (function contextualReaderFunc) Read([]byte) (int, error) {
	return 0, ErrInputUnavailable
}

func (function contextualReaderFunc) ReadContext(ctx context.Context, value []byte) (int, error) {
	return function(ctx, value)
}

type trackingReader struct {
	io.Reader
	closed bool
}

type blockingContextReader struct {
	started chan struct{}
	once    sync.Once
}

func newBlockingContextReader() *blockingContextReader {
	return &blockingContextReader{started: make(chan struct{})}
}

func (reader *blockingContextReader) Read([]byte) (int, error) {
	return 0, ErrInputUnavailable
}

func (reader *blockingContextReader) ReadContext(ctx context.Context, _ []byte) (int, error) {
	reader.once.Do(func() { close(reader.started) })
	<-ctx.Done()
	return 0, ctx.Err()
}

func (reader *trackingReader) Close() error {
	reader.closed = true
	return nil
}
