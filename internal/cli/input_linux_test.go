//go:build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSensitiveInputTerminalDisablesEchoAndRestoresIt(t *testing.T) {
	master, slavePath := newPTY(t)
	defer unix.Close(master)
	monitor, err := unix.Open(slavePath, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(monitor)
	original, err := unix.IoctlGetTermios(monitor, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		value string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, inputErr := SensitiveInput(context.Background(), ValueRequest{
			Source: InputSourceTerminal, TerminalPath: slavePath, MaxBytes: 64, Timeout: time.Second,
		})
		if inputErr != nil {
			done <- result{err: inputErr}
			return
		}
		defer value.Destroy()
		var actual string
		inputErr = value.With(func(bytes []byte) error {
			actual = string(bytes)
			return nil
		})
		done <- result{value: actual, err: inputErr}
	}()

	waitForEcho(t, monitor, false)
	if _, err := unix.Write(master, []byte("terminal-secret\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.value != "terminal-secret" {
			t.Fatalf("unexpected terminal value: %q", result.value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal read did not complete")
	}
	waitForEcho(t, monitor, original.Lflag&unix.ECHO != 0)

	if err := unix.SetNonblock(master, true); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, readErr := unix.Read(master, buffer)
	zero(buffer)
	if n > 0 || (!errors.Is(readErr, unix.EAGAIN) && readErr != nil) {
		t.Fatalf("terminal echoed sensitive input: bytes=%d error=%v", n, readErr)
	}
}

func TestSensitiveInputTerminalRestoresEchoAfterCancellation(t *testing.T) {
	master, slavePath := newPTY(t)
	defer unix.Close(master)
	monitor, err := unix.Open(slavePath, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(monitor)
	original, err := unix.IoctlGetTermios(monitor, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, inputErr := SensitiveInput(ctx, ValueRequest{
			Source: InputSourceTerminal, TerminalPath: slavePath, MaxBytes: 64,
		})
		done <- inputErr
	}()
	waitForEcho(t, monitor, false)
	cancel()
	select {
	case inputErr := <-done:
		if !errors.Is(inputErr, context.Canceled) {
			t.Fatalf("got %v, want cancellation", inputErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal cancellation did not complete")
	}
	waitForEcho(t, monitor, original.Lflag&unix.ECHO != 0)
}

func TestSensitiveFileOpenerUsesNoFollowAndCloseOnExec(t *testing.T) {
	path := t.TempDir() + "/input"
	if err := os.WriteFile(path, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	var gotFlags int
	stream, err := SensitiveStream(context.Background(), StreamRequest{
		Source: InputSourceFile, Path: path, MaxBytes: 8,
		Open: func(name string, flag int, mode os.FileMode) (*os.File, error) {
			gotFlags = flag
			return os.OpenFile(name, flag, mode)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	for _, required := range []int{unix.O_NOFOLLOW, unix.O_CLOEXEC} {
		if gotFlags&required == 0 {
			t.Fatalf("opener flags %#x lack required flag %#x", gotFlags, required)
		}
	}
}

func TestSensitiveStdinPreservesCallerDeadlineAndDescriptor(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	callerDeadline := time.Now().Add(200 * time.Millisecond)
	if err := reader.SetReadDeadline(callerDeadline); err != nil {
		t.Fatal(err)
	}
	_, err = SensitiveInput(context.Background(), ValueRequest{
		Source: InputSourceStdin, Stdin: reader, MaxBytes: 32, Timeout: 25 * time.Millisecond,
	})
	if !errors.Is(err, ErrInputUnavailable) {
		t.Fatalf("got %v, want fail-closed caller-file rejection", err)
	}
	if _, err := writer.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if n, err := reader.Read(buffer); err != nil || string(buffer[:n]) != "next" {
		t.Fatalf("caller descriptor was disturbed: bytes=%q error=%v", buffer[:n], err)
	}
	zero(buffer)

	readDone := make(chan error, 1)
	go func() {
		_, readErr := reader.Read(make([]byte, 1))
		readDone <- readErr
	}()
	select {
	case readErr := <-readDone:
		if !errors.Is(readErr, os.ErrDeadlineExceeded) {
			t.Fatalf("caller deadline was not preserved: %v", readErr)
		}
	case <-time.After(500 * time.Millisecond):
		_ = reader.Close()
		t.Fatal("caller deadline was cleared")
	}
}

func TestSensitiveStreamCloseInterruptsReadWithoutClosingCallerStdin(t *testing.T) {
	reader := newBlockingContextReader()
	stream, err := SensitiveStream(context.Background(), StreamRequest{
		Source: InputSourceStdin, Stdin: reader, MaxBytes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, readErr := stream.Read(make([]byte, 1))
		readDone <- readErr
	}()
	<-reader.started
	closeDone := make(chan error, 1)
	go func() { closeDone <- stream.Close() }()
	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind Read")
	}
	select {
	case readErr := <-readDone:
		if readErr == nil {
			t.Fatal("blocked read unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt Read")
	}
}

func TestSensitiveStreamCloseSerializesRawStdinFD(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	originalFlags, err := unix.FcntlInt(reader.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	originalStdin := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = originalStdin }()

	stream, err := SensitiveStream(context.Background(), StreamRequest{
		Source: InputSourceStdin, MaxBytes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, readErr := stream.Read(make([]byte, 1))
		readDone <- readErr
	}()
	time.Sleep(10 * time.Millisecond)
	closeDone := make(chan error, 1)
	go func() { closeDone <- stream.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("raw stdin close did not wait boundedly for its reader")
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("raw stdin read returned %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("raw stdin reader did not observe cancellation")
	}
	restoredFlags, err := unix.FcntlInt(reader.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if restoredFlags != originalFlags {
		t.Fatalf("process stdin flags changed: before=%#x after=%#x", originalFlags, restoredFlags)
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if n, err := reader.Read(buffer); err != nil || n != 1 || buffer[0] != 'x' {
		t.Fatalf("process stdin was closed: bytes=%q error=%v", buffer[:n], err)
	}
	zero(buffer)
}

func TestSensitiveStreamSerializesProcessStdinOwnership(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	originalStdin := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = originalStdin }()
	originalFlags, err := unix.FcntlInt(reader.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}

	first, err := SensitiveStream(context.Background(), StreamRequest{
		Source: InputSourceStdin, MaxBytes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := SensitiveStream(ctx, StreamRequest{Source: InputSourceStdin, MaxBytes: 8}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("overlapping stdin stream returned %v, want bounded lease timeout", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := SensitiveStream(context.Background(), StreamRequest{
		Source: InputSourceStdin, MaxBytes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	restoredFlags, err := unix.FcntlInt(reader.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if restoredFlags != originalFlags {
		t.Fatalf("overlapping ownership changed stdin flags: before=%#x after=%#x", originalFlags, restoredFlags)
	}
}

func TestSensitiveInputFailsClosedOnOwnedStreamCloseError(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	originalStdin := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = originalStdin }()
	originalClose := inputFDClose
	inputFDClose = func(fd int, flags int) error {
		_ = originalClose(fd, flags)
		return ErrInputRead
	}
	defer func() { inputFDClose = originalClose }()

	if _, err := writer.Write([]byte("secret\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	value, err := SensitiveInput(context.Background(), ValueRequest{
		Source: InputSourceStdin, MaxBytes: 16,
	})
	if value != nil {
		value.Destroy()
		t.Fatal("close failure returned a secret")
	}
	if !errors.Is(err, ErrInputRead) {
		t.Fatalf("got %v, want close failure", err)
	}
}

func TestSensitiveFileRejectsParentSymlink(t *testing.T) {
	directory := t.TempDir()
	realParent := filepath.Join(directory, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(realParent, "profile.conf")
	if err := os.WriteFile(path, []byte("credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(directory, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	_, err := SensitiveInput(context.Background(), ValueRequest{
		Source: InputSourceFile, Path: filepath.Join(linkedParent, "profile.conf"),
		MaxBytes: 64, RequireOwnerOnly: true,
	})
	if !errors.Is(err, ErrInputUnavailable) {
		t.Fatalf("got %v, want parent-symlink rejection", err)
	}
}

func TestSensitiveStreamDetectsFileGrowthAfterOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stream, err := SensitiveStream(context.Background(), StreamRequest{
		Source: InputSourceFile, Path: path, MaxBytes: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := io.ReadAll(stream)
	zero(value)
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("got %v, want growth rejection", err)
	}
}

func TestSensitiveFileRejectsOwnerMismatchAndUnsafeFilesystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("owner", func(t *testing.T) {
		original := inputFstat
		inputFstat = func(fd int, stat *unix.Stat_t) error {
			if err := original(fd, stat); err != nil {
				return err
			}
			stat.Uid = uint32(os.Geteuid()) + 1
			return nil
		}
		defer func() { inputFstat = original }()
		_, err := SensitiveInput(context.Background(), ValueRequest{
			Source: InputSourceFile, Path: path, MaxBytes: 16, RequireOwnerOnly: true,
		})
		if !errors.Is(err, ErrUnsafeInputFile) {
			t.Fatalf("got %v, want owner rejection", err)
		}
	})
	t.Run("filesystem", func(t *testing.T) {
		original := inputFstatfs
		inputFstatfs = func(_ int, stat *unix.Statfs_t) error {
			stat.Type = unix.FUSE_SUPER_MAGIC
			return nil
		}
		defer func() { inputFstatfs = original }()
		_, err := SensitiveInput(context.Background(), ValueRequest{
			Source: InputSourceFile, Path: path, MaxBytes: 16,
		})
		if !errors.Is(err, ErrUnsafeInputFile) {
			t.Fatalf("got %v, want filesystem rejection", err)
		}
	})
}

func TestSensitiveFileOpenHonorsTimeoutAndRedactsError(t *testing.T) {
	const marker = "SENSITIVE-PATH-OR-OPEN-ERROR"
	var called atomic.Bool
	started := time.Now()
	_, err := SensitiveInput(context.Background(), ValueRequest{
		Source: InputSourceFile, Path: marker, MaxBytes: 16, Timeout: 25 * time.Millisecond,
		Open: func(string, int, os.FileMode) (*os.File, error) {
			called.Store(true)
			return nil, errors.New(marker)
		},
	})
	if !errors.Is(err, ErrInputUnavailable) || strings.Contains(err.Error(), marker) {
		t.Fatalf("timed file open did not fail closed: %v", err)
	}
	if called.Load() {
		t.Fatal("timed file request invoked the potentially blocking opener")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timed file rejection was not bounded: %v", elapsed)
	}
}

func TestSensitiveFileRejectsLateOpenSuccessAndClosesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var opened *os.File
	_, err := SensitiveInput(ctx, ValueRequest{
		Source: InputSourceFile, Path: path, MaxBytes: 16,
		Open: func(name string, flags int, mode os.FileMode) (*os.File, error) {
			file, openErr := os.OpenFile(name, flags, mode)
			opened = file
			cancel()
			return file, openErr
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
	if opened == nil {
		t.Fatal("test opener did not return a file")
	}
	if _, err := opened.Read(make([]byte, 1)); err == nil {
		t.Fatal("late-opened file was not closed")
	}
}

func TestSensitiveTerminalRestoresEchoAfterTimeoutAndRestoreFailure(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		master, slavePath := newPTY(t)
		defer unix.Close(master)
		monitor, err := unix.Open(slavePath, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(monitor)
		_, err = SensitiveInput(context.Background(), ValueRequest{
			Source: InputSourceTerminal, TerminalPath: slavePath, MaxBytes: 64, Timeout: 25 * time.Millisecond,
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v, want timeout", err)
		}
		waitForEcho(t, monitor, true)
	})
	t.Run("restore failure", func(t *testing.T) {
		master, slavePath := newPTY(t)
		defer unix.Close(master)
		monitor, err := unix.Open(slavePath, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(monitor)
		original := inputSetTermios
		var calls atomic.Int32
		inputSetTermios = func(fd int, request uint, value *unix.Termios) error {
			if calls.Add(1) == 2 {
				return unix.EIO
			}
			return original(fd, request, value)
		}
		defer func() { inputSetTermios = original }()
		done := make(chan error, 1)
		go func() {
			_, inputErr := SensitiveInput(context.Background(), ValueRequest{
				Source: InputSourceTerminal, TerminalPath: slavePath, MaxBytes: 64, Timeout: time.Second,
			})
			done <- inputErr
		}()
		waitForEcho(t, monitor, false)
		if _, err := unix.Write(master, []byte("value\n")); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, ErrInputRead) {
			t.Fatalf("got %v, want restore failure", err)
		}
		waitForEcho(t, monitor, true)
	})
}

func TestSensitiveTerminalAcquisitionIsSerialized(t *testing.T) {
	master, slavePath := newPTY(t)
	defer unix.Close(master)
	var opens atomic.Int32
	opener := func(name string, flag int, mode os.FileMode) (*os.File, error) {
		opens.Add(1)
		return os.OpenFile(name, flag, mode)
	}
	type result struct {
		value string
		err   error
	}
	read := func(done chan<- result) {
		value, err := SensitiveInput(context.Background(), ValueRequest{
			Source: InputSourceTerminal, TerminalPath: slavePath, Open: opener,
			MaxBytes: 64, Timeout: time.Second,
		})
		if err != nil {
			done <- result{err: err}
			return
		}
		defer value.Destroy()
		var text string
		err = value.With(func(bytes []byte) error { text = string(bytes); return nil })
		done <- result{value: text, err: err}
	}
	first, second := make(chan result, 1), make(chan result, 1)
	go read(first)
	deadline := time.Now().Add(time.Second)
	for opens.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	go read(second)
	time.Sleep(25 * time.Millisecond)
	if opens.Load() != 1 {
		t.Fatalf("second terminal opened concurrently: opens=%d", opens.Load())
	}
	if _, err := unix.Write(master, []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	if got := <-first; got.err != nil || got.value != "first" {
		t.Fatalf("first=%#v", got)
	}
	deadline = time.Now().Add(time.Second)
	for opens.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if opens.Load() != 2 {
		t.Fatal("second terminal acquisition did not start")
	}
	if _, err := unix.Write(master, []byte("second\n")); err != nil {
		t.Fatal(err)
	}
	if got := <-second; got.err != nil || got.value != "second" {
		t.Fatalf("second=%#v", got)
	}
}

func newPTY(t *testing.T) (int, string) {
	t.Helper()
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		unix.Close(master)
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		unix.Close(master)
		t.Fatal(err)
	}
	return master, fmt.Sprintf("/dev/pts/%d", number)
}

func waitForEcho(t *testing.T, fd int, enabled bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if (termios.Lflag&unix.ECHO != 0) == enabled {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("terminal echo enabled=%t was not observed", enabled)
}
