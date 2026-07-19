//go:build linux

package cli

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const terminalPollInterval = 50 * time.Millisecond

var (
	terminalInputLease = make(chan struct{}, 1)
	inputFstat         = unix.Fstat
	inputFstatfs       = unix.Fstatfs
	inputGetTermios    = unix.IoctlGetTermios
	inputSetTermios    = unix.IoctlSetTermios
)

func openSensitiveFile(path string, opener InputOpener, requireOwnerOnly bool) (*os.File, error) {
	var file *os.File
	var err error
	if opener == nil {
		how := &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		}
		fd, openErr := unix.Openat2(unix.AT_FDCWD, path, how)
		if openErr != nil {
			return nil, ErrInputUnavailable
		}
		file = os.NewFile(uintptr(fd), "sensitive-input")
		if file == nil {
			_ = unix.Close(fd)
			return nil, ErrInputUnavailable
		}
	} else {
		file, err = opener(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, ErrInputUnavailable
		}
	}
	if err := validateSensitiveFile(file, requireOwnerOnly); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateSensitiveFile(file *os.File, requireOwnerOnly bool) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrUnsafeInputFile
	}
	var filesystem unix.Statfs_t
	if err := inputFstatfs(int(file.Fd()), &filesystem); err != nil {
		return ErrUnsafeInputFile
	}
	switch filesystem.Type {
	case unix.CIFS_SUPER_MAGIC, unix.FUSE_SUPER_MAGIC, unix.NFS_SUPER_MAGIC, unix.SMB2_SUPER_MAGIC, unix.V9FS_MAGIC:
		// These filesystems can turn a regular-file read into an unbounded
		// userspace or network operation that cannot honor a Go deadline.
		return ErrUnsafeInputFile
	}
	if !requireOwnerOnly {
		return nil
	}
	var stat unix.Stat_t
	if err := inputFstat(int(file.Fd()), &stat); err != nil || stat.Uid != uint32(os.Geteuid()) {
		return ErrUnsafeInputFile
	}
	permission := info.Mode().Perm()
	if permission&0077 != 0 || permission&0111 != 0 {
		return ErrUnsafeInputFile
	}
	return nil
}

func duplicateInputFD(file *os.File) (int, int, error) {
	originalFlags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return -1, 0, ErrInputUnavailable
	}
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, 0, ErrInputUnavailable
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return -1, 0, ErrInputUnavailable
	}
	return fd, originalFlags, nil
}

func closeInputFD(fd int, originalFlags int) error {
	_, flagErr := unix.FcntlInt(uintptr(fd), unix.F_SETFL, originalFlags)
	closeErr := unix.Close(fd)
	if flagErr != nil || closeErr != nil {
		return ErrInputRead
	}
	return nil
}

func readInputFDContext(ctx context.Context, fd int, value []byte) (int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		wait := terminalPollInterval
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, context.DeadlineExceeded
			}
			if remaining < wait {
				wait = remaining
			}
		}
		milliseconds := int(wait.Milliseconds())
		if milliseconds < 1 {
			milliseconds = 1
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		count, err := unix.Poll(poll, milliseconds)
		if errors.Is(err, unix.EINTR) || count == 0 {
			continue
		}
		if err != nil || poll[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return 0, ErrInputRead
		}
		n, err := unix.Read(fd, value)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return n, ErrInputRead
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return n, ctxErr
		}
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

func readTerminalValue(ctx context.Context, request ValueRequest) ([]byte, error) {
	select {
	case terminalInputLease <- struct{}{}:
		defer func() { <-terminalInputLease }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	path := request.TerminalPath
	if path == "" {
		path = defaultTerminalPath
	}
	opener := request.Open
	if opener == nil {
		opener = os.OpenFile
	}
	file, err := opener(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrInputUnavailable
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || info.Mode()&fs.ModeCharDevice == 0 {
		return nil, ErrInputUnavailable
	}
	fd := int(file.Fd())
	original, err := inputGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, ErrInputUnavailable
	}
	noEcho := *original
	noEcho.Lflag &^= unix.ECHO | unix.ECHONL
	if err := inputSetTermios(fd, unix.TCSETS, &noEcho); err != nil {
		return nil, ErrInputUnavailable
	}
	restored := false
	defer func() {
		if !restored {
			_ = inputSetTermios(fd, unix.TCSETS, original)
		}
	}()

	value, readErr := pollTerminalLine(ctx, fd, request.MaxBytes)
	restoreErr := inputSetTermios(fd, unix.TCSETS, original)
	restored = restoreErr == nil
	if restoreErr != nil {
		zero(value)
		return nil, ErrInputRead
	}
	return value, readErr
}

func pollTerminalLine(ctx context.Context, fd int, maximum int64) ([]byte, error) {
	value := make([]byte, 0, int(maximum))
	buffer := make([]byte, 256)
	defer zero(buffer)

	for {
		if err := ctx.Err(); err != nil {
			zero(value)
			return nil, err
		}
		wait := terminalPollInterval
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				zero(value)
				return nil, context.DeadlineExceeded
			}
			if remaining < wait {
				wait = remaining
			}
		}
		milliseconds := int(wait.Milliseconds())
		if milliseconds < 1 {
			milliseconds = 1
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		count, err := unix.Poll(fds, milliseconds)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			zero(value)
			return nil, ErrInputRead
		}
		if count == 0 {
			continue
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			zero(value)
			return nil, ErrInputRead
		}
		n, err := unix.Read(fd, buffer)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n == 0 {
			zero(value)
			return nil, ErrInputRead
		}
		for _, current := range buffer[:n] {
			if current == '\n' {
				if len(value) > 0 && value[len(value)-1] == '\r' {
					value = value[:len(value)-1]
				}
				return value, nil
			}
			if int64(len(value)) >= maximum {
				zero(value)
				return nil, ErrInputTooLarge
			}
			value = append(value, current)
		}
		zero(buffer[:n])
	}
}
