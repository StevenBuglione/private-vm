//go:build linux

package secret

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

const requiredSeals = unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_FUTURE_WRITE | unix.F_SEAL_SEAL

var (
	createMemfd  = unix.MemfdCreate
	lockMemory   = unix.Mlock
	adviseMemory = unix.Madvise
	addSeals     = func(fd int) (int, error) {
		return unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, requiredSeals)
	}
)

func newState(value []byte) (*state, error) {
	fd, err := createMemfd("private-vm-secret", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) {
			return newHeapState(value), nil
		}
		return nil, ErrUnavailable
	}
	protected := &state{fd: fd}
	failed := true
	defer func() {
		if failed {
			clear(protected.value)
			runtime.KeepAlive(protected.value)
			releaseState(protected)
		}
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return nil, ErrUnavailable
	}
	if err := unix.Ftruncate(fd, int64(len(value))); err != nil {
		return nil, ErrUnavailable
	}
	mapped, err := unix.Mmap(fd, 0, len(value), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, ErrUnavailable
	}
	protected.value = mapped
	protected.mapped = true
	copy(protected.value, value)
	if err := adviseMemory(protected.value, unix.MADV_DONTDUMP); err != nil {
		return nil, ErrUnavailable
	}
	if lockMemory(protected.value) == nil {
		protected.locked = true
	}
	if _, err := addSeals(fd); err != nil {
		return nil, ErrUnavailable
	}
	failed = false
	return protected, nil
}

func newHeapState(value []byte) *state {
	return &state{value: append([]byte(nil), value...), fd: -1}
}

func dupFile(protected *state) (*os.File, error) {
	if protected.fd < 0 || !protected.mapped {
		return nil, ErrNotMemfd
	}
	path := fmt.Sprintf("/proc/self/fd/%d", protected.fd)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	valid := false
	defer func() {
		if !valid {
			_ = unix.Close(fd)
		}
	}()
	var source, duplicate unix.Stat_t
	if err := unix.Fstat(protected.fd, &source); err != nil {
		return nil, ErrUnavailable
	}
	if err := unix.Fstat(fd, &duplicate); err != nil {
		return nil, ErrUnavailable
	}
	if source.Dev != duplicate.Dev || source.Ino != duplicate.Ino || source.Size != duplicate.Size {
		return nil, ErrUnavailable
	}
	if _, err := unix.Seek(fd, 0, ioSeekStart); err != nil {
		return nil, ErrUnavailable
	}
	valid = true
	file := os.NewFile(uintptr(fd), "private-vm-secret")
	if file == nil {
		valid = false
		return nil, ErrUnavailable
	}
	return file, nil
}

func releaseState(protected *state) {
	if len(protected.value) != 0 {
		if protected.mapped {
			_ = unix.Msync(protected.value, unix.MS_SYNC)
		}
		if protected.locked {
			_ = unix.Munlock(protected.value)
		}
		if protected.mapped {
			_ = unix.Munmap(protected.value)
		}
	}
	if protected.fd >= 0 {
		_ = unix.Close(protected.fd)
	}
}

const ioSeekStart = 0
