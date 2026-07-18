package secret

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

// Bytes owns one mutable secret buffer. Linux uses an unlinked memfd mapping;
// other platforms fall back to a private heap copy for compile-only support.
// Go and kernel copies outside this object cannot be perfectly guaranteed.
type Bytes struct {
	mu        sync.Mutex
	value     []byte
	fd        int
	locked    bool
	destroyed bool
}

func New(value []byte) (*Bytes, error) {
	if len(value) == 0 {
		return nil, errors.New("secret cannot be empty")
	}
	s := &Bytes{fd: -1}
	if runtime.GOOS == "linux" {
		fd, err := unix.MemfdCreate("private-vm-secret", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
		if err == nil {
			if err = unix.Ftruncate(fd, int64(len(value))); err == nil {
				mapped, mapErr := unix.Mmap(fd, 0, len(value), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
				if mapErr == nil {
					copy(mapped, value)
					s.value, s.fd = mapped, fd
					if unix.Mlock(mapped) == nil {
						s.locked = true
					}
					return s, nil
				}
			}
			_ = unix.Close(fd)
		}
	}
	s.value = append([]byte(nil), value...)
	return s, nil
}

// With exposes the live buffer only for the duration of fn. The callback must
// not retain or mutate it.
func (s *Bytes) With(fn func([]byte) error) error {
	if fn == nil {
		return errors.New("secret callback is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return errors.New("secret destroyed")
	}
	err := fn(s.value)
	runtime.KeepAlive(s)
	return err
}

// DupFile returns a CLOEXEC duplicate suitable for explicit ExtraFiles
// inheritance. The caller owns the returned descriptor.
func (s *Bytes) DupFile() (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return nil, errors.New("secret destroyed")
	}
	if s.fd < 0 {
		return nil, errors.New("secret is not memfd-backed")
	}
	fd, err := unix.FcntlInt(uintptr(s.fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, fmt.Errorf("duplicate secret descriptor: %w", err)
	}
	return os.NewFile(uintptr(fd), "private-vm-secret"), nil
}

func (s *Bytes) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return
	}
	for i := range s.value {
		s.value[i] = 0
	}
	if s.locked {
		_ = unix.Munlock(s.value)
	}
	if s.fd >= 0 {
		_ = unix.Munmap(s.value)
		_ = unix.Close(s.fd)
	}
	s.value = nil
	s.fd = -1
	s.destroyed = true
	runtime.KeepAlive(s)
}

func (s *Bytes) String() string   { return "[REDACTED]" }
func (s *Bytes) GoString() string { return "[REDACTED]" }
func (s *Bytes) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("[REDACTED]"))
}
func (s *Bytes) MarshalJSON() ([]byte, error) {
	return nil, errors.New("secret values cannot be serialized")
}
func (s *Bytes) MarshalText() ([]byte, error) {
	return nil, errors.New("secret values cannot be serialized")
}

var _ fmt.Formatter = (*Bytes)(nil)
var _ json.Marshaler = (*Bytes)(nil)
