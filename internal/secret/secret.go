// Package secret provides bounded, explicitly destroyable secret byte storage.
//
// A Bytes value is a handle to shared private state, so copying the handle does
// not copy a mutex, mapping, or file descriptor. Callers must still avoid
// copying plaintext out of the bounded reader and must call Destroy as soon as
// the value is no longer needed.
package secret

import (
	"crypto/subtle"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

const (
	// MaximumBytes is the largest secret accepted by this package. Higher-level
	// protocols should normally impose much smaller limits.
	MaximumBytes = 16 << 20
	redacted     = "[REDACTED]"
)

var (
	ErrEmpty         = errors.New("secret is empty")
	ErrTooLarge      = errors.New("secret exceeds the size limit")
	ErrUnavailable   = errors.New("secret is unavailable")
	ErrDestroyed     = errors.New("secret is destroyed")
	ErrNotMemfd      = errors.New("secret is not memfd-backed")
	ErrCallback      = errors.New("secret callback is required")
	ErrSerialization = errors.New("secret values cannot be serialized")
)

// Bytes owns one mutable secret buffer. On Linux the buffer is backed by a
// sealed memfd mapping and excluded from core dumps. Other platforms use a
// heap allocation for compile-only support.
//
// Bytes is safe to copy as a handle: all copies refer to the same state and a
// Destroy through any copy invalidates all of them. The zero value is inert.
type Bytes struct {
	state *state
}

type state struct {
	mu        sync.Mutex
	value     []byte
	fd        int
	locked    bool
	mapped    bool
	destroyed bool
}

// New copies value into protected storage. It never takes ownership of the
// caller's slice; the caller remains responsible for clearing that slice.
func New(value []byte) (*Bytes, error) {
	switch {
	case len(value) == 0:
		return nil, ErrEmpty
	case len(value) > MaximumBytes:
		return nil, ErrTooLarge
	}
	protected, err := newState(value)
	if err != nil {
		return nil, err
	}
	return &Bytes{state: protected}, nil
}

// WithReader exposes a forward-only view for the duration of fn. The view
// copies bytes into Read buffers rather than exposing the mutable backing
// slice, and it becomes unusable when fn returns. A callback can necessarily
// retain bytes it explicitly reads; callbacks must therefore remain small and
// trusted.
func (s *Bytes) WithReader(fn func(io.Reader) error) error {
	if fn == nil {
		return ErrCallback
	}
	protected, err := s.liveState()
	if err != nil {
		return err
	}
	protected.mu.Lock()
	defer protected.mu.Unlock()
	if protected.destroyed {
		return ErrDestroyed
	}
	reader := &ephemeralReader{value: protected.value}
	defer reader.invalidate()
	err = fn(reader)
	runtime.KeepAlive(protected)
	return err
}

// Equal compares candidate with the live secret in constant time for equal
// lengths. It does not expose the mutable secret backing to the caller.
func (s *Bytes) Equal(candidate []byte) (bool, error) {
	protected, err := s.liveState()
	if err != nil {
		return false, err
	}
	protected.mu.Lock()
	defer protected.mu.Unlock()
	if protected.destroyed {
		return false, ErrDestroyed
	}
	matched := subtle.ConstantTimeCompare(protected.value, candidate) == 1
	runtime.KeepAlive(protected)
	return matched, nil
}

// DupFile returns an independent, read-only, offset-zero CLOEXEC descriptor
// suitable for explicit ExtraFiles inheritance. The caller owns the returned
// descriptor. Linux memfd size seals prevent truncation or growth.
func (s *Bytes) DupFile() (*os.File, error) {
	protected, err := s.liveState()
	if err != nil {
		return nil, err
	}
	protected.mu.Lock()
	defer protected.mu.Unlock()
	if protected.destroyed {
		return nil, ErrDestroyed
	}
	return dupFile(protected)
}

// Destroy overwrites the current backing bytes before releasing the mapping
// and descriptor. It is idempotent and invalidates every copied handle.
func (s *Bytes) Destroy() {
	if s == nil || s.state == nil {
		return
	}
	protected := s.state
	protected.mu.Lock()
	defer protected.mu.Unlock()
	if protected.destroyed {
		return
	}
	clear(protected.value)
	runtime.KeepAlive(protected.value)
	releaseState(protected)
	protected.value = nil
	protected.fd = -1
	protected.locked = false
	protected.mapped = false
	protected.destroyed = true
	runtime.KeepAlive(protected)
}

func (s *Bytes) liveState() (*state, error) {
	if s == nil || s.state == nil {
		return nil, ErrUnavailable
	}
	return s.state, nil
}

func (s Bytes) String() string   { return redacted }
func (s Bytes) GoString() string { return redacted }
func (s Bytes) Format(formatter fmt.State, _ rune) {
	_, _ = formatter.Write([]byte(redacted))
}
func (s Bytes) MarshalJSON() ([]byte, error) { return nil, ErrSerialization }
func (s Bytes) MarshalText() ([]byte, error) { return nil, ErrSerialization }
func (s Bytes) MarshalBinary() ([]byte, error) {
	return nil, ErrSerialization
}
func (s Bytes) GobEncode() ([]byte, error) { return nil, ErrSerialization }
func (s Bytes) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return ErrSerialization
}

type ephemeralReader struct {
	mu     sync.Mutex
	value  []byte
	offset int
}

func (r *ephemeralReader) Read(destination []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.value == nil {
		return 0, ErrDestroyed
	}
	if r.offset >= len(r.value) {
		return 0, io.EOF
	}
	count := copy(destination, r.value[r.offset:])
	r.offset += count
	return count, nil
}

func (r *ephemeralReader) invalidate() {
	r.mu.Lock()
	r.value = nil
	r.offset = 0
	r.mu.Unlock()
}

var _ fmt.Formatter = (*Bytes)(nil)
var _ fmt.Formatter = Bytes{}
var _ json.Marshaler = (*Bytes)(nil)
var _ json.Marshaler = Bytes{}
var _ xml.Marshaler = (*Bytes)(nil)
var _ xml.Marshaler = Bytes{}
var _ io.Reader = (*ephemeralReader)(nil)
