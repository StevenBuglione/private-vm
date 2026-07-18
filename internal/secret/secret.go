package secret

import (
	"errors"
	"runtime"
	"sync"
)

type Bytes struct {
	mu        sync.Mutex
	value     []byte
	destroyed bool
}

func New(value []byte) (*Bytes, error) {
	if len(value) == 0 {
		return nil, errors.New("secret cannot be empty")
	}
	copied := append([]byte(nil), value...)
	return &Bytes{value: copied}, nil
}

func (s *Bytes) With(fn func([]byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return errors.New("secret destroyed")
	}
	err := fn(s.value)
	runtime.KeepAlive(s)
	return err
}

func (s *Bytes) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.value {
		s.value[i] = 0
	}
	s.value = nil
	s.destroyed = true
	runtime.KeepAlive(s)
}

func (s *Bytes) String() string   { return "[REDACTED]" }
func (s *Bytes) GoString() string { return "[REDACTED]" }
