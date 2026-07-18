package guest

import (
	"errors"
	"fmt"
	"sync"
)

const (
	MinimumGuestCID uint32 = 3
	MaximumGuestCID uint32 = 0x7fffffff
)

var ErrCIDUnavailable = errors.New("VSOCK CID unavailable")

// CIDAllocator owns the daemon's volatile set of allocated guest context IDs.
// Reserve is used by startup reconciliation before new guests are admitted.
type CIDAllocator struct {
	mu   sync.Mutex
	min  uint32
	max  uint32
	next uint32
	used map[uint32]struct{}
}

func NewCIDAllocator(minimum, maximum uint32) (*CIDAllocator, error) {
	if minimum < MinimumGuestCID || maximum < minimum || maximum > MaximumGuestCID {
		return nil, errors.New("invalid VSOCK CID allocation range")
	}
	return &CIDAllocator{
		min: minimum, max: maximum, next: minimum, used: make(map[uint32]struct{}),
	}, nil
}

func NewDefaultCIDAllocator() *CIDAllocator {
	allocator, err := NewCIDAllocator(MinimumGuestCID, MaximumGuestCID)
	if err != nil {
		panic(err)
	}
	return allocator
}

func (a *CIDAllocator) Allocate() (uint32, error) {
	if a == nil {
		return 0, ErrCIDUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	capacity := uint64(a.max) - uint64(a.min) + 1
	for attempts := uint64(0); attempts < capacity; attempts++ {
		candidate := a.next
		a.advance()
		if _, exists := a.used[candidate]; exists {
			continue
		}
		a.used[candidate] = struct{}{}
		return candidate, nil
	}
	return 0, ErrCIDUnavailable
}

func (a *CIDAllocator) Reserve(cid uint32) error {
	if a == nil {
		return ErrCIDUnavailable
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if cid < a.min || cid > a.max {
		return fmt.Errorf("%w: CID outside allocator range", ErrCIDUnavailable)
	}
	if _, exists := a.used[cid]; exists {
		return fmt.Errorf("%w: CID collision", ErrCIDUnavailable)
	}
	a.used[cid] = struct{}{}
	return nil
}

func (a *CIDAllocator) Release(cid uint32) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.used[cid]; !exists {
		return false
	}
	delete(a.used, cid)
	return true
}

func (a *CIDAllocator) advance() {
	if a.next == a.max {
		a.next = a.min
		return
	}
	a.next++
}
