package guest

import (
	"errors"
	"sync"
	"testing"
)

func TestCIDAllocatorBlocksCollisionsAndReusesReleasedCID(t *testing.T) {
	allocator, err := NewCIDAllocator(3, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := allocator.Reserve(3); err != nil {
		t.Fatal(err)
	}
	if err := allocator.Reserve(3); !errors.Is(err, ErrCIDUnavailable) {
		t.Fatalf("Reserve collision error = %v", err)
	}
	cid, err := allocator.Allocate()
	if err != nil || cid != 4 {
		t.Fatalf("Allocate() = %d, %v", cid, err)
	}
	if _, err := allocator.Allocate(); !errors.Is(err, ErrCIDUnavailable) {
		t.Fatalf("exhausted Allocate error = %v", err)
	}
	if !allocator.Release(3) || allocator.Release(3) {
		t.Fatal("Release must succeed exactly once")
	}
	cid, err = allocator.Allocate()
	if err != nil || cid != 3 {
		t.Fatalf("reused Allocate() = %d, %v", cid, err)
	}
}

func TestCIDAllocatorConcurrentUniqueness(t *testing.T) {
	allocator, err := NewCIDAllocator(3, 202)
	if err != nil {
		t.Fatal(err)
	}
	const count = 200
	results := make(chan uint32, count)
	errorsSeen := make(chan error, count)
	var workers sync.WaitGroup
	workers.Add(count)
	for range count {
		go func() {
			defer workers.Done()
			cid, err := allocator.Allocate()
			if err != nil {
				errorsSeen <- err
				return
			}
			results <- cid
		}()
	}
	workers.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatal(err)
	}
	seen := make(map[uint32]bool, count)
	for cid := range results {
		if seen[cid] {
			t.Fatalf("CID collision: %d", cid)
		}
		seen[cid] = true
	}
	if len(seen) != count {
		t.Fatalf("allocated %d unique CIDs, want %d", len(seen), count)
	}
}

func TestCIDAllocatorRejectsReservedRange(t *testing.T) {
	for _, test := range []struct{ minimum, maximum uint32 }{
		{0, 10}, {3, 2}, {3, MaximumGuestCID + 1},
	} {
		if _, err := NewCIDAllocator(test.minimum, test.maximum); err == nil {
			t.Fatalf("NewCIDAllocator(%d, %d) succeeded", test.minimum, test.maximum)
		}
	}
}
