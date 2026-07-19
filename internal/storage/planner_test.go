package storage

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

func TestCapacityPoolSerializesConcurrentReservations(t *testing.T) {
	host := HostCapacity{
		TotalRAMBytes: 32 << 30, AvailableRAMBytes: 24 << 30,
		RuntimeFreeBytes: 16 << 30, ScratchFreeBytes: 100 << 30,
		RuntimeIsTmpfs: true,
	}
	pool, err := NewCapacityPool(host)
	if err != nil {
		t.Fatal(err)
	}
	request := CapacityRequest{GuestRAMBytes: 1 << 30, ExpectedWritesBytes: 1 << 30, SmallScratchMax: 8 << 30}
	const attempts = 20
	reservations := make(chan *CapacityReservation, attempts)
	errorsSeen := make(chan error, attempts)
	var wait sync.WaitGroup
	for index := 0; index < attempts; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			id := fmt.Sprintf("pvm-%032x", index)
			reservation, reserveErr := pool.Reserve(id, request)
			if reserveErr != nil {
				errorsSeen <- reserveErr
				return
			}
			reservations <- reservation
		}(index)
	}
	wait.Wait()
	close(reservations)
	close(errorsSeen)
	var active []*CapacityReservation
	for reservation := range reservations {
		active = append(active, reservation)
	}
	// Eight reservations fit in tmpfs; the ninth safely falls back to LUKS
	// while preserving guest RAM plus the shared host reserve.
	if len(active) != 9 {
		t.Fatalf("atomic pool admitted %d reservations, want 9", len(active))
	}
	if len(errorsSeen) != attempts-len(active) {
		t.Fatal("capacity failures were not reported for rejected reservations")
	}
	for _, reservation := range active {
		if err := reservation.Destroy(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := reservation.Destroy(context.Background()); err != nil {
			t.Fatalf("release was not idempotent: %v", err)
		}
		if err := reservation.Audit(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCapacityPoolBlocksDuplicateAndReleasesForReuse(t *testing.T) {
	host := HostCapacity{
		TotalRAMBytes: 16 << 30, AvailableRAMBytes: 12 << 30,
		RuntimeFreeBytes: 8 << 30, ScratchFreeBytes: 20 << 30,
		RuntimeIsTmpfs: true,
	}
	pool, err := NewCapacityPool(host)
	if err != nil {
		t.Fatal(err)
	}
	request := CapacityRequest{GuestRAMBytes: 4 << 30, ExpectedWritesBytes: 2 << 30, SmallScratchMax: 4 << 30}
	id := "pvm-0123456789abcdef0123456789abcdef"
	reservation, err := pool.Reserve(id, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Reserve(id, request); err == nil {
		t.Fatal("duplicate session reservation unexpectedly passed")
	}
	if err := reservation.Audit(context.Background()); err == nil {
		t.Fatal("active reservation passed absence audit")
	}
	if err := reservation.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	reused, err := pool.Reserve(id, request)
	if err != nil {
		t.Fatalf("released capacity was not reusable: %v", err)
	}
	if err := reused.Destroy(context.Background()); err != nil {
		t.Fatalf("reused reservation cleanup failed: %v", err)
	}
}

func TestLUKSPlanStillReservesGuestMemory(t *testing.T) {
	host := HostCapacity{
		TotalRAMBytes: 16 << 30, AvailableRAMBytes: 5 << 30,
		RuntimeFreeBytes: 1, ScratchFreeBytes: 100 << 30,
		RuntimeIsTmpfs: true,
	}
	request := CapacityRequest{GuestRAMBytes: 4 << 30, ExpectedWritesBytes: 20 << 30, SmallScratchMax: 4 << 30}
	if _, err := PlanCapacity(host, request); err == nil {
		t.Fatal("LUKS plan overcommitted guest memory and host reserve")
	}
}
