package usb

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type fakeDeviceClaim struct {
	mu           sync.Mutex
	releaseCalls int
	releaseErr   error
	auditErr     error
}

func (c *fakeDeviceClaim) Release(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.releaseCalls++
	return c.releaseErr
}

func (c *fakeDeviceClaim) AuditAbsent(context.Context) error { return c.auditErr }

type fakeDeviceClaimer struct {
	handle  *fakeDeviceClaim
	err     error
	acquire func()
}

func (c fakeDeviceClaimer) Acquire(context.Context, Device) (DeviceClaim, error) {
	if c.acquire != nil {
		c.acquire()
	}
	return c.handle, c.err
}

func claimFixture(t *testing.T, claimer DeviceClaimer) (*ClaimManager, Enrollment, Device) {
	t.Helper()
	device := validDevice()
	enrollment, err := NewEnrollmentFromDevice(device, "PRIVATE_VM_TRANSFER", false)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewClaimManager(Enumerator{Source: staticSource{devices: []Device{device}}}, claimer)
	if err != nil {
		t.Fatal(err)
	}
	return manager, enrollment, device
}

func TestClaimRevalidatesAndReleasesIdempotently(t *testing.T) {
	handle := &fakeDeviceClaim{}
	manager, enrollment, device := claimFixture(t, fakeDeviceClaimer{handle: handle})
	claim, err := manager.Claim(t.Context(), "pvm-session", 1000, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if claim.ID == "" || claim.Device.DeviceID != device.DeviceID {
		t.Fatalf("unexpected claim: %#v", claim)
	}
	if _, err := manager.Revalidate(t.Context(), claim.ID, "pvm-session", 1000, enrollment); err != nil {
		t.Fatal(err)
	}
	if err := manager.Release(t.Context(), claim.ID, "pvm-session", 1000); err != nil {
		t.Fatal(err)
	}
	if err := manager.Release(t.Context(), claim.ID, "pvm-session", 1000); err != nil {
		t.Fatalf("idempotent release failed: %v", err)
	}
	if handle.releaseCalls != 1 {
		t.Fatalf("release called %d times", handle.releaseCalls)
	}
}

func TestRevalidateOnlySessionClaimRequiresOneExactOwnedClaim(t *testing.T) {
	manager, enrollment, _ := claimFixture(t, fakeDeviceClaimer{handle: &fakeDeviceClaim{}})
	sessionID := "pvm-0123456789abcdef0123456789abcdef"
	claim, err := manager.Claim(t.Context(), sessionID, 1000, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := manager.RevalidateOnlySessionClaim(t.Context(), sessionID, 1000, enrollment)
	if err != nil || resolved.ID != claim.ID {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	manager.mu.Lock()
	duplicate := *manager.claims[claim.ID]
	duplicate.ID = "claim-duplicate"
	manager.claims[duplicate.ID] = &duplicate
	manager.mu.Unlock()
	_, err = manager.RevalidateOnlySessionClaim(t.Context(), sessionID, 1000, enrollment)
	var usbError *Error
	if !errors.As(err, &usbError) || usbError.Code != CodeAmbiguous {
		t.Fatalf("got %v, want ambiguity", err)
	}
}

func TestClaimBlocksConcurrentIdentityOwner(t *testing.T) {
	handle := &fakeDeviceClaim{}
	manager, enrollment, _ := claimFixture(t, fakeDeviceClaimer{handle: handle})
	if _, err := manager.Claim(t.Context(), "first", 1000, enrollment); err != nil {
		t.Fatal(err)
	}
	_, err := manager.Claim(t.Context(), "second", 1000, enrollment)
	var usbError *Error
	if !errors.As(err, &usbError) || usbError.Code != CodeClaimConflict {
		t.Fatalf("got %v, want claim conflict", err)
	}
}

func TestCanceledClaimRollsBackAndAudits(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	handle := &fakeDeviceClaim{}
	manager, enrollment, _ := claimFixture(t, fakeDeviceClaimer{handle: handle, acquire: cancel})
	if _, err := manager.Claim(ctx, "pvm-session", 1000, enrollment); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
	if handle.releaseCalls != 1 {
		t.Fatal("canceled acquisition was not released")
	}
}

func TestReleaseFailureRetainsClaimForRetry(t *testing.T) {
	handle := &fakeDeviceClaim{releaseErr: errors.New("fixture failure")}
	manager, enrollment, _ := claimFixture(t, fakeDeviceClaimer{handle: handle})
	claim, err := manager.Claim(t.Context(), "pvm-session", 1000, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Release(t.Context(), claim.ID, "pvm-session", 1000); err == nil {
		t.Fatal("release failure accepted")
	}
	handle.releaseErr = nil
	if err := manager.Release(t.Context(), claim.ID, "pvm-session", 1000); err != nil {
		t.Fatalf("release retry failed: %v", err)
	}
}

func TestConcurrentReleaseHasOneCleanupOwner(t *testing.T) {
	handle := &fakeDeviceClaim{}
	manager, enrollment, _ := claimFixture(t, fakeDeviceClaimer{handle: handle})
	claim, err := manager.Claim(t.Context(), "pvm-session", 1000, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 32
	errorsFound := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsFound <- manager.Release(t.Context(), claim.ID, "pvm-session", 1000)
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	if handle.releaseCalls != 1 {
		t.Fatalf("physical claim released %d times", handle.releaseCalls)
	}
}

func TestFailedAcquisitionRetainsSessionRecoveryOwner(t *testing.T) {
	handle := &fakeDeviceClaim{releaseErr: errors.New("fixture rollback failure")}
	manager, enrollment, _ := claimFixture(t, fakeDeviceClaimer{handle: handle, err: errors.New("fixture acquire failure")})
	_, err := manager.Claim(t.Context(), "pvm-session", 1000, enrollment)
	var usbError *Error
	if !errors.As(err, &usbError) || usbError.Code != CodeCleanupIncomplete {
		t.Fatalf("got %v", err)
	}
	handle.releaseErr = nil
	if err := manager.CleanupSession(t.Context(), "pvm-session", 1000); err != nil {
		t.Fatalf("session recovery failed: %v", err)
	}
	if handle.releaseCalls != 2 {
		t.Fatalf("release attempts=%d, want 2", handle.releaseCalls)
	}
}
