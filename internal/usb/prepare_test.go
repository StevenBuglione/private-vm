package usb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

func TestCheckedInPreparePlanExample(t *testing.T) {
	enrollmentData, err := os.ReadFile(filepath.Join("..", "..", "examples", "usb-enrollment.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := DecodeEnrollment(bytes.NewReader(enrollmentData))
	if err != nil {
		t.Fatal(err)
	}
	planData, err := os.ReadFile(filepath.Join("..", "..", "examples", "usb-prepare-plan.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan PreparePlan
	if err := json.Unmarshal(planData, &plan); err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(enrollment, Confirmation{First: plan.FirstPrompt, Second: plan.SecondPrompt}, plan.CreatedAt); err != nil {
		fingerprint, fingerprintErr := enrollment.Identity.Fingerprint()
		t.Fatalf("prepare example invalid: %v (fingerprint %s, err %v)", err, fingerprint, fingerprintErr)
	}
}

type fakePrepareAuthorizer struct {
	calls int
	err   error
	order *[]string
}

func (a *fakePrepareAuthorizer) AuthorizePrepare(context.Context) error {
	a.calls++
	if a.order != nil {
		*a.order = append(*a.order, "authorize")
	}
	return a.err
}

type fakePrepareBackend struct {
	calls   int
	err     error
	receipt PrepareReceipt
	order   *[]string
}

func (b *fakePrepareBackend) Prepare(_ context.Context, _ Claim, _ string, passphrase *secret.Bytes, emit func(PrepareEvent) error) (PrepareReceipt, error) {
	b.calls++
	if b.order != nil {
		*b.order = append(*b.order, "prepare")
	}
	if passphrase == nil {
		return PrepareReceipt{}, errors.New("missing passphrase")
	}
	if err := emit(PrepareEvent{State: PrepareDestinationReady, Code: "USB_LUKS2_EXT4_READY", Message: "The exporter prepared and verified the encrypted filesystem."}); err != nil {
		return PrepareReceipt{}, err
	}
	return b.receipt, b.err
}

func prepareFixture(t *testing.T) (*ClaimManager, Enrollment, Claim, *secret.Bytes, time.Time) {
	t.Helper()
	manager, enrollment, _ := claimFixture(t, fakeDeviceClaimer{handle: &fakeDeviceClaim{}})
	claim, err := manager.Claim(t.Context(), "pvm-session", 1000, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	passphrase, err := secret.New([]byte("public-test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(passphrase.Destroy)
	return manager, enrollment, claim, passphrase, time.Unix(1000, 0)
}

func TestPrepareRequiresTwoExactFreshConfirmations(t *testing.T) {
	manager, enrollment, claim, _, now := prepareFixture(t)
	plan, err := NewPreparePlan(enrollment, claim.Device, now)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		confirmation Confirmation
		when         time.Time
	}{
		{"missing first", Confirmation{Second: plan.SecondPrompt}, now},
		{"missing second", Confirmation{First: plan.FirstPrompt}, now},
		{"changed second", Confirmation{First: plan.FirstPrompt, Second: plan.SecondPrompt + "x"}, now},
		{"expired", Confirmation{First: plan.FirstPrompt, Second: plan.SecondPrompt}, now.Add(maximumPrepareAge + time.Second)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := plan.Validate(enrollment, test.confirmation, test.when); err == nil {
				t.Fatal("invalid destructive confirmation accepted")
			}
		})
	}
	if manager == nil {
		t.Fatal("fixture manager unavailable")
	}
}

func TestPrepareRevalidatesAuthorizesThenCommits(t *testing.T) {
	manager, enrollment, claim, passphrase, now := prepareFixture(t)
	plan, err := NewPreparePlan(enrollment, claim.Device, now)
	if err != nil {
		t.Fatal(err)
	}
	order := []string{}
	authorizer := &fakePrepareAuthorizer{order: &order}
	backend := &fakePrepareBackend{order: &order, receipt: PrepareReceipt{
		SchemaVersion: PrepareSchemaVersion, EnrollmentID: enrollment.EnrollmentID,
		Filesystem: DefaultFilesystem, CapacityBytes: enrollment.Identity.Capacity,
		Fingerprint: plan.Fingerprint, State: PrepareDestinationReady,
	}}
	coordinator := PrepareCoordinator{Claims: manager, Backend: backend, Authorizer: authorizer, Now: func() time.Time { return now }}
	events := make([]PrepareEvent, 0)
	receipt, err := coordinator.Prepare(
		t.Context(), claim.ID, "pvm-session", 1000, enrollment, plan,
		Confirmation{First: plan.FirstPrompt, Second: plan.SecondPrompt}, passphrase,
		func(event PrepareEvent) error {
			events = append(events, event)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != PrepareDestinationReady || len(events) != 4 {
		t.Fatalf("receipt=%#v events=%#v", receipt, events)
	}
	if len(order) != 2 || order[0] != "authorize" || order[1] != "prepare" {
		t.Fatalf("unsafe operation order: %v", order)
	}
}

func TestPrepareCancellationBeforeCommitIsExplicit(t *testing.T) {
	manager, enrollment, claim, passphrase, now := prepareFixture(t)
	plan, _ := NewPreparePlan(enrollment, claim.Device, now)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	authorizer := &fakePrepareAuthorizer{}
	backend := &fakePrepareBackend{}
	coordinator := PrepareCoordinator{Claims: manager, Backend: backend, Authorizer: authorizer, Now: func() time.Time { return now }}
	events := make([]PrepareEvent, 0)
	_, err := coordinator.Prepare(ctx, claim.ID, "pvm-session", 1000, enrollment, plan,
		Confirmation{First: plan.FirstPrompt, Second: plan.SecondPrompt}, passphrase,
		func(event PrepareEvent) error { events = append(events, event); return nil })
	if !errors.Is(err, context.Canceled) || authorizer.calls != 0 || backend.calls != 0 {
		t.Fatalf("err=%v auth=%d backend=%d", err, authorizer.calls, backend.calls)
	}
	if len(events) != 2 || events[1].State != PrepareCanceledPrecommit {
		t.Fatalf("missing precommit cancellation evidence: %#v", events)
	}
}

func TestPrepareBackendFailureReturnsIncompleteEvidence(t *testing.T) {
	manager, enrollment, claim, passphrase, now := prepareFixture(t)
	plan, _ := NewPreparePlan(enrollment, claim.Device, now)
	backend := &fakePrepareBackend{err: errors.New("fixture prepare failure")}
	coordinator := PrepareCoordinator{Claims: manager, Backend: backend, Authorizer: &fakePrepareAuthorizer{}, Now: func() time.Time { return now }}
	events := make([]PrepareEvent, 0)
	_, err := coordinator.Prepare(t.Context(), claim.ID, "pvm-session", 1000, enrollment, plan,
		Confirmation{First: plan.FirstPrompt, Second: plan.SecondPrompt}, passphrase,
		func(event PrepareEvent) error { events = append(events, event); return nil })
	var usbError *Error
	if !errors.As(err, &usbError) || usbError.Code != CodeWriteFailed {
		t.Fatalf("got %v", err)
	}
	if events[len(events)-1].State != PrepareIncomplete {
		t.Fatal("failure did not emit incomplete evidence")
	}
}
