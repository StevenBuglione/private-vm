package daemon

import (
	"errors"
	"io"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
)

type scannerRelayReceiver struct {
	events []*privatevmv1.ScanEvent
	index  int
	err    error
}

func (receiver *scannerRelayReceiver) Recv() (*privatevmv1.ScanEvent, error) {
	if receiver.index < len(receiver.events) {
		value := receiver.events[receiver.index]
		receiver.index++
		return value, nil
	}
	if receiver.err != nil {
		return nil, receiver.err
	}
	return nil, io.EOF
}

func TestScannerGuestRelayRequiresOneTerminalCompleteEvent(t *testing.T) {
	received := 0
	err := relayScannerStream(&scannerRelayReceiver{events: []*privatevmv1.ScanEvent{scannerTestProgress("inventory")}}, func(*privatevmv1.ScanEvent) error {
		received++
		return nil
	})
	if err != nil || received != 1 {
		t.Fatalf("complete relay received=%d err=%v", received, err)
	}

	incomplete := scannerTestProgress("inventory")
	incomplete.Complete = false
	if err := relayScannerStream(&scannerRelayReceiver{events: []*privatevmv1.ScanEvent{incomplete}}, func(*privatevmv1.ScanEvent) error { return nil }); err == nil {
		t.Fatal("incomplete guest stream was accepted")
	}
	if err := relayScannerStream(&scannerRelayReceiver{events: []*privatevmv1.ScanEvent{scannerTestProgress("inventory"), scannerTestProgress("inventory")}}, func(*privatevmv1.ScanEvent) error { return nil }); err == nil {
		t.Fatal("event after terminal completion was accepted")
	}
	fixtureErr := errors.New("injected receive failure")
	if err := relayScannerStream(&scannerRelayReceiver{err: fixtureErr}, func(*privatevmv1.ScanEvent) error { return nil }); !errors.Is(err, fixtureErr) {
		t.Fatalf("receive error=%v", err)
	}
}

func TestScannerGuestRequestIsRoleBoundAndOpaque(t *testing.T) {
	request, err := scannerGuestRequest("pvm-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "safe")
	if err != nil {
		t.Fatal(err)
	}
	if request.GetContext().GetExpectedRole() != privatevmv1.GuestRole_GUEST_ROLE_SCANNER ||
		request.GetContext().GetContext().GetSessionId() != "pvm-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ||
		request.GetContext().GetContext().GetApiVersion().GetMajor() != 1 ||
		request.GetPolicyName() != "safe" || len(request.GetContext().GetContext().GetRequestId()) < 8 {
		t.Fatalf("scanner guest request=%+v", request)
	}
}
