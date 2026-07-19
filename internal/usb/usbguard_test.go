package usb

import (
	"context"
	"errors"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/commandexec"
)

const guardFixture = `1: allow id 1234:5678 serial "EXAMPLE-SERIAL" name "Disk" hash "0123456789abcdef0123456789abcdef" parent-hash "aaaaaaaaaaaaaaaa" via-port "1-2.3" with-interface equals { 08:06:50 }
`

func TestParseUSBGuardRecords(t *testing.T) {
	records, err := ParseUSBGuardRecords([]byte(guardFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Hash != testGuardHash || len(records[0].Interfaces) != 1 {
		t.Fatalf("unexpected records: %#v", records)
	}
	if _, err := ParseUSBGuardRecords([]byte(`1: allow id 1234:5678`)); err == nil {
		t.Fatal("incomplete USBGuard output accepted")
	}
}

type guardExecutor struct {
	result commandexec.Result
	err    error
}

func (e guardExecutor) Run(context.Context, string, ...string) (commandexec.Result, error) {
	return e.result, e.err
}

func TestCommandUSBGuardExactMatchAndRedactedFailure(t *testing.T) {
	adapter := CommandUSBGuard{
		Executor: guardExecutor{result: commandexec.Result{Stdout: []byte(guardFixture)}},
		Binary:   "/usr/bin/usbguard",
	}
	hash, err := adapter.Hash(t.Context(), GuardProbe{
		VendorID: "1234", ProductID: "5678", Serial: "EXAMPLE-SERIAL",
		PortPath: "1-2.3", Interfaces: []string{"08:06:50"},
	})
	if err != nil || hash != testGuardHash {
		t.Fatalf("hash=%q err=%v", hash, err)
	}
	sensitive := errors.New("serial=private-device")
	adapter.Executor = guardExecutor{err: sensitive}
	_, err = adapter.Hash(t.Context(), GuardProbe{})
	if err == nil || errors.Is(err, sensitive) || err.Error() != "USBGuard device listing failed" {
		t.Fatalf("unsafe failure: %v", err)
	}
}
