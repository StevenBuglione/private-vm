package usb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
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

type statefulGuardExecutor struct {
	mu     sync.Mutex
	policy string
	calls  [][]string
	fail   string
}

func (e *statefulGuardExecutor) Run(ctx context.Context, _ string, args ...string) (commandexec.Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return commandexec.Result{}, err
	}
	e.calls = append(e.calls, append([]string(nil), args...))
	if len(args) == 0 {
		return commandexec.Result{}, errors.New("missing operation")
	}
	if args[0] == e.fail {
		return commandexec.Result{}, errors.New("private serial must stay redacted")
	}
	switch args[0] {
	case "list-devices":
		line := strings.Replace(guardFixture, "1: allow", "1: "+e.policy, 1)
		return commandexec.Result{Stdout: []byte(line)}, nil
	case "allow-device":
		e.policy = "allow"
	case "block-device":
		e.policy = "block"
	default:
		return commandexec.Result{}, fmt.Errorf("unexpected operation")
	}
	return commandexec.Result{}, nil
}

func TestCommandUSBGuardClaimAllowsThenBlocksExactNumericRecord(t *testing.T) {
	executor := &statefulGuardExecutor{policy: "block"}
	adapter := CommandUSBGuard{Executor: executor, Binary: "/usr/bin/usbguard"}
	handle, err := adapter.Acquire(t.Context(), validDevice())
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Release(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := handle.AuditAbsent(t.Context()); err != nil {
		t.Fatal(err)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	joined := fmt.Sprint(executor.calls)
	if !strings.Contains(joined, "allow-device 1") || !strings.Contains(joined, "block-device 1") {
		t.Fatalf("calls=%s", joined)
	}
	for _, forbidden := range []string{"EXAMPLE-SERIAL", testGuardHash, "/dev/sdz"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("identity leaked to argv: %s", joined)
		}
	}
}

func TestCommandUSBGuardClaimFailureReturnsCleanupHandle(t *testing.T) {
	executor := &statefulGuardExecutor{policy: "block", fail: "list-devices"}
	adapter := CommandUSBGuard{Executor: executor, Binary: "/usr/bin/usbguard"}
	handle, err := adapter.Acquire(t.Context(), validDevice())
	if err == nil || handle != nil || strings.Contains(err.Error(), "private serial") {
		t.Fatalf("handle=%v error=%v", handle, err)
	}
	executor = &statefulGuardExecutor{policy: "block", fail: "allow-device"}
	adapter.Executor = executor
	handle, err = adapter.Acquire(t.Context(), validDevice())
	if err == nil || handle == nil {
		t.Fatalf("partial allow handle=%v error=%v", handle, err)
	}
	if releaseErr := handle.Release(t.Context()); releaseErr != nil {
		t.Fatal(releaseErr)
	}
	if auditErr := handle.AuditAbsent(t.Context()); auditErr != nil {
		t.Fatal(auditErr)
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
