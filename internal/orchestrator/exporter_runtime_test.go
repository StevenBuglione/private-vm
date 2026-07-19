package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/session"
)

func TestExporterCleanupRetainsOwnershipUntilRetrySucceeds(t *testing.T) {
	failFirst := func() func() error {
		calls := 0
		return func() error {
			calls++
			if calls == 1 {
				return errors.New("injected cleanup failure")
			}
			return nil
		}
	}
	detach := failFirst()
	connection := failFirst()
	process := failFirst()
	images := failFirst()
	directories := failFirst()
	cidCalls := 0
	runtime := &exporterRuntime{
		request: HostRuntimeRequest{Snapshot: session.Snapshot{Role: session.RoleExporter}},
		cid:     77, booted: true, attached: true, inspected: true,
		connectionOwned: true, processOwned: true, imagesOwned: true, directoriesOwned: true,
		cleanup: exporterCleanupHooks{
			detach:          func(context.Context) error { return detach() },
			closeConnection: connection,
			stopProcess:     func(context.Context) error { return process() },
			destroyImages:   images,
			releaseCID: func(uint32) bool {
				cidCalls++
				return cidCalls > 1
			},
			cleanupDirectories: directories,
		},
	}

	if err := runtime.StopExporter(t.Context()); err == nil {
		t.Fatal("injected cleanup failures unexpectedly passed")
	}
	if runtime.stopped || !runtime.attached || !runtime.connectionOwned || !runtime.processOwned || !runtime.imagesOwned || !runtime.directoriesOwned || runtime.cid != 77 {
		t.Fatalf("failed cleanup discarded ownership: %+v", runtime)
	}
	if err := runtime.StopExporter(t.Context()); err != nil {
		t.Fatalf("retry did not converge: %v", err)
	}
	if !runtime.stopped || runtime.attached || runtime.connectionOwned || runtime.processOwned || runtime.imagesOwned || runtime.directoriesOwned || runtime.cid != 0 {
		t.Fatalf("successful retry retained ownership: %+v", runtime)
	}
	if err := runtime.AuditAbsent(t.Context()); err != nil {
		t.Fatalf("absence audit failed: %v", err)
	}
}

func TestExporterProcessAbsenceResolvesAmbiguousUSBDetach(t *testing.T) {
	runtime := &exporterRuntime{
		request:      HostRuntimeRequest{Snapshot: session.Snapshot{Role: session.RoleExporter}},
		booted:       true,
		attached:     true,
		processOwned: true,
		cleanup: exporterCleanupHooks{
			detach:      func(context.Context) error { return errors.New("lost QMP response") },
			stopProcess: func(context.Context) error { return nil },
		},
	}
	if err := runtime.StopExporter(t.Context()); err != nil {
		t.Fatalf("QEMU absence must resolve ambiguous detach: %v", err)
	}
	if !runtime.stopped || runtime.attached || runtime.processOwned || runtime.booted {
		t.Fatalf("runtime did not converge after process absence: %+v", runtime)
	}
}

func TestExporterNoNetworkRequiresGuestInspectionEvidence(t *testing.T) {
	runtime := &exporterRuntime{
		request: HostRuntimeRequest{Snapshot: session.Snapshot{Role: session.RoleExporter}},
		booted:  true,
	}
	if err := runtime.BootNetworkless(t.Context()); err != nil {
		t.Fatalf("typed offline boot evidence rejected: %v", err)
	}
	if err := runtime.VerifyNoNetwork(t.Context()); err == nil {
		t.Fatal("host QEMU shape alone unexpectedly proved guest no-network state")
	}
	runtime.inspected = true
	if err := runtime.VerifyNoNetwork(t.Context()); err != nil {
		t.Fatalf("authenticated InspectUSB evidence rejected: %v", err)
	}
}
