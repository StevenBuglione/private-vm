package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/qemu"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
)

const scannerRuntimeSessionID = "pvm-88888888888888888888888888888888"

type fakeScannerVMStarter struct {
	mu         sync.Mutex
	requests   []ScannerVMRequest
	prepared   int
	forgotten  int
	prepareErr error
	startErr   error
}

func (starter *fakeScannerVMStarter) PrepareUpdate(context.Context, session.Snapshot) error {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	starter.prepared++
	return starter.prepareErr
}

func (starter *fakeScannerVMStarter) Forget(string) {
	starter.mu.Lock()
	starter.forgotten++
	starter.mu.Unlock()
}

func (starter *fakeScannerVMStarter) StartScanner(_ context.Context, request ScannerVMRequest) (ScannerVM, error) {
	starter.mu.Lock()
	starter.requests = append(starter.requests, request)
	starter.mu.Unlock()
	return &fakeScannerVM{}, starter.startErr
}

type fakeScannerVM struct {
	mu      sync.Mutex
	stopped bool
}

func (*fakeScannerVM) Client() (privatevmv1.ScannerGuestServiceClient, error) { return nil, nil }
func (*fakeScannerVM) VerifyReport(scan.AuthenticatedReport) (scan.ScanReport, error) {
	return scan.ScanReport{}, nil
}
func (vm *fakeScannerVM) Stop(context.Context) error {
	vm.mu.Lock()
	vm.stopped = true
	vm.mu.Unlock()
	return nil
}
func (vm *fakeScannerVM) Audit(context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	if !vm.stopped {
		return errors.New("scanner VM remains active")
	}
	return nil
}

func scannerRuntimeFixture(t *testing.T) (*ProductionScannerRuntime, session.Snapshot, session.Snapshot, *hostStorageResource, *fakeHostStorage, *fakeScannerVMStarter) {
	t.Helper()
	log := &hostTestLog{}
	sourceStorage := &hostStorageResource{quarantine: "/runtime/quarantine.raw"}
	sourceRuntime := &fakeHostRuntime{log: log, cleaned: true}
	source := session.Snapshot{
		SchemaVersion: 1, ID: hostRoleSessionID, OwnerUID: 1000, Role: session.RoleDownloader,
		Phase: session.PhaseActive, WorkflowState: "QUARANTINE_SEALED",
	}
	sources := &HostRoles{states: map[string]*hostRoleState{
		source.ID: {plan: hostTestPlan(session.RoleDownloader), storage: sourceStorage, runtime: sourceRuntime},
	}}
	scanner := session.Snapshot{
		SchemaVersion: 1, ID: scannerRuntimeSessionID, OwnerUID: source.OwnerUID, Role: session.RoleScanner,
		Phase: session.PhaseCreated, WorkflowState: "UPDATE_VM_BOOTING",
	}
	storageResource := &fakeHostStorage{log: log}
	starter := &fakeScannerVMStarter{}
	runtime, err := NewProductionScannerRuntime(
		sources,
		fakeHostImageSelector{log: log, image: hostTestImage(t)},
		fakeHostStorageAllocator{log: log, resource: storageResource},
		starter, FailClosedScannerPromotion{},
		ScannerRuntimePlan{VCPUs: 4, MemoryBytes: 8 << 30, RootBytes: 32 << 30},
	)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, source, scanner, sourceStorage, storageResource, starter
}

func TestProductionScannerRuntimeOwnsSameOverlayTwoBootsAndQuarantineLease(t *testing.T) {
	runtime, source, scanner, sourceStorage, _, starter := scannerRuntimeFixture(t)
	if err := runtime.Preflight(t.Context(), source, scanner); err != nil {
		t.Fatal(err)
	}
	if err := runtime.VerifyImage(t.Context(), scanner); err != nil {
		t.Fatal(err)
	}
	storageCleanup, storageAudit, err := runtime.StorageAllocation(source, scanner)(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceStorage.Cleanup(t.Context()); !errors.Is(err, ErrHostStorageUnavailable) {
		t.Fatalf("source cleanup while scanner lease active = %v", err)
	}
	updateCleanup, updateAudit, err := runtime.UpdateRuntimeAllocation(scanner)(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.StopUpdate(t.Context(), scanner); err != nil {
		t.Fatal(err)
	}
	offlineCleanup, offlineAudit, err := runtime.OfflineRuntimeAllocation(scanner)(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.StopOffline(t.Context(), scanner); err != nil {
		t.Fatal(err)
	}
	starter.mu.Lock()
	requests := append([]ScannerVMRequest(nil), starter.requests...)
	starter.mu.Unlock()
	if len(requests) != 2 || requests[0].Mode != qemu.ScannerModeUpdate || requests[1].Mode != qemu.ScannerModeScan ||
		requests[0].Storage != requests[1].Storage || requests[0].Quarantine != requests[1].Quarantine || requests[0].Quarantine.Path() == "" {
		t.Fatalf("scanner boot requests = %#v", requests)
	}
	for _, step := range []struct {
		cleanup session.CleanupFunc
		audit   session.AuditFunc
	}{{offlineCleanup, offlineAudit}, {updateCleanup, updateAudit}, {storageCleanup, storageAudit}} {
		if err := step.cleanup(t.Context()); err != nil || step.audit(t.Context()) != nil {
			t.Fatal("scanner reverse cleanup did not converge")
		}
	}
	if err := sourceStorage.Cleanup(t.Context()); err != nil || sourceStorage.Audit(t.Context()) != nil {
		t.Fatal("sealed downloader storage did not regain ownership")
	}
}

func TestProductionScannerRuntimeFailureCancellationAndTimeoutReturnCleanupOwner(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{{"failure", errors.New("injected scanner start failure")}, {"cancel", context.Canceled}, {"timeout", context.DeadlineExceeded}} {
		t.Run(test.name, func(t *testing.T) {
			runtime, source, scanner, _, _, starter := scannerRuntimeFixture(t)
			storageCleanup, storageAudit, err := runtime.StorageAllocation(source, scanner)(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			starter.startErr = test.err
			cleanup, audit, err := runtime.UpdateRuntimeAllocation(scanner)(t.Context())
			if !errors.Is(err, test.err) || cleanup == nil || audit == nil {
				t.Fatalf("partial scanner allocation cleanup=%v audit=%v err=%v", cleanup != nil, audit != nil, err)
			}
			if err := cleanup(t.Context()); err != nil || audit(t.Context()) != nil {
				t.Fatal("partial scanner runtime did not clean")
			}
			if err := storageCleanup(t.Context()); err != nil || storageAudit(t.Context()) != nil {
				t.Fatal("scanner storage did not clean after partial runtime")
			}
		})
	}
}

type scannerSpecStorage struct{ root string }

func (storage scannerSpecStorage) RootPath() string                        { return storage.root }
func (scannerSpecStorage) QuarantinePath() string                          { return "" }
func (scannerSpecStorage) ActivateImages() (qemu.RuntimeImageLease, error) { return nil, nil }
func (scannerSpecStorage) Cleanup(context.Context) error                   { return nil }
func (scannerSpecStorage) Audit(context.Context) error                     { return nil }

type scannerSpecQuarantine struct{ path string }

func (lease scannerSpecQuarantine) Path() string            { return lease.path }
func (scannerSpecQuarantine) Release(context.Context) error { return nil }
func (scannerSpecQuarantine) Audit(context.Context) error   { return nil }

func TestScannerQEMUDeviceShapesAreOnlineWithoutQuarantineThenOfflineReadOnly(t *testing.T) {
	runtimeRoot, err := os.MkdirTemp("/tmp", "pvm-scan-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeRoot) })
	parent := filepath.Join(runtimeRoot, scannerRuntimeSessionID)
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	directories, err := createRuntimeSocketDirectories(runtimeRoot, scannerRuntimeSessionID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = directories.Cleanup() })
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	base := ScannerVMRequest{
		Snapshot:   session.Snapshot{ID: scannerRuntimeSessionID, Role: session.RoleScanner},
		Plan:       session.LaunchPlan{Role: session.RoleScanner, VCPUs: 2, MemoryBytes: 2 << 30, RootBytes: 32 << 30},
		Storage:    scannerSpecStorage{root: "/runtime/root-scanner.qcow2"},
		Quarantine: scannerSpecQuarantine{path: "/runtime/quarantine.raw"},
	}
	update := base
	update.Mode = qemu.ScannerModeUpdate
	updateSpec, err := scannerQEMUSpec(binary, update, 41, directories)
	if err != nil {
		t.Fatal(err)
	}
	updateArgs, _ := updateSpec.Args()
	updateJoined := strings.Join(updateArgs, " ")
	if !updateSpec.Networked || len(updateSpec.Data) != 0 || !strings.Contains(updateJoined, "-netdev") || strings.Contains(updateJoined, "quarantine") || strings.Contains(updateJoined, "-nic none") ||
		!strings.Contains(updateJoined, "name=opt/private-vm/scanner-boot-mode,string=definitions-update") || strings.Contains(updateJoined, "scan-offline") {
		t.Fatalf("unsafe scanner update device graph: %s", updateJoined)
	}

	// Args validation requires absent socket destinations for each independent
	// boot, matching the real stop-before-reboot sequence.
	offline := base
	offline.Mode = qemu.ScannerModeScan
	offlineSpec, err := scannerQEMUSpec(binary, offline, 42, directories)
	if err != nil {
		t.Fatal(err)
	}
	offlineArgs, _ := offlineSpec.Args()
	offlineJoined := strings.Join(offlineArgs, " ")
	if offlineSpec.Networked || len(offlineSpec.Data) != 1 || !offlineSpec.Data[0].ReadOnly ||
		!strings.Contains(offlineJoined, "-nic none") || !strings.Contains(offlineJoined, "readonly=on") || !strings.Contains(offlineJoined, "quarantine") || strings.Contains(offlineJoined, "-netdev") ||
		!strings.Contains(offlineJoined, "name=opt/private-vm/scanner-boot-mode,string=scan-offline") || strings.Contains(offlineJoined, "definitions-update") {
		t.Fatalf("unsafe scanner offline device graph: %s", offlineJoined)
	}
}
