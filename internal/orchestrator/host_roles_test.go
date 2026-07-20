package orchestrator

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/image"
	"github.com/StevenBuglione/private-vm/internal/qemu"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/torrent"
)

const hostRoleSessionID = "pvm-99999999999999999999999999999999"

type hostTestLog struct {
	mu     sync.Mutex
	values []string
}

func (log *hostTestLog) add(value string) {
	log.mu.Lock()
	log.values = append(log.values, value)
	log.mu.Unlock()
}

type fakeHostImageSelector struct {
	log   *hostTestLog
	image image.RuntimeImage
	err   error
}

func (selector fakeHostImageSelector) Select(context.Context, session.Snapshot, session.LaunchPlan) (image.RuntimeImage, error) {
	selector.log.add("image.verify")
	return selector.image, selector.err
}

type fakeHostStorageAllocator struct {
	log      *hostTestLog
	resource *fakeHostStorage
	err      error
}

func (allocator fakeHostStorageAllocator) Allocate(context.Context, session.Snapshot, session.LaunchPlan, image.RuntimeImage) (HostStorage, error) {
	allocator.log.add("storage.allocate")
	return allocator.resource, allocator.err
}

type fakeHostStorage struct {
	log     *hostTestLog
	cleaned bool
}

func (storage *fakeHostStorage) RootPath() string       { return "/runtime/root.qcow2" }
func (storage *fakeHostStorage) QuarantinePath() string { return "/runtime/quarantine.raw" }
func (storage *fakeHostStorage) ActivateImages() (qemu.RuntimeImageLease, error) {
	return nil, errors.New("not used by host role owner test")
}
func (storage *fakeHostStorage) Cleanup(context.Context) error {
	storage.log.add("storage.cleanup")
	storage.cleaned = true
	return nil
}
func (storage *fakeHostStorage) Audit(context.Context) error {
	storage.log.add("storage.audit")
	if !storage.cleaned {
		return errors.New("storage active")
	}
	return nil
}

type fakeHostRuntimeStarter struct {
	log      *hostTestLog
	resource *fakeHostRuntime
	err      error
}

func (starter fakeHostRuntimeStarter) Start(context.Context, HostRuntimeRequest) (HostRuntime, error) {
	starter.log.add("runtime.start")
	return starter.resource, starter.err
}

type fakeHostRuntime struct {
	log     *hostTestLog
	cleaned bool
	relay   TorrentRelay
}

func (runtime *fakeHostRuntime) Stop(context.Context, bool) error {
	runtime.log.add("runtime.stop")
	runtime.cleaned = true
	return nil
}
func (runtime *fakeHostRuntime) Audit(context.Context) error {
	runtime.log.add("runtime.audit")
	if !runtime.cleaned {
		return errors.New("runtime active")
	}
	return nil
}
func (*fakeHostRuntime) WorkspaceState(context.Context) (string, error) { return "READY", nil }
func (runtime *fakeHostRuntime) Torrent() (TorrentRelay, error) {
	if runtime.relay == nil {
		return nil, ErrHostRuntimeUnavailable
	}
	return runtime.relay, nil
}

type fakeTorrentRelay struct{ sealed bool }

func (*fakeTorrentRelay) Add(context.Context, torrent.InputKind, io.Reader) (*privatevmv1.TorrentMetadata, error) {
	return &privatevmv1.TorrentMetadata{PayloadPaused: true}, nil
}
func (*fakeTorrentRelay) Metadata(context.Context) (*privatevmv1.TorrentMetadata, error) {
	return &privatevmv1.TorrentMetadata{PayloadPaused: true}, nil
}
func (*fakeTorrentRelay) Select(context.Context, []uint32, torrent.CapacityEvidence) (*privatevmv1.TorrentMetadata, error) {
	return &privatevmv1.TorrentMetadata{PayloadPaused: true, SelectedSizeBytes: 1}, nil
}
func (*fakeTorrentRelay) Start(context.Context, func(*privatevmv1.TorrentEvent) error) error {
	return nil
}
func (*fakeTorrentRelay) Pause(context.Context) (*privatevmv1.TorrentStatus, error) {
	return &privatevmv1.TorrentStatus{State: "DOWNLOAD_PAUSED"}, nil
}
func (*fakeTorrentRelay) Status(context.Context) (*privatevmv1.TorrentStatus, error) {
	return &privatevmv1.TorrentStatus{State: "DOWNLOADING"}, nil
}
func (relay *fakeTorrentRelay) Seal(context.Context) (*privatevmv1.TorrentStatus, error) {
	relay.sealed = true
	return &privatevmv1.TorrentStatus{State: "QUARANTINE_SEALED"}, nil
}

func TestHostRolesOwnPlanImageStorageRuntimeAndReverseCleanup(t *testing.T) {
	log := &hostTestLog{}
	storageResource := &fakeHostStorage{log: log}
	runtimeResource := &fakeHostRuntime{log: log}
	roles, err := NewHostRoles(
		fakeHostImageSelector{log: log, image: hostTestImage(t)},
		fakeHostStorageAllocator{log: log, resource: storageResource},
		fakeHostRuntimeStarter{log: log, resource: runtimeResource},
	)
	if err != nil {
		t.Fatal(err)
	}
	roles.PreflightCheck = func(context.Context, session.Snapshot, session.LaunchPlan) error {
		log.add("preflight")
		return nil
	}
	snapshot := hostTestSnapshot(session.RoleWorkstation)
	plan := hostTestPlan(session.RoleWorkstation)
	planCleanup, planAudit, err := roles.PlanAllocation(snapshot, plan)(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := roles.Preflight(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	if err := roles.VerifyImages(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	storageCleanup, storageAudit, err := roles.StorageAllocation(snapshot)(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	runtimeCleanup, runtimeAudit, err := roles.RuntimeAllocation(snapshot)(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if state, err := roles.WorkspaceState(t.Context(), snapshot); err != nil || state != "READY" {
		t.Fatalf("workspace state = %q, %v", state, err)
	}
	if err := runtimeCleanup(t.Context()); err != nil || runtimeAudit(t.Context()) != nil {
		t.Fatal("runtime cleanup or audit failed")
	}
	if err := storageCleanup(t.Context()); err != nil || storageAudit(t.Context()) != nil {
		t.Fatal("storage cleanup or audit failed")
	}
	if err := planCleanup(t.Context()); err != nil || planAudit(t.Context()) != nil {
		t.Fatal("plan cleanup or audit failed")
	}
	want := []string{"preflight", "image.verify", "storage.allocate", "runtime.start", "runtime.stop", "runtime.audit", "storage.cleanup", "storage.audit"}
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.values) != len(want) {
		t.Fatalf("operations = %v", log.values)
	}
	for index := range want {
		if log.values[index] != want[index] {
			t.Fatalf("operations = %v, want %v", log.values, want)
		}
	}
}

func TestHostRolesPartialRuntimeFailureRemainsOwnedForCleanup(t *testing.T) {
	log := &hostTestLog{}
	storageResource := &fakeHostStorage{log: log}
	runtimeResource := &fakeHostRuntime{log: log}
	roles, err := NewHostRoles(
		fakeHostImageSelector{log: log, image: hostTestImage(t)},
		fakeHostStorageAllocator{log: log, resource: storageResource},
		fakeHostRuntimeStarter{log: log, resource: runtimeResource, err: context.DeadlineExceeded},
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := hostTestSnapshot(session.RoleDownloader)
	plan := hostTestPlan(session.RoleDownloader)
	_, _, err = roles.PlanAllocation(snapshot, plan)(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := roles.VerifyImages(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	storageCleanup, _, err := roles.StorageAllocation(snapshot)(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	runtimeCleanup, runtimeAudit, err := roles.RuntimeAllocation(snapshot)(t.Context())
	if !errors.Is(err, context.DeadlineExceeded) || runtimeCleanup == nil || runtimeAudit == nil {
		t.Fatalf("partial runtime contract = cleanup:%v audit:%v err:%v", runtimeCleanup != nil, runtimeAudit != nil, err)
	}
	if err := runtimeCleanup(t.Context()); err != nil || runtimeAudit(t.Context()) != nil {
		t.Fatal("partial runtime did not converge")
	}
	if err := storageCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestHostRolesCanceledRuntimeRemainsOwnedForCleanup(t *testing.T) {
	log := &hostTestLog{}
	storageResource := &fakeHostStorage{log: log}
	runtimeResource := &fakeHostRuntime{log: log}
	roles, err := NewHostRoles(
		fakeHostImageSelector{log: log, image: hostTestImage(t)},
		fakeHostStorageAllocator{log: log, resource: storageResource},
		fakeHostRuntimeStarter{log: log, resource: runtimeResource, err: context.Canceled},
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := hostTestSnapshot(session.RoleWorkstation)
	_, _, _ = roles.PlanAllocation(snapshot, hostTestPlan(session.RoleWorkstation))(t.Context())
	if err := roles.VerifyImages(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	storageCleanup, _, err := roles.StorageAllocation(snapshot)(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	runtimeCleanup, runtimeAudit, err := roles.RuntimeAllocation(snapshot)(canceled)
	if !errors.Is(err, context.Canceled) || runtimeCleanup == nil || runtimeAudit == nil {
		t.Fatalf("canceled runtime contract = cleanup:%v audit:%v err:%v", runtimeCleanup != nil, runtimeAudit != nil, err)
	}
	if err := runtimeCleanup(t.Context()); err != nil || runtimeAudit(t.Context()) != nil {
		t.Fatal("canceled runtime did not converge")
	}
	if err := storageCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestHostRolesImageFailureDoesNotAllocateStorage(t *testing.T) {
	want := errors.New("verification failed")
	log := &hostTestLog{}
	roles, err := NewHostRoles(
		fakeHostImageSelector{log: log, err: want},
		fakeHostStorageAllocator{log: log},
		fakeHostRuntimeStarter{log: log},
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := hostTestSnapshot(session.RoleWorkstation)
	_, _, _ = roles.PlanAllocation(snapshot, hostTestPlan(session.RoleWorkstation))(t.Context())
	if err := roles.VerifyImages(t.Context(), snapshot); !errors.Is(err, want) {
		t.Fatalf("image verification error = %v", err)
	}
	if _, _, err := roles.StorageAllocation(snapshot)(t.Context()); !errors.Is(err, ErrHostImageUnavailable) {
		t.Fatalf("storage after image failure = %v", err)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.values) != 1 || log.values[0] != "image.verify" {
		t.Fatalf("unexpected operations after image failure: %v", log.values)
	}
}

func TestHostRolesDownloaderRelaySealsThenAuditsRuntimeAbsence(t *testing.T) {
	log := &hostTestLog{}
	relay := &fakeTorrentRelay{}
	storageResource := &fakeHostStorage{log: log}
	runtimeResource := &fakeHostRuntime{log: log, relay: relay}
	roles, err := NewHostRoles(
		fakeHostImageSelector{log: log, image: hostTestImage(t)},
		fakeHostStorageAllocator{log: log, resource: storageResource},
		fakeHostRuntimeStarter{log: log, resource: runtimeResource},
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := hostTestSnapshot(session.RoleDownloader)
	plan := hostTestPlan(session.RoleDownloader)
	_, _, _ = roles.PlanAllocation(snapshot, plan)(t.Context())
	if err := roles.VerifyImages(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	_, _, _ = roles.StorageAllocation(snapshot)(t.Context())
	_, _, _ = roles.RuntimeAllocation(snapshot)(t.Context())
	status, err := roles.SealAndDestroy(t.Context(), snapshot)
	if err != nil || status.GetState() != "QUARANTINE_SEALED" || !relay.sealed || !runtimeResource.cleaned {
		t.Fatalf("seal status=%v err=%v sealed=%v cleaned=%v", status, err, relay.sealed, runtimeResource.cleaned)
	}
}

func TestHostRolesScannerRemainsTypedFailClosedAndExporterUsesDedicatedRuntime(t *testing.T) {
	for _, role := range []session.Role{session.RoleScanner, session.RoleExporter} {
		roles, err := NewHostRoles(fakeHostImageSelector{log: &hostTestLog{}}, fakeHostStorageAllocator{log: &hostTestLog{}}, fakeHostRuntimeStarter{log: &hostTestLog{}})
		if err != nil {
			t.Fatal(err)
		}
		snapshot := hostTestSnapshot(role)
		_, _, err = roles.PlanAllocation(snapshot, hostTestPlan(role))(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		preflightErr := roles.Preflight(t.Context(), snapshot)
		if role == session.RoleScanner && !errors.Is(preflightErr, ErrHostRoleUnavailable) {
			t.Fatalf("scanner preflight error = %v", preflightErr)
		}
		if role == session.RoleExporter && preflightErr != nil {
			t.Fatalf("exporter preflight error = %v", preflightErr)
		}
	}
}

func hostTestSnapshot(role session.Role) session.Snapshot {
	return session.Snapshot{SchemaVersion: 1, ID: hostRoleSessionID, OwnerUID: 1000, Role: role, Phase: session.PhaseCreated}
}

func hostTestPlan(role session.Role) session.LaunchPlan {
	plan := session.LaunchPlan{Role: role, VCPUs: 2, MemoryBytes: 2 << 30, RootBytes: 32 << 30}
	if role == session.RoleWorkstation {
		plan.ImageBundle = "basic"
	}
	if role == session.RoleDownloader {
		plan.PolicyName = "safe"
		plan.ScratchBytes = 8 << 30
	}
	return plan
}

func hostTestImage(t *testing.T) image.RuntimeImage {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.qcow2")
	if err := os.WriteFile(path, []byte("fixture"), 0o444); err != nil {
		t.Fatal(err)
	}
	return image.RuntimeImage{
		Entry: image.Entry{ImagePath: path}, ManifestDigest: "sha256:fixture", ImageDigest: "sha256:image",
		SourceCommit: "fixture", Capabilities: []string{"fixture"}, VirtualSizeBytes: 64 << 30,
	}
}
