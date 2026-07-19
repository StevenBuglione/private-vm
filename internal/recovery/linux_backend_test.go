//go:build linux

package recovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/session"
)

const linuxTestSession = "pvm-0123456789abcdef0123456789abcdef"

type recordingToolRunner struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (runner *recordingToolRunner) Run(ctx context.Context, path string, arguments ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	runner.mu.Lock()
	runner.calls = append(runner.calls, filepath.Base(path)+":"+joinArguments(arguments))
	runner.mu.Unlock()
	return runner.err
}

type recordingMounter struct{ err error }

func (mounter *recordingMounter) Unmount(string, int) error { return mounter.err }

type linuxFixture struct {
	root, runtime, scratch, cache, sysBlock, dev, mapper, mountInfo string
	store                                                           *session.Store
	backend                                                         *LinuxBackend
}

func newLinuxFixture(t *testing.T) linuxFixture {
	t.Helper()
	root := t.TempDir()
	paths := linuxFixture{
		root: root, runtime: filepath.Join(root, "run", "private-vm"),
		scratch: filepath.Join(root, "scratch"), cache: filepath.Join(root, "images"),
		sysBlock: filepath.Join(root, "sys", "class", "block"), dev: filepath.Join(root, "dev"),
		mapper: filepath.Join(root, "dev", "mapper"), mountInfo: filepath.Join(root, "mountinfo"),
	}
	for _, path := range []string{filepath.Dir(paths.runtime), paths.scratch, paths.cache, paths.sysBlock, paths.dev, paths.mapper} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(paths.scratch, ".private-vm-no-backup"), []byte("private-vm-ephemeral-scratch-v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.mountInfo, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := session.NewStore(paths.runtime)
	if err != nil {
		t.Fatal(err)
	}
	paths.store = store
	backend, err := NewLinuxBackend(LinuxBackendConfig{
		Store: store, ScratchRoot: paths.scratch, DaemonUID: uint32(os.Geteuid()), DaemonGID: uint32(os.Getegid()), ControlGID: uint32(os.Getegid()),
		Cryptsetup: "/test/bin/cryptsetup", Losetup: "/test/bin/losetup", Runner: &recordingToolRunner{}, Mounter: &recordingMounter{},
		MountInfoPath: paths.mountInfo, SysBlockRoot: paths.sysBlock, DevRoot: paths.dev, DevMapperRoot: paths.mapper,
	})
	if err != nil {
		t.Fatal(err)
	}
	paths.backend = backend
	return paths
}

func (fixture linuxFixture) reconciler(t *testing.T) *Reconciler {
	t.Helper()
	reconciler, err := New(
		fixture.backend, NewStartupRegistry(),
		VolatileKeyEvidence{RuntimeRoot: fixture.runtime, DaemonUID: uint32(os.Geteuid()), DaemonGID: uint32(os.Getegid())},
		FilesystemBaseAuditor{Root: fixture.cache, OwnerUID: uint32(os.Geteuid())},
		Config{DaemonUID: uint32(os.Geteuid()), InventoryTimeout: time.Second, StepTimeout: time.Second, SessionTimeout: 3 * time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}
	return reconciler
}

func TestLinuxRecoveryRemovesEarlyVolatileRecordAndAuditsAbsence(t *testing.T) {
	fixture := newLinuxFixture(t)
	manager, err := session.NewManager(fixture.store, 4)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Create(1000, session.RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	report, err := fixture.reconciler(t).Run(t.Context())
	if err != nil || report.Status != StatusComplete || report.SessionsRecovered != 1 {
		t.Fatalf("early recovery failed: report=%+v err=%v", report, err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.runtime, snapshot.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("early volatile record remains: %v", err)
	}
}

func TestLinuxRecoveryRefusesAdvancedSessionBeforeMutation(t *testing.T) {
	fixture := newLinuxFixture(t)
	manager, err := session.NewManager(fixture.store, 4)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Create(1000, session.RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []session.Phase{session.PhasePreflighted, session.PhaseImagesVerified, session.PhaseStorageReady} {
		if _, err := manager.Transition(t.Context(), snapshot.ID, 1000, phase); err != nil {
			t.Fatal(err)
		}
	}
	report, err := fixture.reconciler(t).Run(t.Context())
	if !errors.Is(err, ErrIncomplete) || report.Status != StatusIncomplete {
		t.Fatalf("advanced recovery did not fail closed: report=%+v err=%v", report, err)
	}
	if _, err := fixture.store.Load(snapshot.ID); err != nil {
		t.Fatalf("failed recovery mutated the volatile record: %v", err)
	}
}

func TestLinuxRecoveryDeletesExactOrphanCiphertextAfterKeyLossProof(t *testing.T) {
	fixture := newLinuxFixture(t)
	ciphertext := filepath.Join(fixture.scratch, linuxTestSession+".luks")
	if err := os.WriteFile(ciphertext, []byte("opaque-ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := fixture.reconciler(t).Run(t.Context())
	if err != nil || report.KeyLossVerifiedSessions != 1 || report.ArtifactsRecovered.Ciphertext != 1 {
		t.Fatalf("ciphertext recovery failed: report=%+v err=%v", report, err)
	}
	if _, err := os.Lstat(ciphertext); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ciphertext remains: %v", err)
	}
}

func TestLinuxRecoveryRetainsCiphertextWhenVolatileKeyLossIsUnknown(t *testing.T) {
	fixture := newLinuxFixture(t)
	manager, err := session.NewManager(fixture.store, 4)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Create(1000, session.RoleDownloader)
	if err != nil {
		t.Fatal(err)
	}
	secrets := filepath.Join(fixture.runtime, snapshot.ID, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "unexpected"), []byte("not-a-real-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	ciphertext := filepath.Join(fixture.scratch, snapshot.ID+".luks")
	if err := os.WriteFile(ciphertext, []byte("opaque-ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := fixture.reconciler(t).Run(t.Context())
	if !errors.Is(err, ErrIncomplete) || report.Status != StatusIncomplete {
		t.Fatalf("unknown key evidence did not fail closed: report=%+v err=%v", report, err)
	}
	if _, err := os.Lstat(ciphertext); err != nil {
		t.Fatalf("unknown key evidence removed ciphertext: %v", err)
	}
}

func TestLinuxRecoveryRejectsIdentityReplacementAndCancellation(t *testing.T) {
	fixture := newLinuxFixture(t)
	manager, err := session.NewManager(fixture.store, 4)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Create(1000, session.RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := fixture.backend.Inventory(t.Context())
	if err != nil || len(candidates) != 1 {
		t.Fatalf("inventory failed: candidates=%d err=%v", len(candidates), err)
	}
	original := filepath.Join(fixture.runtime, snapshot.ID)
	moved := original + ".old"
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := fixture.backend.RevalidateOwned(t.Context(), candidates[0]); err == nil {
		t.Fatal("replacement identity unexpectedly passed")
	}
	if _, err := os.Lstat(original); err != nil {
		t.Fatal("identity rejection removed the replacement")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.backend.Inventory(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled inventory error = %v", err)
	}
}

func TestFilesystemBaseAuditorDetectsChangeAndReportWriterIsClosed(t *testing.T) {
	fixture := newLinuxFixture(t)
	image := filepath.Join(fixture.cache, "image.qcow2")
	if err := os.WriteFile(image, []byte("base"), 0o400); err != nil {
		t.Fatal(err)
	}
	auditor := FilesystemBaseAuditor{Root: fixture.cache, OwnerUID: uint32(os.Geteuid())}
	seal, err := auditor.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(image, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := auditor.Verify(t.Context(), seal); err == nil {
		t.Fatal("changed base image unexpectedly verified")
	}
	report := newReport()
	report.BaseImagesVerified = true
	report = report.finish()
	path := filepath.Join(fixture.root, "private-vm-recovery-test.json")
	if err := WriteReportAtomic(path, report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{linuxTestSession, fixture.root, "fingerprint", "locator"} {
		if containsBytes(data, []byte(forbidden)) {
			t.Fatalf("recovery report leaked %q: %s", forbidden, data)
		}
	}
}

func joinArguments(arguments []string) string {
	result := ""
	for index, argument := range arguments {
		if index != 0 {
			result += ","
		}
		result += argument
	}
	return result
}

func containsBytes(value, fragment []byte) bool {
	if len(fragment) == 0 || len(fragment) > len(value) {
		return false
	}
	for index := 0; index+len(fragment) <= len(value); index++ {
		matched := true
		for offset := range fragment {
			if value[index+offset] != fragment[offset] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}
