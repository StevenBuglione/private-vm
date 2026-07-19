package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLUKSLifecycleKeepsKeyOffArgumentsAndDeletesCiphertext(t *testing.T) {
	manager, runner, mounter, sessionID := testLUKSManager(t)
	handle, err := manager.Create(context.Background(), sessionID, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	path, err := handle.CreateOpaqueFile("quarantine.raw", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(path, handle.OuterPath()+string(filepath.Separator)) {
		t.Fatalf("opaque path escaped outer filesystem: %s", path)
	}
	// The fake mounter does not hide the mounted filesystem after unmount as the
	// kernel would, so remove the fixture before exercising mountpoint cleanup.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.Commands() {
		joined := strings.Join(command.Args, " ")
		if strings.Contains(strings.ToLower(joined), "privatekey") || strings.Contains(strings.ToLower(joined), "passphrase") {
			t.Fatalf("secret-like value entered argv: %v", command.Args)
		}
		if command.Path == manager.Tools.Cryptsetup && (len(command.Args) == 0 || command.Args[0] != "close") {
			if !strings.Contains(joined, "--key-file /proc/self/fd/3") || command.ExtraFiles != 1 {
				t.Fatalf("cryptsetup key was not inherited by FD: %+v", command)
			}
		}
	}
	keyReads, keysMatched := runner.KeyEvidence()
	if keyReads != 2 || !keysMatched {
		t.Fatalf("cryptsetup did not receive the same complete inherited key twice: reads=%d matched=%t", keyReads, keysMatched)
	}
	if err := handle.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !mounter.unmounted {
		t.Fatal("outer filesystem was not unmounted")
	}
	if _, err := os.Stat(filepath.Join(manager.ScratchRoot, sessionID+".luks")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ciphertext remains after key destruction: %v", err)
	}
	if err := handle.Destroy(context.Background()); err != nil {
		t.Fatalf("repeated destruction is not idempotent: %v", err)
	}
}

func TestLUKSCleanupRetriesBeforeDestroyingCiphertext(t *testing.T) {
	manager, runner, _, sessionID := testLUKSManager(t)
	handle, err := manager.Create(context.Background(), sessionID, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	runner.failCloseOnce = true
	if err := handle.Destroy(context.Background()); err == nil {
		t.Fatal("injected mapper close failure unexpectedly passed")
	}
	ciphertext := filepath.Join(manager.ScratchRoot, sessionID+".luks")
	if _, err := os.Stat(ciphertext); err != nil {
		t.Fatalf("ciphertext was removed before mapper cleanup succeeded: %v", err)
	}
	if err := handle.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ciphertext); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ciphertext remains after retry: %v", err)
	}
}

func TestOverlayRequiresReadOnlyBaseAndVerifiesBacking(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "outer")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "base.qcow2")
	if err := os.WriteFile(base, []byte("test"), 0o444); err != nil {
		t.Fatal(err)
	}
	runner := &overlayRunner{base: base}
	manager := OverlayManager{QEMUImg: "/usr/bin/qemu-img", Runner: runner}
	overlay, err := manager.Create(context.Background(), directory, base, "root-workstation.qcow2")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(overlay)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("overlay permissions are %o", info.Mode().Perm())
	}
	if err := os.Chmod(base, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), directory, base, "root-downloader.qcow2"); err == nil {
		t.Fatal("writable base image unexpectedly passed")
	}
}

func TestCapacityPlanSelectsRAMThenLUKSAndFailsClosed(t *testing.T) {
	host := HostCapacity{TotalRAMBytes: 32 << 30, AvailableRAMBytes: 24 << 30, RuntimeFreeBytes: 16 << 30, ScratchFreeBytes: 100 << 30, RuntimeIsTmpfs: true}
	request := CapacityRequest{GuestRAMBytes: 8 << 30, ExpectedWritesBytes: 4 << 30, SmallScratchMax: 8 << 30}
	plan, err := PlanCapacity(host, request)
	if err != nil || plan.Mode != ScratchModeRAM {
		t.Fatalf("RAM plan: %+v %v", plan, err)
	}
	request.ExpectedWritesBytes = 20 << 30
	plan, err = PlanCapacity(host, request)
	if err != nil || plan.Mode != ScratchModeLUKS {
		t.Fatalf("LUKS plan: %+v %v", plan, err)
	}
	host.ScratchFreeBytes = 1
	if _, err := PlanCapacity(host, request); err == nil {
		t.Fatal("insufficient capacity unexpectedly passed")
	}
	host.DiskBackedSwap = true
	if _, err := PlanCapacity(host, request); err == nil {
		t.Fatal("disk-backed swap unexpectedly passed")
	}
}

func TestTmpfsScratchUsesBoundedNoExecMountAndIdempotentCleanup(t *testing.T) {
	root := t.TempDir()
	sessionID := "pvm-0123456789abcdef0123456789abcdef"
	if err := os.Mkdir(filepath.Join(root, sessionID), 0o700); err != nil {
		t.Fatal(err)
	}
	mounter := &fakeMounter{}
	manager := &TmpfsManager{RuntimeRoot: root, Mounter: mounter}
	handle, err := manager.Create(context.Background(), sessionID, 512<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !mounter.mounted || mounter.filesystem != "tmpfs" || !strings.Contains(mounter.data, "size=536870912") {
		t.Fatalf("tmpfs mount was not bounded: %+v", mounter)
	}
	if err := handle.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := handle.Destroy(context.Background()); err != nil {
		t.Fatalf("repeated cleanup failed: %v", err)
	}
}

func testLUKSManager(t *testing.T) (*LUKSManager, *fakeRunner, *fakeMounter, string) {
	t.Helper()
	root := t.TempDir()
	scratch := filepath.Join(root, "scratch")
	runtimeRoot := filepath.Join(root, "run")
	for _, path := range []string{scratch, runtimeRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sessionID := "pvm-0123456789abcdef0123456789abcdef"
	if err := os.Mkdir(filepath.Join(runtimeRoot, sessionID), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	mounter := &fakeMounter{}
	manager := &LUKSManager{
		ScratchRoot: scratch, RuntimeRoot: runtimeRoot,
		Tools:  Tools{Losetup: "/usr/bin/losetup", Cryptsetup: "/usr/bin/cryptsetup", MkfsExt4: "/usr/bin/mkfs.ext4"},
		Runner: runner, Mounter: mounter,
	}
	return manager, runner, mounter, sessionID
}

type recordedCommand struct {
	Path       string
	Args       []string
	ExtraFiles int
}

type fakeRunner struct {
	mu            sync.Mutex
	commands      []recordedCommand
	failCloseOnce bool
	firstKey      []byte
	keyReads      int
	keysMatched   bool
}

func (r *fakeRunner) Run(_ context.Context, command Command) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, recordedCommand{Path: command.Path, Args: append([]string(nil), command.Args...), ExtraFiles: len(command.ExtraFiles)})
	if len(command.ExtraFiles) == 1 && len(command.Args) > 0 && command.Args[0] != "close" {
		key, err := io.ReadAll(io.LimitReader(command.ExtraFiles[0], 65))
		if err != nil || len(key) != 64 {
			clear(key)
			return Result{}, errors.New("inherited key fixture had an invalid length")
		}
		r.keyReads++
		if r.keyReads == 1 {
			r.firstKey = append([]byte(nil), key...)
		} else if r.keyReads == 2 {
			r.keysMatched = bytes.Equal(r.firstKey, key)
			clear(r.firstKey)
			r.firstKey = nil
		}
		clear(key)
	}
	if r.failCloseOnce && len(command.Args) > 0 && command.Args[0] == "close" {
		r.failCloseOnce = false
		return Result{}, errors.New("injected mapper close failure")
	}
	if len(command.Args) == 1 && command.Args[0] == "--find" {
		return Result{Stdout: []byte("/dev/loop7\n")}, nil
	}
	return Result{}, nil
}

func (r *fakeRunner) Commands() []recordedCommand {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedCommand(nil), r.commands...)
}

func (r *fakeRunner) KeyEvidence() (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.keyReads, r.keysMatched
}

type fakeMounter struct {
	mounted    bool
	unmounted  bool
	filesystem string
	data       string
}

func (m *fakeMounter) Mount(_, _ string, filesystem string, _ uintptr, data string) error {
	if filesystem != "ext4" && filesystem != "tmpfs" {
		return fmt.Errorf("unexpected filesystem %s", filesystem)
	}
	m.mounted = true
	m.filesystem = filesystem
	m.data = data
	return nil
}

func (m *fakeMounter) Unmount(string, int) error {
	if !m.mounted {
		return errors.New("not mounted")
	}
	m.unmounted = true
	return nil
}

type overlayRunner struct {
	base string
}

func (r *overlayRunner) Run(_ context.Context, command Command) (Result, error) {
	if len(command.Args) == 0 {
		return Result{}, errors.New("missing qemu-img operation")
	}
	switch command.Args[0] {
	case "create":
		path := command.Args[len(command.Args)-1]
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return Result{}, err
		}
		return Result{}, file.Close()
	case "info":
		path := command.Args[len(command.Args)-1]
		value := imageInfo{Format: "qcow2", VirtualSize: 1 << 30}
		if path != r.base {
			value.FullBackingFilename = r.base
		}
		data, err := json.Marshal(value)
		return Result{Stdout: data}, err
	default:
		return Result{}, errors.New("unexpected qemu-img operation")
	}
}
