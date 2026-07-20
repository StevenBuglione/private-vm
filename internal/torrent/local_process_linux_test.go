//go:build linux

package torrent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

const qbitProcessHelper = "PRIVATE_VM_QBIT_PROCESS_HELPER"

func TestQBittorrentProcessManagerOwnsStopAndCleanup(t *testing.T) {
	manager := testQBittorrentProcessManager(t, "graceful", time.Second)
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if manager.active == nil || manager.active.command.Process == nil {
		t.Fatal("started process is not owned")
	}
	if err := manager.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if manager.active != nil {
		t.Fatal("stopped process ownership was retained")
	}
	if err := manager.Stop(t.Context()); err != nil {
		t.Fatalf("idempotent stop failed: %v", err)
	}
}

func TestQBittorrentProcessManagerCancellationEscalatesAndRetainsNoProcess(t *testing.T) {
	manager := testQBittorrentProcessManager(t, "ignore-term", 200*time.Millisecond)
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.Stop(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled stop = %v", err)
	}
	if manager.active != nil {
		t.Fatal("killed process ownership was retained")
	}
}

func TestQBittorrentProcessManagerStartFailureIsBoundedAndUnowned(t *testing.T) {
	manager, err := newQBittorrentProcessManagerWithFactory(func() *exec.Cmd {
		return exec.Command("/private-vm-test-missing-qbittorrent")
	}, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err == nil || strings.Contains(err.Error(), "/private-vm-test") {
		t.Fatalf("unsafe start error = %v", err)
	}
	if manager.active != nil {
		t.Fatal("failed process start retained ownership")
	}
}

func TestQBittorrentProcessManagerRejectsCanceledStart(t *testing.T) {
	manager := testQBittorrentProcessManager(t, "graceful", time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled start = %v", err)
	}
	if manager.active != nil {
		t.Fatal("canceled start launched a process")
	}
}

func TestQBittorrentProductionCommandIsFixedAndSecretFree(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "qbittorrent")
	if err := os.Symlink(executable, path); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid = 1000
	}
	if gid == 0 {
		gid = 100
	}
	manager, err := newQBittorrentProcessManager(path, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	command := manager.factory()
	if command.Path != path || !slices.Equal(command.Args, []string{path, "--confirm-legal-notice", "--no-splash"}) {
		t.Fatalf("unexpected fixed command: path=%q args=%q", command.Path, command.Args)
	}
	if command.Dir != qbitQuarantineMount || command.SysProcAttr == nil || command.SysProcAttr.Credential == nil ||
		command.SysProcAttr.Credential.Uid != uint32(uid) || command.SysProcAttr.Credential.Gid != uint32(gid) ||
		!command.SysProcAttr.Credential.NoSetGroups || !command.SysProcAttr.Setpgid || command.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatal("fixed process isolation contract is incomplete")
	}
	joined := strings.Join(append(append([]string(nil), command.Args...), command.Env...), "\x00")
	for _, forbidden := range []string{"password", "magnet:", "PrivateKey", "WG_PRIVATE"} {
		if strings.Contains(strings.ToLower(joined), strings.ToLower(forbidden)) {
			t.Fatalf("command contract contains forbidden material marker %q", forbidden)
		}
	}
}

func testQBittorrentProcessManager(t *testing.T, mode string, stopWait time.Duration) *qbittorrentProcessManager {
	t.Helper()
	manager, err := newQBittorrentProcessManagerWithFactory(func() *exec.Cmd {
		command := exec.Command(os.Args[0], "-test.run=^TestQBittorrentProcessHelper$", "--", mode)
		command.Env = []string{qbitProcessHelper + "=" + mode}
		command.Stdout = nil
		command.Stderr = nil
		command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
		return command
	}, stopWait)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = manager.Stop(ctx)
	})
	return manager
}

func TestQBittorrentProcessHelper(t *testing.T) {
	mode := os.Getenv(qbitProcessHelper)
	if mode == "" {
		return
	}
	if mode == "ignore-term" {
		signal.Ignore(syscall.SIGTERM)
		select {}
	}
	terminated := make(chan os.Signal, 1)
	signal.Notify(terminated, syscall.SIGTERM)
	defer signal.Stop(terminated)
	<-terminated
}
