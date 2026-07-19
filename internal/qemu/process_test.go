package qemu

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestLauncherSupervisesFakeQEMUAndCleansCgroup(t *testing.T) {
	spec := validSpec(t)
	spec.Binary = testBinary(t)
	cgroups := &fakeCgroupFactory{}
	launcher, err := NewLauncher(cgroups)
	if err != nil {
		t.Fatal(err)
	}
	launcher.commandBuilder = fakeQEMUCommand("powerdown-exits")
	launcher.qmpWait = 2 * time.Second
	capability, err := os.CreateTemp(t.TempDir(), "capability")
	if err != nil {
		t.Fatal(err)
	}
	defer capability.Close()
	process, err := launcher.Launch(context.Background(), spec, capability)
	if err != nil {
		t.Fatal(err)
	}
	if process.PID() <= 1 || process.Identity().ExecutableInode == 0 || process.Identity().CgroupPath == "" {
		t.Fatalf("process identity is incomplete: %+v", process.Identity())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := process.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if !cgroups.cleaned.Load() {
		t.Fatal("QEMU cgroup was not cleaned")
	}
	process.pidfdMu.Lock()
	pidfd := process.pidfd
	process.pidfdMu.Unlock()
	if pidfd != -1 {
		t.Fatalf("QEMU pidfd remains open: %d", pidfd)
	}
	for _, socket := range []string{spec.QMPSocket, spec.SPICESocket} {
		if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("runtime socket remains after stop: %s: %v", socket, err)
		}
	}
}

func TestLauncherEscalatesAfterIgnoredPowerdown(t *testing.T) {
	spec := validSpec(t)
	spec.Binary = testBinary(t)
	cgroups := &fakeCgroupFactory{}
	launcher, err := NewLauncher(cgroups)
	if err != nil {
		t.Fatal(err)
	}
	launcher.commandBuilder = fakeQEMUCommand("powerdown-stays")
	launcher.qmpWait = 2 * time.Second
	launcher.graceWait = 25 * time.Millisecond
	launcher.termWait = time.Second
	capability, err := os.CreateTemp(t.TempDir(), "capability")
	if err != nil {
		t.Fatal(err)
	}
	defer capability.Close()
	process, err := launcher.Launch(context.Background(), spec, capability)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := process.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if !cgroups.cleaned.Load() {
		t.Fatal("cgroup cleanup did not follow escalation")
	}
}

func TestLauncherFailsWhenQEMUExitsBeforeQMP(t *testing.T) {
	spec := validSpec(t)
	spec.Binary = testBinary(t)
	launcher, err := NewLauncher(&fakeCgroupFactory{})
	if err != nil {
		t.Fatal(err)
	}
	launcher.qmpWait = 2 * time.Second
	launcher.commandBuilder = func(Spec, *os.File) (*exec.Cmd, error) {
		return exec.Command(os.Args[0], "-test.run=TestImmediateExitHelper", "--"), nil
	}
	capability, err := os.CreateTemp(t.TempDir(), "capability")
	if err != nil {
		t.Fatal(err)
	}
	defer capability.Close()
	if _, err := launcher.Launch(context.Background(), spec, capability); err == nil {
		t.Fatal("early QEMU exit unexpectedly passed")
	}
}

func TestSpontaneousQEMUDeathTriggersOwnedCleanup(t *testing.T) {
	spec := validSpec(t)
	cgroups := &fakeCgroupFactory{}
	launcher, err := NewLauncher(cgroups)
	if err != nil {
		t.Fatal(err)
	}
	launcher.commandBuilder = fakeQEMUCommand("spontaneous-exit")
	launcher.qmpWait = 2 * time.Second
	capability, err := os.CreateTemp(t.TempDir(), "capability")
	if err != nil {
		t.Fatal(err)
	}
	defer capability.Close()
	process, err := launcher.Launch(context.Background(), spec, capability)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := process.Wait(ctx); err == nil || (!strings.Contains(err.Error(), "unexpectedly") && !strings.Contains(err.Error(), "QMP supervision")) {
		t.Fatalf("spontaneous exit did not report a safe failure: %v", err)
	}
	if !cgroups.cleaned.Load() {
		t.Fatal("spontaneous exit did not clean its cgroup")
	}
	for _, socket := range []string{spec.QMPSocket, spec.SPICESocket} {
		if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("spontaneous exit left runtime socket %s: %v", socket, err)
		}
	}
}

func TestQMPDisconnectTerminatesQEMUAndCleansOwnedResources(t *testing.T) {
	spec := validSpec(t)
	cgroups := &fakeCgroupFactory{}
	launcher, err := NewLauncher(cgroups)
	if err != nil {
		t.Fatal(err)
	}
	launcher.commandBuilder = fakeQEMUCommand("qmp-disconnect-stays")
	launcher.qmpWait = 2 * time.Second
	launcher.graceWait = 20 * time.Millisecond
	launcher.termWait = 100 * time.Millisecond
	capability, err := os.CreateTemp(t.TempDir(), "capability")
	if err != nil {
		t.Fatal(err)
	}
	defer capability.Close()
	process, err := launcher.Launch(context.Background(), spec, capability)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := process.Wait(ctx); err == nil || !strings.Contains(err.Error(), "QMP supervision") {
		t.Fatalf("QMP loss did not become a safe process failure: %v", err)
	}
	if err := process.Audit(context.Background()); err != nil {
		t.Fatalf("QMP-loss cleanup audit failed: %v", err)
	}
	if !cgroups.cleaned.Load() {
		t.Fatal("QMP loss did not clean the cgroup")
	}
}

func TestCanceledStopStillEscalatesAndCleans(t *testing.T) {
	spec := validSpec(t)
	cgroups := &fakeCgroupFactory{}
	launcher, err := NewLauncher(cgroups)
	if err != nil {
		t.Fatal(err)
	}
	launcher.commandBuilder = fakeQEMUCommand("powerdown-stays")
	launcher.qmpWait = 2 * time.Second
	launcher.graceWait = time.Second
	launcher.termWait = 100 * time.Millisecond
	capability, err := os.CreateTemp(t.TempDir(), "capability")
	if err != nil {
		t.Fatal(err)
	}
	defer capability.Close()
	process, err := launcher.Launch(context.Background(), spec, capability)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := process.Stop(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled stop returned the wrong result: %v", err)
	}
	if !cgroups.cleaned.Load() {
		t.Fatal("canceled stop returned before cgroup cleanup")
	}
}

func TestLauncherEscalatesThroughSIGKILL(t *testing.T) {
	spec := validSpec(t)
	cgroups := &fakeCgroupFactory{}
	launcher, err := NewLauncher(cgroups)
	if err != nil {
		t.Fatal(err)
	}
	launcher.commandBuilder = fakeQEMUCommand("powerdown-ignore-term")
	launcher.qmpWait = 2 * time.Second
	launcher.graceWait = 20 * time.Millisecond
	launcher.termWait = 75 * time.Millisecond
	capability, err := os.CreateTemp(t.TempDir(), "capability")
	if err != nil {
		t.Fatal(err)
	}
	defer capability.Close()
	process, err := launcher.Launch(context.Background(), spec, capability)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := process.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < launcher.termWait {
		t.Fatal("stop completed before the TERM bound, so KILL escalation was not exercised")
	}
	if !cgroups.cleaned.Load() {
		t.Fatal("SIGKILL escalation did not complete cgroup cleanup")
	}
}

func TestQMPStartupTimeoutKillsAndCleans(t *testing.T) {
	spec := validSpec(t)
	cgroups := &fakeCgroupFactory{}
	launcher, err := NewLauncher(cgroups)
	if err != nil {
		t.Fatal(err)
	}
	launcher.qmpWait = 50 * time.Millisecond
	launcher.commandBuilder = func(Spec, *os.File) (*exec.Cmd, error) {
		return exec.Command(os.Args[0], "-test.run=TestNoQMPHelper", "--", "no-qmp"), nil
	}
	capability, err := os.CreateTemp(t.TempDir(), "capability")
	if err != nil {
		t.Fatal(err)
	}
	defer capability.Close()
	if _, err := launcher.Launch(context.Background(), spec, capability); err == nil {
		t.Fatal("missing QMP socket unexpectedly passed")
	}
	if !cgroups.cleaned.Load() {
		t.Fatal("QMP startup failure returned before cgroup cleanup")
	}
}

func TestQEMUHelperProcess(t *testing.T) {
	if len(os.Args) < 3 {
		return
	}
	mode := os.Args[len(os.Args)-3]
	socket := os.Args[len(os.Args)-2]
	spiceSocket := os.Args[len(os.Args)-1]
	if mode != "powerdown-exits" && mode != "powerdown-stays" && mode != "powerdown-ignore-term" && mode != "spontaneous-exit" && mode != "qmp-disconnect-stays" {
		return
	}
	if mode == "powerdown-ignore-term" {
		signal.Ignore(syscall.SIGTERM)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, runtimeSocketMode); err != nil {
		t.Fatal(err)
	}
	spiceListener, err := net.Listen("unix", spiceSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer spiceListener.Close()
	if err := os.Chmod(spiceSocket, runtimeSocketMode); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	encoder := json.NewEncoder(connection)
	decoder := json.NewDecoder(bufio.NewReader(connection))
	if err := encoder.Encode(map[string]any{"QMP": map[string]any{"version": map[string]any{"qemu": map[string]int{"major": 10, "minor": 2, "micro": 4}}, "capabilities": []string{}}}); err != nil {
		t.Fatal(err)
	}
	for {
		var request struct {
			Execute string `json:"execute"`
			ID      string `json:"id"`
		}
		if err := decoder.Decode(&request); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		if err := encoder.Encode(map[string]any{"return": map[string]any{}, "id": request.ID}); err != nil {
			return
		}
		if mode == "spontaneous-exit" && request.Execute == "qmp_capabilities" {
			go func() {
				time.Sleep(150 * time.Millisecond)
				os.Exit(0)
			}()
		}
		if mode == "qmp-disconnect-stays" && request.Execute == "qmp_capabilities" {
			_ = connection.Close()
			for {
				time.Sleep(time.Second)
			}
		}
		if request.Execute == "system_powerdown" {
			if mode == "powerdown-exits" {
				return
			}
			for {
				time.Sleep(time.Second)
			}
		}
	}
}

func TestImmediateExitHelper(t *testing.T) {}

func TestNoQMPHelper(t *testing.T) {
	if len(os.Args) > 1 && os.Args[len(os.Args)-1] == "no-qmp" {
		time.Sleep(10 * time.Second)
	}
}

func fakeQEMUCommand(mode string) func(Spec, *os.File) (*exec.Cmd, error) {
	return func(spec Spec, _ *os.File) (*exec.Cmd, error) {
		return exec.Command(os.Args[0], "-test.run=TestQEMUHelperProcess", "--", mode, spec.QMPSocket, spec.SPICESocket), nil
	}
}

func testBinary(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	return path
}

type fakeCgroupFactory struct {
	cleaned atomic.Bool
}

func (f *fakeCgroupFactory) Place(_ context.Context, sessionID string, pid int, _ CgroupLimits) (CgroupHandle, error) {
	if sessionID == "" || pid <= 1 {
		return nil, errors.New("invalid fake cgroup request")
	}
	return &fakeCgroup{path: filepath.Join("/fake", sessionID), cleaned: &f.cleaned}, nil
}

type fakeCgroup struct {
	path    string
	cleaned *atomic.Bool
}

func (f *fakeCgroup) Path() string { return f.path }

func (f *fakeCgroup) Cleanup(context.Context) error {
	f.cleaned.Store(true)
	return nil
}
