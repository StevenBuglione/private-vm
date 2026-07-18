package qemu

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
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

func TestQEMUHelperProcess(t *testing.T) {
	if len(os.Args) < 3 {
		return
	}
	mode := os.Args[len(os.Args)-2]
	socket := os.Args[len(os.Args)-1]
	if mode != "powerdown-exits" && mode != "powerdown-stays" {
		return
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
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

func fakeQEMUCommand(mode string) func(Spec, *os.File) (*exec.Cmd, error) {
	return func(spec Spec, _ *os.File) (*exec.Cmd, error) {
		return exec.Command(os.Args[0], "-test.run=TestQEMUHelperProcess", "--", mode, spec.QMPSocket), nil
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
