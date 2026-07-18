package qemu

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type ProcessIdentity struct {
	PID             int
	StartTimeTicks  uint64
	ExecutableDev   uint64
	ExecutableInode uint64
	CgroupPath      string
}

type Launcher struct {
	cgroups        CgroupFactory
	qmpLimit       int
	qmpWait        time.Duration
	graceWait      time.Duration
	termWait       time.Duration
	commandBuilder func(Spec, *os.File) (*exec.Cmd, error)
}

func NewLauncher(cgroups CgroupFactory) (*Launcher, error) {
	if cgroups == nil {
		return nil, errors.New("QEMU cgroup factory is required")
	}
	return &Launcher{
		cgroups: cgroups, qmpLimit: DefaultQMPFrameLimit,
		qmpWait: 10 * time.Second, graceWait: 5 * time.Second, termWait: 3 * time.Second,
	}, nil
}

type Process struct {
	command  *exec.Cmd
	identity ProcessIdentity
	pidfdMu  sync.Mutex
	pidfd    int
	cgroup   CgroupHandle
	qmpMu    sync.Mutex
	qmp      *QMPClient

	waitDone     chan struct{}
	waitMu       sync.RWMutex
	waitErr      error
	stopMu       sync.Mutex
	expectedStop atomic.Bool
	graceWait    time.Duration
	termWait     time.Duration
}

func (l *Launcher) Launch(ctx context.Context, spec Spec, capability *os.File) (*Process, error) {
	if capability == nil {
		return nil, errors.New("inherited fw_cfg capability file is required")
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if spec.FWCfgTokenFD != 3 {
		return nil, errors.New("fw_cfg capability must be the first inherited descriptor")
	}
	builder := l.commandBuilder
	if builder == nil {
		builder = productionCommand
	}
	command, err := builder(spec, capability)
	if err != nil {
		return nil, err
	}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.Setpgid = true
	command.SysProcAttr.Pdeathsig = syscall.SIGKILL
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start QEMU: %w", err)
	}
	process := &Process{
		command: command, pidfd: -1, waitDone: make(chan struct{}),
		graceWait: l.graceWait, termWait: l.termWait,
	}
	rollback := true
	waitStarted := false
	defer func() {
		if rollback {
			_ = command.Process.Kill()
			if waitStarted {
				_ = process.Wait(context.Background())
			} else {
				_, _ = command.Process.Wait()
			}
		}
	}()
	identity, err := inspectProcessIdentity(command.Process.Pid, spec.Binary)
	if err != nil {
		return nil, err
	}
	process.identity = identity
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		return nil, fmt.Errorf("open QEMU pidfd: %w", err)
	}
	process.pidfd = pidfd
	handle, err := l.cgroups.Place(ctx, spec.SessionID, command.Process.Pid, CgroupLimits{MemoryBytes: spec.MemoryBytes, VCPUs: spec.CPUs, PIDs: 256})
	if err != nil {
		_ = unix.Close(pidfd)
		return nil, err
	}
	process.cgroup = handle
	process.identity.CgroupPath = handle.Path()
	go process.waitOwner()
	waitStarted = true
	qmpContext, cancel := context.WithTimeout(ctx, l.qmpWait)
	defer cancel()
	qmp, err := waitForQMP(qmpContext, spec.QMPSocket, l.qmpLimit, process.waitDone)
	if err != nil {
		process.expectedStop.Store(true)
		return nil, err
	}
	process.qmpMu.Lock()
	process.qmp = qmp
	alreadyExited := exited(process.waitDone)
	if alreadyExited {
		process.qmp = nil
	}
	process.qmpMu.Unlock()
	if alreadyExited {
		_ = qmp.Close()
		process.expectedStop.Store(true)
		return nil, errors.New("QEMU exited during QMP startup")
	}
	rollback = false
	return process, nil
}

func productionCommand(spec Spec, capability *os.File) (*exec.Cmd, error) {
	args, err := spec.Args()
	if err != nil {
		return nil, err
	}
	command := exec.Command(spec.Binary, args...)
	command.Env = []string{"LANG=C.UTF-8"}
	command.ExtraFiles = []*os.File{capability}
	return command, nil
}

func (p *Process) PID() int { return p.identity.PID }

func (p *Process) Identity() ProcessIdentity { return p.identity }

func (p *Process) Wait(ctx context.Context) error {
	select {
	case <-p.waitDone:
		p.waitMu.RLock()
		defer p.waitMu.RUnlock()
		return p.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Process) Stop(ctx context.Context) error {
	p.stopMu.Lock()
	defer p.stopMu.Unlock()
	p.expectedStop.Store(true)
	if exited(p.waitDone) {
		return p.Wait(context.Background())
	}
	graceContext, graceCancel := boundedChildContext(ctx, 5*time.Second)
	p.qmpMu.Lock()
	qmp := p.qmp
	p.qmpMu.Unlock()
	if qmp != nil {
		_ = qmp.Powerdown(graceContext)
	}
	graceCancel()
	if waitForDone(ctx, p.waitDone, p.graceWait) {
		return p.Wait(context.Background())
	}
	if err := p.signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	if waitForDone(ctx, p.waitDone, p.termWait) {
		return p.Wait(context.Background())
	}
	if err := p.signal(syscall.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return p.Wait(ctx)
}

func (p *Process) signal(signal syscall.Signal) error {
	p.pidfdMu.Lock()
	if p.pidfd >= 0 {
		if err := unix.PidfdSendSignal(p.pidfd, signal, nil, 0); err == nil || errors.Is(err, unix.ESRCH) {
			p.pidfdMu.Unlock()
			return nil
		}
	}
	p.pidfdMu.Unlock()
	if err := verifyProcessIdentity(p.identity); err != nil {
		return err
	}
	return p.command.Process.Signal(signal)
}

func (p *Process) waitOwner() {
	err := p.command.Wait()
	if p.expectedStop.Load() {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			err = nil
		}
	}
	p.qmpMu.Lock()
	if p.qmp != nil {
		_ = p.qmp.Close()
		p.qmp = nil
	}
	p.qmpMu.Unlock()
	p.pidfdMu.Lock()
	if p.pidfd >= 0 {
		_ = unix.Close(p.pidfd)
		p.pidfd = -1
	}
	p.pidfdMu.Unlock()
	if p.cgroup != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cleanupErr := p.cgroup.Cleanup(ctx)
		cancel()
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}
	p.waitMu.Lock()
	p.waitErr = err
	p.waitMu.Unlock()
	close(p.waitDone)
}

func inspectProcessIdentity(pid int, expectedBinary string) (ProcessIdentity, error) {
	start, err := processStartTime(pid)
	if err != nil {
		return ProcessIdentity{}, err
	}
	info, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("inspect QEMU executable identity: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ProcessIdentity{}, errors.New("QEMU executable identity is unavailable")
	}
	expected, err := os.Stat(expectedBinary)
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("inspect expected QEMU binary: %w", err)
	}
	expectedStat, ok := expected.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev != expectedStat.Dev || stat.Ino != expectedStat.Ino {
		return ProcessIdentity{}, errors.New("started process executable does not match verified QEMU binary")
	}
	return ProcessIdentity{PID: pid, StartTimeTicks: start, ExecutableDev: uint64(stat.Dev), ExecutableInode: stat.Ino}, nil
}

func verifyProcessIdentity(identity ProcessIdentity) error {
	start, err := processStartTime(identity.PID)
	if err != nil {
		return err
	}
	if start != identity.StartTimeTicks {
		return errors.New("refusing to signal a reused process ID")
	}
	info, err := os.Stat("/proc/" + strconv.Itoa(identity.PID) + "/exe")
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != identity.ExecutableDev || stat.Ino != identity.ExecutableInode {
		return errors.New("refusing to signal a process with changed executable identity")
	}
	return nil
}

func processStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, fmt.Errorf("read process start time: %w", err)
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return 0, errors.New("process stat record is malformed")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return 0, errors.New("process stat record is incomplete")
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, errors.New("process start time is invalid")
	}
	return value, nil
}

func waitForQMP(ctx context.Context, path string, limit int, exited <-chan struct{}) (*QMPClient, error) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		client, err := DialQMP(ctx, path, limit)
		if err == nil {
			return client, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("QMP startup timeout: %w", ctx.Err())
		case <-exited:
			return nil, errors.New("QEMU exited before QMP became ready")
		case <-ticker.C:
		}
	}
}

func boundedChildContext(parent context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(duration)
	if current, ok := parent.Deadline(); ok && current.Before(deadline) {
		return context.WithCancel(parent)
	}
	return context.WithDeadline(parent, deadline)
}

func waitForDone(ctx context.Context, done <-chan struct{}, maximum time.Duration) bool {
	timer := time.NewTimer(maximum)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	}
}

func exited(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}
