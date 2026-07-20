//go:build linux

package torrent

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	qbitQuarantineMount = "/mnt/quarantine"
	qbitStopTimeout     = 10 * time.Second
)

type processCommandFactory func() *exec.Cmd

// qbittorrentProcessManager keeps qBittorrent in guestd's systemd-created
// mount namespace. That is required because guestd mounts the verified virtio
// quarantine after startup; a second systemd service receives a different
// mount namespace and cannot safely observe that mount. The child inherits
// guestd's no-new-privileges, seccomp, filesystem and capability restrictions,
// then drops to the fixed private user before exec.
type qbittorrentProcessManager struct {
	mu       sync.Mutex
	factory  processCommandFactory
	active   *qbittorrentProcess
	stopWait time.Duration
}

type qbittorrentProcess struct {
	command *exec.Cmd
	done    chan struct{}
	pidfdMu sync.Mutex
	pidfd   int
}

func newQBittorrentProcessManager(path string, uid, gid int) (*qbittorrentProcessManager, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "qbittorrent" || uid <= 0 || gid <= 0 {
		return nil, invalidRequest()
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("fixed qBittorrent executable is unavailable or unsafe")
	}
	factory := func() *exec.Cmd {
		command := exec.Command(path, "--confirm-legal-notice", "--no-splash")
		command.Env = []string{
			"DISPLAY=:0",
			"HOME=/home/private",
			"LANG=C.UTF-8",
			"XAUTHORITY=/home/private/.Xauthority",
			"XDG_CACHE_HOME=" + qbitQuarantineMount + "/.qbit-cache",
			"XDG_CONFIG_HOME=" + qbitRuntimeRoot + "/config",
			"XDG_DATA_HOME=" + qbitQuarantineMount + "/.qbit-data",
		}
		command.Dir = qbitQuarantineMount
		command.Stdin = nil
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		command.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true},
			Pdeathsig:  syscall.SIGKILL,
			Setpgid:    true,
		}
		return command
	}
	return newQBittorrentProcessManagerWithFactory(factory, qbitStopTimeout)
}

func newQBittorrentProcessManagerWithFactory(factory processCommandFactory, stopWait time.Duration) (*qbittorrentProcessManager, error) {
	if factory == nil || stopWait <= 0 {
		return nil, invalidRequest()
	}
	return &qbittorrentProcessManager{factory: factory, stopWait: stopWait}, nil
}

func (manager *qbittorrentProcessManager) Start(ctx context.Context) error {
	if manager == nil || ctx == nil {
		return invalidRequest()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.active != nil {
		select {
		case <-manager.active.done:
			manager.active.closePidfd()
			manager.active = nil
		default:
			return nil
		}
	}
	command := manager.factory()
	if command == nil || command.Path == "" {
		return errors.New("fixed qBittorrent process configuration is unavailable")
	}
	if err := command.Start(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("fixed qBittorrent process failed to start")
	}
	process := &qbittorrentProcess{command: command, pidfd: -1, done: make(chan struct{})}
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
		return errors.New("fixed qBittorrent process ownership is unavailable")
	}
	process.pidfd = pidfd
	manager.active = process
	go process.waitOwner()
	return nil
}

func (manager *qbittorrentProcessManager) Stop(ctx context.Context) error {
	if manager == nil || ctx == nil {
		return invalidRequest()
	}
	manager.mu.Lock()
	process := manager.active
	manager.mu.Unlock()
	if process == nil {
		return nil
	}
	if process.exited() {
		manager.release(process)
		return nil
	}
	termErr := process.signal(syscall.SIGTERM)
	graceCtx, cancel := context.WithTimeout(ctx, manager.stopWait)
	graceful := process.wait(graceCtx)
	cancel()
	if graceful {
		manager.release(process)
		if termErr != nil && !errors.Is(termErr, unix.ESRCH) {
			return errors.New("fixed qBittorrent process stop failed")
		}
		return nil
	}
	callerErr := ctx.Err()
	killErr := process.signal(syscall.SIGKILL)
	killCtx, killCancel := context.WithTimeout(context.Background(), 5*time.Second)
	killed := process.wait(killCtx)
	killCancel()
	if killed {
		manager.release(process)
	}
	if callerErr != nil {
		return callerErr
	}
	if !killed || (killErr != nil && !errors.Is(killErr, unix.ESRCH)) {
		return errors.New("fixed qBittorrent process cleanup failed")
	}
	return nil
}

func (manager *qbittorrentProcessManager) release(process *qbittorrentProcess) {
	process.closePidfd()
	manager.mu.Lock()
	if manager.active == process {
		manager.active = nil
	}
	manager.mu.Unlock()
}

func (process *qbittorrentProcess) waitOwner() {
	_ = process.command.Wait()
	close(process.done)
}

func (process *qbittorrentProcess) signal(signal syscall.Signal) error {
	if process == nil {
		return os.ErrProcessDone
	}
	process.pidfdMu.Lock()
	defer process.pidfdMu.Unlock()
	if process.pidfd < 0 {
		return os.ErrProcessDone
	}
	if err := unix.PidfdSendSignal(process.pidfd, signal, nil, 0); err != nil {
		return err
	}
	// The leader is still owned by pidfd, so its process-group identity cannot
	// have been reused. Signal any fixed-program descendants in the same group.
	if err := unix.Kill(-process.command.Process.Pid, signal); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}

func (process *qbittorrentProcess) exited() bool {
	select {
	case <-process.done:
		return true
	default:
		return false
	}
}

func (process *qbittorrentProcess) wait(ctx context.Context) bool {
	select {
	case <-process.done:
		return true
	case <-ctx.Done():
		return false
	}
}

func (process *qbittorrentProcess) closePidfd() {
	process.pidfdMu.Lock()
	defer process.pidfdMu.Unlock()
	if process.pidfd >= 0 {
		_ = unix.Close(process.pidfd)
		process.pidfd = -1
	}
}

var _ localServiceManager = (*qbittorrentProcessManager)(nil)
