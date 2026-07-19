package orchestrator

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/StevenBuglione/private-vm/internal/session"
	"golang.org/x/sys/unix"
)

const displayProxyStopTimeout = 5 * time.Second

// DisplaySocketPath is the fixed, non-secret local handoff derived only from a
// validated opaque session ID. The daemon creates this socket; callers cannot
// select another source or destination path.
func DisplaySocketPath(runtimeRoot, sessionID string) (string, error) {
	if !filepath.IsAbs(runtimeRoot) || filepath.Clean(runtimeRoot) != runtimeRoot || runtimeRoot == "/" || session.ValidateID(sessionID) != nil {
		return "", ErrHostRuntimeUnavailable
	}
	return filepath.Join(runtimeRoot, "display", sessionID+".sock"), nil
}

type displayProxy struct {
	mu          sync.Mutex
	listener    *net.UnixListener
	source      string
	target      string
	ownerUID    uint32
	dev         uint64
	ino         uint64
	cancel      context.CancelFunc
	done        chan struct{}
	active      map[*net.UnixConn]struct{}
	relayActive bool
	stopped     bool
	stopOnce    sync.Once
	stopErr     error
}

func startDisplayProxy(runtimeRoot, sessionID string, ownerUID uint32, source string) (*displayProxy, error) {
	if err := validatePrivateSPICESocket(source); err != nil {
		return nil, err
	}
	target, err := DisplaySocketPath(runtimeRoot, sessionID)
	if err != nil {
		return nil, err
	}
	directory := filepath.Dir(target)
	if err := ensureDisplayDirectory(directory); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return nil, ErrHostRuntimeUnavailable
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: target, Net: "unix"})
	if err != nil {
		return nil, ErrHostRuntimeUnavailable
	}
	listener.SetUnlinkOnClose(false)
	fail := func() (*displayProxy, error) {
		_ = listener.Close()
		_ = os.Remove(target)
		return nil, ErrHostRuntimeUnavailable
	}
	before, err := os.Lstat(target)
	if err != nil || before.Mode()&os.ModeSocket == 0 {
		return fail()
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || beforeStat.Uid != uint32(os.Geteuid()) || beforeStat.Gid != uint32(os.Getegid()) {
		return fail()
	}
	if err := os.Chown(target, int(ownerUID), -1); err != nil {
		return fail()
	}
	if err := os.Chmod(target, 0o600); err != nil {
		return fail()
	}
	after, err := os.Lstat(target)
	if err != nil || after.Mode()&os.ModeSocket == 0 || after.Mode().Perm() != 0o600 {
		return fail()
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || afterStat.Uid != ownerUID || afterStat.Gid != beforeStat.Gid || afterStat.Dev != beforeStat.Dev || afterStat.Ino != beforeStat.Ino {
		return fail()
	}
	ctx, cancel := context.WithCancel(context.Background())
	proxy := &displayProxy{
		listener: listener, source: source, target: target, ownerUID: ownerUID,
		dev: uint64(afterStat.Dev), ino: afterStat.Ino, cancel: cancel,
		done: make(chan struct{}), active: make(map[*net.UnixConn]struct{}),
	}
	go proxy.serve(ctx)
	return proxy, nil
}

func (proxy *displayProxy) serve(ctx context.Context) {
	var relays sync.WaitGroup
	defer func() {
		relays.Wait()
		close(proxy.done)
	}()
	for {
		client, err := proxy.listener.AcceptUnix()
		if err != nil {
			return
		}
		if ctx.Err() != nil || peerUnixUID(client) != proxy.ownerUID || !proxy.claimClient(client) {
			_ = client.Close()
			continue
		}
		source, err := dialPrivateSPICE(ctx, proxy.source)
		if err != nil {
			proxy.releaseClient(client, nil)
			_ = client.Close()
			continue
		}
		proxy.trackSource(source)
		relays.Add(1)
		go func() {
			defer relays.Done()
			proxy.relay(client, source)
			proxy.releaseClient(client, source)
		}()
	}
}

func (proxy *displayProxy) relay(left, right *net.UnixConn) {
	var wait sync.WaitGroup
	wait.Add(2)
	copyOne := func(destination, source *net.UnixConn) {
		defer wait.Done()
		buffer := make([]byte, 64<<10)
		_, _ = io.CopyBuffer(destination, source, buffer)
		clear(buffer)
		_ = destination.Close()
		_ = source.Close()
	}
	go copyOne(left, right)
	go copyOne(right, left)
	wait.Wait()
}

func (proxy *displayProxy) claimClient(connection *net.UnixConn) bool {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if proxy.stopped || proxy.relayActive {
		return false
	}
	proxy.relayActive = true
	proxy.active[connection] = struct{}{}
	return true
}

func (proxy *displayProxy) trackSource(connection *net.UnixConn) {
	proxy.mu.Lock()
	proxy.active[connection] = struct{}{}
	proxy.mu.Unlock()
}

func (proxy *displayProxy) releaseClient(client, source *net.UnixConn) {
	proxy.mu.Lock()
	delete(proxy.active, client)
	if source != nil {
		delete(proxy.active, source)
	}
	proxy.relayActive = false
	proxy.mu.Unlock()
}

func (proxy *displayProxy) Stop() error {
	if proxy == nil {
		return nil
	}
	proxy.stopOnce.Do(func() { proxy.stopErr = proxy.stop() })
	return proxy.stopErr
}

func (proxy *displayProxy) stop() error {
	proxy.mu.Lock()
	proxy.stopped = true
	proxy.cancel()
	_ = proxy.listener.Close()
	for connection := range proxy.active {
		_ = connection.Close()
	}
	proxy.mu.Unlock()
	timer := time.NewTimer(displayProxyStopTimeout)
	defer timer.Stop()
	select {
	case <-proxy.done:
	case <-timer.C:
		return ErrHostRuntimeUnavailable
	}
	if err := removeOwnedDisplaySocket(proxy.target, proxy.ownerUID, proxy.dev, proxy.ino); err != nil {
		return err
	}
	return nil
}

func (proxy *displayProxy) Audit() error {
	if proxy == nil {
		return nil
	}
	proxy.mu.Lock()
	stopped := proxy.stopped
	active := len(proxy.active)
	relayActive := proxy.relayActive
	proxy.mu.Unlock()
	if !stopped || active != 0 || relayActive {
		return ErrHostRuntimeUnavailable
	}
	if _, err := os.Lstat(proxy.target); !errors.Is(err, os.ErrNotExist) {
		return ErrHostRuntimeUnavailable
	}
	return nil
}

func ensureDisplayDirectory(path string) error {
	if err := os.Mkdir(path, 0o711); err != nil && !errors.Is(err, os.ErrExist) {
		return ErrHostRuntimeUnavailable
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o711 {
		return ErrHostRuntimeUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return ErrHostRuntimeUnavailable
	}
	return nil
}

func validatePrivateSPICESocket(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrHostRuntimeUnavailable
	}
	parent, err := inspectRuntimeDirectory(filepath.Dir(path))
	if err != nil || parent.path == "" {
		return ErrHostRuntimeUnavailable
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return ErrHostRuntimeUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return ErrHostRuntimeUnavailable
	}
	return nil
}

func dialPrivateSPICE(ctx context.Context, path string) (*net.UnixConn, error) {
	if err := validatePrivateSPICESocket(path); err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, ErrHostRuntimeUnavailable
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, ErrHostRuntimeUnavailable
	}
	return unixConnection, nil
}

func peerUnixUID(connection *net.UnixConn) uint32 {
	if connection == nil {
		return ^uint32(0)
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return ^uint32(0)
	}
	uid := ^uint32(0)
	if err := raw.Control(func(fd uintptr) {
		credential, credentialErr := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credentialErr == nil {
			uid = credential.Uid
		}
	}); err != nil {
		return ^uint32(0)
	}
	return uid
}

func removeOwnedDisplaySocket(path string, ownerUID uint32, dev, ino uint64) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return ErrHostRuntimeUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || uint64(stat.Dev) != dev || stat.Ino != ino {
		return ErrHostRuntimeUnavailable
	}
	if err := os.Remove(path); err != nil {
		return ErrHostRuntimeUnavailable
	}
	return nil
}
