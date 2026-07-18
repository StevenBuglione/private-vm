package storage

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/StevenBuglione/private-vm/internal/secret"
	"golang.org/x/sys/unix"
)

var (
	storageSessionPattern = regexp.MustCompile(`^pvm-[a-f0-9]{32}$`)
	loopPattern           = regexp.MustCompile(`^/dev/loop[0-9]+$`)
	opaqueNames           = map[string]bool{
		"root-workstation.qcow2": true, "root-downloader.qcow2": true,
		"root-scanner.qcow2": true, "root-exporter.qcow2": true,
		"quarantine.raw": true, "uefi-vars.fd": true,
	}
)

type Tools struct {
	Losetup    string
	Cryptsetup string
	MkfsExt4   string
}

type Mounter interface {
	Mount(source, target, filesystem string, flags uintptr, data string) error
	Unmount(target string, flags int) error
}

type UnixMounter struct{}

func (UnixMounter) Mount(source, target, filesystem string, flags uintptr, data string) error {
	return unix.Mount(source, target, filesystem, flags, data)
}

func (UnixMounter) Unmount(target string, flags int) error { return unix.Unmount(target, flags) }

type LUKSManager struct {
	ScratchRoot string
	RuntimeRoot string
	Tools       Tools
	Runner      Runner
	Mounter     Mounter
}

type LUKSHandle struct {
	mu         sync.Mutex
	manager    *LUKSManager
	sessionID  string
	ciphertext string
	loop       string
	mapping    string
	mount      string
	key        *secret.Bytes
	mounted    bool
	opened     bool
	attached   bool
	destroyed  bool
}

func (m *LUKSManager) Create(ctx context.Context, sessionID string, sizeBytes uint64) (*LUKSHandle, error) {
	if !storageSessionPattern.MatchString(sessionID) {
		return nil, errors.New("invalid internal storage session ID")
	}
	if sizeBytes < 1<<30 || sizeBytes > 16<<40 {
		return nil, errors.New("encrypted scratch size must be between 1 GiB and 16 TiB")
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	ciphertext := filepath.Join(m.ScratchRoot, sessionID+".luks")
	mountPath := filepath.Join(m.RuntimeRoot, sessionID, "mount")
	if err := verifyPrivateDirectory(filepath.Dir(mountPath)); err != nil {
		return nil, err
	}
	if err := os.Mkdir(mountPath, 0o700); err != nil {
		return nil, fmt.Errorf("create outer session mountpoint: %w", err)
	}
	handle := &LUKSHandle{manager: m, sessionID: sessionID, ciphertext: ciphertext, mapping: "pvm-" + strings.TrimPrefix(sessionID, "pvm-")[:16], mount: mountPath}
	rollback := true
	defer func() {
		if rollback {
			_ = handle.Destroy(context.Background())
		}
	}()
	file, err := os.OpenFile(ciphertext, os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create encrypted scratch ciphertext: %w", err)
	}
	if err := file.Truncate(int64(sizeBytes)); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("size encrypted scratch ciphertext: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close encrypted scratch ciphertext: %w", err)
	}
	keyBytes := make([]byte, 64)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("generate encrypted scratch key: %w", err)
	}
	key, err := secret.New(keyBytes)
	clear(keyBytes)
	if err != nil {
		return nil, err
	}
	handle.key = key
	result, err := m.Runner.Run(ctx, Command{Path: m.Tools.Losetup, Args: []string{"--find"}})
	if err != nil {
		return nil, err
	}
	handle.loop = strings.TrimSpace(string(result.Stdout))
	if !loopPattern.MatchString(handle.loop) {
		return nil, errors.New("losetup returned an invalid loop device")
	}
	if _, err := m.Runner.Run(ctx, Command{Path: m.Tools.Losetup, Args: []string{handle.loop, ciphertext}}); err != nil {
		return nil, err
	}
	handle.attached = true
	if err := m.cryptsetupWithKey(ctx, key, []string{"luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "argon2id", "--key-file", "/proc/self/fd/3", handle.loop}); err != nil {
		return nil, err
	}
	if err := m.cryptsetupWithKey(ctx, key, []string{"open", "--type", "luks2", "--key-file", "/proc/self/fd/3", handle.loop, handle.mapping}); err != nil {
		return nil, err
	}
	handle.opened = true
	mapperPath := filepath.Join("/dev/mapper", handle.mapping)
	if _, err := m.Runner.Run(ctx, Command{Path: m.Tools.MkfsExt4, Args: []string{"-q", "-E", "lazy_itable_init=0,lazy_journal_init=0", mapperPath}}); err != nil {
		return nil, err
	}
	flags := uintptr(unix.MS_NODEV | unix.MS_NOSUID | unix.MS_NOEXEC)
	if err := m.Mounter.Mount(mapperPath, mountPath, "ext4", flags, "errors=remount-ro"); err != nil {
		return nil, fmt.Errorf("mount outer encrypted session filesystem: %w", err)
	}
	handle.mounted = true
	rollback = false
	return handle, nil
}

func (m *LUKSManager) validate() error {
	if m.Runner == nil || m.Mounter == nil {
		return errors.New("storage runner and mounter are required")
	}
	for label, path := range map[string]string{"scratch root": m.ScratchRoot, "runtime root": m.RuntimeRoot, "losetup": m.Tools.Losetup, "cryptsetup": m.Tools.Cryptsetup, "mkfs.ext4": m.Tools.MkfsExt4} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("%s must be a clean absolute path", label)
		}
	}
	return verifyPrivateDirectory(m.ScratchRoot)
}

func (m *LUKSManager) cryptsetupWithKey(ctx context.Context, key *secret.Bytes, args []string) error {
	file, err := key.DupFile()
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = m.Runner.Run(ctx, Command{Path: m.Tools.Cryptsetup, Args: args, ExtraFiles: []*os.File{file}})
	return err
}

func (h *LUKSHandle) OuterPath() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mount
}

func (h *LUKSHandle) CreateOpaqueFile(name string, sizeBytes uint64) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.destroyed || !h.mounted {
		return "", errors.New("encrypted scratch is not mounted")
	}
	if !opaqueNames[name] || sizeBytes == 0 || sizeBytes > 16<<40 {
		return "", errors.New("invalid opaque session file request")
	}
	path := filepath.Join(h.mount, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", fmt.Errorf("create opaque session file: %w", err)
	}
	defer file.Close()
	if err := file.Truncate(int64(sizeBytes)); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("size opaque session file: %w", err)
	}
	return path, nil
}

func (h *LUKSHandle) Destroy(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.destroyed {
		return nil
	}
	if h.mounted {
		if err := h.manager.Mounter.Unmount(h.mount, 0); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("unmount outer encrypted session filesystem: %w", err)
		}
		h.mounted = false
	}
	if h.opened {
		if _, err := h.manager.Runner.Run(ctx, Command{Path: h.manager.Tools.Cryptsetup, Args: []string{"close", h.mapping}}); err != nil {
			return err
		}
		h.opened = false
	}
	if h.attached {
		if _, err := h.manager.Runner.Run(ctx, Command{Path: h.manager.Tools.Losetup, Args: []string{"--detach", h.loop}}); err != nil {
			return err
		}
		h.attached = false
	}
	if h.key != nil {
		h.key.Destroy()
		h.key = nil
	}
	if err := os.Remove(h.ciphertext); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove encrypted scratch ciphertext: %w", err)
	}
	if err := os.Remove(h.mount); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove outer session mountpoint: %w", err)
	}
	h.destroyed = true
	return nil
}

func verifyPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private storage directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("private storage directory must be a real directory with mode 0700")
	}
	return nil
}
