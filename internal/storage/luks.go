package storage

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

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

const (
	noBackupMarkerName    = ".private-vm-no-backup"
	noBackupMarkerContent = "private-vm-ephemeral-scratch-v1"
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
	Inspector   DeviceInspector
	CleanupWait time.Duration
}

type LUKSHandle struct {
	mu             sync.Mutex
	manager        *LUKSManager
	sessionID      string
	ciphertext     string
	cipherIdentity imageFileIdentity
	scratchParent  pathIdentity
	loop           string
	mapping        string
	mount          string
	underlay       pathIdentity
	mountedAt      pathIdentity
	mountParent    pathIdentity
	key            *secret.Bytes
	mounted        bool
	opened         bool
	attached       bool
	destroyed      bool
}

func (m *LUKSManager) Create(ctx context.Context, sessionID string, sizeBytes uint64) (created *LUKSHandle, returnErr error) {
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
	mountParent, err := inspectPrivateDirectoryIdentity(filepath.Dir(mountPath))
	if err != nil {
		return nil, err
	}
	scratchParent, err := inspectPrivateDirectoryIdentity(m.ScratchRoot)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(mountPath, 0o700); err != nil {
		return nil, fmt.Errorf("create outer session mountpoint: %w", err)
	}
	handle := &LUKSHandle{manager: m, sessionID: sessionID, ciphertext: ciphertext, mapping: sessionID, mount: mountPath, scratchParent: scratchParent, mountParent: mountParent}
	underlay, err := inspectPrivateDirectoryIdentity(mountPath)
	if err != nil {
		_ = os.Remove(mountPath)
		return nil, err
	}
	handle.underlay = underlay
	rollback := true
	defer func() {
		if rollback {
			wait := m.CleanupWait
			if wait <= 0 {
				wait = 30 * time.Second
			}
			cleanupCtx, cancel := context.WithTimeout(context.Background(), wait)
			if cleanupErr := handle.Destroy(cleanupCtx); cleanupErr != nil {
				created = handle
				returnErr = errors.Join(returnErr, fmt.Errorf("rollback encrypted scratch: %w", cleanupErr))
			}
			cancel()
		}
	}()
	file, err := os.OpenFile(ciphertext, os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create encrypted scratch ciphertext: %w", err)
	}
	if identity, identityErr := ownedFileIdentity(file, true); identityErr != nil {
		_ = file.Close()
		return nil, identityErr
	} else {
		handle.cipherIdentity = identity
	}
	if err := file.Truncate(int64(sizeBytes)); err != nil {
		if identity, identityErr := ownedFileIdentity(file, true); identityErr == nil {
			handle.cipherIdentity = identity
		}
		_ = file.Close()
		return nil, fmt.Errorf("size encrypted scratch ciphertext: %w", err)
	}
	if identity, identityErr := ownedFileIdentity(file, false); identityErr != nil {
		_ = file.Close()
		return nil, identityErr
	} else {
		handle.cipherIdentity = identity
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
	result, err := m.Runner.Run(ctx, Command{Path: m.Tools.Losetup, Args: []string{"--find", "--show", ciphertext}})
	if err != nil {
		return nil, err
	}
	handle.loop = strings.TrimSpace(string(result.Stdout))
	if !loopPattern.MatchString(handle.loop) {
		return nil, errors.New("losetup returned an invalid loop device")
	}
	handle.attached = true
	if err := m.Inspector.VerifyLoopBacking(handle.loop, ciphertext); err != nil {
		return nil, err
	}
	if err := m.cryptsetupWithKey(ctx, key, []string{"luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "argon2id", "--key-file", "/proc/self/fd/3", handle.loop}); err != nil {
		return nil, err
	}
	if err := m.cryptsetupWithKey(ctx, key, []string{"open", "--type", "luks2", "--key-file", "/proc/self/fd/3", handle.loop, handle.mapping}); err != nil {
		return nil, err
	}
	handle.opened = true
	if err := m.Inspector.VerifyMapperBacking(handle.mapping, handle.loop); err != nil {
		return nil, err
	}
	mapperPath := filepath.Join("/dev/mapper", handle.mapping)
	if _, err := m.Runner.Run(ctx, Command{Path: m.Tools.MkfsExt4, Args: []string{"-q", "-E", "lazy_itable_init=0,lazy_journal_init=0", mapperPath}}); err != nil {
		return nil, err
	}
	flags := uintptr(unix.MS_NODEV | unix.MS_NOSUID | unix.MS_NOEXEC)
	if err := m.Mounter.Mount(mapperPath, mountPath, "ext4", flags, "errors=remount-ro"); err != nil {
		return nil, fmt.Errorf("mount outer encrypted session filesystem: %w", err)
	}
	handle.mounted = true
	if err := os.Chmod(mountPath, 0o700); err != nil {
		return nil, errors.New("restrict outer encrypted filesystem root failed")
	}
	mountedAt, err := inspectPrivateDirectoryIdentity(mountPath)
	if err != nil {
		return nil, err
	}
	handle.mountedAt = mountedAt
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	rollback = false
	return handle, nil
}

func (m *LUKSManager) validate() error {
	if m.Runner == nil || m.Mounter == nil {
		return errors.New("storage runner and mounter are required")
	}
	if m.Inspector == nil {
		m.Inspector = SystemDeviceInspector{}
	}
	for label, path := range map[string]string{"scratch root": m.ScratchRoot, "runtime root": m.RuntimeRoot, "losetup": m.Tools.Losetup, "cryptsetup": m.Tools.Cryptsetup, "mkfs.ext4": m.Tools.MkfsExt4} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("%s must be a clean absolute path", label)
		}
	}
	if err := verifyPrivateDirectory(m.ScratchRoot); err != nil {
		return err
	}
	return verifyNoBackupMarker(m.ScratchRoot)
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
		current, err := inspectPrivateDirectoryIdentity(h.mount)
		if err != nil || !current.sameObject(h.mountedAt) {
			return errors.New("encrypted scratch mount identity changed before unmount")
		}
		if err := h.manager.Mounter.Unmount(h.mount, 0); err != nil {
			return fmt.Errorf("unmount outer encrypted session filesystem: %w", err)
		}
		h.mounted = false
		current, err = inspectPrivateDirectoryIdentity(h.mount)
		if err != nil || !current.sameObject(h.underlay) {
			return errors.New("encrypted scratch underlay identity changed after unmount")
		}
	}
	if h.opened {
		if err := h.manager.Inspector.VerifyMapperBacking(h.mapping, h.loop); err != nil {
			return err
		}
		if _, err := h.manager.Runner.Run(ctx, Command{Path: h.manager.Tools.Cryptsetup, Args: []string{"close", h.mapping}}); err != nil {
			return err
		}
		h.opened = false
	}
	if h.attached {
		if err := h.manager.Inspector.VerifyLoopBacking(h.loop, h.ciphertext); err != nil {
			return err
		}
		if _, err := h.manager.Runner.Run(ctx, Command{Path: h.manager.Tools.Losetup, Args: []string{"--detach", h.loop}}); err != nil {
			return err
		}
		h.attached = false
	}
	if h.key != nil {
		h.key.Destroy()
		h.key = nil
	}
	if err := removeOwnedImage(h.ciphertext, h.scratchParent, h.cipherIdentity); err != nil {
		return fmt.Errorf("remove encrypted scratch ciphertext: %w", err)
	}
	if err := removeOwnedDirectory(h.mount, h.mountParent, h.underlay); err != nil {
		return fmt.Errorf("remove outer session mountpoint: %w", err)
	}
	h.destroyed = true
	return nil
}

func ownedFileIdentity(file *os.File, allowEmpty bool) (imageFileIdentity, error) {
	if file == nil {
		return imageFileIdentity{}, errors.New("owned file descriptor is required")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return imageFileIdentity{}, errors.New("inspect owned file identity failed")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || (!allowEmpty && stat.Size <= 0) || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || stat.Gid != uint32(os.Getegid()) {
		return imageFileIdentity{}, errors.New("owned file type, mode, links, size, owner, or group is unsafe")
	}
	return imageFileIdentity{device: uint64(stat.Dev), inode: stat.Ino, size: stat.Size, uid: stat.Uid, gid: stat.Gid, mode: stat.Mode, links: stat.Nlink}, nil
}

func (h *LUKSHandle) Audit(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.destroyed || h.mounted || h.opened || h.attached || h.key != nil {
		return errors.New("encrypted scratch cleanup state is incomplete")
	}
	for _, path := range []string{h.ciphertext, h.mount} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("encrypted scratch resource remains present")
		}
	}
	mapperExists, err := h.manager.Inspector.MapperExists(h.mapping)
	if err != nil || mapperExists {
		return errors.New("encrypted scratch mapper state could not be proven absent")
	}
	if loopPattern.MatchString(h.loop) {
		attached, err := h.manager.Inspector.LoopStillBacks(h.loop, h.ciphertext)
		if err != nil {
			return errors.New("encrypted scratch loop state could not be audited")
		}
		if attached {
			return errors.New("encrypted scratch loop device remains attached")
		}
	}
	return nil
}

func verifyNoBackupMarker(root string) error {
	rootFD, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return fmt.Errorf("open scratch directory for backup-exclusion evidence: %w", err)
	}
	defer unix.Close(rootFD)
	markerFD, err := unix.Openat2(rootFD, noBackupMarkerName, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return fmt.Errorf("open scratch backup-exclusion marker: %w", err)
	}
	file := os.NewFile(uintptr(markerFD), "private-vm-backup-exclusion-marker")
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect scratch backup-exclusion marker: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != int64(len(noBackupMarkerContent)) {
		return errors.New("scratch backup-exclusion marker must be a mode-0600 regular file")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Nlink != 1 {
		return errors.New("scratch backup-exclusion marker ownership is invalid")
	}
	data := make([]byte, len(noBackupMarkerContent))
	if _, err := io.ReadFull(file, data); err != nil {
		return fmt.Errorf("read scratch backup-exclusion marker: %w", err)
	}
	if string(data) != noBackupMarkerContent {
		return errors.New("scratch backup-exclusion marker content is invalid")
	}
	return nil
}

func verifyPrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("private storage directory must be a narrow absolute path")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return fmt.Errorf("open private storage directory safely: %w", err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect private storage directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o777 != 0o700 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("private storage directory must be daemon-owned with exact mode 0700")
	}
	return nil
}
