package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

type TmpfsManager struct {
	RuntimeRoot string
	Mounter     Mounter
}

type TmpfsHandle struct {
	mu        sync.Mutex
	manager   *TmpfsManager
	mount     string
	mounted   bool
	destroyed bool
}

func (m *TmpfsManager) Create(ctx context.Context, sessionID string, capacityBytes uint64) (*TmpfsHandle, error) {
	if m.Mounter == nil || !filepath.IsAbs(m.RuntimeRoot) || filepath.Clean(m.RuntimeRoot) != m.RuntimeRoot {
		return nil, errors.New("tmpfs manager requires an absolute runtime root and mounter")
	}
	if !storageSessionPattern.MatchString(sessionID) || capacityBytes < 256<<20 || capacityBytes > 1<<40 {
		return nil, errors.New("invalid tmpfs scratch request")
	}
	sessionPath := filepath.Join(m.RuntimeRoot, sessionID)
	if err := verifyPrivateDirectory(sessionPath); err != nil {
		return nil, err
	}
	mountPath := filepath.Join(sessionPath, "mount")
	if err := os.Mkdir(mountPath, 0o700); err != nil {
		return nil, fmt.Errorf("create tmpfs scratch mountpoint: %w", err)
	}
	select {
	case <-ctx.Done():
		_ = os.Remove(mountPath)
		return nil, ctx.Err()
	default:
	}
	flags := uintptr(unix.MS_NODEV | unix.MS_NOSUID | unix.MS_NOEXEC)
	data := "size=" + strconv.FormatUint(capacityBytes, 10) + ",mode=0700"
	if err := m.Mounter.Mount("private-vm-"+sessionID, mountPath, "tmpfs", flags, data); err != nil {
		_ = os.Remove(mountPath)
		return nil, fmt.Errorf("mount bounded tmpfs scratch: %w", err)
	}
	return &TmpfsHandle{manager: m, mount: mountPath, mounted: true}, nil
}

func (h *TmpfsHandle) OuterPath() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mount
}

func (h *TmpfsHandle) CreateOpaqueFile(name string, sizeBytes uint64) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.destroyed || !h.mounted {
		return "", errors.New("tmpfs scratch is not mounted")
	}
	if !opaqueNames[name] || sizeBytes == 0 || sizeBytes > 1<<40 {
		return "", errors.New("invalid opaque tmpfs file request")
	}
	path := filepath.Join(h.mount, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", fmt.Errorf("create opaque tmpfs file: %w", err)
	}
	defer file.Close()
	if err := file.Truncate(int64(sizeBytes)); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("size opaque tmpfs file: %w", err)
	}
	return path, nil
}

func (h *TmpfsHandle) Destroy(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.destroyed {
		return nil
	}
	if h.mounted {
		if err := h.manager.Mounter.Unmount(h.mount, 0); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("unmount tmpfs scratch: %w", err)
		}
		h.mounted = false
	}
	if err := os.Remove(h.mount); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove tmpfs scratch mountpoint: %w", err)
	}
	h.destroyed = true
	return nil
}
