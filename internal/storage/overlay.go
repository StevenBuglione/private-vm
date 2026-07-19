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
	"sync"

	"golang.org/x/sys/unix"
)

type OverlayManager struct {
	QEMUImg  string
	Runner   Runner
	Registry *ImageUseRegistry
}

type imageInfo struct {
	Format              string `json:"format"`
	VirtualSize         uint64 `json:"virtual-size"`
	BackingFilename     string `json:"backing-filename"`
	FullBackingFilename string `json:"full-backing-filename"`
}

type OverlayHandle struct {
	mu        sync.Mutex
	path      string
	basePath  string
	identity  imageFileIdentity
	parent    pathIdentity
	registry  *ImageUseRegistry
	destroyed bool
}

type imageFileIdentity struct {
	device uint64
	inode  uint64
	size   int64
	uid    uint32
	gid    uint32
	mode   uint32
	links  uint64
}

func (h *OverlayHandle) Path() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.path
}

func (h *OverlayHandle) Activate() (*ImageLease, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.destroyed {
		return nil, errors.New("destroyed root overlay cannot be activated")
	}
	if err := verifyImageIdentity(h.path, h.identity); err != nil {
		return nil, err
	}
	return h.registry.Activate(h.basePath, h.path)
}

func (h *OverlayHandle) Destroy(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.destroyed {
		return nil
	}
	if !h.registry.removable(h.path) {
		return errors.New("refusing to remove an active root overlay")
	}
	if err := removeOwnedImage(h.path, h.parent, h.identity); err != nil {
		return err
	}
	h.destroyed = true
	return nil
}

func (h *OverlayHandle) Audit(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.destroyed {
		return errors.New("root overlay cleanup has not completed")
	}
	if _, err := os.Lstat(h.path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("root overlay remains present")
	}
	return nil
}

func (m OverlayManager) Create(ctx context.Context, outerDirectory, basePath, name string) (*OverlayHandle, error) {
	if m.Runner == nil || m.Registry == nil || !filepath.IsAbs(m.QEMUImg) || filepath.Clean(m.QEMUImg) != m.QEMUImg {
		return nil, errors.New("absolute qemu-img path, runner and image-use registry are required")
	}
	if !opaqueNames[name] || filepath.Ext(name) != ".qcow2" {
		return nil, errors.New("overlay name is not allowlisted")
	}
	if err := verifyPrivateDirectory(outerDirectory); err != nil {
		return nil, err
	}
	parentIdentity, err := inspectPrivateDirectoryIdentity(outerDirectory)
	if err != nil {
		return nil, err
	}
	baseIdentity, err := verifyReadOnlyBase(basePath)
	if err != nil {
		return nil, err
	}
	overlay := filepath.Join(outerDirectory, name)
	var handle *OverlayHandle
	err = m.Registry.withTool([]string{basePath, overlay}, func() (operationErr error) {
		if err := verifyImageIdentity(basePath, baseIdentity); err != nil {
			return err
		}
		baseInfo, err := m.info(ctx, basePath)
		if err != nil {
			return err
		}
		if baseInfo.Format != "qcow2" || baseInfo.VirtualSize == 0 || baseInfo.BackingFilename != "" || baseInfo.FullBackingFilename != "" {
			return errors.New("verified base image is not a standalone non-empty QCOW2 image")
		}
		if err := verifyImageIdentity(basePath, baseIdentity); err != nil {
			return err
		}
		if _, err := m.Runner.Run(ctx, Command{Path: m.QEMUImg, Args: []string{"create", "-f", "qcow2", "-F", "qcow2", "-b", basePath, overlay}}); err != nil {
			return err
		}
		overlayFile, overlayIdentity, err := openCreatedOverlay(overlay)
		if err != nil {
			return err
		}
		defer overlayFile.Close()
		remove := true
		defer func() {
			if remove {
				if cleanupErr := removeOwnedImage(overlay, parentIdentity, overlayIdentity); cleanupErr != nil {
					operationErr = errors.Join(operationErr, errors.New("rollback root overlay removal failed"))
				}
			}
		}()
		if err := overlayFile.Chmod(0o600); err != nil {
			return errors.New("restrict root overlay permissions failed")
		}
		overlayIdentity, err = imageIdentityFromFile(overlayFile, true)
		if err != nil {
			return err
		}
		createdInfo, err := m.info(ctx, overlay)
		if err != nil {
			return err
		}
		backing := createdInfo.FullBackingFilename
		if backing == "" {
			backing = createdInfo.BackingFilename
		}
		if createdInfo.Format != "qcow2" || createdInfo.VirtualSize != baseInfo.VirtualSize || filepath.Clean(backing) != basePath {
			return errors.New("created overlay does not reference the verified base exactly")
		}
		if err := verifyImageIdentity(basePath, baseIdentity); err != nil {
			return err
		}
		if err := verifyImageIdentity(overlay, overlayIdentity); err != nil {
			return err
		}
		handle = &OverlayHandle{path: overlay, basePath: basePath, identity: overlayIdentity, parent: parentIdentity, registry: m.Registry}
		remove = false
		return nil
	})
	if err != nil {
		return nil, err
	}
	return handle, nil
}

func (m OverlayManager) info(ctx context.Context, path string) (imageInfo, error) {
	result, err := m.Runner.Run(ctx, Command{Path: m.QEMUImg, Args: []string{"info", "--output=json", path}})
	if err != nil {
		return imageInfo{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(result.Stdout))
	decoder.DisallowUnknownFields()
	var value imageInfo
	if err := decoder.Decode(&value); err != nil {
		return imageInfo{}, errors.New("qemu-img returned malformed bounded JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return imageInfo{}, errors.New("qemu-img returned trailing JSON")
	}
	return value, nil
}

func verifyReadOnlyBase(path string) (imageFileIdentity, error) {
	return inspectImageFile(path, false)
}

func inspectImageFile(path string, writable bool) (imageFileIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return imageFileIdentity{}, errors.New("image path must be a clean absolute path")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return imageFileIdentity{}, fmt.Errorf("open verified image safely: %w", err)
	}
	defer unix.Close(fd)
	return imageIdentityFromFD(fd, writable)
}

func imageIdentityFromFile(file *os.File, writable bool) (imageFileIdentity, error) {
	if file == nil {
		return imageFileIdentity{}, errors.New("verified image descriptor is required")
	}
	return imageIdentityFromFD(int(file.Fd()), writable)
}

func imageIdentityFromFD(fd int, writable bool) (imageFileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return imageFileIdentity{}, fmt.Errorf("inspect verified image: %w", err)
	}
	expectedMode := uint32(0)
	if writable {
		expectedMode = 0o600
	} else {
		expectedMode = 0o444
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != expectedMode || stat.Nlink != 1 || stat.Size <= 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || stat.Gid != uint32(os.Getegid()) {
		return imageFileIdentity{}, errors.New("verified image type, mode, links, owner, or group is unsafe")
	}
	return imageFileIdentity{device: uint64(stat.Dev), inode: stat.Ino, size: stat.Size, uid: stat.Uid, gid: stat.Gid, mode: stat.Mode, links: stat.Nlink}, nil
}

func openCreatedOverlay(path string) (*os.File, imageFileIdentity, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDWR | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, imageFileIdentity{}, errors.New("open created root overlay safely failed")
	}
	file := os.NewFile(uintptr(fd), "private-vm-root-overlay")
	identity, err := imageIdentityFromFD(fd, false)
	if err != nil {
		// qemu-img commonly creates mode 0644; validate the invariant that
		// matters before tightening it to exact 0600 below.
		var stat unix.Stat_t
		if statErr := unix.Fstat(fd, &stat); statErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o022 != 0 || stat.Nlink != 1 || stat.Size <= 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || stat.Gid != uint32(os.Getegid()) {
			_ = file.Close()
			return nil, imageFileIdentity{}, errors.New("created root overlay identity is unsafe")
		}
		identity = imageFileIdentity{device: uint64(stat.Dev), inode: stat.Ino, size: stat.Size, uid: stat.Uid, gid: stat.Gid, mode: stat.Mode, links: stat.Nlink}
	}
	return file, identity, nil
}

func removeOwnedImage(path string, parent pathIdentity, identity imageFileIdentity) error {
	directory, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("open root overlay parent for cleanup failed")
	}
	defer unix.Close(directory)
	var parentStat unix.Stat_t
	if err := unix.Fstat(directory, &parentStat); err != nil || !parent.sameStat(parentStat) {
		return errors.New("root overlay parent identity changed before cleanup")
	}
	var current unix.Stat_t
	err = unix.Fstatat(directory, filepath.Base(path), &current, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || !identity.sameStat(current) {
		return errors.New("refusing to remove a replaced root overlay")
	}
	if err := unix.Unlinkat(directory, filepath.Base(path), 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return errors.New("remove root overlay failed")
	}
	return nil
}

func verifyImageIdentity(path string, expected imageFileIdentity) error {
	current, err := inspectImageFile(path, expected.mode&0o777 == 0o600)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("verified image identity changed during operation")
	}
	return nil
}

func (i imageFileIdentity) sameStat(stat unix.Stat_t) bool {
	return i.device == uint64(stat.Dev) && i.inode == stat.Ino && i.size == stat.Size && i.uid == stat.Uid && i.gid == stat.Gid && i.mode == stat.Mode && i.links == stat.Nlink
}
