package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type OverlayManager struct {
	QEMUImg string
	Runner  Runner
}

type imageInfo struct {
	Format              string `json:"format"`
	VirtualSize         uint64 `json:"virtual-size"`
	BackingFilename     string `json:"backing-filename"`
	FullBackingFilename string `json:"full-backing-filename"`
}

func (m OverlayManager) Create(ctx context.Context, outerDirectory, basePath, name string) (string, error) {
	if m.Runner == nil || !filepath.IsAbs(m.QEMUImg) {
		return "", errors.New("absolute qemu-img path and runner are required")
	}
	if !opaqueNames[name] || filepath.Ext(name) != ".qcow2" {
		return "", errors.New("overlay name is not allowlisted")
	}
	if err := verifyPrivateDirectory(outerDirectory); err != nil {
		return "", err
	}
	if err := verifyReadOnlyBase(basePath); err != nil {
		return "", err
	}
	baseInfo, err := m.info(ctx, basePath)
	if err != nil {
		return "", err
	}
	if baseInfo.Format != "qcow2" || baseInfo.VirtualSize == 0 {
		return "", errors.New("verified base image is not a non-empty QCOW2 image")
	}
	overlay := filepath.Join(outerDirectory, name)
	if _, err := m.Runner.Run(ctx, Command{Path: m.QEMUImg, Args: []string{"create", "-f", "qcow2", "-F", "qcow2", "-b", basePath, overlay}}); err != nil {
		return "", err
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(overlay)
		}
	}()
	if err := os.Chmod(overlay, 0o600); err != nil {
		return "", fmt.Errorf("restrict root overlay permissions: %w", err)
	}
	created, err := m.info(ctx, overlay)
	if err != nil {
		return "", err
	}
	backing := created.FullBackingFilename
	if backing == "" {
		backing = created.BackingFilename
	}
	if created.Format != "qcow2" || filepath.Clean(backing) != basePath {
		return "", errors.New("created overlay does not reference the verified base")
	}
	remove = false
	return overlay, nil
}

func (m OverlayManager) info(ctx context.Context, path string) (imageInfo, error) {
	result, err := m.Runner.Run(ctx, Command{Path: m.QEMUImg, Args: []string{"info", "--output=json", path}})
	if err != nil {
		return imageInfo{}, err
	}
	var value imageInfo
	if err := json.Unmarshal(result.Stdout, &value); err != nil {
		return imageInfo{}, errors.New("qemu-img returned malformed bounded JSON")
	}
	return value, nil
}

func verifyReadOnlyBase(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("base image path must be a clean absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect verified base image: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o222 != 0 {
		return errors.New("verified base image must be a read-only regular file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open verified base image without symlinks: %w", err)
	}
	return file.Close()
}
