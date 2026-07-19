//go:build linux

package config

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openConfigFile(path string, trust FileTrust) (*os.File, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "private-vm-configuration")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("invalid configuration descriptor")
	}
	var stat unix.Stat_t
	var filesystem unix.Statfs_t
	statErr := unix.Fstat(fd, &stat)
	filesystemErr := unix.Fstatfs(fd, &filesystem)
	if statErr != nil || filesystemErr != nil {
		_ = file.Close()
		return nil, errors.New("unverifiable configuration file")
	}
	if !localConfigurationFilesystem(filesystem.Type) {
		_ = file.Close()
		return nil, errors.New("unsafe configuration filesystem")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o022 != 0 || stat.Mode&0o111 != 0 {
		_ = file.Close()
		return nil, errors.New("unsafe configuration mode")
	}
	switch trust {
	case TrustAny:
	case TrustSystem:
		if stat.Uid != 0 {
			_ = file.Close()
			return nil, errors.New("unsafe system configuration owner")
		}
	case TrustUser:
		if stat.Uid != uint32(os.Geteuid()) {
			_ = file.Close()
			return nil, errors.New("unsafe user configuration owner")
		}
	default:
		_ = file.Close()
		return nil, errors.New("invalid configuration trust policy")
	}
	return file, nil
}

func localConfigurationFilesystem(filesystemType int64) bool {
	const zfsSuperMagic = 0x2fc12fc1
	switch filesystemType {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC,
		unix.F2FS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.RAMFS_MAGIC,
		unix.ECRYPTFS_SUPER_MAGIC, unix.OVERLAYFS_SUPER_MAGIC,
		unix.SQUASHFS_MAGIC, unix.EROFS_SUPER_MAGIC_V1, zfsSuperMagic:
		return true
	default:
		return false
	}
}
