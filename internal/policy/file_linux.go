//go:build linux

package policy

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openPolicyFile(path string) (*os.File, error) {
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "private-vm-policy")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("invalid policy descriptor")
	}
	var stat unix.Stat_t
	var filesystem unix.Statfs_t
	statErr := unix.Fstat(fd, &stat)
	filesystemErr := unix.Fstatfs(fd, &filesystem)
	if statErr != nil || filesystemErr != nil {
		_ = file.Close()
		return nil, errors.New("unverifiable policy file")
	}
	if !localPolicyFilesystem(filesystem.Type) {
		_ = file.Close()
		return nil, errors.New("unsafe policy filesystem")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o022 != 0 || stat.Mode&0o111 != 0 ||
		(stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		_ = file.Close()
		return nil, errors.New("unsafe policy ownership or mode")
	}
	return file, nil
}

func localPolicyFilesystem(filesystemType int64) bool {
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
