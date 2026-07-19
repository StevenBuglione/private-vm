//go:build linux

package scan

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func extractionParentIsTmpfs(path string) bool {
	var stat unix.Statfs_t
	return unix.Statfs(path, &stat) == nil && uint64(stat.Type) == uint64(unix.TMPFS_MAGIC)
}

type unixFileIdentity struct {
	device uint64
	inode  uint64
}

func captureFileInfoIdentity(info os.FileInfo) fileInfoIdentity {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileInfoIdentity{mode: info.Mode()}
	}
	return fileInfoIdentity{mode: info.Mode(), native: unixFileIdentity{device: uint64(stat.Dev), inode: stat.Ino}}
}

func sameFileInfoIdentity(info os.FileInfo, identity fileInfoIdentity) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	want, valid := identity.native.(unixFileIdentity)
	return ok && valid && info.Mode() == identity.mode && uint64(stat.Dev) == want.device && stat.Ino == want.inode
}
