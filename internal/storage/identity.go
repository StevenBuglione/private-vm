package storage

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type pathIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
	mode   uint32
}

func inspectPrivateDirectoryIdentity(path string) (pathIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return pathIdentity{}, errors.New("private path must be a narrow clean absolute path")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return pathIdentity{}, errors.New("open private path identity failed")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return pathIdentity{}, errors.New("inspect private path identity failed")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o777 != 0o700 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return pathIdentity{}, errors.New("private path identity, owner, group, or mode is unsafe")
	}
	return pathIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, uid: stat.Uid,
		gid: stat.Gid, mode: stat.Mode,
	}, nil
}

func (i pathIdentity) sameObject(other pathIdentity) bool {
	return i.device == other.device && i.inode == other.inode && i.uid == other.uid && i.gid == other.gid && i.mode == other.mode
}

func (i pathIdentity) sameStat(stat unix.Stat_t) bool {
	return i.device == uint64(stat.Dev) && i.inode == stat.Ino && i.uid == stat.Uid && i.gid == stat.Gid && i.mode == stat.Mode
}

func removeOwnedDirectory(path string, parent, target pathIdentity) error {
	directory, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("open owned directory parent for cleanup failed")
	}
	defer unix.Close(directory)
	var parentStat unix.Stat_t
	if err := unix.Fstat(directory, &parentStat); err != nil || !parent.sameStat(parentStat) {
		return errors.New("owned directory parent identity changed before cleanup")
	}
	var current unix.Stat_t
	err = unix.Fstatat(directory, filepath.Base(path), &current, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || !target.sameStat(current) || current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("refusing to remove a replaced owned directory")
	}
	if err := unix.Unlinkat(directory, filepath.Base(path), unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return errors.New("remove owned directory failed")
	}
	return nil
}
