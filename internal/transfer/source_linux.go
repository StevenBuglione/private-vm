//go:build linux

package transfer

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openSourceNoFollow(path string) (*os.File, *os.File, error) {
	parentPath := filepath.Dir(path)
	parentFD, err := unix.Openat2(unix.AT_FDCWD, parentPath, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, nil, err
	}
	parent := os.NewFile(uintptr(parentFD), parentPath)
	name := filepath.Base(path)
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		_ = parent.Close()
		return nil, nil, err
	}
	return os.NewFile(uintptr(fd), name), parent, nil
}
