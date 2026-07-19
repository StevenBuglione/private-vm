//go:build linux

package transfer

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openSourceNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), filepath.Base(path)), nil
}
