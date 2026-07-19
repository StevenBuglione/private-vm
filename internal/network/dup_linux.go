//go:build linux

package network

import (
	"os"

	"golang.org/x/sys/unix"
)

func duplicateTAPFile(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, ErrTopologyNotReady
	}
	fd, err := unix.FcntlInt(source.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, ErrTopologyNotReady
	}
	return os.NewFile(uintptr(fd), "private-vm-tap"), nil
}
