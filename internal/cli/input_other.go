//go:build !linux

package cli

import (
	"context"
	"os"
)

func openSensitiveFile(path string, opener InputOpener, requireOwnerOnly bool) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, ErrUnsafeInputFile
	}
	if requireOwnerOnly && (info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0111 != 0) {
		return nil, ErrUnsafeInputFile
	}
	if opener == nil {
		opener = os.OpenFile
	}
	file, err := opener(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, ErrInputUnavailable
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, ErrUnsafeInputFile
	}
	return file, nil
}

func readTerminalValue(context.Context, ValueRequest) ([]byte, error) {
	return nil, ErrInputUnavailable
}

func duplicateInputFD(file *os.File) (int, int, error) {
	return -1, 0, ErrInputUnavailable
}

func closeInputFD(fd int, originalFlags int) error {
	return ErrInputUnavailable
}

func readInputFDContext(ctx context.Context, fd int, value []byte) (int, error) {
	return 0, ErrInputUnavailable
}
