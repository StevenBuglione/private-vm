//go:build linux

package scan

import (
	"os"
	"path/filepath"
	"syscall"
)

func trustedExecutablePlatform(path string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink == 0 {
		return false
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		parentInfo, err := os.Lstat(parent)
		if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
			return false
		}
		parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
		if !ok || parentStat.Uid != 0 {
			return false
		}
		if parent == string(filepath.Separator) {
			break
		}
	}
	return true
}
