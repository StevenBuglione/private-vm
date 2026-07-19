package usb

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

const DefaultEnrollmentRoot = "/var/lib/private-vm/enrollments"

// OwnerStores resolves one private enrollment directory from the
// kernel-authenticated numeric owner. The root is daemon-owned and not
// user-writable, so an owner cannot redirect another owner's record.
type OwnerStores struct {
	root      string
	daemonUID uint32
}

func NewOwnerStores(root string, daemonUID uint32) (*OwnerStores, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("USB enrollment root must be a clean absolute path")
	}
	if err := validatePrivateDirectory(root, daemonUID); err != nil {
		return nil, errors.New("USB enrollment root is unavailable or unsafe")
	}
	return &OwnerStores{root: root, daemonUID: daemonUID}, nil
}

func (s *OwnerStores) ForOwner(ownerUID uint32, create bool) (*Store, error) {
	if s == nil {
		return nil, errors.New("USB owner store resolver is unavailable")
	}
	if err := validatePrivateDirectory(s.root, s.daemonUID); err != nil {
		return nil, errors.New("USB enrollment root identity changed")
	}
	directory := filepath.Join(s.root, strconv.FormatUint(uint64(ownerUID), 10))
	if create {
		created := false
		if err := os.Mkdir(directory, 0o700); err == nil {
			created = true
		} else if !errors.Is(err, os.ErrExist) {
			return nil, errors.New("create private USB enrollment directory")
		}
		if created {
			if err := os.Chown(directory, int(ownerUID), -1); err != nil {
				return nil, errors.New("set private USB enrollment directory owner")
			}
			if err := os.Chmod(directory, 0o700); err != nil {
				return nil, errors.New("set private USB enrollment directory mode")
			}
		}
	}
	return NewStore(directory, ownerUID)
}

func validatePrivateDirectory(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("private directory identity is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Nlink == 0 {
		return fmt.Errorf("private directory owner is invalid")
	}
	return nil
}
