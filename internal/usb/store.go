package usb

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

const enrollmentFileName = "usb-enrollment.json"

// Store persists only the reviewed, content-free enrollment identity. The
// directory must already exist and be private to the expected owner.
type Store struct {
	directory string
	ownerUID  uint32
}

func NewStore(directory string, ownerUID uint32) (*Store, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("USB enrollment directory must be a clean absolute path")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("USB enrollment directory is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("USB enrollment directory must be private and owned by the expected user")
	}
	return &Store{directory: directory, ownerUID: ownerUID}, nil
}

func (s *Store) path() string { return filepath.Join(s.directory, enrollmentFileName) }

func (s *Store) Save(enrollment Enrollment) error {
	data, err := EncodeEnrollment(enrollment)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.directory, ".usb-enrollment-*")
	if err != nil {
		return errors.New("create temporary USB enrollment")
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.New("set USB enrollment permissions")
	}
	if _, err := temporary.Write(data); err != nil {
		return errors.New("write USB enrollment")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("sync USB enrollment")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close USB enrollment")
	}
	if err := validateRegularOwner(temporaryName, s.ownerUID, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, s.path()); err != nil {
		return errors.New("commit USB enrollment")
	}
	committed = true
	directory, err := os.Open(s.directory)
	if err != nil {
		return errors.New("open USB enrollment directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("sync USB enrollment directory")
	}
	return nil
}

func (s *Store) Load() (Enrollment, error) {
	path := s.path()
	if err := validateRegularOwner(path, s.ownerUID, 0o600); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Enrollment{}, newError(CodeNotEnrolled, "No USB device is enrolled.", "Enroll one dedicated mass-storage-only USB device before exporting.", err)
		}
		return Enrollment{}, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Enrollment{}, errors.New("open USB enrollment")
	}
	defer file.Close()
	return DecodeEnrollment(file)
}

func (s *Store) Forget() error {
	path := s.path()
	if err := validateRegularOwner(path, s.ownerUID, 0o600); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.New("remove USB enrollment")
	}
	return nil
}

func validateRegularOwner(path string, ownerUID uint32, mode fs.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != ownerUID || info.Mode().Perm() != mode {
		return fmt.Errorf("USB enrollment file has unsafe identity or permissions")
	}
	return nil
}
