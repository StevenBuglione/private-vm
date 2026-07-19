package storage

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type DeviceInspector interface {
	VerifyLoopBacking(loopPath, backingPath string) error
	VerifyMapperBacking(mappingName, loopPath string) error
	LoopStillBacks(loopPath, backingPath string) (bool, error)
	MapperExists(mappingName string) (bool, error)
}

type SystemDeviceInspector struct{}

func (SystemDeviceInspector) VerifyLoopBacking(loopPath, backingPath string) error {
	if !loopPattern.MatchString(loopPath) || !filepath.IsAbs(backingPath) || filepath.Clean(backingPath) != backingPath {
		return errors.New("loop-device verification inputs are invalid")
	}
	var stat unix.Stat_t
	if err := unix.Stat(loopPath, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFBLK || stat.Uid != 0 {
		return errors.New("allocated loop path is not a trusted block device")
	}
	actual, err := readBoundedDeviceEvidence(loopBackingEvidencePath(loopPath), 4096)
	if err != nil || filepath.Clean(strings.TrimSpace(string(actual))) != backingPath {
		return errors.New("allocated loop device does not reference the owned ciphertext")
	}
	return nil
}

func (SystemDeviceInspector) VerifyMapperBacking(mappingName, loopPath string) error {
	if !storageSessionPattern.MatchString(mappingName) || !loopPattern.MatchString(loopPath) {
		return errors.New("mapper verification inputs are invalid")
	}
	mapperPath := filepath.Join("/dev/mapper", mappingName)
	info, err := os.Lstat(mapperPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return errors.New("owned mapper link is unavailable")
	}
	resolved, err := filepath.EvalSymlinks(mapperPath)
	if err != nil || !strings.HasPrefix(resolved, "/dev/dm-") || filepath.Dir(resolved) != "/dev" {
		return errors.New("owned mapper target is invalid")
	}
	var stat unix.Stat_t
	if err := unix.Stat(resolved, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFBLK || stat.Uid != 0 {
		return errors.New("owned mapper target is not a trusted block device")
	}
	dmName := filepath.Base(resolved)
	name, err := readBoundedDeviceEvidence(filepath.Join("/sys/class/block", dmName, "dm", "name"), 128)
	if err != nil || strings.TrimSpace(string(name)) != mappingName {
		return errors.New("device-mapper name does not match the owned mapping")
	}
	slaves, err := os.ReadDir(filepath.Join("/sys/class/block", dmName, "slaves"))
	if err != nil || len(slaves) != 1 || slaves[0].Name() != filepath.Base(loopPath) {
		return errors.New("device-mapper backing device does not match the owned loop")
	}
	return nil
}

func (SystemDeviceInspector) LoopStillBacks(loopPath, backingPath string) (bool, error) {
	data, err := readBoundedDeviceEvidence(loopBackingEvidencePath(loopPath), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	actual := strings.TrimSpace(string(data))
	if actual == "" {
		return false, nil
	}
	return filepath.Clean(actual) == backingPath, nil
}

func (SystemDeviceInspector) MapperExists(mappingName string) (bool, error) {
	if !storageSessionPattern.MatchString(mappingName) {
		return false, errors.New("mapper name is invalid")
	}
	_, err := os.Lstat(filepath.Join("/dev/mapper", mappingName))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func loopBackingEvidencePath(loopPath string) string {
	return filepath.Join("/sys/class/block", filepath.Base(loopPath), "loop", "backing_file")
}

func readBoundedDeviceEvidence(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("device identity evidence exceeded its bound")
	}
	return data, nil
}
