//go:build linux

package torrent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	quarantineDevicePath = "/dev/disk/by-id/virtio-quarantine"
	maximumMountInfo     = 256 << 10
	minimumDiskSectors   = 16384
)

var (
	ErrQuarantineMountTargetUnsafe    = errors.New("quarantine mount target is unsafe")
	ErrQuarantineMountSystemCall      = errors.New("quarantine mount system call failed")
	ErrQuarantineMountEvidenceInvalid = errors.New("quarantine mount evidence is invalid")
)

type quarantineFormatState uint8

const (
	quarantineBlank quarantineFormatState = iota + 1
	quarantineExt4
)

type linuxQuarantineBackend struct {
	mu        sync.Mutex
	mkfs      string
	device    *os.File
	major     uint32
	minor     uint32
	uid       int
	gid       int
	mountPath string
}

func PrepareLinuxQuarantine(ctx context.Context, mkfsPath string, privateUID, privateGID int) (*QuarantineOwner, error) {
	backend, err := newLinuxQuarantineBackend(mkfsPath, quarantineDevicePath, QuarantineMountPath, privateUID, privateGID)
	if err != nil {
		return nil, err
	}
	owner, err := newQuarantineOwner(backend)
	if err != nil {
		_ = backend.Close()
		return nil, err
	}
	if err := owner.Prepare(ctx); err != nil {
		_ = backend.Close()
		return nil, err
	}
	return owner, nil
}

func newLinuxQuarantineBackend(mkfs, devicePath, mountPath string, uid, gid int) (*linuxQuarantineBackend, error) {
	if !filepath.IsAbs(mkfs) || filepath.Clean(mkfs) != mkfs || filepath.Base(mkfs) != "mkfs.ext4" ||
		!filepath.IsAbs(devicePath) || filepath.Clean(devicePath) != devicePath || !filepath.IsAbs(mountPath) || filepath.Clean(mountPath) != mountPath || uid <= 0 || gid <= 0 {
		return nil, invalidRequest()
	}
	backend := &linuxQuarantineBackend{mkfs: mkfs, uid: uid, gid: gid, mountPath: mountPath}
	resolved, err := filepath.EvalSymlinks(devicePath)
	if err != nil || !strings.HasPrefix(resolved, "/dev/") || filepath.Clean(resolved) != resolved {
		return nil, errors.New("fixed quarantine device unavailable")
	}
	fd, err := unix.Open(resolved, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("fixed quarantine device unavailable")
	}
	backend.device = os.NewFile(uintptr(fd), "virtio-quarantine")
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFBLK {
		_ = backend.Close()
		return nil, errors.New("fixed quarantine device is not block storage")
	}
	backend.major, backend.minor = unix.Major(uint64(stat.Rdev)), unix.Minor(uint64(stat.Rdev))
	if err := backend.verifySysfsIdentity(); err != nil {
		_ = backend.Close()
		return nil, err
	}
	return backend, nil
}

func (backend *linuxQuarantineBackend) verifySysfsIdentity() error {
	serialPath, readOnlyPath, capacityPath := quarantineSysfsAttributePaths(backend.major, backend.minor)
	serial, err := readSmallFile(serialPath, 64)
	if err != nil || string(bytes.TrimSpace(serial)) != "quarantine" {
		clearBytes(serial)
		return errors.New("fixed quarantine device identity mismatch")
	}
	clearBytes(serial)
	readOnly, err := readSmallFile(readOnlyPath, 8)
	if err != nil || string(bytes.TrimSpace(readOnly)) != "0" {
		clearBytes(readOnly)
		return errors.New("fixed quarantine device is not writable")
	}
	clearBytes(readOnly)
	sectors, err := readSmallFile(capacityPath, 32)
	if err != nil {
		return errors.New("fixed quarantine capacity unavailable")
	}
	count, parseErr := strconv.ParseUint(string(bytes.TrimSpace(sectors)), 10, 64)
	clearBytes(sectors)
	if parseErr != nil || count < minimumDiskSectors {
		return errors.New("fixed quarantine capacity invalid")
	}
	return nil
}

func quarantineSysfsAttributePaths(major, minor uint32) (string, string, string) {
	root := "/sys/dev/block/" + strconv.FormatUint(uint64(major), 10) + ":" + strconv.FormatUint(uint64(minor), 10)
	// Virtio-blk publishes serial on the block device. The device directory
	// points back to the transport and does not contain this attribute.
	return filepath.Join(root, "serial"), filepath.Join(root, "ro"), filepath.Join(root, "size")
}

func (backend *linuxQuarantineBackend) Mounted(context.Context) (bool, error) {
	return backend.mountEvidence()
}

func (backend *linuxQuarantineBackend) PrepareFilesystem(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	state, err := inspectQuarantineFormat(backend.device)
	if err != nil {
		return err
	}
	if state == quarantineExt4 {
		return nil
	}
	command := exec.CommandContext(ctx, backend.mkfs, "-F", "-q", "-L", "private-vm-quarantine", "/proc/self/fd/3")
	command.Env = []string{"LANG=C.UTF-8"}
	command.ExtraFiles = []*os.File{backend.device}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("bounded ext4 format failed")
	}
	state, err = inspectQuarantineFormat(backend.device)
	if err != nil || state != quarantineExt4 {
		return errors.New("formatted quarantine identity invalid")
	}
	return nil
}

func (backend *linuxQuarantineBackend) Mount(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateMountTarget(backend.mountPath); err != nil {
		return err
	}
	source := "/proc/self/fd/" + strconv.FormatUint(uint64(backend.device.Fd()), 10)
	flags := uintptr(unix.MS_NODEV | unix.MS_NOSUID | unix.MS_NOEXEC)
	if err := unix.Mount(source, backend.mountPath, "ext4", flags, "errors=remount-ro"); err != nil {
		return ErrQuarantineMountSystemCall
	}
	mounted, err := backend.mountEvidence()
	if err != nil || !mounted {
		_ = unix.Unmount(backend.mountPath, 0)
		return ErrQuarantineMountEvidenceInvalid
	}
	return nil
}

func (backend *linuxQuarantineBackend) PrepareDirectories(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Chown(backend.mountPath, 0, backend.gid); err != nil || os.Chmod(backend.mountPath, 0o750) != nil {
		return errors.New("quarantine root permissions failed")
	}
	for _, path := range []string{QuarantineDownloadDir, filepath.Join(QuarantineMountPath, ".incomplete"), filepath.Join(QuarantineMountPath, ".qbit-data"), filepath.Join(QuarantineMountPath, ".qbit-cache")} {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return errors.New("quarantine directory creation failed")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("quarantine directory identity invalid")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink < 2 || (stat.Uid != 0 && stat.Uid != uint32(backend.uid)) {
			return errors.New("quarantine directory identity invalid")
		}
		if err := os.Chown(path, backend.uid, backend.gid); err != nil || os.Chmod(path, 0o700) != nil {
			return errors.New("quarantine directory permissions failed")
		}
	}
	return nil
}

func (backend *linuxQuarantineBackend) Sync(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := unix.Open(backend.mountPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("quarantine sync handle unavailable")
	}
	defer unix.Close(fd)
	if err := unix.Syncfs(fd); err != nil {
		return errors.New("quarantine sync failed")
	}
	return nil
}

func (backend *linuxQuarantineBackend) Unmount(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	mounted, err := backend.mountEvidence()
	if err != nil || !mounted {
		return err
	}
	if err := unix.Unmount(backend.mountPath, 0); err != nil {
		return errors.New("quarantine unmount failed")
	}
	return nil
}

func (backend *linuxQuarantineBackend) AuditAbsent(context.Context) error {
	mounted, err := backend.mountEvidence()
	if err != nil {
		return err
	}
	if mounted {
		return errors.New("quarantine mount remains active")
	}
	return nil
}

func (backend *linuxQuarantineBackend) CapacityBytes() (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(backend.mountPath, &stat); err != nil || stat.Bsize <= 0 {
		return 0, errors.New("quarantine capacity unavailable")
	}
	blockSize := uint64(stat.Bsize)
	if stat.Bavail > ^uint64(0)/blockSize {
		return 0, errors.New("quarantine capacity invalid")
	}
	return stat.Bavail * blockSize, nil
}

func (backend *linuxQuarantineBackend) Close() error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.device == nil {
		return nil
	}
	err := backend.device.Close()
	backend.device = nil
	return err
}

func (backend *linuxQuarantineBackend) mountEvidence() (bool, error) {
	raw, err := readSmallFile("/proc/self/mountinfo", maximumMountInfo)
	if err != nil {
		return false, errors.New("quarantine mount inventory unavailable")
	}
	defer clearBytes(raw)
	return parseQuarantineMountEvidence(raw, backend.major, backend.minor, backend.mountPath)
}

func parseQuarantineMountEvidence(raw []byte, major, minor uint32, mountPath string) (bool, error) {
	prefix := strconv.FormatUint(uint64(major), 10) + ":" + strconv.FormatUint(uint64(minor), 10)
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) < 10 {
			continue
		}
		deviceMatches := string(fields[2]) == prefix
		targetMatches := string(fields[4]) == mountPath
		if targetMatches && !deviceMatches {
			// systemd realizes ReadWritePaths beneath ProtectSystem=strict as an
			// exact bind of the directory to itself before making the surrounding
			// image read-only. This trusted staging mount is required so guestd can
			// mount the verified quarantine over it. It is not quarantine evidence.
			if string(fields[3]) == mountPath && strings.Contains(","+string(fields[5])+",", ",rw,") {
				continue
			}
			return false, errors.New("quarantine mount ownership conflict")
		}
		if deviceMatches && !targetMatches {
			return false, errors.New("quarantine mount ownership conflict")
		}
		if !deviceMatches {
			continue
		}
		separator := -1
		for index, field := range fields {
			if bytes.Equal(field, []byte("-")) {
				separator = index
				break
			}
		}
		if separator < 6 || separator+3 >= len(fields) || string(fields[separator+1]) != "ext4" {
			return false, errors.New("quarantine mount shape invalid")
		}
		options := "," + string(fields[5]) + ","
		for _, required := range []string{",rw,", ",nosuid,", ",nodev,", ",noexec,"} {
			if !strings.Contains(options, required) {
				return false, errors.New("quarantine mount policy invalid")
			}
		}
		return true, nil
	}
	return false, nil
}

func inspectQuarantineFormat(file *os.File) (quarantineFormatState, error) {
	if file == nil {
		return 0, errors.New("quarantine device unavailable")
	}
	value := make([]byte, 4096)
	n, err := file.ReadAt(value, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		clearBytes(value)
		return 0, errors.New("quarantine format inspection failed")
	}
	if n < 2048 {
		clearBytes(value)
		return 0, errors.New("quarantine device too small")
	}
	defer clearBytes(value)
	if value[1080] == 0x53 && value[1081] == 0xef {
		return quarantineExt4, nil
	}
	for _, current := range value {
		if current != 0 {
			return 0, errors.New("quarantine contains an unexpected filesystem signature")
		}
	}
	return quarantineBlank, nil
}

func validateMountTarget(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !validMountTargetInfo(info, 0) {
		return ErrQuarantineMountTargetUnsafe
	}
	return nil
}

func validMountTargetInfo(info os.FileInfo, owner uint32) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == owner && stat.Nlink == 2
}

func readSmallFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		clearBytes(value)
		return nil, errors.New("bounded file read failed")
	}
	return value, nil
}

var _ quarantineBackend = (*linuxQuarantineBackend)(nil)
