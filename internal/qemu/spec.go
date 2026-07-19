package qemu

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/StevenBuglione/private-vm/internal/session"
)

// Linux sockaddr_un.sun_path has 108 bytes including the trailing NUL.
const maxUnixSocketPath = 107

var (
	qemuNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type Disk struct {
	Path     string
	Format   string
	ReadOnly bool
	Serial   string
}

type ScannerMode string

const (
	ScannerModeUpdate ScannerMode = "update"
	ScannerModeScan   ScannerMode = "scan"

	scannerBootModeFWCfg = "opt/private-vm/scanner-boot-mode"
)

type Spec struct {
	Binary       string
	SessionID    string
	Name         string
	Role         session.Role
	ScannerMode  ScannerMode
	Machine      string
	CPUs         uint32
	MemoryBytes  uint64
	Root         Disk
	Data         []Disk
	QMPSocket    string
	SPICESocket  string
	VSOCKCID     uint32
	Networked    bool
	NetworkFD    int
	EnableAudio  bool
	FWCfgTokenFD int
}

func (s Spec) Validate() error {
	if err := validateExecutable(s.Binary); err != nil {
		return err
	}
	if err := session.ValidateID(s.SessionID); err != nil {
		return err
	}
	if !qemuNamePattern.MatchString(s.Name) {
		return errors.New("QEMU name must be a bounded safe identifier")
	}
	if err := session.ValidateRole(s.Role); err != nil {
		return err
	}
	if s.Machine != "" && s.Machine != "q35,accel=kvm" {
		return errors.New("only the verified q35 KVM machine profile is supported")
	}
	if s.CPUs < 1 || s.CPUs > 64 || s.MemoryBytes < 512<<20 || s.MemoryBytes > 256<<30 || s.MemoryBytes%(1<<20) != 0 {
		return errors.New("invalid CPU or memory allocation")
	}
	if err := validateDisk(s.Root, true); err != nil {
		return fmt.Errorf("root disk: %w", err)
	}
	for i, disk := range s.Data {
		if err := validateDisk(disk, false); err != nil {
			return fmt.Errorf("data disk %d: %w", i, err)
		}
	}
	if err := validateSocketDestination(s.QMPSocket, "QMP"); err != nil {
		return err
	}
	graphical := s.Role != session.RoleExporter
	if graphical {
		if err := validateSocketDestination(s.SPICESocket, "SPICE"); err != nil {
			return err
		}
		if s.SPICESocket == s.QMPSocket {
			return errors.New("QMP and SPICE require distinct Unix sockets")
		}
	} else if s.SPICESocket != "" {
		return errors.New("exporter guest cannot expose SPICE")
	}
	if s.VSOCKCID < 3 || s.VSOCKCID == ^uint32(0) {
		return errors.New("VSOCK CID must be an allocatable guest CID")
	}
	if s.Networked && s.NetworkFD != 4 {
		return errors.New("networked guest requires the second inherited descriptor as TAP")
	}
	if !s.Networked && s.NetworkFD != 0 {
		return errors.New("offline guest cannot inherit a TAP descriptor")
	}
	if s.FWCfgTokenFD < 3 {
		return errors.New("fw_cfg capability FD must be inherited and >= 3")
	}
	return s.validateRoleDevices()
}

func (s Spec) validateRoleDevices() error {
	if s.Role != session.RoleScanner && s.ScannerMode != "" {
		return errors.New("scanner boot mode is restricted to scanner guests")
	}
	switch s.Role {
	case session.RoleWorkstation:
		if !s.Networked || len(s.Data) != 0 {
			return errors.New("workstation requires network and forbids data disks")
		}
	case session.RoleDownloader:
		if !s.Networked || len(s.Data) != 1 || s.Data[0].ReadOnly {
			return errors.New("downloader requires network and one writable quarantine disk")
		}
	case session.RoleScanner:
		if s.EnableAudio {
			return errors.New("scanner guests forbid audio")
		}
		switch s.ScannerMode {
		case ScannerModeUpdate:
			if !s.Networked || len(s.Data) != 0 {
				return errors.New("scanner update boot requires network and forbids quarantine")
			}
		case ScannerModeScan:
			if s.Networked || len(s.Data) != 1 || !s.Data[0].ReadOnly {
				return errors.New("scanner scan boot requires no network and one read-only quarantine disk")
			}
		default:
			return errors.New("scanner boot mode must be update or scan")
		}
	case session.RoleExporter:
		if s.Networked || len(s.Data) != 0 || s.EnableAudio {
			return errors.New("exporter forbids network, quarantine and audio")
		}
	}
	return nil
}

func validateDisk(disk Disk, root bool) error {
	if !filepath.IsAbs(disk.Path) || filepath.Clean(disk.Path) != disk.Path {
		return errors.New("path must be a clean absolute path")
	}
	switch disk.Format {
	case "qcow2", "raw":
	default:
		return errors.New("format must be qcow2 or raw")
	}
	if strings.ContainsAny(disk.Path, ",\n\r") || !deviceIDPattern.MatchString(disk.Serial) {
		return errors.New("path or serial is not a safe typed value")
	}
	if root && disk.ReadOnly {
		return errors.New("session root overlay must be writable")
	}
	return nil
}

func validateExecutable(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("QEMU binary must be a clean absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("QEMU binary is unavailable")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("QEMU binary path must not contain symbolic links")
	}
	if err := validateExecutableInfo(info); err != nil {
		return err
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parentInfo.IsDir() {
		return errors.New("QEMU binary parent is unavailable")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || (parentStat.Uid != 0 && parentStat.Uid != uint32(os.Geteuid())) {
		return errors.New("QEMU binary parent owner is not trusted")
	}
	if parentInfo.Mode().Perm()&0o022 != 0 && !(parentStat.Uid == 0 && parentInfo.Mode()&os.ModeSticky != 0) {
		return errors.New("QEMU binary parent is writable by an untrusted group or user")
	}
	return nil
}

func validateExecutableInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return errors.New("QEMU binary must be a directly referenced executable regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("QEMU binary must not be writable by group or other")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return errors.New("QEMU binary owner is not trusted")
	}
	return nil
}

func validateSocketDestination(path, label string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > maxUnixSocketPath || strings.ContainsAny(path, ",\n\r") {
		return fmt.Errorf("%s socket must be a bounded clean absolute path", label)
	}
	if err := validateSocketParent(filepath.Dir(path)); err != nil {
		return fmt.Errorf("%s socket parent: %w", label, err)
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s socket path must not already exist", label)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect %s socket destination", label)
	}
	return nil
}

func validateSocketParent(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("path contains a missing or symbolic-link component")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a real directory")
	}
	if info.Mode().Perm() != 0o700 {
		return errors.New("mode must be exactly 0700")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return errors.New("owner or group does not match the daemon")
	}
	return nil
}

// Args returns a direct argv vector. It never invokes or requires a shell.
func (s Spec) Args() ([]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	memoryMiB := s.MemoryBytes / (1024 * 1024)
	args := []string{
		"-nodefaults",
		"-no-user-config",
		"-name", s.Name,
		"-machine", valueOr(s.Machine, "q35,accel=kvm"),
		"-cpu", "host",
		"-smp", strconv.FormatUint(uint64(s.CPUs), 10),
		"-m", strconv.FormatUint(memoryMiB, 10),
		"-display", "none",
		"-monitor", "none",
		"-serial", "none",
		"-no-reboot",
		"-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
		"-qmp", "unix:" + s.QMPSocket + ",server=on,wait=off",
		"-device", "vhost-vsock-pci,guest-cid=" + strconv.FormatUint(uint64(s.VSOCKCID), 10),
		"-object", "rng-random,filename=/dev/urandom,id=rng0",
		"-device", "virtio-rng-pci,rng=rng0",
		"-fw_cfg", "name=opt/private-vm/session-capability,file=/proc/self/fd/" + strconv.Itoa(s.FWCfgTokenFD),
	}
	if s.Role == session.RoleScanner {
		bootMode, ok := scannerBootMode(s.ScannerMode)
		if !ok {
			return nil, errors.New("scanner boot mode is unavailable")
		}
		args = append(args, "-fw_cfg", "name="+scannerBootModeFWCfg+",string="+bootMode)
	}
	if s.Role != session.RoleExporter {
		args = append(args,
			"-spice", "unix=on,addr="+s.SPICESocket+
				",disable-ticketing=on,disable-copy-paste=on,disable-agent-file-xfer=on",
			"-device", "virtio-vga",
			"-device", "virtio-keyboard-pci",
			"-device", "virtio-mouse-pci",
			"-device", "virtio-serial-pci,id=spice-serial",
			"-chardev", "spicevmc,id=spiceagent,name=vdagent",
			"-device", "virtserialport,bus=spice-serial.0,chardev=spiceagent,name=com.redhat.spice.0",
		)
	}
	args = append(args, diskArgs("root", s.Root)...)
	for i, disk := range s.Data {
		args = append(args, diskArgs(fmt.Sprintf("data%d", i), disk)...)
	}
	if s.Networked {
		args = append(args,
			"-netdev", "tap,id=net0,fd="+strconv.Itoa(s.NetworkFD)+",vhost=on",
			"-device", "virtio-net-pci,netdev=net0",
		)
	} else {
		args = append(args, "-nic", "none")
	}
	if !s.EnableAudio {
		args = append(args, "-audiodev", "none,id=noaudio")
	}
	if s.Role == session.RoleExporter {
		args = append(args, "-device", "qemu-xhci,id=usb-controller")
	}
	if err := validateRenderedArgs(args); err != nil {
		return nil, err
	}
	return args, nil
}

func scannerBootMode(mode ScannerMode) (string, bool) {
	switch mode {
	case ScannerModeUpdate:
		return "definitions-update", true
	case ScannerModeScan:
		return "scan-offline", true
	default:
		return "", false
	}
}

func diskArgs(id string, disk Disk) []string {
	drive := "file=" + disk.Path + ",if=none,id=" + id + ",format=" + disk.Format + ",cache=none,discard=unmap"
	if disk.ReadOnly {
		drive += ",readonly=on"
	}
	return []string{
		"-drive", drive,
		"-device", "virtio-blk-pci,drive=" + id + ",serial=" + disk.Serial,
	}
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// ValidateNoTCPListener catches accidental display/network listeners in future
// argument transformations.
func ValidateNoTCPListener(args []string) error {
	for _, value := range args {
		lower := strings.ToLower(value)
		if strings.Contains(lower, "port=") || strings.Contains(lower, "tls-port=") {
			return errors.New("SPICE TCP port is forbidden")
		}
		if strings.HasPrefix(value, "unix:") || strings.Contains(value, "unix=on") {
			continue
		}
		if _, _, err := net.SplitHostPort(value); err == nil {
			return fmt.Errorf("unexpected host:port argument %q", value)
		}
	}
	return nil
}

func validateRenderedArgs(args []string) error {
	for _, value := range args {
		lower := strings.ToLower(value)
		for _, forbidden := range []string{"virtiofs", "vhost-user-fs", "virtio-9p", "-virtfs", "-fsdev", "usb-redir", "-daemonize"} {
			if strings.Contains(lower, forbidden) {
				return errors.New("rendered QEMU arguments contain a forbidden device or mode")
			}
		}
	}
	return ValidateNoTCPListener(args)
}
