package qemu

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/StevenBuglione/private-vm/internal/session"
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
)

type USBDevice struct {
	Bus     uint8
	Address uint8
}

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
	TAPName      string
	Networked    bool
	EnableAudio  bool
	FWCfgTokenFD int
	USB          *USBDevice
}

func (s Spec) Validate() error {
	if !filepath.IsAbs(s.Binary) {
		return errors.New("QEMU binary must be absolute")
	}
	if s.SessionID == "" || s.Name == "" {
		return errors.New("session ID and name are required")
	}
	if err := session.ValidateRole(s.Role); err != nil {
		return err
	}
	if s.Machine != "" && s.Machine != "q35,accel=kvm" {
		return errors.New("only the verified q35 KVM machine profile is supported")
	}
	if s.CPUs < 1 || s.CPUs > 64 || s.MemoryBytes < 512<<20 || s.MemoryBytes > 256<<30 {
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
	if s.QMPSocket == "" || !filepath.IsAbs(s.QMPSocket) || strings.ContainsAny(s.QMPSocket, ",\n\r") {
		return errors.New("QMP socket must be a safe absolute path")
	}
	graphical := s.Role != session.RoleExporter
	if graphical {
		if s.SPICESocket == "" || !filepath.IsAbs(s.SPICESocket) || strings.ContainsAny(s.SPICESocket, ",\n\r") {
			return errors.New("graphical guest SPICE socket must be a safe absolute path")
		}
	} else if s.SPICESocket != "" {
		return errors.New("exporter guest cannot expose SPICE")
	}
	if s.VSOCKCID < 3 {
		return errors.New("VSOCK CID must be >= 3")
	}
	if s.Networked && s.TAPName == "" {
		return errors.New("networked guest requires TAP")
	}
	if !s.Networked && s.TAPName != "" {
		return errors.New("offline guest cannot have TAP")
	}
	if s.FWCfgTokenFD < 3 {
		return errors.New("fw_cfg capability FD must be inherited and >= 3")
	}
	return s.validateRoleDevices()
}

func (s Spec) validateRoleDevices() error {
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
	if s.USB != nil && (s.Role != session.RoleExporter || s.USB.Bus == 0 || s.USB.Address == 0) {
		return errors.New("exact USB passthrough is restricted to exporter")
	}
	return nil
}

func validateDisk(disk Disk, root bool) error {
	if !filepath.IsAbs(disk.Path) {
		return errors.New("path must be absolute")
	}
	switch disk.Format {
	case "qcow2", "raw":
	default:
		return errors.New("format must be qcow2 or raw")
	}
	if disk.Serial == "" {
		return errors.New("serial is required")
	}
	if strings.ContainsAny(disk.Path+disk.Serial, ",\n\r") {
		return errors.New("path or serial contains unsafe delimiter")
	}
	if root && disk.ReadOnly {
		return errors.New("session root overlay must be writable")
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
	if s.Role != session.RoleExporter {
		args = append(args,
			"-spice", "unix=on,addr="+s.SPICESocket+
				",disable-ticketing=on,disable-copy-paste=on,disable-agent-file-xfer=on",
			"-device", "virtio-vga",
			"-device", "virtio-keyboard-pci",
			"-device", "virtio-mouse-pci",
			"-chardev", "spicevmc,id=spiceagent,name=vdagent",
			"-device", "virtserialport,chardev=spiceagent,name=com.redhat.spice.0",
		)
	}
	args = append(args, diskArgs("root", s.Root)...)
	for i, disk := range s.Data {
		args = append(args, diskArgs(fmt.Sprintf("data%d", i), disk)...)
	}
	if s.Networked {
		args = append(args,
			"-netdev", "tap,id=net0,ifname="+s.TAPName+",script=no,downscript=no,vhost=on",
			"-device", "virtio-net-pci,netdev=net0",
		)
	} else {
		args = append(args, "-nic", "none")
	}
	if !s.EnableAudio {
		args = append(args, "-audiodev", "none,id=noaudio")
	}
	if s.USB != nil {
		args = append(args,
			"-device", "qemu-xhci,id=usb-controller",
			"-device", "usb-host,bus=usb-controller.0,hostbus="+strconv.Itoa(int(s.USB.Bus))+",hostaddr="+strconv.Itoa(int(s.USB.Address)),
		)
	}
	return args, nil
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
		if strings.Contains(value, "spice") && strings.Contains(value, "port=") {
			return errors.New("SPICE TCP port is forbidden")
		}
		if strings.HasPrefix(value, "unix:") || strings.Contains(value, "unix=on") {
			continue
		}
		if host, _, err := net.SplitHostPort(value); err == nil && host != "" {
			return fmt.Errorf("unexpected host:port argument %q", value)
		}
	}
	return nil
}
