package qemu

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

type Disk struct {
	Path     string
	Format   string
	ReadOnly bool
	Serial   string
}

type Spec struct {
	Binary       string
	SessionID    string
	Name         string
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
}

func (s Spec) Validate() error {
	if !filepath.IsAbs(s.Binary) {
		return errors.New("QEMU binary must be absolute")
	}
	if s.SessionID == "" || s.Name == "" {
		return errors.New("session ID and name are required")
	}
	if s.CPUs < 1 || s.MemoryBytes < 512<<20 {
		return errors.New("invalid CPU or memory allocation")
	}
	if err := validateDisk(s.Root, true); err != nil {
		return fmt.Errorf("root disk: %w", err)
	}
	for i, d := range s.Data {
		if err := validateDisk(d, false); err != nil {
			return fmt.Errorf("data disk %d: %w", i, err)
		}
	}
	for label, value := range map[string]string{"QMP": s.QMPSocket, "SPICE": s.SPICESocket} {
		if value == "" || !filepath.IsAbs(value) {
			return fmt.Errorf("%s socket must be an absolute path", label)
		}
		if strings.ContainsAny(value, ",\n\r") {
			return fmt.Errorf("%s socket contains unsafe delimiter", label)
		}
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
	return nil
}

func validateDisk(d Disk, root bool) error {
	if !filepath.IsAbs(d.Path) {
		return errors.New("path must be absolute")
	}
	switch d.Format {
	case "qcow2", "raw":
	default:
		return errors.New("format must be qcow2 or raw")
	}
	if d.Serial == "" {
		return errors.New("serial is required")
	}
	if strings.ContainsAny(d.Path+d.Serial, ",\n\r") {
		return errors.New("path or serial contains unsafe delimiter")
	}
	if root && d.ReadOnly {
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
		"-qmp", "unix:" + s.QMPSocket + ",server=on,wait=off",
		"-spice", "unix=on,addr=" + s.SPICESocket +
			",disable-ticketing=on,disable-copy-paste=on,disable-agent-file-xfer=on",
		"-device", "virtio-vga",
		"-chardev", "spicevmc,id=spiceagent,name=vdagent",
		"-device", "virtserialport,chardev=spiceagent,name=com.redhat.spice.0",
		"-device", "vhost-vsock-pci,guest-cid=" + strconv.FormatUint(uint64(s.VSOCKCID), 10),
		"-fw_cfg", "name=opt/private-vm/session-capability,file=/proc/self/fd/" + strconv.Itoa(s.FWCfgTokenFD),
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
