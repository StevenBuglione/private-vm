package runtime

import (
	"context"
	"io"
	"net/netip"
	"os"

	"github.com/StevenBuglione/private-vm/internal/vpn"
)

type LaunchSpec struct {
	SessionID    string
	Role         string
	ImagePath    string
	RootOverlay  string
	QMPSocket    string
	SPICESocket  string
	VSOCKCID     uint32
	VCPUs        uint32
	MemoryBytes  uint64
	Networked    bool
	ReadOnlyData []Disk
	WritableData []Disk
}

type Disk struct {
	Path   string
	Format string
	Serial string
}

type Process interface {
	PID() int
	Wait() error
	Stop(context.Context) error
}

type QEMU interface {
	Validate(LaunchSpec) error
	Launch(context.Context, LaunchSpec, InheritedFiles) (Process, error)
}

// InheritedFiles is a typed descriptor contract, never an interface name or
// arbitrary QEMU argument. Networked launches require TAP; offline launches
// must leave it nil.
type InheritedFiles struct {
	Capability *os.File
	TAP        *os.File
}

type Storage interface {
	CreateRootOverlay(context.Context, string, string) (string, error)
	CreateScratch(context.Context, uint64) (Scratch, error)
}

type Scratch interface {
	DevicePath() string
	Close(context.Context) error
	Destroy(context.Context) error
}

type Network interface {
	CreateVPNRestricted(context.Context, string, uint32, string, *vpn.MemoryStore, vpn.ResolutionPlan) (NetworkHandle, error)
	CreateOffline(context.Context, string) (NetworkHandle, error)
}

type NetworkHandle interface {
	WithTAP(context.Context, func(context.Context, *os.File) error) error
	WithGuestAddressing(context.Context, func(context.Context, GuestAddressing) error) error
	WithGuestVPNConfig(context.Context, func(context.Context, io.Reader) error) error
	Destroy(context.Context) error
}

type GuestAddressing interface {
	IPv4Address() netip.Prefix
	IPv4Gateway() netip.Addr
	IPv6Address() netip.Prefix
	IPv6Gateway() netip.Addr
}

type USB interface {
	Enumerate(context.Context) ([]USBDevice, error)
	Claim(context.Context, USBDevice) (USBHandle, error)
}

type USBDevice struct {
	SysfsPath  string
	VendorID   string
	ProductID  string
	Serial     string
	Capacity   uint64
	Interfaces []string
}

type USBHandle interface {
	QEMUDeviceArguments() []string
	Release(context.Context) error
}
