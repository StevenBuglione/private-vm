package runtime

import "context"

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
	Launch(context.Context, LaunchSpec) (Process, error)
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
	CreateVPNRestricted(context.Context, string, Endpoint) (NetworkHandle, error)
	CreateOffline(context.Context, string) (NetworkHandle, error)
}

type Endpoint struct {
	IP   string
	Port uint16
}

type NetworkHandle interface {
	TAPName() string
	Destroy(context.Context) error
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
