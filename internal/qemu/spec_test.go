package qemu

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/session"
)

func validSpec(t *testing.T) Spec {
	t.Helper()
	dir := privateTestDir(t)
	return Spec{
		Binary:       testBinary(t),
		SessionID:    "pvm-0123456789abcdef0123456789abcdef",
		Name:         "private-vm-test",
		Role:         session.RoleWorkstation,
		CPUs:         4,
		MemoryBytes:  4 << 30,
		Root:         Disk{Path: filepath.Join(dir, "root.qcow2"), Format: "qcow2", Serial: "root"},
		QMPSocket:    filepath.Join(dir, "qmp.sock"),
		SPICESocket:  filepath.Join(dir, "spice.sock"),
		VSOCKCID:     42,
		Networked:    true,
		NetworkFD:    4,
		FWCfgTokenFD: 3,
	}
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestWorkstationArgsUseOnlyUnixDisplayAndExpectedDevices(t *testing.T) {
	spec := validSpec(t)
	args, err := spec.Args()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"unix=on,addr=" + spec.SPICESocket,
		"disable-copy-paste=on",
		"disable-agent-file-xfer=on",
		"spicevmc",
		"virtio-serial-pci,id=spice-serial",
		"virtserialport,bus=spice-serial.0,chardev=spiceagent,name=com.redhat.spice.0",
		"vhost-vsock-pci",
		"virtio-rng-pci",
		"virtio-net-pci",
		"tap,id=net0,fd=4,vhost=on",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing required argument %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{"virtiofs", "9p", "usb-redir", "usb-host", "-daemonize", "port=", "ifname=", "script="} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("forbidden argument %q present", forbidden)
		}
	}
	if err := ValidateNoTCPListener(args); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkDescriptorPositionIsFixed(t *testing.T) {
	spec := validSpec(t)
	for _, descriptor := range []int{-1, 0, 3, 5} {
		spec.NetworkFD = descriptor
		if err := spec.Validate(); err == nil {
			t.Fatalf("network descriptor %d unexpectedly passed", descriptor)
		}
	}
}

func TestScannerScanArgsHaveReadOnlyQuarantineAndNoNIC(t *testing.T) {
	spec := validSpec(t)
	spec.Role = session.RoleScanner
	spec.ScannerMode = ScannerModeScan
	spec.Networked = false
	spec.NetworkFD = 0
	spec.Data = []Disk{{Path: filepath.Join(t.TempDir(), "quarantine.raw"), Format: "raw", ReadOnly: true, Serial: "quarantine"}}
	args, err := spec.Args()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-nic none") || !strings.Contains(joined, "readonly=on") || strings.Contains(joined, "virtio-net-pci") {
		t.Fatalf("scanner isolation arguments are wrong: %s", joined)
	}
}

func TestExporterHasNoDisplayOrNetwork(t *testing.T) {
	spec := validSpec(t)
	spec.Role = session.RoleExporter
	spec.Networked = false
	spec.NetworkFD = 0
	spec.SPICESocket = ""
	spec.USB = &USBDevice{Bus: 2, Address: 4}
	args, err := spec.Args()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-spice") || strings.Contains(joined, "virtio-vga") || strings.Contains(joined, "virtio-net") {
		t.Fatalf("exporter received a forbidden display or network device: %s", joined)
	}
	if !strings.Contains(joined, "usb-host") || !strings.Contains(joined, "-nic none") {
		t.Fatalf("exporter arguments are incomplete: %s", joined)
	}
}

func TestRoleDeviceMatrixFailsClosed(t *testing.T) {
	tests := []func(*Spec){
		func(spec *Spec) { spec.Networked, spec.NetworkFD = false, 0 },
		func(spec *Spec) {
			spec.Role = session.RoleDownloader
			spec.Data = nil
		},
		func(spec *Spec) {
			spec.Role = session.RoleScanner
			spec.ScannerMode = ScannerModeScan
		},
		func(spec *Spec) { spec.USB = &USBDevice{Bus: 1, Address: 1} },
	}
	for index, mutate := range tests {
		spec := validSpec(t)
		mutate(&spec)
		if err := spec.Validate(); err == nil {
			t.Fatalf("case %d unexpectedly passed", index)
		}
	}
}

func TestExecutableValidationFailsClosed(t *testing.T) {
	t.Run("relative", func(t *testing.T) {
		spec := validSpec(t)
		spec.Binary = "qemu"
		if err := spec.Validate(); err == nil {
			t.Fatal("expected validation error")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		spec := validSpec(t)
		link := filepath.Join(t.TempDir(), "qemu")
		if err := os.Symlink(spec.Binary, link); err != nil {
			t.Fatal(err)
		}
		spec.Binary = link
		if err := spec.Validate(); err == nil {
			t.Fatal("expected symbolic executable rejection")
		}
	})
	t.Run("writable", func(t *testing.T) {
		spec := validSpec(t)
		binary := filepath.Join(t.TempDir(), "qemu")
		if err := os.WriteFile(binary, []byte("not executed"), 0o775); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(binary, 0o775); err != nil {
			t.Fatal(err)
		}
		spec.Binary = binary
		if err := spec.Validate(); err == nil {
			t.Fatal("expected group-writable executable rejection")
		}
	})
}

func TestSocketDestinationTrustFailsClosed(t *testing.T) {
	t.Run("existing", func(t *testing.T) {
		spec := validSpec(t)
		if err := os.WriteFile(spec.QMPSocket, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := spec.Validate(); err == nil {
			t.Fatal("expected pre-existing socket destination rejection")
		}
	})
	t.Run("broad parent", func(t *testing.T) {
		spec := validSpec(t)
		parent := filepath.Dir(spec.QMPSocket)
		if err := os.Chmod(parent, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := spec.Validate(); err == nil {
			t.Fatal("expected broad socket-parent mode rejection")
		}
	})
	t.Run("same endpoint", func(t *testing.T) {
		spec := validSpec(t)
		spec.SPICESocket = spec.QMPSocket
		if err := spec.Validate(); err == nil {
			t.Fatal("expected shared QMP/SPICE endpoint rejection")
		}
	})
}

func TestRenderedArgumentGuardRejectsSharedFilesystemsAndTCP(t *testing.T) {
	for _, args := range [][]string{
		{"-fsdev", "local,id=fs0,path=/tmp"},
		{"-device", "vhost-user-fs-pci,chardev=char0"},
		{"-spice", "port=5900"},
		{"-qmp", "127.0.0.1:4444"},
		{"-device", "usb-redir,chardev=redir0"},
	} {
		if err := validateRenderedArgs(args); err == nil {
			t.Fatalf("forbidden arguments passed: %v", args)
		}
	}
}

func TestDownloaderAndScannerUpdateDeviceMatrix(t *testing.T) {
	downloader := validSpec(t)
	downloader.Role = session.RoleDownloader
	downloader.Data = []Disk{{Path: filepath.Join(t.TempDir(), "quarantine.raw"), Format: "raw", Serial: "quarantine"}}
	if _, err := downloader.Args(); err != nil {
		t.Fatalf("valid downloader: %v", err)
	}

	update := validSpec(t)
	update.Role = session.RoleScanner
	update.ScannerMode = ScannerModeUpdate
	if _, err := update.Args(); err != nil {
		t.Fatalf("valid scanner update: %v", err)
	}
}
