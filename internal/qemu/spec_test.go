package qemu

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/session"
)

func validSpec(t *testing.T) Spec {
	t.Helper()
	dir := t.TempDir()
	return Spec{
		Binary:       "/usr/bin/qemu-system-x86_64",
		SessionID:    "s1",
		Name:         "private-vm-s1",
		Role:         session.RoleWorkstation,
		CPUs:         4,
		MemoryBytes:  4 << 30,
		Root:         Disk{Path: filepath.Join(dir, "root.qcow2"), Format: "qcow2", Serial: "root"},
		QMPSocket:    filepath.Join(dir, "qmp.sock"),
		SPICESocket:  filepath.Join(dir, "spice.sock"),
		VSOCKCID:     42,
		TAPName:      "tap-pvm-test",
		Networked:    true,
		FWCfgTokenFD: 3,
	}
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
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing required argument %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{"virtiofs", "9p", "usb-redir", "usb-host", "-daemonize", "port="} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("forbidden argument %q present", forbidden)
		}
	}
	if err := ValidateNoTCPListener(args); err != nil {
		t.Fatal(err)
	}
}

func TestScannerScanArgsHaveReadOnlyQuarantineAndNoNIC(t *testing.T) {
	spec := validSpec(t)
	spec.Role = session.RoleScanner
	spec.ScannerMode = ScannerModeScan
	spec.Networked = false
	spec.TAPName = ""
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
	spec.TAPName = ""
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
		func(spec *Spec) { spec.Networked, spec.TAPName = false, "" },
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

func TestRejectsRelativeBinary(t *testing.T) {
	spec := validSpec(t)
	spec.Binary = "qemu"
	if err := spec.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}
