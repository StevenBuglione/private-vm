//go:build linux

package usb

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

type fixtureGuard struct{ hash string }

func (g fixtureGuard) Hash(context.Context, GuardProbe) (string, error) { return g.hash, nil }

func TestSysfsSourceBuildsBoundedExactSnapshot(t *testing.T) {
	root := t.TempDir()
	devicesRoot := filepath.Join(root, "sys", "devices")
	usbRoot := filepath.Join(root, "sys", "bus", "usb", "devices")
	blockRoot := filepath.Join(root, "sys", "class", "block")
	devRoot := filepath.Join(root, "dev")
	devicePath := filepath.Join(devicesRoot, "pci0000:00", "usb1", "1-2.3")
	interfacePath := filepath.Join(devicePath, "1-2.3:1.0")
	blockPath := filepath.Join(devicePath, "host0", "target0", "block", "sdz")
	for _, directory := range []string{usbRoot, interfacePath, blockPath, filepath.Join(blockRoot, "sdz"), devRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture(filepath.Join(devicePath, "idVendor"), "1234")
	writeFixture(filepath.Join(devicePath, "idProduct"), "5678")
	writeFixture(filepath.Join(devicePath, "busnum"), "1")
	writeFixture(filepath.Join(devicePath, "devnum"), "2")
	writeFixture(filepath.Join(devicePath, "serial"), "EXAMPLE-SERIAL")
	writeFixture(filepath.Join(devicePath, "product"), "Dedicated Disk")
	writeFixture(filepath.Join(interfacePath, "bInterfaceClass"), "08")
	writeFixture(filepath.Join(interfacePath, "bInterfaceSubClass"), "06")
	writeFixture(filepath.Join(interfacePath, "bInterfaceProtocol"), "50")
	writeFixture(filepath.Join(blockRoot, "sdz", "size"), "268435456")
	writeFixture(filepath.Join(blockRoot, "sdz", "ro"), "0")
	writeFixture(filepath.Join(blockRoot, "sdz", "dev"), "8:240")
	if err := os.Symlink(devicePath, filepath.Join(usbRoot, "1-2.3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(interfacePath, filepath.Join(usbRoot, "1-2.3:1.0")); err != nil {
		t.Fatal(err)
	}
	mountInfo := filepath.Join(root, "mountinfo")
	writeFixture(mountInfo, "25 1 0:23 / / rw - ext4 /dev/root rw")

	source := SysfsSource{
		USBDevicesRoot: usbRoot, DevicesRoot: devicesRoot, BlockClassRoot: blockRoot,
		DevRoot: devRoot, MountInfoPath: mountInfo, Guard: fixtureGuard{hash: testGuardHash},
	}
	devices, err := source.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("got %d devices", len(devices))
	}
	device := devices[0]
	if device.Identity.Capacity != 128<<30 || device.Identity.Interfaces[0] != "08:06:50" || device.Bus != 1 || device.Address != 2 {
		t.Fatalf("unexpected snapshot: %#v", device)
	}
}

func TestMountClassificationMarksHostRoot(t *testing.T) {
	mounted, host := classifyMounts(map[string]struct{}{"8:1": {}}, []mountEvidence{{device: "8:1", mountPoint: "/boot"}})
	if !mounted || !host {
		t.Fatal("boot mount was not classified as host filesystem")
	}
}
