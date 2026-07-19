package usb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testGuardHash = "0123456789abcdef0123456789abcdef"

func validIdentity() Identity {
	return Identity{
		VendorID: "1234", ProductID: "5678", Serial: "EXAMPLE-SERIAL",
		USBGuardHash: testGuardHash, PortPath: "1-2.3", Capacity: 128 << 30,
		Interfaces: []string{"08:06:50"}, Model: "Dedicated Disk",
	}
}

func validDevice() Device {
	identity := validIdentity()
	return Device{
		DeviceID: snapshotDeviceID(identity, 1, 2, "/dev/sdz"),
		Identity: identity, SysfsPath: "/sys/devices/test", BlockPath: "/dev/sdz",
		Bus: 1, Address: 2,
	}
}

func TestIdentityRejectsCompositeDevice(t *testing.T) {
	id := validIdentity()
	id.Interfaces = []string{"08:06:50", "03:01:01"}
	if err := id.ValidateForEnrollment(); err == nil {
		t.Fatal("expected composite interface rejection")
	}
}

func TestIdentityRequiresSerialOrAcceptedPortBinding(t *testing.T) {
	id := validIdentity()
	id.Serial = ""
	if err := id.ValidateForEnrollment(); err == nil {
		t.Fatal("expected missing serial rejection")
	}
	id.PortBound = true
	if err := id.ValidateForEnrollment(); err != nil {
		t.Fatalf("accepted port-bound identity rejected: %v", err)
	}
}

func TestIdentityMatchingPinsCompleteIdentity(t *testing.T) {
	enrolled := validIdentity()
	current := validIdentity()
	current.Interfaces = []string{"08:06:62"}
	if enrolled.Matches(current) {
		t.Fatal("changed interface protocol matched enrollment")
	}
	current = validIdentity()
	current.Capacity++
	if enrolled.Matches(current) {
		t.Fatal("changed capacity matched enrollment")
	}
}

func TestEnrollmentRoundTripAndUnknownFieldRejection(t *testing.T) {
	enrollment, err := NewEnrollment(validIdentity(), "PRIVATE_VM_TRANSFER")
	if err != nil {
		t.Fatal(err)
	}
	data, err := EncodeEnrollment(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEnrollment(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.EnrollmentID != enrollment.EnrollmentID || !decoded.Identity.Matches(enrollment.Identity) {
		t.Fatal("enrollment round trip changed identity")
	}
	mutated := bytes.Replace(data, []byte(`"filesystem"`), []byte(`"unexpected":true,"filesystem"`), 1)
	if _, err := DecodeEnrollment(bytes.NewReader(mutated)); err == nil {
		t.Fatal("unknown enrollment field accepted")
	}
}

func TestCheckedInEnrollmentExample(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "usb-enrollment.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var enrollment Enrollment
	if err := json.Unmarshal(data, &enrollment); err != nil {
		t.Fatal(err)
	}
	sum, err := enrollment.Identity.fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	want := "usb-" + fmt.Sprintf("%x", sum[:8])
	if enrollment.EnrollmentID != want {
		t.Fatalf("example enrollment id is %s; want %s", enrollment.EnrollmentID, want)
	}
}

func TestUSBGuardRulePinsExactMassStorageIdentity(t *testing.T) {
	enrollment, err := NewEnrollment(validIdentity(), "PRIVATE_VM_TRANSFER")
	if err != nil {
		t.Fatal(err)
	}
	rule, err := USBGuardRule(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"id 1234:5678", `serial "EXAMPLE-SERIAL"`, `hash "` + testGuardHash + `"`, `via-port "1-2.3"`, "with-interface equals { 08:06:50 }"} {
		if !strings.Contains(rule, expected) {
			t.Fatalf("rule %q missing %q", rule, expected)
		}
	}
}

func TestStoreRoundTripAndSymlinkRejection(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(directory, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, _ := NewEnrollment(validIdentity(), "PRIVATE_VM_TRANSFER")
	if err := store.Save(enrollment); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.EnrollmentID != enrollment.EnrollmentID {
		t.Fatal("stored enrollment changed")
	}
	if err := store.Forget(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("forgotten enrollment loaded")
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, enrollmentFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("symlinked enrollment loaded")
	}
}

type staticSource struct {
	devices []Device
	err     error
}

func (s staticSource) Snapshot(context.Context) ([]Device, error) {
	return append([]Device(nil), s.devices...), s.err
}

func TestEnumeratorFailsClosedOnMountedHostAndCompositeDevices(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Device)
		code ErrorCode
	}{
		{"mounted", func(device *Device) { device.Mounted = true }, CodeMounted},
		{"host", func(device *Device) { device.HostFilesystem = true }, CodeHostFilesystem},
		{"read-only", func(device *Device) { device.ReadOnly = true }, CodeReadOnly},
		{"composite", func(device *Device) { device.Identity.Interfaces = append(device.Identity.Interfaces, "03:01:01") }, CodeComposite},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			device := validDevice()
			test.edit(&device)
			device.DeviceID = snapshotDeviceID(device.Identity, device.Bus, device.Address, device.BlockPath)
			enumerator := Enumerator{Source: staticSource{devices: []Device{device}}}
			_, err := enumerator.Inspect(t.Context(), device.DeviceID)
			var usbError *Error
			if !errors.As(err, &usbError) || usbError.Code != test.code {
				t.Fatalf("got %v, want %s", err, test.code)
			}
		})
	}
}

func TestResolveEnrollmentRejectsIdentityDriftAndAmbiguity(t *testing.T) {
	device := validDevice()
	enrollment, err := NewEnrollmentFromDevice(device, "PRIVATE_VM_TRANSFER", false)
	if err != nil {
		t.Fatal(err)
	}
	changed := device
	changed.Identity.Capacity++
	changed.DeviceID = snapshotDeviceID(changed.Identity, changed.Bus, changed.Address, changed.BlockPath)
	if _, err := (Enumerator{Source: staticSource{devices: []Device{changed}}}).ResolveEnrollment(t.Context(), enrollment); err == nil {
		t.Fatal("changed capacity resolved")
	}
	if _, err := (Enumerator{Source: staticSource{devices: []Device{device, device}}}).ResolveEnrollment(t.Context(), enrollment); err == nil {
		t.Fatal("duplicate device resolved")
	}
}
