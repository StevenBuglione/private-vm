package usb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var deviceIDPattern = regexp.MustCompile(`^usbdev-[0-9a-f]{16}$`)

// Device is a single, point-in-time kernel observation. BlockPath, Bus and
// Address can be used only after ResolveEnrollment returns this exact snapshot.
type Device struct {
	DeviceID       string
	Identity       Identity
	SysfsPath      string
	BlockPath      string
	Bus            uint8
	Address        uint8
	Mounted        bool
	ReadOnly       bool
	HostFilesystem bool
}

type Source interface {
	Snapshot(context.Context) ([]Device, error)
}

type Enumerator struct {
	Source Source
}

func (e Enumerator) List(ctx context.Context) ([]Device, error) {
	if e.Source == nil {
		return nil, newError(CodeDiscoveryFailed, "USB discovery is unavailable.", "Install the USB discovery integration and retry.", nil)
	}
	devices, err := e.Source.Snapshot(ctx)
	if err != nil {
		return nil, newError(CodeDiscoveryFailed, "USB discovery failed.", "Reconnect the dedicated device and retry USB inspection.", err)
	}
	seen := make(map[string]struct{}, len(devices))
	for index := range devices {
		if err := validateObservedDevice(devices[index]); err != nil {
			return nil, newError(CodeDiscoveryFailed, "USB discovery returned invalid device evidence.", "Reconnect the dedicated device and retry USB inspection.", err)
		}
		if _, exists := seen[devices[index].DeviceID]; exists {
			return nil, newError(CodeAmbiguous, "USB discovery returned an ambiguous device identity.", "Disconnect duplicate devices and retry.", nil)
		}
		seen[devices[index].DeviceID] = struct{}{}
	}
	sort.Slice(devices, func(a, b int) bool { return devices[a].DeviceID < devices[b].DeviceID })
	return devices, nil
}

func (e Enumerator) Inspect(ctx context.Context, deviceID string) (Device, error) {
	if !deviceIDPattern.MatchString(deviceID) {
		return Device{}, newError(CodeIdentityMismatch, "The USB selection identifier is invalid.", "Run usb list again and select one displayed identifier.", nil)
	}
	devices, err := e.List(ctx)
	if err != nil {
		return Device{}, err
	}
	var matches []Device
	for _, device := range devices {
		if device.DeviceID == deviceID {
			matches = append(matches, device)
		}
	}
	if len(matches) != 1 {
		code := CodeIdentityMismatch
		message := "The selected USB device is no longer present."
		if len(matches) > 1 {
			code = CodeAmbiguous
			message = "The selected USB device is ambiguous."
		}
		return Device{}, newError(code, message, "Run usb list again and reselect the exact dedicated device.", nil)
	}
	if err := validateSelectable(matches[0]); err != nil {
		return Device{}, err
	}
	return matches[0], nil
}

func NewEnrollmentFromDevice(device Device, label string, acceptPortBinding bool) (Enrollment, error) {
	if err := validateSelectable(device); err != nil {
		return Enrollment{}, err
	}
	identity := device.Identity.normalized()
	identity.PortBound = identity.Serial == "" && acceptPortBinding
	if identity.Serial == "" && !identity.PortBound {
		return Enrollment{}, newError(CodeIdentityMismatch, "The USB device has no stable serial identity.", "Explicitly accept binding this enrollment to the displayed physical port.", nil)
	}
	return NewEnrollment(identity, label)
}

func (e Enumerator) ResolveEnrollment(ctx context.Context, enrollment Enrollment) (Device, error) {
	if err := enrollment.Validate(); err != nil {
		return Device{}, newError(CodeNotEnrolled, "The USB enrollment record is invalid.", "Forget and re-enroll the dedicated device.", err)
	}
	devices, err := e.List(ctx)
	if err != nil {
		return Device{}, err
	}
	matches := make([]Device, 0, 1)
	for _, device := range devices {
		observed := device.Identity
		observed.PortBound = enrollment.Identity.PortBound
		if enrollment.Identity.Matches(observed) {
			matches = append(matches, device)
		}
	}
	if len(matches) == 0 {
		return Device{}, newError(CodeIdentityMismatch, "No connected USB matches the enrolled identity.", "Reconnect the enrolled device at its enrolled physical port and retry.", nil)
	}
	if len(matches) != 1 {
		return Device{}, newError(CodeAmbiguous, "More than one connected USB matches the enrolled identity.", "Disconnect duplicate devices and retry.", nil)
	}
	if err := validateSelectable(matches[0]); err != nil {
		return Device{}, err
	}
	return matches[0], nil
}

func validateObservedDevice(device Device) error {
	if !deviceIDPattern.MatchString(device.DeviceID) {
		return errors.New("invalid USB snapshot identifier")
	}
	if device.SysfsPath == "" || device.BlockPath == "" || device.Bus == 0 || device.Address == 0 {
		return errors.New("incomplete USB kernel observation")
	}
	identity := device.Identity.normalized()
	if !hexIDPattern.MatchString(identity.VendorID) || !hexIDPattern.MatchString(identity.ProductID) ||
		!portPattern.MatchString(identity.PortPath) || !usbGuardHashPattern.MatchString(identity.USBGuardHash) ||
		identity.Capacity == 0 || len(identity.Interfaces) == 0 || len(identity.Interfaces) > 32 {
		return errors.New("invalid USB identity observation")
	}
	for _, iface := range identity.Interfaces {
		if !interfacePattern.MatchString(iface) {
			return errors.New("invalid USB interface observation")
		}
	}
	return nil
}

func validateSelectable(device Device) error {
	if err := validateObservedDevice(device); err != nil {
		return newError(CodeIdentityMismatch, "The selected USB identity is incomplete.", "Reconnect the dedicated device and inspect it again.", err)
	}
	if device.HostFilesystem {
		return newError(CodeHostFilesystem, "A host root or boot device cannot be selected.", "Use a separate dedicated USB mass-storage device.", nil)
	}
	if device.Mounted {
		return newError(CodeMounted, "The selected USB device is mounted on the host.", "Unmount it through the operating system and disable automount before retrying.", nil)
	}
	if device.ReadOnly {
		return newError(CodeReadOnly, "The selected USB device is read-only.", "Use a writable dedicated USB device.", nil)
	}
	for _, iface := range device.Identity.Interfaces {
		if !strings.HasPrefix(strings.ToLower(iface), MassStorageClass+":") {
			return newError(CodeComposite, "The selected USB exposes a non-storage interface.", "Use a device whose complete interface set is mass-storage only.", nil)
		}
	}
	return nil
}

func snapshotDeviceID(identity Identity, bus, address uint8, blockPath string) string {
	interfaces := append([]string(nil), identity.Interfaces...)
	sort.Strings(interfaces)
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%s\x00%s", identity.VendorID, identity.ProductID, identity.Serial, identity.PortPath, bus, address, blockPath, strings.Join(interfaces, ","))))
	return "usbdev-" + hex.EncodeToString(sum[:8])
}
