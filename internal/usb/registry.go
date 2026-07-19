package usb

import (
	"context"
	"errors"
)

const DefaultEnrollmentLabel = "PRIVATE_VM_TRANSFER"

// DeviceStatus is the bounded, typed review view that may cross the daemon
// boundary. It includes the exact identity and transient block observation the
// user must review, but never raw USBGuard output or transient bus/address.
// BlockPath is not persisted and is never accepted as authorization.
type DeviceStatus struct {
	DeviceID            string
	VendorID            string
	ProductID           string
	Model               string
	Serial              string
	USBGuardHash        string
	PortPath            string
	BlockPath           string
	Interfaces          []string
	CapacityBytes       uint64
	Mounted             bool
	ReadOnly            bool
	HostFilesystem      bool
	Selectable          bool
	IdentityFingerprint string
	Code                string
	Remediation         string
}

// EnrollmentStatus is the owner-specific identity review view. BlockPath is
// populated only after live re-resolution and is absent from the stored record.
type EnrollmentStatus struct {
	EnrollmentID        string
	Label               string
	Filesystem          string
	VendorID            string
	ProductID           string
	Model               string
	Serial              string
	USBGuardHash        string
	BlockPath           string
	PortPath            string
	PortBound           bool
	Interfaces          []string
	CapacityBytes       uint64
	IdentityFingerprint string
	Verified            bool
	Code                string
	Remediation         string
}

type OwnerStoreProvider interface {
	ForOwner(ownerUID uint32, create bool) (*Store, error)
}

// Registry owns USB discovery and the exact enrollment record for each
// kernel-authenticated Unix owner. It exposes semantic operations only.
type Registry struct {
	enumerator Enumerator
	stores     OwnerStoreProvider
}

func NewRegistry(enumerator Enumerator, stores OwnerStoreProvider) (*Registry, error) {
	if enumerator.Source == nil || stores == nil {
		return nil, errors.New("USB registry requires discovery and owner stores")
	}
	return &Registry{enumerator: enumerator, stores: stores}, nil
}

func (r *Registry) List(ctx context.Context, _ uint32) ([]DeviceStatus, error) {
	devices, err := r.enumerator.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]DeviceStatus, 0, len(devices))
	for _, device := range devices {
		result = append(result, deviceStatus(device))
	}
	return result, nil
}

func (r *Registry) Inspect(ctx context.Context, _ uint32, deviceID string) (DeviceStatus, error) {
	if !deviceIDPattern.MatchString(deviceID) {
		return DeviceStatus{}, newError(CodeIdentityMismatch, "The USB selection identifier is invalid.", "Run usb list again and select one displayed identifier.", nil)
	}
	devices, err := r.enumerator.List(ctx)
	if err != nil {
		return DeviceStatus{}, err
	}
	for _, device := range devices {
		if device.DeviceID == deviceID {
			return deviceStatus(device), nil
		}
	}
	return DeviceStatus{}, newError(CodeIdentityMismatch, "The selected USB device is no longer present.", "Run usb list again and reselect the exact dedicated device.", nil)
}

func (r *Registry) Enroll(ctx context.Context, ownerUID uint32, deviceID, label string, acceptPortBinding bool) (EnrollmentStatus, error) {
	device, err := r.enumerator.Inspect(ctx, deviceID)
	if err != nil {
		return EnrollmentStatus{}, err
	}
	if err := ctx.Err(); err != nil {
		return EnrollmentStatus{}, err
	}
	if label == "" {
		label = DefaultEnrollmentLabel
	}
	enrollment, err := NewEnrollmentFromDevice(device, label, acceptPortBinding)
	if err != nil {
		var application *Error
		if errors.As(err, &application) {
			return EnrollmentStatus{}, err
		}
		return EnrollmentStatus{}, newError(CodeIdentityMismatch, "The USB enrollment request is invalid.", "Use a reviewed uppercase label and inspect the exact device again.", err)
	}
	store, err := r.stores.ForOwner(ownerUID, true)
	if err != nil {
		return EnrollmentStatus{}, newError(CodeDiscoveryFailed, "The private USB enrollment store is unavailable.", "Verify the installed enrollment directory ownership and retry.", err)
	}
	if err := store.Save(enrollment); err != nil {
		return EnrollmentStatus{}, newError(CodeDiscoveryFailed, "The USB enrollment could not be saved safely.", "Verify the private enrollment directory ownership and retry.", err)
	}
	status := enrollmentStatus(enrollment, true, "USB_ENROLLMENT_VERIFIED", "The exact enrolled USB identity is connected and selectable.")
	status.BlockPath = device.BlockPath
	return status, nil
}

func (r *Registry) Load(ownerUID uint32) (Enrollment, error) {
	store, err := r.stores.ForOwner(ownerUID, false)
	if err != nil {
		return Enrollment{}, newError(CodeNotEnrolled, "No USB device is enrolled.", "Enroll one dedicated mass-storage-only USB device before exporting.", err)
	}
	return store.Load()
}

func (r *Registry) Get(ctx context.Context, ownerUID uint32) (EnrollmentStatus, error) {
	if err := ctx.Err(); err != nil {
		return EnrollmentStatus{}, err
	}
	enrollment, err := r.Load(ownerUID)
	if err != nil {
		return EnrollmentStatus{}, err
	}
	return enrollmentStatus(enrollment, false, "USB_ENROLLMENT_PRESENT", "Run usb verify with the enrolled device connected before claiming it."), nil
}

func (r *Registry) Verify(ctx context.Context, ownerUID uint32) (EnrollmentStatus, error) {
	enrollment, err := r.Load(ownerUID)
	if err != nil {
		return EnrollmentStatus{}, err
	}
	device, err := r.enumerator.ResolveEnrollment(ctx, enrollment)
	if err != nil {
		return EnrollmentStatus{}, err
	}
	status := enrollmentStatus(enrollment, true, "USB_ENROLLMENT_VERIFIED", "The exact enrolled USB identity is connected and selectable.")
	status.BlockPath = device.BlockPath
	return status, nil
}

func (r *Registry) Forget(ctx context.Context, ownerUID uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store, err := r.stores.ForOwner(ownerUID, false)
	if err != nil {
		return nil
	}
	return store.Forget()
}

func deviceStatus(device Device) DeviceStatus {
	identity := device.Identity.normalized()
	fingerprint, _ := identity.Fingerprint()
	status := DeviceStatus{
		DeviceID: device.DeviceID, VendorID: identity.VendorID, ProductID: identity.ProductID,
		Model: identity.Model, Serial: identity.Serial, USBGuardHash: identity.USBGuardHash, PortPath: identity.PortPath, BlockPath: device.BlockPath,
		Interfaces: append([]string(nil), identity.Interfaces...), CapacityBytes: identity.Capacity,
		Mounted: device.Mounted, ReadOnly: device.ReadOnly, HostFilesystem: device.HostFilesystem,
		IdentityFingerprint: fingerprint,
	}
	if err := validateSelectable(device); err != nil {
		var application *Error
		if errors.As(err, &application) {
			status.Code = string(application.Code)
			status.Remediation = application.Remediation
		} else {
			status.Code = string(CodeIdentityMismatch)
			status.Remediation = "Reconnect the dedicated device and inspect it again."
		}
		return status
	}
	status.Selectable = true
	status.Code = "USB_DEVICE_SELECTABLE"
	status.Remediation = "Inspect this identity before enrollment."
	return status
}

func enrollmentStatus(enrollment Enrollment, verified bool, code, remediation string) EnrollmentStatus {
	identity := enrollment.Identity.normalized()
	fingerprint, _ := identity.Fingerprint()
	return EnrollmentStatus{
		EnrollmentID: enrollment.EnrollmentID, Label: enrollment.Label, Filesystem: enrollment.Filesystem,
		VendorID: identity.VendorID, ProductID: identity.ProductID, Model: identity.Model,
		Serial: identity.Serial, USBGuardHash: identity.USBGuardHash, PortPath: identity.PortPath, PortBound: identity.PortBound,
		Interfaces: append([]string(nil), identity.Interfaces...), CapacityBytes: identity.Capacity,
		IdentityFingerprint: fingerprint, Verified: verified, Code: code, Remediation: remediation,
	}
}
