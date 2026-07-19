package daemon

import (
	"context"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/usb"
)

type registryFixture struct {
	owner     uint32
	forgotten bool
	enrolled  usb.Enrollment
}

func (f *registryFixture) List(ctx context.Context, owner uint32) ([]usb.DeviceStatus, error) {
	f.owner = owner
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []usb.DeviceStatus{registryDevice()}, nil
}
func (f *registryFixture) Inspect(ctx context.Context, owner uint32, _ string) (usb.DeviceStatus, error) {
	f.owner = owner
	if err := ctx.Err(); err != nil {
		return usb.DeviceStatus{}, err
	}
	return registryDevice(), nil
}
func (f *registryFixture) Enroll(ctx context.Context, owner uint32, _, _ string, _ bool) (usb.EnrollmentStatus, error) {
	f.owner = owner
	if err := ctx.Err(); err != nil {
		return usb.EnrollmentStatus{}, err
	}
	return registryEnrollment(), nil
}
func (f *registryFixture) Get(context.Context, uint32) (usb.EnrollmentStatus, error) {
	return registryEnrollment(), nil
}
func (f *registryFixture) Verify(ctx context.Context, owner uint32) (usb.EnrollmentStatus, error) {
	f.owner = owner
	if err := ctx.Err(); err != nil {
		return usb.EnrollmentStatus{}, err
	}
	return registryEnrollment(), nil
}
func (f *registryFixture) Forget(ctx context.Context, owner uint32) error {
	f.owner = owner
	if err := ctx.Err(); err != nil {
		return err
	}
	f.forgotten = true
	return nil
}
func (f *registryFixture) Load(uint32) (usb.Enrollment, error) { return f.enrolled, nil }

func registryDevice() usb.DeviceStatus {
	return usb.DeviceStatus{DeviceID: "usbdev-0123456789abcdef", VendorID: "1234", ProductID: "5678", Model: "Disk", Serial: "SERIAL", USBGuardHash: "0123456789abcdef", PortPath: "1-2", BlockPath: "/dev/sdz", Interfaces: []string{"08:06:50"}, CapacityBytes: 8 << 30, Selectable: true, IdentityFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Code: "USB_DEVICE_SELECTABLE", Remediation: "Inspect this identity."}
}
func registryEnrollment() usb.EnrollmentStatus {
	d := registryDevice()
	return usb.EnrollmentStatus{EnrollmentID: "usb-0123456789abcdef", Label: "PRIVATE_VM_TRANSFER", Filesystem: "luks2-ext4", VendorID: d.VendorID, ProductID: d.ProductID, Model: d.Model, Serial: d.Serial, USBGuardHash: d.USBGuardHash, BlockPath: d.BlockPath, PortPath: d.PortPath, Interfaces: d.Interfaces, CapacityBytes: d.CapacityBytes, IdentityFingerprint: d.IdentityFingerprint, Verified: true, Code: "USB_ENROLLMENT_VERIFIED", Remediation: "The exact identity is verified."}
}

func TestUSBRegistryRPCsAreKernelOwnerBoundAndTyped(t *testing.T) {
	registry := &registryFixture{}
	service := &Service{USBRegistry: registry}
	identity := currentProcessIdentity(t)
	ctx := context.WithValue(t.Context(), identityContextKey{}, identity)
	listed, err := service.ListUSBDevices(ctx, &privatevmv1.ListUSBDevicesRequest{Context: validRequestContext("")})
	if err != nil || len(listed.GetDevices()) != 1 || listed.GetDevices()[0].GetBlockPath() != "/dev/sdz" {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	enrolled, err := service.EnrollUSBDevice(ctx, &privatevmv1.EnrollUSBDeviceRequest{Context: validRequestContext(""), DeviceId: "usbdev-0123456789abcdef", Label: "PRIVATE_VM_TRANSFER"})
	if err != nil || !enrolled.GetVerified() {
		t.Fatalf("enroll=%+v err=%v", enrolled, err)
	}
	if _, err := service.VerifyUSBEnrollment(ctx, &privatevmv1.VerifyUSBEnrollmentRequest{Context: validRequestContext("")}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ForgetUSBEnrollment(ctx, &privatevmv1.ForgetUSBEnrollmentRequest{Context: validRequestContext("")}); err != nil {
		t.Fatal(err)
	}
	if registry.owner != identity.UID || !registry.forgotten {
		t.Fatalf("owner=%d forgot=%t", registry.owner, registry.forgotten)
	}
}

func TestUSBRegistryRPCCancellationDoesNotMutate(t *testing.T) {
	registry := &registryFixture{}
	service := &Service{USBRegistry: registry}
	identity := currentProcessIdentity(t)
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), identityContextKey{}, identity))
	cancel()
	if _, err := service.EnrollUSBDevice(ctx, &privatevmv1.EnrollUSBDeviceRequest{Context: validRequestContext(""), DeviceId: "usbdev-0123456789abcdef", Label: "PRIVATE_VM_TRANSFER"}); err == nil {
		t.Fatal("canceled enrollment succeeded")
	}
	if registry.forgotten {
		t.Fatal("canceled operation mutated registry")
	}
}
