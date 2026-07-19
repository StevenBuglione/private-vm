package cli

import (
	"context"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
)

type fakeUSBDaemon struct {
	privatevmv1.UnimplementedPrivateVMDaemonServiceServer
	enrollRequest *privatevmv1.EnrollUSBDeviceRequest
	forgot        bool
}

func usbProtoDevice() *privatevmv1.USBDeviceStatus {
	return &privatevmv1.USBDeviceStatus{SchemaVersion: 1, DeviceId: "usbdev-0123456789abcdef", VendorId: "1234", ProductId: "5678", Model: "Dedicated Disk", Serial: "EXAMPLE-SERIAL", UsbguardHash: testGuardHashCLI, BlockPath: "/dev/sdz", PortPath: "1-2.3", Interfaces: []string{"08:06:50"}, CapacityBytes: 8 << 30, Selectable: true, IdentityFingerprint: testFingerprintCLI, Code: "USB_DEVICE_SELECTABLE", Remediation: "Inspect this identity before enrollment."}
}

const testGuardHashCLI = "0123456789abcdef0123456789abcdef"
const testFingerprintCLI = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func usbProtoEnrollment() *privatevmv1.USBEnrollmentStatus {
	return &privatevmv1.USBEnrollmentStatus{SchemaVersion: 1, EnrollmentId: "usb-0123456789abcdef", Label: "PRIVATE_VM_TRANSFER", Filesystem: "luks2-ext4", VendorId: "1234", ProductId: "5678", Model: "Dedicated Disk", Serial: "EXAMPLE-SERIAL", UsbguardHash: testGuardHashCLI, BlockPath: "/dev/sdz", PortPath: "1-2.3", Interfaces: []string{"08:06:50"}, CapacityBytes: 8 << 30, IdentityFingerprint: testFingerprintCLI, Verified: true, Code: "USB_ENROLLMENT_VERIFIED", Remediation: "The exact enrolled USB identity is connected and selectable."}
}

func (f *fakeUSBDaemon) ListUSBDevices(context.Context, *privatevmv1.ListUSBDevicesRequest) (*privatevmv1.ListUSBDevicesResponse, error) {
	return &privatevmv1.ListUSBDevicesResponse{Devices: []*privatevmv1.USBDeviceStatus{usbProtoDevice()}}, nil
}
func (f *fakeUSBDaemon) InspectUSBDevice(context.Context, *privatevmv1.InspectUSBDeviceRequest) (*privatevmv1.USBDeviceStatus, error) {
	return usbProtoDevice(), nil
}
func (f *fakeUSBDaemon) EnrollUSBDevice(_ context.Context, request *privatevmv1.EnrollUSBDeviceRequest) (*privatevmv1.USBEnrollmentStatus, error) {
	f.enrollRequest = request
	return usbProtoEnrollment(), nil
}
func (f *fakeUSBDaemon) VerifyUSBEnrollment(context.Context, *privatevmv1.VerifyUSBEnrollmentRequest) (*privatevmv1.USBEnrollmentStatus, error) {
	return usbProtoEnrollment(), nil
}
func (f *fakeUSBDaemon) ForgetUSBEnrollment(context.Context, *privatevmv1.ForgetUSBEnrollmentRequest) (*privatevmv1.Empty, error) {
	f.forgot = true
	return &privatevmv1.Empty{}, nil
}

func TestProductionUSBInvokerUsesTypedSemanticRPCs(t *testing.T) {
	service := &fakeUSBDaemon{}
	socket, stop := startSessionInvokerDaemon(t, service)
	defer stop()
	invoker := &ProductionInvoker{socketPath: socket, requestID: func() (string, error) { return "request-usb-1234", nil }}
	for _, test := range []struct {
		id     CommandID
		intent Intent
		code   Code
	}{
		{CommandUSBList, EmptyIntent{}, CodeUSBDevices},
		{CommandUSBInspect, USBDeviceIntent{DeviceID: "usbdev-0123456789abcdef"}, CodeUSBDevices},
		{CommandUSBEnroll, USBDeviceIntent{DeviceID: "usbdev-0123456789abcdef", Label: "PRIVATE_VM_TRANSFER", AcceptPortBinding: true}, CodeUSBEnrollment},
		{CommandUSBVerify, EmptyIntent{}, CodeUSBEnrollment},
		{CommandUSBForget, EmptyIntent{}, CodeAcknowledged},
	} {
		result, err := invoker.Invoke(t.Context(), test.id, test.intent)
		if err != nil || result.Code != test.code {
			t.Fatalf("%s result=%+v err=%v", test.id, result, err)
		}
		if _, err := NewRenderer(true).renderSuccessBytes(result.Code, result.Data); err != nil {
			t.Fatalf("%s renderer: %v", test.id, err)
		}
	}
	if service.enrollRequest == nil || !service.enrollRequest.GetAcceptPortBinding() || service.enrollRequest.GetDeviceId() == "/dev/sdz" {
		t.Fatalf("enroll request=%+v", service.enrollRequest)
	}
	if !service.forgot {
		t.Fatal("forget RPC not invoked")
	}
}
