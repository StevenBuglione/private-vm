package cli

import (
	"bytes"
	"context"
	"io"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/secret"
)

type fakeUSBDaemon struct {
	privatevmv1.UnimplementedPrivateVMDaemonServiceServer
	enrollRequest *privatevmv1.EnrollUSBDeviceRequest
	forgot        bool
	prepared      bool
	exported      bool
	aborted       bool
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

func (f *fakeUSBDaemon) GetUSBEnrollment(context.Context, *privatevmv1.GetUSBEnrollmentRequest) (*privatevmv1.USBEnrollmentStatus, error) {
	return usbProtoEnrollment(), nil
}

func (f *fakeUSBDaemon) CreateSession(context.Context, *privatevmv1.CreateSessionRequest) (*privatevmv1.Session, error) {
	return &privatevmv1.Session{Id: "pvm-11111111111111111111111111111111", Role: privatevmv1.GuestRole_GUEST_ROLE_EXPORTER, Phase: privatevmv1.SessionPhase_SESSION_PHASE_CREATED}, nil
}

func (f *fakeUSBDaemon) ClaimUSB(context.Context, *privatevmv1.ClaimUSBRequest) (*privatevmv1.USBClaim, error) {
	return &privatevmv1.USBClaim{ClaimId: "usbclaim-0123456789abcdef0123456789abcdef", EnrollmentId: "usb-0123456789abcdef"}, nil
}

func (f *fakeUSBDaemon) PlanUSBPreparation(context.Context, *privatevmv1.PlanUSBPreparationRequest) (*privatevmv1.USBPreparePlan, error) {
	return &privatevmv1.USBPreparePlan{SchemaVersion: 1, EnrollmentId: "usb-0123456789abcdef", IdentityFingerprint: testFingerprintCLI, CapacityBytes: 8 << 30, Filesystem: "luks2-ext4", Challenge: "0123456789abcdef0123456789abcdef", FirstConfirmation: "ERASE usb-0123456789abcdef", SecondConfirmation: "ERASE usb-0123456789abcdef exact"}, nil
}

func (f *fakeUSBDaemon) PrepareUSB(stream privatevmv1.PrivateVMDaemonService_PrepareUSBServer) error {
	first, err := stream.Recv()
	if err != nil || first.GetBegin() == nil || first.GetBegin().GetFirstConfirmation() != "ERASE usb-0123456789abcdef" || first.GetBegin().GetSecondConfirmation() != "ERASE usb-0123456789abcdef exact" {
		return io.ErrUnexpectedEOF
	}
	var passphrase bytes.Buffer
	for {
		frame, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil || frame.GetPassphraseChunk() == nil {
			return io.ErrUnexpectedEOF
		}
		passphrase.Write(frame.GetPassphraseChunk().GetData())
	}
	if passphrase.String() != "correct horse battery staple" {
		return io.ErrUnexpectedEOF
	}
	f.prepared = true
	return stream.SendAndClose(&privatevmv1.USBPrepareReceipt{SchemaVersion: 1, EnrollmentId: "usb-0123456789abcdef", Filesystem: "luks2-ext4", CapacityBytes: 8 << 30, IdentityFingerprint: testFingerprintCLI, State: "DESTINATION_PREPARED"})
}

func (f *fakeUSBDaemon) ExportApprovedToUSB(context.Context, *privatevmv1.USBExportRequest) (*privatevmv1.USBExportReceipt, error) {
	f.exported = true
	return &privatevmv1.USBExportReceipt{SchemaVersion: 1, EnrollmentId: "usb-0123456789abcdef", BytesWritten: 64, ScannerRelayHashEqual: true, RelayExporterHashEqual: true, ExporterRereadHashEqual: true, FileSynced: true, FilesystemSynced: true, AtomicRename: true, UsbUnmounted: true, UsbDetached: true, ExporterStopped: true, CleanupComplete: true}, nil
}

func (f *fakeUSBDaemon) AbortSession(context.Context, *privatevmv1.AbortSessionRequest) (*privatevmv1.Session, error) {
	f.aborted = true
	return &privatevmv1.Session{}, nil
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

func TestProductionUSBPrepareUsesProtectedPromptsAndExportReceipt(t *testing.T) {
	service := &fakeUSBDaemon{}
	socket, stop := startSessionInvokerDaemon(t, service)
	defer stop()
	inputs := [][]byte{[]byte("ERASE usb-0123456789abcdef"), []byte("ERASE usb-0123456789abcdef exact"), []byte("correct horse battery staple")}
	index := 0
	invoker := &ProductionInvoker{socketPath: socket, prompt: io.Discard, requestID: func() (string, error) { return "request-usb-prepare", nil }}
	invoker.readInput = func(context.Context, ValueRequest) (*secret.Bytes, error) {
		value, err := secret.New(inputs[index])
		index++
		return value, err
	}
	prepared, err := invoker.Invoke(t.Context(), CommandUSBPrepare, USBPrepareIntent{Format: "luks2-ext4"})
	if err != nil || prepared.Code != CodeUSBPrepared || !service.prepared || service.aborted {
		t.Fatalf("prepare=%+v err=%v prepared=%t aborted=%t", prepared, err, service.prepared, service.aborted)
	}
	exported, err := invoker.Invoke(t.Context(), CommandUSBExport, USBExportIntent{ExporterSession: "pvm-11111111111111111111111111111111", ClaimID: "usbclaim-0123456789abcdef0123456789abcdef", SourceSession: "pvm-22222222222222222222222222222222", OutputID: "output-opaque-01"})
	if err != nil || exported.Code != CodeUSBExported || !service.exported {
		t.Fatalf("export=%+v err=%v", exported, err)
	}
	if _, err := NewRenderer(true).renderSuccessBytes(prepared.Code, prepared.Data); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRenderer(true).renderSuccessBytes(exported.Code, exported.Data); err != nil {
		t.Fatal(err)
	}
}
