package daemon

import (
	"context"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/usb"
	"google.golang.org/grpc/codes"
)

func (s *Service) ListUSBDevices(ctx context.Context, request *privatevmv1.ListUSBDevicesRequest) (*privatevmv1.ListUSBDevicesResponse, error) {
	identity, err := s.usbRegistryIdentity(ctx, request.GetContext())
	if err != nil {
		return nil, err
	}
	devices, err := s.USBRegistry.List(ctx, identity.UID)
	if err != nil {
		return nil, usbRPCError(err)
	}
	if len(devices) > 256 {
		return nil, rpcError(codes.ResourceExhausted, "USB_DISCOVERY_LIMIT", "USB discovery exceeded its bounded device limit.", "Disconnect unrelated USB devices and retry.", false)
	}
	result := &privatevmv1.ListUSBDevicesResponse{Devices: make([]*privatevmv1.USBDeviceStatus, 0, len(devices))}
	for _, device := range devices {
		result.Devices = append(result.Devices, usbDeviceToProto(device))
	}
	return result, nil
}

func (s *Service) InspectUSBDevice(ctx context.Context, request *privatevmv1.InspectUSBDeviceRequest) (*privatevmv1.USBDeviceStatus, error) {
	identity, err := s.usbRegistryIdentity(ctx, request.GetContext())
	if err != nil {
		return nil, err
	}
	device, err := s.USBRegistry.Inspect(ctx, identity.UID, request.GetDeviceId())
	if err != nil {
		return nil, usbRPCError(err)
	}
	return usbDeviceToProto(device), nil
}

func (s *Service) EnrollUSBDevice(ctx context.Context, request *privatevmv1.EnrollUSBDeviceRequest) (*privatevmv1.USBEnrollmentStatus, error) {
	identity, err := s.usbRegistryIdentity(ctx, request.GetContext())
	if err != nil {
		return nil, err
	}
	status, err := s.USBRegistry.Enroll(ctx, identity.UID, request.GetDeviceId(), request.GetLabel(), request.GetAcceptPortBinding())
	if err != nil {
		return nil, usbRPCError(err)
	}
	return usbEnrollmentToProto(status), nil
}

func (s *Service) GetUSBEnrollment(ctx context.Context, request *privatevmv1.GetUSBEnrollmentRequest) (*privatevmv1.USBEnrollmentStatus, error) {
	identity, err := s.usbRegistryIdentity(ctx, request.GetContext())
	if err != nil {
		return nil, err
	}
	value, err := s.USBRegistry.Get(ctx, identity.UID)
	if err != nil {
		return nil, usbRPCError(err)
	}
	return usbEnrollmentToProto(value), nil
}

func (s *Service) VerifyUSBEnrollment(ctx context.Context, request *privatevmv1.VerifyUSBEnrollmentRequest) (*privatevmv1.USBEnrollmentStatus, error) {
	identity, err := s.usbRegistryIdentity(ctx, request.GetContext())
	if err != nil {
		return nil, err
	}
	value, err := s.USBRegistry.Verify(ctx, identity.UID)
	if err != nil {
		return nil, usbRPCError(err)
	}
	return usbEnrollmentToProto(value), nil
}

func (s *Service) ForgetUSBEnrollment(ctx context.Context, request *privatevmv1.ForgetUSBEnrollmentRequest) (*privatevmv1.Empty, error) {
	identity, err := s.usbRegistryIdentity(ctx, request.GetContext())
	if err != nil {
		return nil, err
	}
	if err := s.USBRegistry.Forget(ctx, identity.UID); err != nil {
		return nil, usbRPCError(err)
	}
	return &privatevmv1.Empty{}, nil
}

func (s *Service) usbRegistryIdentity(ctx context.Context, request *privatevmv1.RequestContext) (PeerIdentity, error) {
	if err := validateRequestContext(request, false); err != nil {
		return PeerIdentity{}, err
	}
	if s.USBRegistry == nil {
		return PeerIdentity{}, rpcError(codes.Unavailable, "USB_INTEGRATION_UNAVAILABLE", "The exact USB discovery integration is unavailable.", "Install and configure the USBGuard-backed host integration before retrying.", false)
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return PeerIdentity{}, sessionError(err)
	}
	return identity, nil
}

func usbDeviceToProto(value usb.DeviceStatus) *privatevmv1.USBDeviceStatus {
	return &privatevmv1.USBDeviceStatus{
		SchemaVersion: 1, DeviceId: value.DeviceID, VendorId: value.VendorID, ProductId: value.ProductID,
		Model: value.Model, Serial: value.Serial, UsbguardHash: value.USBGuardHash, PortPath: value.PortPath, BlockPath: value.BlockPath,
		Interfaces: append([]string(nil), value.Interfaces...), CapacityBytes: value.CapacityBytes,
		Mounted: value.Mounted, ReadOnly: value.ReadOnly, HostFilesystem: value.HostFilesystem,
		Selectable: value.Selectable, IdentityFingerprint: value.IdentityFingerprint,
		Code: value.Code, Remediation: value.Remediation,
	}
}

func usbEnrollmentToProto(value usb.EnrollmentStatus) *privatevmv1.USBEnrollmentStatus {
	return &privatevmv1.USBEnrollmentStatus{
		SchemaVersion: 1, EnrollmentId: value.EnrollmentID, Label: value.Label, Filesystem: value.Filesystem,
		VendorId: value.VendorID, ProductId: value.ProductID, Model: value.Model,
		Serial: value.Serial, UsbguardHash: value.USBGuardHash, BlockPath: value.BlockPath, PortPath: value.PortPath, PortBound: value.PortBound,
		Interfaces: append([]string(nil), value.Interfaces...), CapacityBytes: value.CapacityBytes,
		IdentityFingerprint: value.IdentityFingerprint, Verified: value.Verified,
		Code: value.Code, Remediation: value.Remediation,
	}
}
