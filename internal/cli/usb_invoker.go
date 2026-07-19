package cli

import (
	"context"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

func (invoker *ProductionInvoker) invokeUSB(ctx context.Context, id CommandID, intent Intent) (Result, error) {
	connection, client, err := invoker.client()
	if err != nil {
		return Result{}, err
	}
	defer connection.Close()
	requestID, err := invoker.nextRequestID()
	if err != nil {
		return Result{}, internalUSBError()
	}
	requestContext := vpnRequestContext(requestID)
	switch id {
	case CommandUSBList:
		response, callErr := client.ListUSBDevices(ctx, &privatevmv1.ListUSBDevicesRequest{Context: requestContext})
		if callErr != nil {
			return Result{}, daemonRPCError(callErr)
		}
		return usbDevicesResult(response.GetDevices())
	case CommandUSBInspect:
		request, ok := intent.(USBDeviceIntent)
		if !ok {
			return Result{}, invalidUSBIntent()
		}
		response, callErr := client.InspectUSBDevice(ctx, &privatevmv1.InspectUSBDeviceRequest{Context: requestContext, DeviceId: request.DeviceID})
		if callErr != nil {
			return Result{}, daemonRPCError(callErr)
		}
		return usbDevicesResult([]*privatevmv1.USBDeviceStatus{response})
	case CommandUSBEnroll:
		request, ok := intent.(USBDeviceIntent)
		if !ok {
			return Result{}, invalidUSBIntent()
		}
		response, callErr := client.EnrollUSBDevice(ctx, &privatevmv1.EnrollUSBDeviceRequest{Context: requestContext, DeviceId: request.DeviceID, Label: request.Label, AcceptPortBinding: request.AcceptPortBinding})
		if callErr != nil {
			return Result{}, daemonRPCError(callErr)
		}
		return usbEnrollmentResult(response)
	case CommandUSBVerify:
		response, callErr := client.VerifyUSBEnrollment(ctx, &privatevmv1.VerifyUSBEnrollmentRequest{Context: requestContext})
		if callErr != nil {
			return Result{}, daemonRPCError(callErr)
		}
		return usbEnrollmentResult(response)
	case CommandUSBForget:
		if _, callErr := client.ForgetUSBEnrollment(ctx, &privatevmv1.ForgetUSBEnrollmentRequest{Context: requestContext}); callErr != nil {
			return Result{}, daemonRPCError(callErr)
		}
		return Result{Code: CodeAcknowledged, Data: AcknowledgementPayload{Message: "The current owner's USB enrollment was removed."}}, nil
	default:
		return Result{}, invalidUSBIntent()
	}
}

func usbDevicesResult(values []*privatevmv1.USBDeviceStatus) (Result, error) {
	payload := USBDevicesPayload{Devices: make([]USBDevicePayload, 0, len(values))}
	for _, value := range values {
		if value == nil {
			return Result{}, internalUSBError()
		}
		payload.Devices = append(payload.Devices, USBDevicePayload{
			SchemaVersion: value.GetSchemaVersion(), DeviceID: value.GetDeviceId(), VendorID: value.GetVendorId(), ProductID: value.GetProductId(),
			Model: value.GetModel(), Serial: value.GetSerial(), USBGuardHash: value.GetUsbguardHash(), BlockPath: value.GetBlockPath(), PortPath: value.GetPortPath(), Interfaces: append([]string(nil), value.GetInterfaces()...),
			CapacityBytes: value.GetCapacityBytes(), Mounted: value.GetMounted(), ReadOnly: value.GetReadOnly(), HostFilesystem: value.GetHostFilesystem(),
			Selectable: value.GetSelectable(), IdentityFingerprint: value.GetIdentityFingerprint(), Code: value.GetCode(), Remediation: value.GetRemediation(),
		})
	}
	return Result{Code: CodeUSBDevices, Data: payload}, nil
}

func usbEnrollmentResult(value *privatevmv1.USBEnrollmentStatus) (Result, error) {
	if value == nil {
		return Result{}, internalUSBError()
	}
	return Result{Code: CodeUSBEnrollment, Data: USBEnrollmentPayload{
		SchemaVersion: value.GetSchemaVersion(), EnrollmentID: value.GetEnrollmentId(), Label: value.GetLabel(), Filesystem: value.GetFilesystem(),
		VendorID: value.GetVendorId(), ProductID: value.GetProductId(), Model: value.GetModel(), Serial: value.GetSerial(), USBGuardHash: value.GetUsbguardHash(), BlockPath: value.GetBlockPath(),
		PortPath: value.GetPortPath(), PortBound: value.GetPortBound(), Interfaces: append([]string(nil), value.GetInterfaces()...),
		CapacityBytes: value.GetCapacityBytes(), IdentityFingerprint: value.GetIdentityFingerprint(), Verified: value.GetVerified(),
		Code: value.GetCode(), Remediation: value.GetRemediation(),
	}}, nil
}

func invalidUSBIntent() error {
	return apperror.New("USB_REQUEST_INVALID", exitcode.USBExport, "The USB request contract is invalid.", "Use the documented USB command syntax and an opaque discovery identifier.")
}

func internalUSBError() error {
	return apperror.New("INTERNAL_ERROR", exitcode.Internal, "The USB request could not be prepared safely.", "Retry once; if the error persists, export a redacted diagnostic bundle.")
}
