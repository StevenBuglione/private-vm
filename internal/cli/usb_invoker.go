package cli

import (
	"context"
	"errors"
	"io"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"google.golang.org/grpc"
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
	case CommandUSBPrepare:
		request, ok := intent.(USBPrepareIntent)
		if !ok || request.Format != "luks2-ext4" {
			return Result{}, invalidUSBIntent()
		}
		return invoker.prepareUSB(ctx, client, requestID)
	case CommandUSBExport:
		request, ok := intent.(USBExportIntent)
		if !ok {
			return Result{}, invalidUSBIntent()
		}
		response, callErr := client.ExportApprovedToUSB(ctx, &privatevmv1.USBExportRequest{Context: sessionRequestContext(requestID, request.ExporterSession), ClaimId: request.ClaimID, ScannerSessionId: request.SourceSession, OutputId: request.OutputID})
		if callErr != nil {
			return Result{}, daemonRPCError(callErr)
		}
		return usbExportResult(response)
	default:
		return Result{}, invalidUSBIntent()
	}
}

func (invoker *ProductionInvoker) prepareUSB(ctx context.Context, client privatevmv1.PrivateVMDaemonServiceClient, requestID string) (result Result, resultErr error) {
	enrollment, err := client.GetUSBEnrollment(ctx, &privatevmv1.GetUSBEnrollmentRequest{Context: sessionRequestContext(requestID, "")})
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	created, err := client.CreateSession(ctx, &privatevmv1.CreateSessionRequest{Context: sessionRequestContext(requestID, ""), Role: privatevmv1.GuestRole_GUEST_ROLE_EXPORTER})
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	completed := false
	defer func() {
		if completed {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = client.AbortSession(cleanup, &privatevmv1.AbortSessionRequest{Context: sessionRequestContext(requestID, created.GetId()), ReasonCode: "USB_PREPARE_CLIENT_FAILED"})
		cancel()
	}()
	claim, err := client.ClaimUSB(ctx, &privatevmv1.ClaimUSBRequest{Context: sessionRequestContext(requestID, created.GetId()), EnrollmentId: enrollment.GetEnrollmentId()})
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	plan, err := client.PlanUSBPreparation(ctx, &privatevmv1.PlanUSBPreparationRequest{Context: sessionRequestContext(requestID, created.GetId()), ClaimId: claim.GetClaimId()})
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	first, err := invoker.readUSBPrompt(ctx, "First destructive confirmation ("+plan.GetFirstConfirmation()+"): ", 512)
	if err != nil {
		return Result{}, err
	}
	second, err := invoker.readUSBPrompt(ctx, "Second destructive confirmation ("+plan.GetSecondConfirmation()+"): ", 512)
	if err != nil {
		return Result{}, err
	}
	passphrase, err := invoker.readUSBSecret(ctx, "New USB LUKS2 passphrase: ", 1024)
	if err != nil {
		return Result{}, err
	}
	defer passphrase.Destroy()
	stream, err := client.PrepareUSB(ctx, grpc.MaxCallSendMsgSize(4096), grpc.MaxCallRecvMsgSize(64<<10))
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	if err := stream.Send(&privatevmv1.HostUSBPrepareFrame{Frame: &privatevmv1.HostUSBPrepareFrame_Begin{Begin: &privatevmv1.HostUSBPrepareBegin{Context: sessionRequestContext(requestID, created.GetId()), ClaimId: claim.GetClaimId(), Challenge: plan.GetChallenge(), FirstConfirmation: first, SecondConfirmation: second}}}); err != nil {
		return Result{}, daemonRPCError(err)
	}
	err = passphrase.WithReader(func(reader io.Reader) error {
		buffer := make([]byte, 256)
		defer clear(buffer)
		for {
			count, readErr := reader.Read(buffer)
			if count > 0 {
				chunk := append([]byte(nil), buffer[:count]...)
				sendErr := stream.Send(&privatevmv1.HostUSBPrepareFrame{Frame: &privatevmv1.HostUSBPrepareFrame_PassphraseChunk{PassphraseChunk: &privatevmv1.HostUSBPrepareSecretChunk{Data: chunk}}})
				clear(chunk)
				clear(buffer[:count])
				if sendErr != nil {
					return sendErr
				}
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if readErr != nil {
				return readErr
			}
		}
	})
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	receipt, err := stream.CloseAndRecv()
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	completed = true
	return Result{Code: CodeUSBPrepared, Data: USBPreparePayload{SchemaVersion: receipt.GetSchemaVersion(), ExporterSessionID: created.GetId(), ClaimID: claim.GetClaimId(), EnrollmentID: receipt.GetEnrollmentId(), Filesystem: receipt.GetFilesystem(), CapacityBytes: receipt.GetCapacityBytes(), IdentityFingerprint: receipt.GetIdentityFingerprint(), State: receipt.GetState()}}, nil
}

func (invoker *ProductionInvoker) readUSBPrompt(ctx context.Context, prompt string, maximum int64) (string, error) {
	value, err := invoker.readUSBSecret(ctx, prompt, maximum)
	if err != nil {
		return "", err
	}
	defer value.Destroy()
	var result string
	err = value.WithReader(func(reader io.Reader) error {
		bytes, readErr := io.ReadAll(reader)
		defer clear(bytes)
		if readErr == nil {
			result = string(bytes)
		}
		return readErr
	})
	return result, err
}

func (invoker *ProductionInvoker) readUSBSecret(ctx context.Context, prompt string, maximum int64) (*secret.Bytes, error) {
	destination := invoker.prompt
	if destination == nil {
		destination = io.Discard
	}
	if _, err := io.WriteString(destination, prompt); err != nil {
		return nil, usbInputError()
	}
	read := invoker.readInput
	if read == nil {
		read = SensitiveInput
	}
	value, err := read(ctx, ValueRequest{Source: InputSourceTerminal, MaxBytes: maximum})
	if err != nil {
		return nil, usbInputError()
	}
	return value, nil
}

func usbExportResult(value *privatevmv1.USBExportReceipt) (Result, error) {
	if value == nil {
		return Result{}, internalUSBError()
	}
	return Result{Code: CodeUSBExported, Data: USBExportPayload{SchemaVersion: value.GetSchemaVersion(), EnrollmentID: value.GetEnrollmentId(), BytesWritten: value.GetBytesWritten(), SourceRelayHashEqual: value.GetScannerRelayHashEqual(), RelayExporterHashEqual: value.GetRelayExporterHashEqual(), ExporterRereadHashEqual: value.GetExporterRereadHashEqual(), FileSynced: value.GetFileSynced(), FilesystemSynced: value.GetFilesystemSynced(), AtomicRename: value.GetAtomicRename(), USBUnmounted: value.GetUsbUnmounted(), USBDetached: value.GetUsbDetached(), ExporterStopped: value.GetExporterStopped(), CleanupComplete: value.GetCleanupComplete()}}, nil
}

func usbInputError() error {
	return apperror.New("USB_INPUT_UNAVAILABLE", exitcode.USBExport, "Protected USB confirmation input is unavailable.", "Retry from an interactive terminal and enter both exact confirmations plus the LUKS2 passphrase.")
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
