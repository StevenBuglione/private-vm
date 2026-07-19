package daemon

import (
	"context"
	"errors"
	"io"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/usb"
	"google.golang.org/grpc/codes"
)

const (
	maximumHostUSBPassphraseBytes = 1024
	maximumHostUSBSecretChunk     = 256
	maximumHostUSBSecretFrames    = 4
)

// USBWorkflowOrchestrator is the privileged semantic boundary. Implementations
// own the one-use plan, exact claim revalidation, Polkit call, authenticated
// exporter transport, scanner source and retryable cleanup. No method accepts a
// block path, mount path, command, QEMU argument or arbitrary device selector.
type USBWorkflowOrchestrator interface {
	PlanPreparation(context.Context, session.Snapshot, string, usb.Enrollment) (usb.PreparePlan, error)
	Prepare(context.Context, session.Snapshot, string, usb.Enrollment, string, usb.Confirmation, *secret.Bytes) (usb.PrepareReceipt, error)
	Export(context.Context, session.Snapshot, string, string, string, usb.Enrollment) (usb.ExportReceipt, error)
}

func (s *Service) PlanUSBPreparation(ctx context.Context, request *privatevmv1.PlanUSBPreparationRequest) (*privatevmv1.USBPreparePlan, error) {
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return nil, err
	}
	lock := s.roleOperation(request.GetContext().GetSessionId())
	lock.Lock()
	defer lock.Unlock()
	_, snapshot, enrollment, err := s.usbWorkflowAdmission(ctx, request.GetContext().GetSessionId(), request.GetClaimId(), "USB_CLAIMED")
	if err != nil {
		return nil, err
	}
	plan, err := s.USBWorkflows.PlanPreparation(ctx, snapshot, request.GetClaimId(), enrollment)
	if err != nil {
		return nil, usbRPCError(err)
	}
	if plan.SchemaVersion != usb.PrepareSchemaVersion || plan.EnrollmentID != enrollment.EnrollmentID || plan.Filesystem != usb.DefaultFilesystem ||
		plan.CapacityBytes != enrollment.Identity.Capacity || len(plan.Challenge) != 32 || plan.CreatedAt.IsZero() || plan.FirstPrompt == "" || plan.SecondPrompt == "" {
		return nil, rpcError(codes.Internal, "USB_PREPARE_PLAN_INVALID", "The USB preparation plan is incomplete.", "Destroy the exporter session and retry with the fixed-policy integration.", false)
	}
	return &privatevmv1.USBPreparePlan{SchemaVersion: uint32(plan.SchemaVersion), EnrollmentId: plan.EnrollmentID,
		IdentityFingerprint: plan.Fingerprint, CapacityBytes: plan.CapacityBytes, Filesystem: plan.Filesystem,
		Challenge: plan.Challenge, CreatedUnixSeconds: plan.CreatedAt.UTC().Unix(), FirstConfirmation: plan.FirstPrompt, SecondConfirmation: plan.SecondPrompt}, nil
}

func (s *Service) PrepareUSB(stream privatevmv1.PrivateVMDaemonService_PrepareUSBServer) error {
	first, err := stream.Recv()
	if err != nil || first.GetBegin() == nil {
		clearHostUSBFrame(first)
		return rpcError(codes.InvalidArgument, "USB_PREPARE_BEGIN_REQUIRED", "USB preparation must begin with its session, claim and exact confirmations.", "Request a fresh preparation plan and retry its complete protected stream.", false)
	}
	begin := first.GetBegin()
	ctx, err := requestContextWithMetadata(stream.Context(), begin.GetContext(), true)
	if err != nil {
		return err
	}
	buffer := make([]byte, 0, maximumHostUSBPassphraseBytes)
	defer clear(buffer)
	frames := 0
	for {
		frame, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			clearHostUSBFrame(frame)
			return sessionError(recvErr)
		}
		frames++
		chunk := frame.GetPassphraseChunk()
		if chunk == nil || len(chunk.Data) == 0 || len(chunk.Data) > maximumHostUSBSecretChunk || frames > maximumHostUSBSecretFrames ||
			len(chunk.Data) > maximumHostUSBPassphraseBytes-len(buffer) {
			clearHostUSBFrame(frame)
			return rpcError(codes.InvalidArgument, "USB_PASSPHRASE_STREAM_INVALID", "The bounded USB passphrase stream is invalid.", "Retry from a protected prompt with a passphrase of at most 1024 bytes.", false)
		}
		buffer = append(buffer, chunk.Data...)
		clear(chunk.Data)
	}
	if len(buffer) < 8 {
		return rpcError(codes.InvalidArgument, "USB_PASSPHRASE_INVALID", "The encryption passphrase is missing or too short.", "Enter at least eight bytes through the protected prompt.", false)
	}
	passphrase, err := secret.New(buffer)
	if err != nil {
		return rpcError(codes.Internal, "USB_SECRET_UNAVAILABLE", "Protected passphrase memory is unavailable.", "Retry after checking memfd and memory-lock support.", false)
	}
	defer passphrase.Destroy()
	lock := s.roleOperation(begin.GetContext().GetSessionId())
	lock.Lock()
	defer lock.Unlock()
	identity, snapshot, enrollment, err := s.usbWorkflowAdmission(ctx, begin.GetContext().GetSessionId(), begin.GetClaimId(), "USB_CLAIMED")
	if err != nil {
		return err
	}
	receipt, err := s.USBWorkflows.Prepare(ctx, snapshot, begin.GetClaimId(), enrollment, begin.GetChallenge(), usb.Confirmation{First: begin.GetFirstConfirmation(), Second: begin.GetSecondConfirmation()}, passphrase)
	if err != nil {
		return usbRPCError(err)
	}
	if receipt.SchemaVersion != usb.PrepareSchemaVersion || receipt.EnrollmentID != enrollment.EnrollmentID || receipt.Filesystem != usb.DefaultFilesystem ||
		receipt.CapacityBytes != enrollment.Identity.Capacity || receipt.State != usb.PrepareDestinationReady {
		return rpcError(codes.FailedPrecondition, "USB_PREPARE_INCOMPLETE", "USB preparation returned incomplete evidence.", "Keep the device attached and run session cleanup before retrying.", true)
	}
	for _, state := range []string{"EXPORTER_BOOTING", "GUEST_AUTHENTICATED", "NO_NETWORK_VERIFIED", "USB_ATTACHED", "DESTINATION_PREPARED"} {
		if _, err := s.Sessions.TransitionWorkflow(ctx, snapshot.ID, identity.UID, state); err != nil {
			return sessionError(err)
		}
	}
	return stream.SendAndClose(&privatevmv1.USBPrepareReceipt{SchemaVersion: uint32(receipt.SchemaVersion), EnrollmentId: receipt.EnrollmentID,
		Filesystem: receipt.Filesystem, CapacityBytes: receipt.CapacityBytes, IdentityFingerprint: receipt.Fingerprint, State: string(receipt.State)})
}

func (s *Service) ExportApprovedToUSB(ctx context.Context, request *privatevmv1.USBExportRequest) (*privatevmv1.USBExportReceipt, error) {
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return nil, err
	}
	lock := s.roleOperation(request.GetContext().GetSessionId())
	lock.Lock()
	defer lock.Unlock()
	identity, snapshot, enrollment, err := s.usbWorkflowAdmission(ctx, request.GetContext().GetSessionId(), request.GetClaimId(), "DESTINATION_PREPARED")
	if err != nil {
		return nil, err
	}
	if session.ValidateID(request.GetScannerSessionId()) != nil || request.GetOutputId() == "" || len(request.GetOutputId()) > 128 {
		return nil, rpcError(codes.InvalidArgument, "USB_EXPORT_SELECTION_INVALID", "The scanner source selection is invalid.", "Select one authenticated approved scanner output and retry.", false)
	}
	scanner, err := s.Sessions.Get(request.GetScannerSessionId(), identity.UID)
	if err != nil || scanner.Role != session.RoleScanner || scanner.WorkflowState != "POLICY_APPROVED" {
		return nil, rpcError(codes.FailedPrecondition, "USB_SCANNER_APPROVAL_REQUIRED", "The source is not owned by an approved scanner session.", "Complete the authenticated scanner report and approve one reconstructed output.", false)
	}
	receipt, err := s.USBWorkflows.Export(ctx, snapshot, request.GetClaimId(), scanner.ID, request.GetOutputId(), enrollment)
	if err != nil {
		return nil, usbRPCError(err)
	}
	if err := receipt.Validate(); err != nil {
		return nil, rpcError(codes.FailedPrecondition, "USB_EXPORT_INCOMPLETE", "USB export returned incomplete verification evidence.", "Keep the device attached and retry session cleanup.", true)
	}
	for _, state := range []string{"STREAMING", "STREAM_COMPLETE", "FLUSHED", "POST_WRITE_VERIFIED", "USB_UNMOUNTED", "USB_DETACHED", "EXPORTER_STOPPED"} {
		if _, err := s.Sessions.TransitionWorkflow(ctx, snapshot.ID, identity.UID, state); err != nil {
			return nil, sessionError(err)
		}
	}
	return exportReceiptToProto(receipt), nil
}

func (s *Service) usbWorkflowAdmission(ctx context.Context, sessionID, claimID, workflow string) (PeerIdentity, session.Snapshot, usb.Enrollment, error) {
	if s.USBEnrollments == nil || s.USBClaims == nil || s.USBWorkflows == nil {
		return PeerIdentity{}, session.Snapshot{}, usb.Enrollment{}, rpcError(codes.Unavailable, "USB_WORKFLOW_UNAVAILABLE", "The fixed-policy USB exporter integration is unavailable.", "Install the exporter image and configure exact claim, Polkit and guest transport adapters.", false)
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return PeerIdentity{}, session.Snapshot{}, usb.Enrollment{}, sessionError(err)
	}
	snapshot, err := s.Sessions.Get(sessionID, identity.UID)
	if err != nil {
		return PeerIdentity{}, session.Snapshot{}, usb.Enrollment{}, sessionError(err)
	}
	if snapshot.Role != session.RoleExporter || snapshot.WorkflowState != workflow || claimID == "" {
		return PeerIdentity{}, session.Snapshot{}, usb.Enrollment{}, rpcError(codes.FailedPrecondition, "USB_EXPORTER_STATE_INVALID", "The owning exporter session is not ready for this operation.", "Inspect the exporter session and follow the documented claim, prepare and export order.", false)
	}
	enrollment, err := s.USBEnrollments.Load()
	if err != nil {
		return PeerIdentity{}, session.Snapshot{}, usb.Enrollment{}, usbRPCError(err)
	}
	if _, err := s.USBClaims.Revalidate(ctx, claimID, sessionID, identity.UID, enrollment); err != nil {
		return PeerIdentity{}, session.Snapshot{}, usb.Enrollment{}, usbRPCError(err)
	}
	return identity, snapshot, enrollment, nil
}

func exportReceiptToProto(receipt usb.ExportReceipt) *privatevmv1.USBExportReceipt {
	return &privatevmv1.USBExportReceipt{SchemaVersion: uint32(receipt.SchemaVersion), EnrollmentId: receipt.EnrollmentID, BytesWritten: receipt.BytesWritten,
		ScannerRelayHashEqual: receipt.ScannerRelayHashEqual, RelayExporterHashEqual: receipt.RelayExporterHashEqual,
		ExporterRereadHashEqual: receipt.ExporterRereadHashEqual, FileSynced: receipt.FileSynced, FilesystemSynced: receipt.FilesystemSynced,
		AtomicRename: receipt.AtomicRename, UsbUnmounted: receipt.USBUnmounted, UsbDetached: receipt.USBDetached,
		ExporterStopped: receipt.ExporterStopped, CleanupComplete: receipt.CleanupComplete}
}

func clearHostUSBFrame(frame *privatevmv1.HostUSBPrepareFrame) {
	if frame != nil && frame.GetPassphraseChunk() != nil {
		clear(frame.GetPassphraseChunk().Data)
	}
}
