package daemon

import (
	"context"
	"errors"
	"math"
	"regexp"
	"strings"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const scannerCleanupTimeout = 30 * time.Second

var scannerFindingCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

// ScannerDestination is a closed promotion target. It deliberately cannot
// represent a host path, device identifier, socket, guest CID or QEMU option.
type ScannerDestination string

const (
	ScannerDestinationWorkstation ScannerDestination = "workstation"
	ScannerDestinationUSB         ScannerDestination = "usb"
)

// ScannerReportEvidence is the authenticated, canonical report retained only
// in volatile daemon memory. Host responses are projected to aggregate counts;
// this value, including logical names and hashes, never crosses the CLI API.
type ScannerReportEvidence struct {
	Report scan.ScanReport
}

// ScannerOrchestrator is the daemon's narrow scanner boundary. Allocation
// methods must return cleanup and absence-audit owners. StorageAllocation must
// acquire an exclusive sealed-quarantine lease from source: cleanup of the
// downloader may not invalidate that lease and the host must never mount the
// quarantine. UpdateRuntimeAllocation permits network but no quarantine;
// OfflineRuntimeAllocation requires the retained overlay, no NIC and one
// read-only quarantine device.
//
// Phase methods relay only through the already-authenticated scanner guest.
// Report must verify the volatile report MAC before returning. Promote must
// stream only report-listed reconstructed output and complete destination hash
// verification before it returns success.
type ScannerOrchestrator interface {
	Preflight(context.Context, session.Snapshot, session.Snapshot) error
	VerifyImage(context.Context, session.Snapshot) error
	StorageAllocation(session.Snapshot, session.Snapshot) session.AllocateFunc
	UpdateRuntimeAllocation(session.Snapshot) session.AllocateFunc
	UpdateDefinitions(context.Context, session.Snapshot) (*privatevmv1.DefinitionsStatus, error)
	StopUpdate(context.Context, session.Snapshot) error
	OfflineRuntimeAllocation(session.Snapshot) session.AllocateFunc
	VerifyOffline(context.Context, session.Snapshot) (*privatevmv1.OfflineStatus, error)
	Inventory(context.Context, session.Snapshot, string, func(*privatevmv1.ScanEvent) error) error
	Scan(context.Context, session.Snapshot, string, func(*privatevmv1.ScanEvent) error) error
	Reconstruct(context.Context, session.Snapshot, string, func(*privatevmv1.ScanEvent) error) error
	Report(context.Context, session.Snapshot, string) (ScannerReportEvidence, error)
	Promote(context.Context, session.Snapshot, ScannerReportEvidence, ScannerDestination) error
	StopOffline(context.Context, session.Snapshot) error
}

func (s *Service) StartScanner(request *privatevmv1.HostScannerStartRequest, stream privatevmv1.PrivateVMDaemonService_StartScannerServer) error {
	if request == nil {
		return scannerServiceError(errors.New("scanner request is absent"))
	}
	ctx, err := requestContextWithMetadata(stream.Context(), request.GetContext(), true)
	if err != nil {
		return err
	}
	if request.GetPolicyName() != "safe" {
		return scannerRPCError(codes.InvalidArgument, "SCANNER_POLICY_INVALID", "The scanner requires the installed safe policy.", "Use the safe policy for reconstruction and promotion.")
	}
	if s.Scanners == nil {
		return unimplemented("Authenticated scanner workflow")
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return sessionError(err)
	}
	source, err := s.Sessions.Get(request.GetContext().GetSessionId(), identity.UID)
	if err != nil {
		return sessionError(err)
	}
	if source.Role != session.RoleDownloader || source.Phase != session.PhaseActive || source.WorkflowState != "QUARANTINE_SEALED" {
		return scannerStateError("an active downloader with QUARANTINE_SEALED")
	}

	// Serialize against downloader status/seal/cleanup admission while the
	// quarantine ownership handoff and complete scan are in flight.
	sourceLock := s.roleOperation(source.ID)
	sourceLock.Lock()
	defer sourceLock.Unlock()
	source, err = s.Sessions.Get(source.ID, identity.UID)
	if err != nil {
		return sessionError(err)
	}
	if source.Role != session.RoleDownloader || source.Phase != session.PhaseActive || source.WorkflowState != "QUARANTINE_SEALED" {
		return scannerStateError("an active downloader with QUARANTINE_SEALED")
	}

	scanner, err := s.Sessions.Create(identity.UID, session.RoleScanner)
	if err != nil {
		return sessionError(err)
	}
	scannerLock := s.roleOperation(scanner.ID)
	scannerLock.Lock()
	defer scannerLock.Unlock()
	fail := func(cause error) error {
		return s.failedScanner(scanner.ID, identity.UID, cause)
	}
	transitionWorkflow := func(state string) error {
		var transitionErr error
		scanner, transitionErr = s.Sessions.TransitionWorkflow(ctx, scanner.ID, identity.UID, state)
		if transitionErr != nil {
			return transitionErr
		}
		return s.sendScannerStatus(stream, scanner, nil)
	}
	transitionPhase := func(phase session.Phase) error {
		var transitionErr error
		scanner, transitionErr = s.Sessions.Transition(ctx, scanner.ID, identity.UID, phase)
		return transitionErr
	}

	if err := transitionWorkflow("UPDATE_VM_BOOTING"); err != nil {
		return fail(err)
	}
	if err := s.Scanners.Preflight(ctx, source, scanner); err != nil {
		return fail(err)
	}
	if err := transitionPhase(session.PhasePreflighted); err != nil {
		return fail(err)
	}
	if err := s.Scanners.VerifyImage(ctx, scanner); err != nil {
		return fail(err)
	}
	if err := transitionPhase(session.PhaseImagesVerified); err != nil {
		return fail(err)
	}
	storage := s.Scanners.StorageAllocation(source, scanner)
	if storage == nil {
		return fail(errors.New("scanner storage allocation is unavailable"))
	}
	if err := s.Sessions.AcquireResource(ctx, scanner.ID, identity.UID, "scanner-storage", storage); err != nil {
		return fail(err)
	}
	if err := transitionPhase(session.PhaseStorageReady); err != nil {
		return fail(err)
	}
	updateRuntime := s.Scanners.UpdateRuntimeAllocation(scanner)
	if updateRuntime == nil {
		return fail(errors.New("scanner update runtime allocation is unavailable"))
	}
	if err := s.Sessions.AcquireResource(ctx, scanner.ID, identity.UID, "scanner-update-runtime", updateRuntime); err != nil {
		return fail(err)
	}
	if err := transitionPhase(session.PhaseActive); err != nil {
		return fail(err)
	}
	if err := transitionWorkflow("DEFINITIONS_UPDATING"); err != nil {
		return fail(err)
	}
	definitions, err := s.Scanners.UpdateDefinitions(ctx, scanner)
	if err != nil || definitions == nil || !definitions.GetCurrent() || definitions.GetDatabaseVersion() == "" || definitions.GetUpdatedUnixSeconds() <= 0 {
		if err == nil {
			err = errors.New("scanner definition evidence is incomplete")
		}
		return fail(err)
	}
	if err := transitionWorkflow("DEFINITIONS_VERIFIED"); err != nil {
		return fail(err)
	}
	if err := s.Scanners.StopUpdate(ctx, scanner); err != nil {
		return fail(err)
	}
	if err := transitionWorkflow("UPDATE_VM_STOPPED"); err != nil {
		return fail(err)
	}
	if err := transitionWorkflow("SCAN_VM_BOOTING_OFFLINE"); err != nil {
		return fail(err)
	}
	offlineRuntime := s.Scanners.OfflineRuntimeAllocation(scanner)
	if offlineRuntime == nil {
		return fail(errors.New("scanner offline runtime allocation is unavailable"))
	}
	if err := s.Sessions.AcquireResource(ctx, scanner.ID, identity.UID, "scanner-offline-runtime", offlineRuntime); err != nil {
		return fail(err)
	}
	offline, err := s.Scanners.VerifyOffline(ctx, scanner)
	if err != nil || offline == nil || !offline.GetNoNetwork() || !offline.GetQuarantineReadOnly() {
		if err == nil {
			err = errors.New("scanner offline evidence is incomplete")
		}
		return fail(err)
	}
	if err := transitionWorkflow("OFFLINE_VERIFIED"); err != nil {
		return fail(err)
	}
	if err := transitionWorkflow("QUARANTINE_ATTACHED_READ_ONLY"); err != nil {
		return fail(err)
	}
	relay := func(event *privatevmv1.ScanEvent) error { return s.sendScannerProgress(stream, scanner, event) }
	if err := s.Scanners.Inventory(ctx, scanner, request.GetPolicyName(), relay); err != nil {
		return fail(err)
	}
	if err := transitionWorkflow("INVENTORY_COMPLETE"); err != nil {
		return fail(err)
	}
	if err := s.Scanners.Scan(ctx, scanner, request.GetPolicyName(), relay); err != nil {
		return fail(err)
	}
	if err := transitionWorkflow("MALWARE_SCAN_COMPLETE"); err != nil {
		return fail(err)
	}
	if err := s.Scanners.Reconstruct(ctx, scanner, request.GetPolicyName(), relay); err != nil {
		return fail(err)
	}
	if err := transitionWorkflow("RECONSTRUCTION_COMPLETE"); err != nil {
		return fail(err)
	}
	evidence, err := s.Scanners.Report(ctx, scanner, request.GetPolicyName())
	if err != nil {
		return fail(err)
	}
	if err := validateScannerEvidence(scanner, evidence); err != nil {
		return fail(err)
	}
	if err := transitionWorkflow("REPORT_COMPLETE"); err != nil {
		return fail(err)
	}
	if evidence.Report.Result == "rejected" {
		if err := transitionWorkflow("POLICY_REJECTED"); err != nil {
			return fail(err)
		}
		if err := s.Scanners.StopOffline(ctx, scanner); err != nil {
			return fail(err)
		}
		if err := transitionWorkflow("SCAN_VM_STOPPED"); err != nil {
			return fail(err)
		}
	}
	return s.sendScannerStatus(stream, scanner, &evidence)
}

func (s *Service) GetScannerStatus(ctx context.Context, request *privatevmv1.HostScannerControlRequest) (*privatevmv1.HostScannerStatus, error) {
	identity, scanner, err := s.scannerSession(ctx, request)
	if err != nil {
		return nil, err
	}
	lock := s.roleOperation(scanner.ID)
	lock.Lock()
	defer lock.Unlock()
	scanner, err = s.Sessions.Get(scanner.ID, identity.UID)
	if err != nil {
		return nil, sessionError(err)
	}
	if scanner.Role != session.RoleScanner || scanner.Phase != session.PhaseActive {
		return nil, scannerStateError("an active scanner session")
	}
	var evidence *ScannerReportEvidence
	if scanner.WorkflowState == "REPORT_COMPLETE" || scanner.WorkflowState == "POLICY_APPROVED" || scanner.WorkflowState == "POLICY_REJECTED" || scanner.WorkflowState == "SCAN_VM_STOPPED" {
		value, reportErr := s.Scanners.Report(ctx, scanner, "safe")
		if reportErr != nil {
			return nil, scannerServiceError(reportErr)
		}
		if err := validateScannerEvidence(scanner, value); err != nil {
			return nil, scannerServiceError(err)
		}
		evidence = &value
	}
	return scannerStatusProto(scanner, evidence), nil
}

func (s *Service) GetScannerReport(ctx context.Context, request *privatevmv1.HostScannerControlRequest) (*privatevmv1.HostScannerReportSummary, error) {
	identity, scanner, err := s.scannerSession(ctx, request)
	if err != nil {
		return nil, err
	}
	lock := s.roleOperation(scanner.ID)
	lock.Lock()
	defer lock.Unlock()
	scanner, err = s.Sessions.Get(scanner.ID, identity.UID)
	if err != nil {
		return nil, sessionError(err)
	}
	if scanner.Role != session.RoleScanner || scanner.Phase != session.PhaseActive {
		return nil, scannerStateError("an active scanner session")
	}
	if scanner.WorkflowState != "REPORT_COMPLETE" && scanner.WorkflowState != "POLICY_APPROVED" && scanner.WorkflowState != "POLICY_REJECTED" && scanner.WorkflowState != "SCAN_VM_STOPPED" {
		return nil, scannerStateError("REPORT_COMPLETE")
	}
	evidence, err := s.Scanners.Report(ctx, scanner, "safe")
	if err != nil {
		return nil, scannerServiceError(err)
	}
	if err := validateScannerEvidence(scanner, evidence); err != nil {
		return nil, scannerServiceError(err)
	}
	return scannerReportProto(scanner.ID, evidence.Report), nil
}

func (s *Service) ApproveScanner(ctx context.Context, request *privatevmv1.HostScannerApprovalRequest) (*privatevmv1.HostScannerStatus, error) {
	if request == nil {
		return nil, scannerServiceError(errors.New("scanner approval request is absent"))
	}
	destination, err := scannerDestination(request.GetDestination())
	if err != nil {
		return nil, err
	}
	identity, scanner, err := s.scannerSessionContext(ctx, request.GetContext())
	if err != nil {
		return nil, err
	}
	lock := s.roleOperation(scanner.ID)
	lock.Lock()
	defer lock.Unlock()
	scanner, err = s.Sessions.Get(scanner.ID, identity.UID)
	if err != nil {
		return nil, sessionError(err)
	}
	if scanner.Role != session.RoleScanner || scanner.Phase != session.PhaseActive {
		return nil, scannerStateError("an active scanner session")
	}
	if scanner.WorkflowState != "REPORT_COMPLETE" {
		return nil, scannerStateError("REPORT_COMPLETE")
	}
	evidence, err := s.Scanners.Report(ctx, scanner, "safe")
	if err != nil || validateScannerEvidence(scanner, evidence) != nil || evidence.Report.Result != "approved" {
		if err == nil {
			err = errors.New("scanner report does not authorize promotion")
		}
		return nil, scannerServiceError(err)
	}
	if err := s.Scanners.Promote(ctx, scanner, evidence, destination); err != nil {
		return nil, scannerServiceError(err)
	}
	if scanner, err = s.Sessions.TransitionWorkflow(ctx, scanner.ID, identity.UID, "POLICY_APPROVED"); err != nil {
		return nil, sessionError(err)
	}
	if err := s.Scanners.StopOffline(ctx, scanner); err != nil {
		return nil, s.failedScanner(scanner.ID, identity.UID, err)
	}
	if scanner, err = s.Sessions.TransitionWorkflow(ctx, scanner.ID, identity.UID, "SCAN_VM_STOPPED"); err != nil {
		return nil, s.failedScanner(scanner.ID, identity.UID, err)
	}
	statusView := scannerStatusProto(scanner, &evidence)
	if _, err := s.cleanupScanner(scanner.ID, identity.UID); err != nil {
		return nil, err
	}
	return statusView, nil
}

func (s *Service) RejectScanner(ctx context.Context, request *privatevmv1.HostScannerControlRequest) (*privatevmv1.HostScannerStatus, error) {
	identity, scanner, err := s.scannerSession(ctx, request)
	if err != nil {
		return nil, err
	}
	lock := s.roleOperation(scanner.ID)
	lock.Lock()
	defer lock.Unlock()
	scanner, err = s.Sessions.Get(scanner.ID, identity.UID)
	if err != nil {
		return nil, sessionError(err)
	}
	if scanner.Role != session.RoleScanner || scanner.Phase != session.PhaseActive {
		return nil, scannerStateError("an active scanner session")
	}
	var evidence *ScannerReportEvidence
	if scanner.WorkflowState == "REPORT_COMPLETE" {
		value, reportErr := s.Scanners.Report(ctx, scanner, "safe")
		if reportErr == nil && validateScannerEvidence(scanner, value) == nil {
			evidence = &value
		}
		if scanner, err = s.Sessions.TransitionWorkflow(ctx, scanner.ID, identity.UID, "POLICY_REJECTED"); err != nil {
			return nil, sessionError(err)
		}
	}
	if scanner.WorkflowState == "POLICY_REJECTED" {
		if err := s.Scanners.StopOffline(ctx, scanner); err != nil {
			return nil, s.failedScanner(scanner.ID, identity.UID, err)
		}
		if scanner, err = s.Sessions.TransitionWorkflow(ctx, scanner.ID, identity.UID, "SCAN_VM_STOPPED"); err != nil {
			return nil, s.failedScanner(scanner.ID, identity.UID, err)
		}
	}
	if scanner.WorkflowState != "SCAN_VM_STOPPED" {
		return nil, scannerStateError("REPORT_COMPLETE, POLICY_REJECTED, or SCAN_VM_STOPPED")
	}
	statusView := scannerStatusProto(scanner, evidence)
	statusView.PolicyApproved = false
	statusView.PolicyRejected = true
	statusView.Code = "SCAN_REJECTED"
	statusView.Remediation = "The scanner cleanup owner is destroying its volatile resources; do not promote any original content."
	if _, err := s.cleanupScanner(scanner.ID, identity.UID); err != nil {
		return nil, err
	}
	return statusView, nil
}

func (s *Service) scannerSession(ctx context.Context, request *privatevmv1.HostScannerControlRequest) (PeerIdentity, session.Snapshot, error) {
	if request == nil {
		return PeerIdentity{}, session.Snapshot{}, scannerServiceError(errors.New("scanner control request is absent"))
	}
	return s.scannerSessionContext(ctx, request.GetContext())
}

func (s *Service) scannerSessionContext(ctx context.Context, request *privatevmv1.RequestContext) (PeerIdentity, session.Snapshot, error) {
	if s.Scanners == nil {
		return PeerIdentity{}, session.Snapshot{}, unimplemented("Authenticated scanner workflow")
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return PeerIdentity{}, session.Snapshot{}, sessionError(err)
	}
	snapshot, err := s.Sessions.Get(request.GetSessionId(), identity.UID)
	if err != nil {
		return PeerIdentity{}, session.Snapshot{}, sessionError(err)
	}
	if snapshot.Role != session.RoleScanner || snapshot.Phase != session.PhaseActive {
		return PeerIdentity{}, session.Snapshot{}, scannerStateError("an active scanner session")
	}
	return identity, snapshot, nil
}

func (s *Service) failedScanner(id string, ownerUID uint32, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), scannerCleanupTimeout)
	_, cleanupErr := s.Sessions.Cleanup(cleanupCtx, id, ownerUID)
	cancel()
	if cleanupErr != nil {
		return sessionError(session.ErrCleanupIncomplete)
	}
	return scannerServiceError(cause)
}

func (s *Service) cleanupScanner(id string, ownerUID uint32) (session.Snapshot, error) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), scannerCleanupTimeout)
	defer cancel()
	result, err := s.Sessions.Cleanup(cleanupCtx, id, ownerUID)
	if err != nil {
		return session.Snapshot{}, sessionError(err)
	}
	return result, nil
}

func (s *Service) sendScannerStatus(stream privatevmv1.PrivateVMDaemonService_StartScannerServer, scanner session.Snapshot, evidence *ScannerReportEvidence) error {
	return stream.Send(&privatevmv1.HostScannerEvent{Status: scannerStatusProto(scanner, evidence)})
}

func (s *Service) sendScannerProgress(stream privatevmv1.PrivateVMDaemonService_StartScannerServer, scanner session.Snapshot, event *privatevmv1.ScanEvent) error {
	if event == nil || event.GetProgress() == nil {
		return scannerServiceError(errors.New("scanner progress is incomplete"))
	}
	progress := event.GetProgress()
	if !scannerProgressOperation(progress.GetOperation()) || progress.GetTotal() == 0 || progress.GetCompleted() > progress.GetTotal() || !scannerProgressUnit(progress.GetUnit()) {
		return scannerServiceError(errors.New("scanner progress is invalid"))
	}
	result := &privatevmv1.HostScannerEvent{
		Status:   scannerStatusProto(scanner, nil),
		Progress: &privatevmv1.Progress{Operation: progress.GetOperation(), Completed: progress.GetCompleted(), Total: progress.GetTotal(), Unit: progress.GetUnit()},
	}
	if finding := event.GetFinding(); finding != nil {
		if !scannerFindingCodePattern.MatchString(finding.GetCode()) {
			return scannerServiceError(errors.New("scanner finding code is invalid"))
		}
		severity := finding.GetSeverity()
		if severity != privatevmv1.Diagnostic_SEVERITY_WARNING && severity != privatevmv1.Diagnostic_SEVERITY_BLOCKING {
			return scannerServiceError(errors.New("scanner finding severity is invalid"))
		}
		result.Finding = &privatevmv1.Diagnostic{
			Code: finding.GetCode(), Severity: severity,
			Summary:     "The scanner recorded a policy finding.",
			Remediation: "Inspect the authenticated aggregate report and reject blocking content.",
			Overridable: false,
		}
	}
	if err := stream.Send(result); err != nil {
		if stream.Context().Err() != nil {
			return stream.Context().Err()
		}
		return errors.New("scanner progress stream failed")
	}
	return nil
}

func scannerProgressOperation(value string) bool {
	return value == "inventory" || value == "malware-scan" || value == "reconstruction"
}

func scannerProgressUnit(value string) bool { return value == "phase" || value == "files" }

func validateScannerEvidence(scanner session.Snapshot, evidence ScannerReportEvidence) error {
	report := evidence.Report
	if err := report.Validate(); err != nil || report.SessionID != scanner.ID || report.Policy != "safe" || !report.Complete || (report.Result != "approved" && report.Result != "rejected") {
		return errors.New("authenticated scanner report evidence is invalid")
	}
	var total uint64
	for _, output := range report.SanitizedOutputs {
		if total > math.MaxUint64-output.SizeBytes {
			return errors.New("authenticated scanner output total overflows")
		}
		total += output.SizeBytes
	}
	return nil
}

func scannerStatusProto(snapshot session.Snapshot, evidence *ScannerReportEvidence) *privatevmv1.HostScannerStatus {
	result := &privatevmv1.HostScannerStatus{
		SchemaVersion: 1, ScannerSessionId: snapshot.ID, WorkflowState: snapshot.WorkflowState,
		PolicyApproved: snapshot.WorkflowState == "POLICY_APPROVED",
		PolicyRejected: snapshot.WorkflowState == "POLICY_REJECTED",
		Code:           "SCANNER_RUNNING", Remediation: "Wait for every scanner phase to complete before making a policy decision.",
	}
	if evidence != nil {
		report := evidence.Report
		result.ReportComplete = report.Complete
		result.FindingCount = uint32(len(report.Findings))
		for _, finding := range report.Findings {
			if finding.Severity == scan.SeverityBlocking {
				result.BlockingFindingCount++
			}
		}
		result.SanitizedOutputCount = uint32(len(report.SanitizedOutputs))
		for _, output := range report.SanitizedOutputs {
			result.SanitizedOutputBytes += output.SizeBytes
		}
		if report.Result == "approved" {
			result.Code = "SCAN_REPORT_APPROVABLE"
			result.Remediation = "Choose exactly one documented promotion destination or reject the result."
		} else {
			result.Code = "SCAN_REJECTED"
			result.Remediation = "Reject and clean the scanner session; do not promote any original content."
			result.PolicyRejected = true
		}
	}
	if snapshot.WorkflowState == "POLICY_APPROVED" || (snapshot.WorkflowState == "SCAN_VM_STOPPED" && evidence != nil && evidence.Report.Result == "approved") {
		result.PolicyApproved = true
		result.PolicyRejected = false
		result.Code = "SCAN_PROMOTION_VERIFIED"
		result.Remediation = "The scanner cleanup owner is destroying its volatile resources."
	}
	return result
}

func scannerReportProto(sessionID string, report scan.ScanReport) *privatevmv1.HostScannerReportSummary {
	result := &privatevmv1.HostScannerReportSummary{
		SchemaVersion: 1, ScannerSessionId: sessionID, Complete: report.Complete, Result: report.Result,
		InputCount: uint32(len(report.Inputs)), FindingCount: uint32(len(report.Findings)),
		SanitizedOutputCount: uint32(len(report.SanitizedOutputs)),
		Code:                 "SCAN_REJECTED", Remediation: "Reject and clean the scanner session; do not promote any original content.",
	}
	for _, finding := range report.Findings {
		if finding.Severity == scan.SeverityBlocking {
			result.BlockingFindingCount++
		}
	}
	for _, output := range report.SanitizedOutputs {
		result.SanitizedOutputBytes += output.SizeBytes
	}
	if report.Result == "approved" {
		result.Code = "SCAN_REPORT_APPROVABLE"
		result.Remediation = "Choose exactly one documented promotion destination or reject the result."
	}
	return result
}

func scannerDestination(value privatevmv1.ScannerApprovalDestination) (ScannerDestination, error) {
	switch value {
	case privatevmv1.ScannerApprovalDestination_SCANNER_APPROVAL_DESTINATION_WORKSTATION:
		return ScannerDestinationWorkstation, nil
	case privatevmv1.ScannerApprovalDestination_SCANNER_APPROVAL_DESTINATION_USB:
		return ScannerDestinationUSB, nil
	default:
		return "", scannerRPCError(codes.InvalidArgument, "SCANNER_DESTINATION_INVALID", "The scanner promotion destination is invalid.", "Choose exactly one fresh workstation or enrolled USB destination.")
	}
}

func scannerStateError(expected string) error {
	return scannerRPCError(codes.FailedPrecondition, "SCANNER_STATE_INVALID", "The scanner is not in the required workflow state.", "Inspect volatile scanner status and continue only from "+expected+".")
}

func scannerServiceError(err error) error {
	if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
		return sessionError(context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded {
		return sessionError(context.DeadlineExceeded)
	}
	if converted, ok := status.FromError(err); ok {
		for _, detail := range converted.Details() {
			if safe, matched := detail.(*privatevmv1.ErrorDetail); matched && scannerFindingCodePattern.MatchString(safe.GetCode()) && safe.GetSafeMessage() != "" && safe.GetRemediation() != "" {
				return scannerRPCError(converted.Code(), safe.GetCode(), safe.GetSafeMessage(), safe.GetRemediation())
			}
		}
	}
	code := "SCAN_ERROR"
	message := "The scanner operation failed without complete trusted evidence."
	remediation := "Destroy the scanner and retry with the verified scanner image."
	var scanError *scan.Error
	if errors.As(err, &scanError) && scannerFindingCodePattern.MatchString(scanError.Code) && scanError.Message != "" && scanError.Remediation != "" {
		code, message, remediation = scanError.Code, scanError.Message, scanError.Remediation
	}
	grpcCode := codes.FailedPrecondition
	if strings.Contains(code, "LIMIT") {
		grpcCode = codes.ResourceExhausted
	} else if strings.Contains(code, "UNAVAILABLE") || strings.Contains(code, "UPDATE_FAILED") {
		grpcCode = codes.Unavailable
	}
	return scannerRPCError(grpcCode, code, message, remediation)
}

func scannerRPCError(grpcCode codes.Code, code, message, remediation string) error {
	return rpcError(grpcCode, code, message, remediation, grpcCode == codes.Unavailable)
}
