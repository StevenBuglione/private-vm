package guest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/policy"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/transfer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultScannerCleanupTimeout = 5 * time.Second
	maximumScannerCleanupTimeout = 30 * time.Second
	defaultScannerControlTimeout = 2 * time.Minute
	maximumScannerControlTimeout = 10 * time.Minute
	defaultScannerExportTimeout  = 30 * time.Minute
	maximumScannerExportTimeout  = 24 * time.Hour
	defaultScannerExportBytes    = uint64(1 << 40)
	maximumScannerExportBytes    = uint64(4 << 40)
)

type scannerRPCState string

const (
	scannerStateBoot                scannerRPCState = "BOOT"
	scannerStateDefinitionsVerified scannerRPCState = "DEFINITIONS_VERIFIED"
	scannerStateOfflineVerified     scannerRPCState = "OFFLINE_VERIFIED"
	scannerStateInventoryComplete   scannerRPCState = "INVENTORY_COMPLETE"
	scannerStateScanComplete        scannerRPCState = "MALWARE_SCAN_COMPLETE"
	scannerStateReportComplete      scannerRPCState = "REPORT_COMPLETE"
	scannerStateClosed              scannerRPCState = "CLOSED"
)

// ScannerDefinitionAdapter owns the update receipt boundary. Status must load
// the receipt from the retained scanner overlay rather than trusting caller
// input, so a new offline guest process can prove it uses the updated overlay.
type ScannerDefinitionAdapter interface {
	Update(context.Context) (scan.UpdateReceipt, error)
	Status(context.Context) (scan.UpdateReceipt, error)
}

// ScannerIsolationAdapter collects guest-local device evidence and validates
// it against the stored definition receipt. The host cannot assert this state.
type ScannerIsolationAdapter interface {
	Verify(context.Context, scan.UpdateReceipt) (scan.BootEvidence, error)
}

type ScannerInventoryAdapter interface {
	Inventory(context.Context, policy.Policy) (scan.Inventory, error)
}

type ScannerMalwareAdapter interface {
	Scan(context.Context, scan.Inventory, policy.Policy) (scan.ScanSummary, error)
}

// ScannerReconstruction is the complete, bounded result of archive inspection,
// reconstruction and output rescanning. Outputs contain report metadata only;
// OpenApproved resolves an ID to an already identity-pinned volatile object.
type ScannerReconstruction struct {
	Archives                  []scan.ReportArchive
	Findings                  []scan.Finding
	Outputs                   []scan.ReportSanitizedOutput
	Tools                     []scan.ToolEvidence
	ArchiveInspectionComplete bool
	ReconstructionComplete    bool
	OutputRescanComplete      bool
}

type ScannerReconstructionAdapter interface {
	Reconstruct(context.Context, scan.Inventory, scan.ScanSummary, policy.Policy) (ScannerReconstruction, error)
	OpenApproved(context.Context, string) (io.ReadCloser, error)
	Cleanup(context.Context) error
}

type ScannerPolicyResolver interface {
	Resolve(string) (policy.Policy, error)
}

type ScannerPolicyResolverFunc func(string) (policy.Policy, error)

func (function ScannerPolicyResolverFunc) Resolve(name string) (policy.Policy, error) {
	return function(name)
}

type ScannerServiceConfig struct {
	Identity       Identity
	Definitions    ScannerDefinitionAdapter
	Isolation      ScannerIsolationAdapter
	Inventory      ScannerInventoryAdapter
	Malware        ScannerMalwareAdapter
	Reconstruction ScannerReconstructionAdapter
	Policies       ScannerPolicyResolver
	Now            func() time.Time
	CleanupTimeout time.Duration
	ControlTimeout time.Duration
	ExportTimeout  time.Duration
	MaxExportBytes uint64
}

// ScannerService serializes the complete scanner workflow. It intentionally
// has no method that accepts a path, command, device or external-tool output.
type ScannerService struct {
	privatevmv1.UnimplementedScannerGuestServiceServer

	mu             sync.Mutex
	identity       Identity
	reportKey      *Token
	definitions    ScannerDefinitionAdapter
	isolation      ScannerIsolationAdapter
	inventoryTool  ScannerInventoryAdapter
	malwareTool    ScannerMalwareAdapter
	reconstruction ScannerReconstructionAdapter
	policies       ScannerPolicyResolver
	now            func() time.Time
	cleanupTimeout time.Duration
	controlTimeout time.Duration
	exportTimeout  time.Duration
	maxExportBytes uint64

	state         scannerRPCState
	sessionID     string
	policyName    string
	startedAt     time.Time
	receipt       scan.UpdateReceipt
	offline       scan.BootEvidence
	inventory     scan.Inventory
	scanSummary   scan.ScanSummary
	reconstructed ScannerReconstruction
	report        scan.AuthenticatedReport
	closed        bool
}

func NewScannerService(config ScannerServiceConfig, reportKey *Token) (*ScannerService, error) {
	if config.Identity.Role != session.RoleScanner {
		return nil, errors.New("scanner service requires the scanner compiled identity")
	}
	if err := config.Identity.Validate(); err != nil {
		return nil, fmt.Errorf("scanner identity: %w", err)
	}
	if reportKey == nil || reportKey.value == nil {
		return nil, errors.New("scanner report capability is required")
	}
	if config.Definitions == nil || config.Isolation == nil || config.Inventory == nil ||
		config.Malware == nil || config.Reconstruction == nil || config.Policies == nil {
		return nil, errors.New("scanner service requires every typed phase adapter")
	}
	cleanupTimeout := config.CleanupTimeout
	if cleanupTimeout == 0 {
		cleanupTimeout = defaultScannerCleanupTimeout
	}
	if cleanupTimeout < time.Millisecond || cleanupTimeout > maximumScannerCleanupTimeout {
		return nil, errors.New("scanner cleanup timeout is outside supported bounds")
	}
	controlTimeout := config.ControlTimeout
	if controlTimeout == 0 {
		controlTimeout = defaultScannerControlTimeout
	}
	if controlTimeout < time.Millisecond || controlTimeout > maximumScannerControlTimeout {
		return nil, errors.New("scanner control timeout is outside supported bounds")
	}
	exportTimeout := config.ExportTimeout
	if exportTimeout == 0 {
		exportTimeout = defaultScannerExportTimeout
	}
	if exportTimeout < time.Millisecond || exportTimeout > maximumScannerExportTimeout {
		return nil, errors.New("scanner export timeout is outside supported bounds")
	}
	maxExportBytes := config.MaxExportBytes
	if maxExportBytes == 0 {
		maxExportBytes = defaultScannerExportBytes
	}
	if maxExportBytes > maximumScannerExportBytes {
		return nil, errors.New("scanner export bound exceeds the supported maximum")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &ScannerService{
		identity: config.Identity, reportKey: reportKey,
		definitions: config.Definitions, isolation: config.Isolation,
		inventoryTool: config.Inventory, malwareTool: config.Malware,
		reconstruction: config.Reconstruction, policies: config.Policies,
		now: now, cleanupTimeout: cleanupTimeout, controlTimeout: controlTimeout,
		exportTimeout: exportTimeout, maxExportBytes: maxExportBytes,
		state: scannerStateBoot,
	}, nil
}

func (service *ScannerService) UpdateDefinitions(ctx context.Context, request *privatevmv1.ScannerRequest) (*privatevmv1.DefinitionsStatus, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.validateRequest(request, "", scannerStateBoot); err != nil {
		return nil, err
	}
	operationContext, cancel := context.WithTimeout(ctx, service.controlTimeout)
	defer cancel()
	receipt, err := service.definitions.Update(operationContext)
	if err != nil {
		return nil, service.rpcError(operationError(operationContext, err))
	}
	if err := operationContext.Err(); err != nil {
		return nil, service.rpcError(err)
	}
	service.receipt = receipt
	service.state = scannerStateDefinitionsVerified
	return definitionsStatus(receipt), nil
}

func (service *ScannerService) GetDefinitionsStatus(ctx context.Context, request *privatevmv1.ScannerRequest) (*privatevmv1.DefinitionsStatus, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.validateRequestForStates(request, "", scannerStateBoot, scannerStateDefinitionsVerified, scannerStateOfflineVerified,
		scannerStateInventoryComplete, scannerStateScanComplete, scannerStateReportComplete); err != nil {
		return nil, err
	}
	operationContext, cancel := context.WithTimeout(ctx, service.controlTimeout)
	defer cancel()
	receipt, err := service.definitions.Status(operationContext)
	if err != nil {
		return nil, service.rpcError(operationError(operationContext, err))
	}
	if err := operationContext.Err(); err != nil {
		return nil, service.rpcError(err)
	}
	service.receipt = receipt
	if service.state == scannerStateBoot {
		service.state = scannerStateDefinitionsVerified
	}
	return definitionsStatus(receipt), nil
}

func (service *ScannerService) VerifyOfflineMode(ctx context.Context, request *privatevmv1.ScannerRequest) (*privatevmv1.OfflineStatus, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := service.validateRequestForStates(request, "", scannerStateBoot, scannerStateDefinitionsVerified); err != nil {
		return nil, err
	}
	operationContext, cancel := context.WithTimeout(ctx, service.controlTimeout)
	defer cancel()
	receipt, err := service.definitions.Status(operationContext)
	if err != nil {
		return nil, service.rpcError(operationError(operationContext, err))
	}
	evidence, err := service.isolation.Verify(operationContext, receipt)
	if err != nil {
		return nil, service.rpcError(operationError(operationContext, err))
	}
	if err := operationContext.Err(); err != nil {
		return nil, service.rpcError(err)
	}
	service.receipt = receipt
	service.offline = cloneBootEvidence(evidence)
	service.startedAt = service.now().UTC()
	service.state = scannerStateOfflineVerified
	return &privatevmv1.OfflineStatus{NoNetwork: true, QuarantineReadOnly: true}, nil
}

func (service *ScannerService) Inventory(request *privatevmv1.ScannerRequest, stream grpc.ServerStreamingServer[privatevmv1.ScanEvent]) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	selected, err := service.validatePolicyRequest(request, scannerStateOfflineVerified)
	if err != nil {
		return err
	}
	if err := sendScanProgress(stream, "inventory", 0, 1, "phase", false, false); err != nil {
		return service.streamError(stream.Context(), err)
	}
	operationContext, cancel := scannerPolicyContext(stream.Context(), selected)
	defer cancel()
	inventory, err := service.inventoryTool.Inventory(operationContext, selected)
	if err != nil {
		return service.rpcError(operationError(operationContext, err))
	}
	if err := operationContext.Err(); err != nil {
		return service.rpcError(err)
	}
	if len(inventory.Entries) == 0 || inventory.TotalBytes == 0 || uint64(len(inventory.Entries)) > selected.Limits().MaxFiles() || inventory.TotalBytes > selected.Limits().MaxInputBytes() {
		return service.rpcError(&scan.Error{Code: "SCAN_INVENTORY_INVALID", Message: "The scanner inventory is empty or exceeds policy.", Remediation: "Reject the quarantine and repeat bounded inventory."})
	}
	service.inventory = cloneInventory(inventory)
	service.policyName = selected.Name()
	service.state = scannerStateInventoryComplete
	return sendScanProgress(stream, "inventory", 1, 1, "phase", false, true)
}

func (service *ScannerService) Scan(request *privatevmv1.ScannerRequest, stream grpc.ServerStreamingServer[privatevmv1.ScanEvent]) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	selected, err := service.validatePolicyRequest(request, scannerStateInventoryComplete)
	if err != nil {
		return err
	}
	if err := sendScanProgress(stream, "malware-scan", 0, uint64(len(service.inventory.Entries)), "files", false, false); err != nil {
		return service.streamError(stream.Context(), err)
	}
	operationContext, cancel := scannerPolicyContext(stream.Context(), selected)
	defer cancel()
	summary, err := service.malwareTool.Scan(operationContext, cloneInventory(service.inventory), selected)
	if err != nil {
		return service.rpcError(operationError(operationContext, err))
	}
	if err := operationContext.Err(); err != nil {
		return service.rpcError(err)
	}
	if err := validateScanSummary(service.inventory, summary); err != nil {
		return service.rpcError(err)
	}
	service.scanSummary = cloneScanSummary(summary)
	service.state = scannerStateScanComplete
	for _, finding := range summary.Findings {
		if finding.Severity == scan.SeverityInfo {
			continue
		}
		if err := stream.Send(&privatevmv1.ScanEvent{Finding: scannerDiagnostic(finding)}); err != nil {
			return service.streamError(stream.Context(), err)
		}
	}
	return sendScanProgress(stream, "malware-scan", summary.ScannedFiles, uint64(len(service.inventory.Entries)), "files", !hasBlockingFinding(summary.Findings), true)
}

func (service *ScannerService) Reconstruct(request *privatevmv1.ScannerRequest, stream grpc.ServerStreamingServer[privatevmv1.ScanEvent]) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	selected, err := service.validatePolicyRequest(request, scannerStateScanComplete)
	if err != nil {
		return err
	}
	if selected.Mode() != policy.ModeSafe {
		return scannerStatusError(codes.FailedPrecondition, "SCANNER_POLICY_INVALID", "Reconstruction requires the safe scanner policy.", "Restart scanning with the installed safe policy.", false, string(service.state))
	}
	if err := sendScanProgress(stream, "reconstruction", 0, uint64(len(service.inventory.Entries)), "files", false, false); err != nil {
		return service.streamError(stream.Context(), err)
	}
	reconstructed := ScannerReconstruction{
		ArchiveInspectionComplete: true, ReconstructionComplete: true, OutputRescanComplete: true,
	}
	if !hasBlockingFinding(service.scanSummary.Findings) {
		operationContext, cancel := scannerPolicyContext(stream.Context(), selected)
		defer cancel()
		reconstructed, err = service.reconstruction.Reconstruct(operationContext, cloneInventory(service.inventory), cloneScanSummary(service.scanSummary), selected)
		if err != nil {
			cleanupErr := service.cleanupReconstruction()
			if cleanupErr != nil {
				return service.rpcError(cleanupErr)
			}
			return service.rpcError(operationError(operationContext, err))
		}
		if err := operationContext.Err(); err != nil {
			cleanupErr := service.cleanupReconstruction()
			if cleanupErr != nil {
				return service.rpcError(cleanupErr)
			}
			return service.rpcError(err)
		}
	}
	service.reconstructed = cloneReconstruction(reconstructed)
	report, err := service.buildReport(request.GetContext().GetContext().GetSessionId(), selected)
	if err != nil {
		cleanupErr := service.cleanupReconstruction()
		if cleanupErr != nil {
			return service.rpcError(cleanupErr)
		}
		return service.rpcError(err)
	}
	authenticated, err := scan.SignReport(report, service.reportKey.value)
	if err != nil {
		cleanupErr := service.cleanupReconstruction()
		if cleanupErr != nil {
			return service.rpcError(cleanupErr)
		}
		return service.rpcError(err)
	}
	service.report = cloneAuthenticatedReport(authenticated)
	service.state = scannerStateReportComplete
	return sendScanProgress(stream, "reconstruction", uint64(len(service.inventory.Entries)), uint64(len(service.inventory.Entries)), "files", report.Result == "approved", true)
}

func (service *ScannerService) GetScanReport(_ context.Context, request *privatevmv1.ScannerRequest) (*privatevmv1.ScanReportEnvelope, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if _, err := service.validatePolicyRequest(request, scannerStateReportComplete); err != nil {
		return nil, err
	}
	return &privatevmv1.ScanReportEnvelope{
		CanonicalJson:     slices.Clone(service.report.CanonicalJSON),
		AuthenticationTag: slices.Clone(service.report.AuthenticationTag),
		Complete:          service.report.Complete,
	}, nil
}

func (service *ScannerService) ExportApprovedFile(request *privatevmv1.ExportApprovedFileRequest, stream grpc.ServerStreamingServer[privatevmv1.TransferFrame]) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if request == nil || request.GetContext() == nil {
		return scannerStatusError(codes.InvalidArgument, "GUEST_CONTEXT_REQUIRED", "A complete guest request context is required.", "Retry through the private-vm daemon.", false, string(service.state))
	}
	if err := service.bindContext(request.GetContext()); err != nil {
		return err
	}
	if service.state != scannerStateReportComplete || service.closed {
		return service.stateError(scannerStateReportComplete)
	}
	report, err := scan.VerifyApproval(cloneAuthenticatedReport(service.report), service.reportKey.value)
	if err != nil {
		return service.rpcError(err)
	}
	var output *scan.ReportSanitizedOutput
	for index := range report.SanitizedOutputs {
		if report.SanitizedOutputs[index].OutputID == request.GetOutputId() {
			copyOfOutput := report.SanitizedOutputs[index]
			output = &copyOfOutput
			break
		}
	}
	if output == nil {
		return scannerStatusError(codes.NotFound, "SANITIZED_OUTPUT_UNAVAILABLE", "The approved sanitized output is unavailable.", "Request an output identifier from the authenticated scan report.", false, string(service.state))
	}
	if output.SizeBytes > service.maxExportBytes {
		return scannerStatusError(codes.ResourceExhausted, "SCAN_LIMIT_REACHED", "The approved output exceeds the bounded export limit.", "Reduce the selected content and repeat scanning.", false, string(service.state))
	}
	wantDigest, err := hex.DecodeString(output.SHA256)
	if err != nil || len(wantDigest) != sha256.Size {
		clear(wantDigest)
		return scannerStatusError(codes.FailedPrecondition, "REPORT_INCOMPLETE", "The approved output digest is invalid.", "Destroy the scanner and repeat the complete scan workflow.", false, string(service.state))
	}
	defer clear(wantDigest)
	operationContext, cancel := context.WithTimeout(stream.Context(), service.exportTimeout)
	defer cancel()
	reader, err := service.reconstruction.OpenApproved(operationContext, output.OutputID)
	if err != nil {
		return service.rpcError(operationError(operationContext, err))
	}
	if reader == nil {
		return scannerStatusError(codes.FailedPrecondition, "SANITIZED_OUTPUT_UNAVAILABLE", "The approved sanitized output is unavailable.", "Repeat reconstruction in a fresh scanner.", false, string(service.state))
	}
	begin := &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{
		Context: request.GetContext().GetContext(), TransferId: output.OutputID,
		Descriptor_: &privatevmv1.FileDescriptor{
			LogicalName: output.LogicalName, SizeBytes: output.SizeBytes, DetectedMime: output.DetectedMIME,
			Digest: &privatevmv1.Hash{Algorithm: "sha256", Value: slices.Clone(wantDigest)},
		},
	}}}
	if err := stream.Send(begin); err != nil {
		_ = reader.Close()
		return service.streamError(stream.Context(), err)
	}
	hasher := sha256.New()
	buffer := make([]byte, transfer.DefaultMaxChunk)
	var total, sequence uint64
	for total < output.SizeBytes {
		if err := operationContext.Err(); err != nil {
			_ = reader.Close()
			return service.rpcError(err)
		}
		remaining := output.SizeBytes - total
		chunk := buffer
		if remaining < uint64(len(chunk)) {
			chunk = chunk[:remaining]
		}
		count, readErr := io.ReadFull(reader, chunk)
		if count > 0 {
			_, _ = hasher.Write(chunk[:count])
			frame := &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{
				Sequence: sequence, Data: slices.Clone(chunk[:count]),
			}}}
			if err := stream.Send(frame); err != nil {
				_ = reader.Close()
				return service.streamError(stream.Context(), err)
			}
			total += uint64(count)
			sequence++
		}
		if readErr != nil {
			_ = reader.Close()
			return scannerStatusError(codes.FailedPrecondition, "SANITIZED_OUTPUT_CHANGED", "The sanitized output ended before its authenticated size.", "Reject the output and repeat reconstruction.", false, string(service.state))
		}
	}
	var extra [1]byte
	extraCount, extraErr := reader.Read(extra[:])
	closeErr := reader.Close()
	digest := hasher.Sum(nil)
	if extraCount != 0 || (extraErr != nil && !errors.Is(extraErr, io.EOF)) || closeErr != nil || !slices.Equal(digest, wantDigest) {
		clear(digest)
		return scannerStatusError(codes.FailedPrecondition, "SANITIZED_OUTPUT_CHANGED", "The sanitized output no longer matches its authenticated report.", "Reject the output and repeat reconstruction.", false, string(service.state))
	}
	endDigest := slices.Clone(digest)
	clear(digest)
	return service.streamSend(stream, &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{
		TotalSize: total, Digest: &privatevmv1.Hash{Algorithm: "sha256", Value: endDigest},
	}}})
}

func scannerPolicyContext(parent context.Context, selected policy.Policy) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, time.Duration(selected.Limits().ScanTimeoutSeconds())*time.Second)
}

func operationError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Close is the scanner process cleanup-owner hook. It is idempotent and does
// not report success until the reconstruction adapter proves its volatile
// outputs absent.
func (service *ScannerService) Close(ctx context.Context) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed {
		return nil
	}
	if err := service.reconstruction.Cleanup(ctx); err != nil {
		return service.rpcError(err)
	}
	service.closed = true
	service.state = scannerStateClosed
	service.report = scan.AuthenticatedReport{}
	service.reconstructed = ScannerReconstruction{}
	service.inventory = scan.Inventory{}
	service.scanSummary = scan.ScanSummary{}
	return nil
}

func (service *ScannerService) validateRequest(request *privatevmv1.ScannerRequest, policyName string, state scannerRPCState) error {
	return service.validateRequestForStates(request, policyName, state)
}

func (service *ScannerService) validateRequestForStates(request *privatevmv1.ScannerRequest, policyName string, states ...scannerRPCState) error {
	if request == nil || request.GetContext() == nil {
		return scannerStatusError(codes.InvalidArgument, "GUEST_CONTEXT_REQUIRED", "A complete guest request context is required.", "Retry through the private-vm daemon.", false, string(service.state))
	}
	if err := service.bindContext(request.GetContext()); err != nil {
		return err
	}
	if request.GetPolicyName() != policyName {
		return scannerStatusError(codes.InvalidArgument, "SCANNER_POLICY_INVALID", "The scanner policy is invalid for this phase.", "Use no policy for isolation phases and the installed policy for content phases.", false, string(service.state))
	}
	if service.closed || !slices.Contains(states, service.state) {
		return service.stateError(states...)
	}
	return nil
}

func (service *ScannerService) validatePolicyRequest(request *privatevmv1.ScannerRequest, state scannerRPCState) (policy.Policy, error) {
	if request == nil || request.GetContext() == nil {
		return policy.Policy{}, scannerStatusError(codes.InvalidArgument, "GUEST_CONTEXT_REQUIRED", "A complete guest request context is required.", "Retry through the private-vm daemon.", false, string(service.state))
	}
	if err := service.bindContext(request.GetContext()); err != nil {
		return policy.Policy{}, err
	}
	if service.closed || service.state != state {
		return policy.Policy{}, service.stateError(state)
	}
	selected, err := service.policies.Resolve(request.GetPolicyName())
	if err != nil || selected.Validate() != nil || selected.Name() != request.GetPolicyName() {
		return policy.Policy{}, scannerStatusError(codes.InvalidArgument, "SCANNER_POLICY_INVALID", "The requested scanner policy is unavailable or invalid.", "Use an installed, validated safe or quarantine policy.", false, string(service.state))
	}
	if service.policyName != "" && service.policyName != selected.Name() {
		return policy.Policy{}, scannerStatusError(codes.FailedPrecondition, "SCANNER_POLICY_CHANGED", "The scanner policy changed after inventory.", "Destroy the scanner and repeat every phase with one immutable policy.", false, string(service.state))
	}
	return selected, nil
}

func (service *ScannerService) bindContext(request *privatevmv1.GuestContext) error {
	if err := ValidateGuestContext(request, session.RoleScanner); err != nil {
		return err
	}
	sessionID := request.GetContext().GetSessionId()
	if service.sessionID == "" {
		service.sessionID = sessionID
		return nil
	}
	if service.sessionID != sessionID {
		return scannerStatusError(codes.FailedPrecondition, "SCANNER_SESSION_MISMATCH", "The scanner request does not match this guest session.", "Destroy the guest and retry through its owning daemon session.", false, string(service.state))
	}
	return nil
}

func (service *ScannerService) stateError(expected ...scannerRPCState) error {
	names := make([]string, len(expected))
	for index, state := range expected {
		names[index] = string(state)
	}
	return scannerStatusError(codes.FailedPrecondition, "SCANNER_STATE_INVALID", "The scanner phase is not valid for this operation.", "Complete the scanner phases in order; expected "+strings.Join(names, " or ")+".", false, string(service.state))
}

func (service *ScannerService) rpcError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return scannerStatusError(codes.Canceled, "SCAN_CANCELLED", "The scanner operation was cancelled.", "Retry from the last verified scanner phase.", true, string(service.state))
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return scannerStatusError(codes.DeadlineExceeded, "SCAN_TIMEOUT", "The scanner operation exceeded its deadline.", "Destroy the scanner or retry within the bounded policy timeout.", true, string(service.state))
	}
	var scanErr *scan.Error
	if !errors.As(err, &scanErr) || scanErr.Code == "" || scanErr.Message == "" || scanErr.Remediation == "" {
		return scannerStatusError(codes.Internal, "SCAN_ERROR", "The scanner operation failed without complete trusted evidence.", "Destroy the scanner and retry with the verified scanner image.", false, string(service.state))
	}
	grpcCode := scannerGRPCCode(scanErr.Code)
	retryable := grpcCode == codes.Unavailable || grpcCode == codes.DeadlineExceeded || grpcCode == codes.Canceled
	return scannerStatusError(grpcCode, scanErr.Code, scanErr.Message, scanErr.Remediation, retryable, string(service.state))
}

func (service *ScannerService) streamError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return service.rpcError(ctx.Err())
	}
	switch status.Code(err) {
	case codes.Canceled:
		return service.rpcError(context.Canceled)
	case codes.DeadlineExceeded:
		return service.rpcError(context.DeadlineExceeded)
	}
	return scannerStatusError(codes.Unavailable, "SCAN_STREAM_FAILED", "The bounded scanner result stream could not be delivered.", "Inspect scanner status before retrying the operation.", true, string(service.state))
}

func (service *ScannerService) streamSend(stream grpc.ServerStreamingServer[privatevmv1.TransferFrame], frame *privatevmv1.TransferFrame) error {
	if err := stream.Send(frame); err != nil {
		return service.streamError(stream.Context(), err)
	}
	return nil
}

func (service *ScannerService) cleanupReconstruction() error {
	ctx, cancel := context.WithTimeout(context.Background(), service.cleanupTimeout)
	defer cancel()
	if err := service.reconstruction.Cleanup(ctx); err != nil {
		return &scan.Error{Code: "SANITIZED_OUTPUT_CLEANUP_INCOMPLETE", Message: "Volatile scanner output cleanup did not complete.", Remediation: "Destroy the scanner so its cleanup owner can retry."}
	}
	service.reconstructed = ScannerReconstruction{}
	return nil
}

func (service *ScannerService) buildReport(sessionID string, selected policy.Policy) (scan.ScanReport, error) {
	if !service.reconstructed.ArchiveInspectionComplete || !service.reconstructed.ReconstructionComplete || !service.reconstructed.OutputRescanComplete {
		return scan.ScanReport{}, &scan.Error{Code: "REPORT_INCOMPLETE", Message: "The reconstruction evidence is incomplete.", Remediation: "Repeat every scanner phase before requesting promotion."}
	}
	inputs, err := reportInputs(service.inventory, service.scanSummary)
	if err != nil {
		return scan.ScanReport{}, err
	}
	findings := append([]scan.Finding(nil), service.scanSummary.Findings...)
	findings = append(findings, service.reconstructed.Findings...)
	sort.Slice(findings, func(left, right int) bool {
		leftKey := findings[left].RelativePath + "\x00" + findings[left].Code + "\x00" + findings[left].Identifier
		rightKey := findings[right].RelativePath + "\x00" + findings[right].Code + "\x00" + findings[right].Identifier
		return leftKey < rightKey
	})
	archives := append([]scan.ReportArchive(nil), service.reconstructed.Archives...)
	sort.Slice(archives, func(left, right int) bool {
		if archives[left].SourceSHA256 == archives[right].SourceSHA256 {
			return archives[left].Depth < archives[right].Depth
		}
		return archives[left].SourceSHA256 < archives[right].SourceSHA256
	})
	outputs := append([]scan.ReportSanitizedOutput(nil), service.reconstructed.Outputs...)
	sort.Slice(outputs, func(left, right int) bool { return outputs[left].OutputID < outputs[right].OutputID })
	tools := canonicalTools(append(append([]scan.ToolEvidence(nil), service.reconstructed.Tools...), scan.ToolEvidence{
		Name: "clamav-engine", Version: service.receipt.Definitions.EngineVersion,
	}))
	completedAt := service.now().UTC()
	result := "approved"
	if hasBlockingFinding(findings) {
		result = "rejected"
		outputs = nil
	}
	report := scan.ScanReport{
		SchemaVersion: scan.ScanReportSchemaVersion, SessionID: sessionID, Policy: selected.Name(),
		StartedAt: service.startedAt, CompletedAt: completedAt,
		Scanner: scan.ReportScannerIdentity{
			ImageDigest: service.identity.ImageDigest, SourceCommit: service.identity.SourceCommit,
			GuestdVersion: service.identity.GuestdVersion,
		},
		Definitions: scan.ReportDefinitions{
			EngineVersion: service.receipt.Definitions.EngineVersion, DatabaseVersion: service.receipt.Definitions.DatabaseVersion,
			UpdatedAt: service.receipt.Definitions.UpdatedAt.UTC(), Official: service.receipt.Definitions.Official,
			Compatible: service.receipt.Definitions.Compatible,
		},
		Isolation: scan.ReportIsolation{
			NoNetwork: true, QuarantineReadOnly: true, MountOptions: []string{"nodev", "noexec", "nosuid", "ro"},
		},
		Phases: scan.ReportPhases{
			DefinitionsVerified: true, OfflineVerified: true, InventoryComplete: true, MalwareScanComplete: true,
			ArchiveInspectionComplete: true, ReconstructionComplete: true, OutputRescanComplete: true,
		},
		Inputs: inputs, Archives: archives, Findings: findings, SanitizedOutputs: outputs, Tools: tools,
		Result: result, Complete: true,
	}
	if completedAt.After(service.startedAt) {
		report.DurationMillis = uint64(completedAt.Sub(service.startedAt) / time.Millisecond)
	}
	if err := report.Validate(); err != nil {
		return scan.ScanReport{}, err
	}
	return report, nil
}

func definitionsStatus(receipt scan.UpdateReceipt) *privatevmv1.DefinitionsStatus {
	return &privatevmv1.DefinitionsStatus{
		Current: true, DatabaseVersion: receipt.Definitions.DatabaseVersion,
		UpdatedUnixSeconds: receipt.Definitions.UpdatedAt.UTC().Unix(),
	}
}

func validateScanSummary(inventory scan.Inventory, summary scan.ScanSummary) error {
	if !summary.Complete || summary.ScannedFiles != uint64(len(inventory.Entries)) || len(summary.Findings) != len(inventory.Entries) {
		return &scan.Error{Code: "SCAN_FILE_SKIPPED", Message: "The malware scan did not cover every inventoried file.", Remediation: "Reject the quarantine and repeat scanning in a fresh scanner."}
	}
	seen := make(map[string]struct{}, len(summary.Findings))
	for _, finding := range summary.Findings {
		if finding.RelativePath == "" || !validScannerCode(finding.Code) ||
			(finding.Code == "CLAMAV_CLEAN" && finding.Severity != scan.SeverityInfo) ||
			(finding.Code != "CLAMAV_CLEAN" && finding.Severity != scan.SeverityBlocking) {
			return &scan.Error{Code: "SCAN_ERROR", Message: "A scanner finding lacks its inventory association.", Remediation: "Destroy the scanner and retry with the verified scanner image."}
		}
		if _, exists := seen[finding.RelativePath]; exists {
			return &scan.Error{Code: "SCAN_ERROR", Message: "The scanner returned ambiguous findings.", Remediation: "Destroy the scanner and retry with the verified scanner image."}
		}
		seen[finding.RelativePath] = struct{}{}
	}
	for _, entry := range inventory.Entries {
		if _, exists := seen[entry.RelativePath]; !exists {
			return &scan.Error{Code: "SCAN_FILE_SKIPPED", Message: "An inventoried file has no malware verdict.", Remediation: "Reject the quarantine and repeat scanning in a fresh scanner."}
		}
	}
	return nil
}

func validScannerCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, character := range code {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func reportInputs(inventory scan.Inventory, summary scan.ScanSummary) ([]scan.ReportInput, error) {
	verdicts := make(map[string]string, len(summary.Findings))
	for _, finding := range summary.Findings {
		verdicts[finding.RelativePath] = finding.Code
	}
	inputs := make([]scan.ReportInput, 0, len(inventory.Entries))
	for _, entry := range inventory.Entries {
		verdict := verdicts[entry.RelativePath]
		if verdict == "" {
			return nil, &scan.Error{Code: "REPORT_INCOMPLETE", Message: "A scan input lacks its malware verdict.", Remediation: "Repeat the complete offline scan."}
		}
		inputs = append(inputs, scan.ReportInput{
			LogicalName: entry.RelativePath, SizeBytes: entry.SizeBytes, SHA256: entry.SHA256,
			DetectedMIME: entry.DetectedMIME, ExtensionMIME: entry.ExtensionMIME,
			ExtensionAgreement: entry.ExtensionAgreement, ClamAVVerdict: verdict,
		})
	}
	sort.Slice(inputs, func(left, right int) bool { return inputs[left].LogicalName < inputs[right].LogicalName })
	return inputs, nil
}

func canonicalTools(values []scan.ToolEvidence) []scan.ToolEvidence {
	result := append([]scan.ToolEvidence(nil), values...)
	sort.Slice(result, func(left, right int) bool {
		leftKey := result[left].Name + "\x00" + result[left].Version
		rightKey := result[right].Name + "\x00" + result[right].Version
		return leftKey < rightKey
	})
	compacted := result[:0]
	for _, value := range result {
		if len(compacted) == 0 || compacted[len(compacted)-1] != value {
			compacted = append(compacted, value)
		}
	}
	return compacted
}

func hasBlockingFinding(findings []scan.Finding) bool {
	for _, finding := range findings {
		if finding.Severity == scan.SeverityBlocking {
			return true
		}
	}
	return false
}

func scannerDiagnostic(finding scan.Finding) *privatevmv1.Diagnostic {
	severity := privatevmv1.Diagnostic_SEVERITY_WARNING
	if finding.Severity == scan.SeverityBlocking {
		severity = privatevmv1.Diagnostic_SEVERITY_BLOCKING
	}
	return &privatevmv1.Diagnostic{
		Code: finding.Code, Severity: severity, Summary: "The scanner recorded a policy finding.",
		Remediation: "Inspect the authenticated scan report and reject blocking content.", Overridable: false,
	}
}

func sendScanProgress(stream grpc.ServerStreamingServer[privatevmv1.ScanEvent], operation string, completed, total uint64, unit string, approved, complete bool) error {
	return stream.Send(&privatevmv1.ScanEvent{
		Progress: &privatevmv1.Progress{Operation: operation, Completed: completed, Total: total, Unit: unit},
		Approved: approved, Complete: complete,
	})
}

func scannerGRPCCode(code string) codes.Code {
	switch {
	case code == "SCAN_CANCELLED":
		return codes.Canceled
	case code == "SCAN_TIMEOUT":
		return codes.DeadlineExceeded
	case strings.Contains(code, "LIMIT"):
		return codes.ResourceExhausted
	case strings.Contains(code, "UNAVAILABLE") || strings.Contains(code, "UPDATE_FAILED"):
		return codes.Unavailable
	case strings.Contains(code, "INVALID") || strings.Contains(code, "PATH_UNSAFE"):
		return codes.InvalidArgument
	case strings.Contains(code, "CLEANUP_INCOMPLETE"):
		return codes.FailedPrecondition
	default:
		return codes.FailedPrecondition
	}
}

func scannerStatusError(grpcCode codes.Code, code, message, remediation string, retryable bool, state string) error {
	base := status.New(grpcCode, code+": "+message)
	withDetail, err := base.WithDetails(&privatevmv1.ErrorDetail{
		Code: code, SafeMessage: message, Remediation: remediation, Retryable: retryable, SessionState: state,
	})
	if err != nil {
		return base.Err()
	}
	return withDetail.Err()
}

func cloneBootEvidence(value scan.BootEvidence) scan.BootEvidence {
	value.Interfaces = append([]scan.InterfaceEvidence(nil), value.Interfaces...)
	value.Quarantine.MountOptions = append([]string(nil), value.Quarantine.MountOptions...)
	return value
}

func cloneInventory(value scan.Inventory) scan.Inventory {
	value.Entries = append([]scan.InventoryEntry(nil), value.Entries...)
	return value
}

func cloneScanSummary(value scan.ScanSummary) scan.ScanSummary {
	value.Findings = append([]scan.Finding(nil), value.Findings...)
	return value
}

func cloneReconstruction(value ScannerReconstruction) ScannerReconstruction {
	value.Archives = append([]scan.ReportArchive(nil), value.Archives...)
	value.Findings = append([]scan.Finding(nil), value.Findings...)
	value.Outputs = append([]scan.ReportSanitizedOutput(nil), value.Outputs...)
	value.Tools = append([]scan.ToolEvidence(nil), value.Tools...)
	return value
}

func cloneAuthenticatedReport(value scan.AuthenticatedReport) scan.AuthenticatedReport {
	value.CanonicalJSON = slices.Clone(value.CanonicalJSON)
	value.AuthenticationTag = slices.Clone(value.AuthenticationTag)
	return value
}
