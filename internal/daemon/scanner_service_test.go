package daemon

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc/codes"
)

type fakeScannerOrchestrator struct {
	mu         sync.Mutex
	operations []string
	failAt     string
	failErr    error
	cleanupErr error
	rejected   bool
	report     scan.ScanReport
}

func (fake *fakeScannerOrchestrator) record(operation string) error {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.operations = append(fake.operations, operation)
	if fake.failAt == operation {
		return fake.failErr
	}
	return nil
}

func (fake *fakeScannerOrchestrator) Preflight(context.Context, session.Snapshot, session.Snapshot) error {
	return fake.record("preflight")
}

func (fake *fakeScannerOrchestrator) VerifyImage(context.Context, session.Snapshot) error {
	return fake.record("verify-image")
}

func (fake *fakeScannerOrchestrator) StorageAllocation(_, scanner session.Snapshot) session.AllocateFunc {
	return fake.allocation("storage", scanner.ID)
}

func (fake *fakeScannerOrchestrator) UpdateRuntimeAllocation(scanner session.Snapshot) session.AllocateFunc {
	return fake.allocation("update-runtime", scanner.ID)
}

func (fake *fakeScannerOrchestrator) OfflineRuntimeAllocation(scanner session.Snapshot) session.AllocateFunc {
	return fake.allocation("offline-runtime", scanner.ID)
}

func (fake *fakeScannerOrchestrator) allocation(name, scannerID string) session.AllocateFunc {
	return func(context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		if err := fake.record(name + ".allocate"); err != nil {
			return nil, nil, err
		}
		return func(context.Context) error {
				if err := fake.record(name + ".cleanup"); err != nil {
					return err
				}
				return fake.cleanupErr
			}, func(context.Context) error {
				if err := fake.record(name + ".audit"); err != nil {
					return err
				}
				return nil
			}, nil
	}
}

func (fake *fakeScannerOrchestrator) UpdateDefinitions(context.Context, session.Snapshot) (*privatevmv1.DefinitionsStatus, error) {
	if err := fake.record("definitions"); err != nil {
		return nil, err
	}
	return &privatevmv1.DefinitionsStatus{Current: true, DatabaseVersion: "fixture-definitions", UpdatedUnixSeconds: time.Now().UTC().Unix()}, nil
}

func (fake *fakeScannerOrchestrator) StopUpdate(context.Context, session.Snapshot) error {
	return fake.record("stop-update")
}

func (fake *fakeScannerOrchestrator) VerifyOffline(context.Context, session.Snapshot) (*privatevmv1.OfflineStatus, error) {
	if err := fake.record("verify-offline"); err != nil {
		return nil, err
	}
	return &privatevmv1.OfflineStatus{NoNetwork: true, QuarantineReadOnly: true}, nil
}

func (fake *fakeScannerOrchestrator) Inventory(_ context.Context, _ session.Snapshot, _ string, emit func(*privatevmv1.ScanEvent) error) error {
	if err := fake.record("inventory"); err != nil {
		return err
	}
	return emit(scannerTestProgress("inventory"))
}

func (fake *fakeScannerOrchestrator) Scan(_ context.Context, _ session.Snapshot, _ string, emit func(*privatevmv1.ScanEvent) error) error {
	if err := fake.record("scan"); err != nil {
		return err
	}
	return emit(scannerTestProgress("malware-scan"))
}

func (fake *fakeScannerOrchestrator) Reconstruct(_ context.Context, _ session.Snapshot, _ string, emit func(*privatevmv1.ScanEvent) error) error {
	if err := fake.record("reconstruct"); err != nil {
		return err
	}
	return emit(scannerTestProgress("reconstruction"))
}

func (fake *fakeScannerOrchestrator) Report(_ context.Context, scanner session.Snapshot, _ string) (ScannerReportEvidence, error) {
	if err := fake.record("report"); err != nil {
		return ScannerReportEvidence{}, err
	}
	report := fake.report
	if report.SessionID == "" {
		report = approvedScannerTestReport(scanner.ID)
	}
	if fake.rejected {
		report.Result = "rejected"
		report.SanitizedOutputs = nil
		report.Findings = []scan.Finding{{
			Code:         "MALWARE_DETECTED",
			Severity:     scan.SeverityBlocking,
			RelativePath: "fixture.pdf",
			Detail:       "The fixture was blocked.",
		}}
	}
	return ScannerReportEvidence{Report: report}, nil
}

func (fake *fakeScannerOrchestrator) Promote(_ context.Context, _ session.Snapshot, _ ScannerReportEvidence, destination ScannerDestination) error {
	return fake.record("promote-" + string(destination))
}

func (fake *fakeScannerOrchestrator) StopOffline(context.Context, session.Snapshot) error {
	return fake.record("stop-offline")
}

func (fake *fakeScannerOrchestrator) log() []string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return slices.Clone(fake.operations)
}

func TestScannerHostWorkflowOwnsUpdateOfflineReportPromotionAndCleanup(t *testing.T) {
	server, socket, _ := newUnstartedTestServer(t, 0)
	fake := &fakeScannerOrchestrator{}
	server.options.Service.Scanners = fake
	source := sealedDownloaderSession(t, server.options.Service.Sessions)
	done := startTestServer(t, server)
	connection, client := dialTestDaemon(t, socket)
	defer connection.Close()

	stream, err := client.StartScanner(t.Context(), &privatevmv1.HostScannerStartRequest{Context: validRequestContext(source.ID), PolicyName: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	var final *privatevmv1.HostScannerStatus
	var progress int
	for {
		event, receiveErr := stream.Recv()
		if errors.Is(receiveErr, io.EOF) {
			break
		}
		if receiveErr != nil {
			t.Fatal(receiveErr)
		}
		final = event.GetStatus()
		if event.GetProgress() != nil {
			progress++
		}
	}
	if final == nil || final.GetWorkflowState() != "REPORT_COMPLETE" || !final.GetReportComplete() || final.GetSanitizedOutputCount() != 1 || progress != 3 {
		t.Fatalf("final scanner status=%+v progress=%d", final, progress)
	}
	report, err := client.GetScannerReport(t.Context(), &privatevmv1.HostScannerControlRequest{Context: validRequestContext(final.GetScannerSessionId())})
	if err != nil || report.GetInputCount() != 1 || report.GetSanitizedOutputCount() != 1 || report.GetResult() != "approved" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	approved, err := client.ApproveScanner(t.Context(), &privatevmv1.HostScannerApprovalRequest{
		Context:     validRequestContext(final.GetScannerSessionId()),
		Destination: privatevmv1.ScannerApprovalDestination_SCANNER_APPROVAL_DESTINATION_WORKSTATION,
	})
	if err != nil || approved.GetWorkflowState() != "SCAN_VM_STOPPED" || !approved.GetPolicyApproved() {
		t.Fatalf("approval=%+v err=%v", approved, err)
	}
	cleaned, err := server.options.Service.Sessions.Get(final.GetScannerSessionId(), uint32(os.Geteuid()))
	if err != nil || cleaned.Phase != session.PhaseDestroyed {
		t.Fatalf("cleaned scanner=%+v err=%v", cleaned, err)
	}
	wantPrefix := []string{
		"preflight", "verify-image", "storage.allocate", "update-runtime.allocate", "definitions", "stop-update",
		"offline-runtime.allocate", "verify-offline", "inventory", "scan", "reconstruct", "report", "report", "report",
		"promote-workstation", "stop-offline", "offline-runtime.cleanup", "offline-runtime.audit",
		"update-runtime.cleanup", "update-runtime.audit", "storage.cleanup", "storage.audit",
	}
	if !slices.Equal(fake.log(), wantPrefix) {
		t.Fatalf("scanner operations=%v want=%v", fake.log(), wantPrefix)
	}
	stopTestServer(t, server, done)
}

func TestScannerHostFailureCancellationTimeoutAndCleanupFailClosed(t *testing.T) {
	for _, test := range []struct {
		name       string
		failure    error
		cleanupErr error
		grpcCode   codes.Code
		code       string
		phase      session.Phase
	}{
		{name: "failure", failure: &scan.Error{Code: "SCAN_ERROR", Message: "The scanner fixture failed.", Remediation: "Reject the fixture."}, grpcCode: codes.FailedPrecondition, code: "SCAN_ERROR", phase: session.PhaseDestroyed},
		{name: "cancellation", failure: context.Canceled, grpcCode: codes.Canceled, code: "REQUEST_CANCELED", phase: session.PhaseDestroyed},
		{name: "timeout", failure: context.DeadlineExceeded, grpcCode: codes.DeadlineExceeded, code: "REQUEST_TIMEOUT", phase: session.PhaseDestroyed},
		{name: "cleanup", failure: errors.New("injected scan failure"), cleanupErr: errors.New("injected cleanup failure"), grpcCode: codes.FailedPrecondition, code: "CLEANUP_INCOMPLETE", phase: session.PhaseDestroying},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, socket, _ := newUnstartedTestServer(t, 0)
			fake := &fakeScannerOrchestrator{failAt: "inventory", failErr: test.failure, cleanupErr: test.cleanupErr}
			server.options.Service.Scanners = fake
			source := sealedDownloaderSession(t, server.options.Service.Sessions)
			done := startTestServer(t, server)
			connection, client := dialTestDaemon(t, socket)
			stream, err := client.StartScanner(t.Context(), &privatevmv1.HostScannerStartRequest{Context: validRequestContext(source.ID), PolicyName: "safe"})
			if err != nil {
				t.Fatal(err)
			}
			var scannerID string
			for {
				event, receiveErr := stream.Recv()
				if event != nil && event.GetStatus() != nil {
					scannerID = event.GetStatus().GetScannerSessionId()
				}
				if receiveErr != nil {
					assertRPCError(t, receiveErr, test.grpcCode, test.code)
					break
				}
			}
			if scannerID == "" {
				t.Fatal("scanner id was not emitted before failure")
			}
			current, getErr := server.options.Service.Sessions.Get(scannerID, uint32(os.Geteuid()))
			if getErr != nil || current.Phase != test.phase {
				t.Fatalf("scanner after failure=%+v err=%v", current, getErr)
			}
			_ = connection.Close()
			stopTestServer(t, server, done)
		})
	}
}

func TestScannerRejectStopsRejectedGuestBeforeCleanup(t *testing.T) {
	server, socket, _ := newUnstartedTestServer(t, 0)
	fake := &fakeScannerOrchestrator{}
	server.options.Service.Scanners = fake
	source := sealedDownloaderSession(t, server.options.Service.Sessions)
	done := startTestServer(t, server)
	connection, client := dialTestDaemon(t, socket)
	defer connection.Close()

	stream, err := client.StartScanner(t.Context(), &privatevmv1.HostScannerStartRequest{Context: validRequestContext(source.ID), PolicyName: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	var scannerID string
	for {
		event, receiveErr := stream.Recv()
		if event != nil && event.GetStatus() != nil {
			scannerID = event.GetStatus().GetScannerSessionId()
		}
		if errors.Is(receiveErr, io.EOF) {
			break
		}
		if receiveErr != nil {
			t.Fatal(receiveErr)
		}
	}
	rejected, err := client.RejectScanner(t.Context(), &privatevmv1.HostScannerControlRequest{Context: validRequestContext(scannerID)})
	if err != nil || rejected.GetWorkflowState() != "SCAN_VM_STOPPED" || !rejected.GetPolicyRejected() {
		t.Fatalf("rejected=%+v err=%v", rejected, err)
	}
	if slices.Contains(fake.log(), "promote-workstation") || slices.Contains(fake.log(), "promote-usb") {
		t.Fatalf("reject invoked promotion: %v", fake.log())
	}
	stopTestServer(t, server, done)
}

func TestBlockingScannerReportStopsOfflineGuestAndCannotApprove(t *testing.T) {
	server, socket, _ := newUnstartedTestServer(t, 0)
	fake := &fakeScannerOrchestrator{rejected: true}
	server.options.Service.Scanners = fake
	source := sealedDownloaderSession(t, server.options.Service.Sessions)
	done := startTestServer(t, server)
	connection, client := dialTestDaemon(t, socket)
	defer connection.Close()

	stream, err := client.StartScanner(t.Context(), &privatevmv1.HostScannerStartRequest{Context: validRequestContext(source.ID), PolicyName: "safe"})
	if err != nil {
		t.Fatal(err)
	}
	var scannerID string
	var final *privatevmv1.HostScannerStatus
	for {
		event, receiveErr := stream.Recv()
		if event != nil && event.GetStatus() != nil {
			scannerID = event.GetStatus().GetScannerSessionId()
			final = event.GetStatus()
		}
		if errors.Is(receiveErr, io.EOF) {
			break
		}
		if receiveErr != nil {
			t.Fatal(receiveErr)
		}
	}
	if scannerID == "" || final == nil || final.GetWorkflowState() != "SCAN_VM_STOPPED" || !final.GetPolicyRejected() || final.GetSanitizedOutputCount() != 0 {
		t.Fatalf("blocking scanner result=%+v", final)
	}
	_, err = client.ApproveScanner(t.Context(), &privatevmv1.HostScannerApprovalRequest{
		Context:     validRequestContext(scannerID),
		Destination: privatevmv1.ScannerApprovalDestination_SCANNER_APPROVAL_DESTINATION_WORKSTATION,
	})
	assertRPCError(t, err, codes.FailedPrecondition, "SCANNER_STATE_INVALID")
	if slices.Contains(fake.log(), "promote-workstation") || slices.Contains(fake.log(), "promote-usb") {
		t.Fatalf("blocking report invoked promotion: %v", fake.log())
	}
	rejected, err := client.RejectScanner(t.Context(), &privatevmv1.HostScannerControlRequest{Context: validRequestContext(scannerID)})
	if err != nil || rejected.GetWorkflowState() != "SCAN_VM_STOPPED" || !rejected.GetPolicyRejected() {
		t.Fatalf("rejected=%+v err=%v", rejected, err)
	}
	current, getErr := server.options.Service.Sessions.Get(scannerID, uint32(os.Geteuid()))
	if getErr != nil || current.Phase != session.PhaseDestroyed {
		t.Fatalf("blocking scanner did not clean: %+v err=%v", current, getErr)
	}
	stopTestServer(t, server, done)
}

func sealedDownloaderSession(t *testing.T, manager *session.Manager) session.Snapshot {
	t.Helper()
	snapshot := activeDownloaderSession(t, manager, nil)
	var err error
	for _, state := range []string{
		"METADATA_FETCHING", "METADATA_READY", "FILE_SELECTION_REQUIRED", "CAPACITY_VERIFIED",
		"DOWNLOADING", "DOWNLOAD_COMPLETE", "DOWNLOADER_STOPPED", "QUARANTINE_SEALED",
	} {
		snapshot, err = manager.TransitionWorkflow(t.Context(), snapshot.ID, snapshot.OwnerUID, state)
		if err != nil {
			t.Fatal(err)
		}
	}
	return snapshot
}

func scannerTestProgress(operation string) *privatevmv1.ScanEvent {
	return &privatevmv1.ScanEvent{Progress: &privatevmv1.Progress{Operation: operation, Completed: 1, Total: 1, Unit: "files"}, Approved: true, Complete: true}
}

func approvedScannerTestReport(sessionID string) scan.ScanReport {
	started := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Millisecond)
	completed := started.Add(5 * time.Minute)
	return scan.ScanReport{
		SchemaVersion: scan.ScanReportSchemaVersion, SessionID: sessionID, Policy: "safe",
		StartedAt: started, CompletedAt: completed, DurationMillis: 300000,
		Scanner: scan.ReportScannerIdentity{
			ImageDigest: "sha256:" + strings.Repeat("a", 64), SourceCommit: strings.Repeat("b", 40), GuestdVersion: "1.0.0-test",
		},
		Definitions: scan.ReportDefinitions{
			EngineVersion: "1.5.1", DatabaseVersion: "fixture-definitions", UpdatedAt: started.Add(-time.Hour), Official: true, Compatible: true,
		},
		Isolation: scan.ReportIsolation{NoNetwork: true, QuarantineReadOnly: true, MountOptions: []string{"nodev", "noexec", "nosuid", "ro"}},
		Phases: scan.ReportPhases{
			DefinitionsVerified: true, OfflineVerified: true, InventoryComplete: true, MalwareScanComplete: true,
			ArchiveInspectionComplete: true, ReconstructionComplete: true, OutputRescanComplete: true,
		},
		Inputs: []scan.ReportInput{{
			LogicalName: "fixture.pdf", SizeBytes: 12, SHA256: strings.Repeat("c", 64), DetectedMIME: "application/pdf",
			ExtensionMIME: "application/pdf", ExtensionAgreement: true, ClamAVVerdict: "CLAMAV_CLEAN",
		}},
		Archives: []scan.ReportArchive{},
		Findings: []scan.Finding{{Code: "PDF_ACTIVE_CONTENT_REMOVED", Severity: scan.SeverityInfo, RelativePath: "fixture.pdf", Detail: "The fixture was reconstructed."}},
		SanitizedOutputs: []scan.ReportSanitizedOutput{{
			OutputID: "scan-out-" + strings.Repeat("d", 32), LogicalName: "fixture.safe.pdf", SourceSHA256: strings.Repeat("c", 64),
			SizeBytes: 20, SHA256: strings.Repeat("e", 64), DetectedMIME: "application/pdf", Transformation: "pdf-raster-rebuild-v1", RescanVerdict: "CLAMAV_CLEAN",
		}},
		Tools: []scan.ToolEvidence{{Name: "clamav", Version: "1.5.1"}}, Result: "approved", Complete: true,
	}
}
