package cli

import (
	"bytes"
	"context"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const cliScannerID = "pvm-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

type cliScannerDaemon struct {
	privatevmv1.UnimplementedPrivateVMDaemonServiceServer
	source      string
	destination privatevmv1.ScannerApprovalDestination
}

func (daemon *cliScannerDaemon) StartScanner(request *privatevmv1.HostScannerStartRequest, stream grpc.ServerStreamingServer[privatevmv1.HostScannerEvent]) error {
	daemon.source = request.GetContext().GetSessionId()
	return stream.Send(&privatevmv1.HostScannerEvent{
		Status:   scannerCLIStatus("REPORT_COMPLETE", true, false, false),
		Progress: &privatevmv1.Progress{Operation: "reconstruction", Completed: 1, Total: 1, Unit: "files"},
	})
}

func (*cliScannerDaemon) GetScannerStatus(context.Context, *privatevmv1.HostScannerControlRequest) (*privatevmv1.HostScannerStatus, error) {
	return scannerCLIStatus("REPORT_COMPLETE", true, false, false), nil
}

func (*cliScannerDaemon) GetScannerReport(context.Context, *privatevmv1.HostScannerControlRequest) (*privatevmv1.HostScannerReportSummary, error) {
	return &privatevmv1.HostScannerReportSummary{
		SchemaVersion: 1, ScannerSessionId: cliScannerID, Complete: true, Result: "approved",
		InputCount: 2, FindingCount: 1, SanitizedOutputCount: 1, SanitizedOutputBytes: 64,
		Code: "SCAN_REPORT_APPROVABLE", Remediation: "Choose one documented destination.",
	}, nil
}

func (daemon *cliScannerDaemon) ApproveScanner(_ context.Context, request *privatevmv1.HostScannerApprovalRequest) (*privatevmv1.HostScannerStatus, error) {
	daemon.destination = request.GetDestination()
	return scannerCLIStatus("SCAN_VM_STOPPED", true, true, false), nil
}

func (*cliScannerDaemon) RejectScanner(context.Context, *privatevmv1.HostScannerControlRequest) (*privatevmv1.HostScannerStatus, error) {
	return scannerCLIStatus("SCAN_VM_STOPPED", true, false, true), nil
}

func TestProductionScannerInvokerUsesDaemonWorkflowAndAggregateOnlyOutput(t *testing.T) {
	daemon := &cliScannerDaemon{}
	socket, stop := startSessionInvokerDaemon(t, daemon)
	defer stop()
	invoker := &ProductionInvoker{socketPath: socket, requestID: func() (string, error) { return "request-scanner-1234", nil }}

	start, err := invoker.Invoke(t.Context(), CommandScannerStart, ScannerIntent{SessionID: cliSessionID})
	if err != nil || daemon.source != cliSessionID {
		t.Fatalf("start=%+v source=%q err=%v", start, daemon.source, err)
	}
	status, err := invoker.Invoke(t.Context(), CommandScannerStatus, ScannerIntent{SessionID: cliScannerID})
	if err != nil || status.Data.(ScannerStatusPayload).Decision != "pending" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	report, err := invoker.Invoke(t.Context(), CommandScannerReport, ScannerIntent{SessionID: cliScannerID})
	if err != nil || report.Data.(ScannerStatusPayload).InputCount != 2 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	approved, err := invoker.Invoke(t.Context(), CommandScannerApprove, ScanApprovalIntent{SessionID: cliScannerID, To: "usb"})
	if err != nil || approved.Data.(ScannerStatusPayload).Decision != "approved" || daemon.destination != privatevmv1.ScannerApprovalDestination_SCANNER_APPROVAL_DESTINATION_USB {
		t.Fatalf("approved=%+v destination=%s err=%v", approved, daemon.destination, err)
	}
	rejected, err := invoker.Invoke(t.Context(), CommandScannerReject, ScannerIntent{SessionID: cliScannerID})
	if err != nil || rejected.Data.(ScannerStatusPayload).Decision != "rejected" {
		t.Fatalf("rejected=%+v err=%v", rejected, err)
	}

	for _, result := range []Result{start, status, report, approved, rejected} {
		rendered, renderErr := NewRenderer(true).renderSuccessBytes(result.Code, result.Data)
		if renderErr != nil {
			t.Fatal(renderErr)
		}
		for _, forbidden := range [][]byte{[]byte("private-name.pdf"), []byte("sha256:"), []byte("malware-signature"), []byte("canonical_json")} {
			if bytes.Contains(rendered, forbidden) {
				t.Fatalf("scanner output exposed forbidden detail %q: %s", forbidden, rendered)
			}
		}
	}
}

func TestProductionScannerInvokerRejectsIncompleteDaemonEvidence(t *testing.T) {
	if _, err := scannerStatusResult(&privatevmv1.HostScannerStatus{SchemaVersion: 1, ScannerSessionId: cliScannerID, WorkflowState: "REPORT_COMPLETE"}); err == nil {
		t.Fatal("incomplete scanner status was accepted")
	}
	if _, err := scannerReportResult(&privatevmv1.HostScannerReportSummary{SchemaVersion: 1, ScannerSessionId: cliScannerID, Result: "approved"}); err == nil {
		t.Fatal("incomplete scanner report was accepted")
	}
}

func TestScannerDaemonDetailsMapToScanExit(t *testing.T) {
	for _, code := range []string{"SCANNER_STATE_INVALID", "REPORT_INCOMPLETE", "ARCHIVE_LIMIT_REACHED", "CLAMAV_UNAVAILABLE", "QUARANTINE_NOT_READ_ONLY"} {
		application := apperror.From(daemonRPCError(daemonSafeError(t, codes.FailedPrecondition, code)))
		if application.Code != code || application.ExitCode != exitcode.ScanRejected {
			t.Fatalf("scanner detail %s mapped to %+v", code, application)
		}
	}
}

func scannerCLIStatus(state string, complete, approved, rejected bool) *privatevmv1.HostScannerStatus {
	code := "SCAN_REPORT_APPROVABLE"
	remediation := "Choose one documented destination."
	if approved {
		code, remediation = "SCAN_PROMOTION_VERIFIED", "The volatile scanner is being cleaned."
	} else if rejected {
		code, remediation = "SCAN_REJECTED", "Do not promote the original content."
	}
	return &privatevmv1.HostScannerStatus{
		SchemaVersion: 1, ScannerSessionId: cliScannerID, WorkflowState: state, ReportComplete: complete,
		PolicyApproved: approved, PolicyRejected: rejected, FindingCount: 1, SanitizedOutputCount: 1,
		SanitizedOutputBytes: 64, Code: code, Remediation: remediation,
	}
}
