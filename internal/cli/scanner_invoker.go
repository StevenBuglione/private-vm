package cli

import (
	"context"
	"errors"
	"io"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"google.golang.org/grpc"
)

func (invoker *ProductionInvoker) invokeScanner(ctx context.Context, id CommandID, intent Intent) (Result, error) {
	connection, client, err := invoker.client()
	if err != nil {
		return Result{}, err
	}
	defer connection.Close()
	requestID, err := invoker.nextRequestID()
	if err != nil {
		return Result{}, internalScannerError()
	}

	switch id {
	case CommandScannerStart:
		request, ok := intent.(ScannerIntent)
		if !ok || request.SessionID == "" {
			return Result{}, invalidScannerIntent()
		}
		stream, err := client.StartScanner(ctx, &privatevmv1.HostScannerStartRequest{
			Context: sessionRequestContext(requestID, request.SessionID), PolicyName: "safe",
		}, grpc.MaxCallRecvMsgSize(4<<20))
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		var final *privatevmv1.HostScannerStatus
		for {
			event, receiveErr := stream.Recv()
			if errors.Is(receiveErr, io.EOF) {
				break
			}
			if receiveErr != nil {
				return Result{}, daemonRPCError(receiveErr)
			}
			if event == nil || event.GetStatus() == nil {
				return Result{}, internalScannerError()
			}
			if progress := event.GetProgress(); progress != nil && (progress.GetTotal() == 0 || progress.GetCompleted() > progress.GetTotal()) {
				return Result{}, internalScannerError()
			}
			final = event.GetStatus()
		}
		return scannerStatusResult(final)
	case CommandScannerStatus:
		request, ok := intent.(ScannerIntent)
		if !ok || request.SessionID == "" {
			return Result{}, invalidScannerIntent()
		}
		response, err := client.GetScannerStatus(ctx, &privatevmv1.HostScannerControlRequest{Context: sessionRequestContext(requestID, request.SessionID)})
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		return scannerStatusResult(response)
	case CommandScannerReport:
		request, ok := intent.(ScannerIntent)
		if !ok || request.SessionID == "" {
			return Result{}, invalidScannerIntent()
		}
		response, err := client.GetScannerReport(ctx, &privatevmv1.HostScannerControlRequest{Context: sessionRequestContext(requestID, request.SessionID)})
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		return scannerReportResult(response)
	case CommandScannerApprove:
		request, ok := intent.(ScanApprovalIntent)
		if !ok || request.SessionID == "" || (request.OpenIn == "") == (request.To == "") {
			return Result{}, invalidScannerIntent()
		}
		destination := privatevmv1.ScannerApprovalDestination_SCANNER_APPROVAL_DESTINATION_UNSPECIFIED
		if request.OpenIn == "workstation" && request.To == "" {
			destination = privatevmv1.ScannerApprovalDestination_SCANNER_APPROVAL_DESTINATION_WORKSTATION
		} else if request.To == "usb" && request.OpenIn == "" {
			destination = privatevmv1.ScannerApprovalDestination_SCANNER_APPROVAL_DESTINATION_USB
		} else {
			return Result{}, invalidScannerIntent()
		}
		response, err := client.ApproveScanner(ctx, &privatevmv1.HostScannerApprovalRequest{
			Context: sessionRequestContext(requestID, request.SessionID), Destination: destination,
		})
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		return scannerStatusResult(response)
	case CommandScannerReject:
		request, ok := intent.(ScannerIntent)
		if !ok || request.SessionID == "" {
			return Result{}, invalidScannerIntent()
		}
		response, err := client.RejectScanner(ctx, &privatevmv1.HostScannerControlRequest{Context: sessionRequestContext(requestID, request.SessionID)})
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		return scannerStatusResult(response)
	default:
		return Result{}, invalidScannerIntent()
	}
}

func scannerStatusResult(response *privatevmv1.HostScannerStatus) (Result, error) {
	if response == nil || response.GetSchemaVersion() != 1 || response.GetScannerSessionId() == "" || response.GetWorkflowState() == "" || response.GetCode() == "" || response.GetRemediation() == "" || response.GetBlockingFindingCount() > response.GetFindingCount() || (response.GetPolicyApproved() && response.GetPolicyRejected()) {
		return Result{}, internalScannerError()
	}
	decision := "pending"
	if response.GetPolicyApproved() {
		decision = "approved"
	} else if response.GetPolicyRejected() {
		decision = "rejected"
	}
	payload := ScannerStatusPayload{
		SchemaVersion: response.GetSchemaVersion(), SessionID: response.GetScannerSessionId(), WorkflowState: response.GetWorkflowState(),
		ReportComplete: response.GetReportComplete(), Decision: decision, FindingCount: response.GetFindingCount(),
		BlockingFindingCount: response.GetBlockingFindingCount(), SanitizedOutputCount: response.GetSanitizedOutputCount(),
		SanitizedOutputBytes: response.GetSanitizedOutputBytes(), Code: response.GetCode(), Remediation: response.GetRemediation(),
	}
	return Result{Code: CodeScannerStatus, Data: payload}, nil
}

func scannerReportResult(response *privatevmv1.HostScannerReportSummary) (Result, error) {
	if response == nil || response.GetSchemaVersion() != 1 || response.GetScannerSessionId() == "" || !response.GetComplete() || (response.GetResult() != "approved" && response.GetResult() != "rejected") || response.GetCode() == "" || response.GetRemediation() == "" || response.GetBlockingFindingCount() > response.GetFindingCount() {
		return Result{}, internalScannerError()
	}
	payload := ScannerStatusPayload{
		SchemaVersion: response.GetSchemaVersion(), SessionID: response.GetScannerSessionId(), WorkflowState: "REPORT_COMPLETE",
		ReportComplete: response.GetComplete(), Decision: response.GetResult(), InputCount: response.GetInputCount(),
		FindingCount: response.GetFindingCount(), BlockingFindingCount: response.GetBlockingFindingCount(),
		SanitizedOutputCount: response.GetSanitizedOutputCount(), SanitizedOutputBytes: response.GetSanitizedOutputBytes(),
		Code: response.GetCode(), Remediation: response.GetRemediation(),
	}
	return Result{Code: CodeScannerStatus, Data: payload}, nil
}

func invalidScannerIntent() error {
	return apperror.New("SCANNER_REQUEST_INVALID", exitcode.ScanRejected, "The scanner request contract is invalid.", "Use an exact sealed downloader or active scanner session and one documented destination.")
}

func internalScannerError() error {
	return apperror.New("INTERNAL_ERROR", exitcode.Internal, "The scanner response could not be represented safely.", "Inspect volatile scanner status and retry only if its documented state permits it.")
}
