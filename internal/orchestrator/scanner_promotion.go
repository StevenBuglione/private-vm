package orchestrator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/transfer"
	"google.golang.org/grpc"
)

// WorkstationScannerPromotion is the one-way, in-memory scanner-to-workstation
// relay. The daemon creates and starts the destination session; this owner can
// address only that active workstation and one output authenticated by the
// complete safe-policy report.
type WorkstationScannerPromotion struct{ roles *HostRoles }

func NewWorkstationScannerPromotion(roles *HostRoles) (*WorkstationScannerPromotion, error) {
	if roles == nil {
		return nil, ErrScannerPromotionPending
	}
	return &WorkstationScannerPromotion{roles: roles}, nil
}

func (promotion *WorkstationScannerPromotion) Promote(ctx context.Context, scanner session.Snapshot, report scan.ScanReport, destination string, workstation session.Snapshot, client privatevmv1.ScannerGuestServiceClient) error {
	if promotion == nil || promotion.roles == nil || ctx == nil || destination != "workstation" || nilLikeHost(client) ||
		scanner.Role != session.RoleScanner || scanner.Phase != session.PhaseActive || scanner.WorkflowState != "REPORT_COMPLETE" ||
		workstation.Role != session.RoleWorkstation || workstation.Phase != session.PhaseActive || workstation.WorkflowState != "WORKING" ||
		workstation.OwnerUID != scanner.OwnerUID || workstation.ID == scanner.ID || !workstation.CreatedAt.After(scanner.CreatedAt) {
		return ErrScannerPromotionPending
	}
	source, err := newApprovedScannerWorkspaceSource(scanner, report, client)
	if err != nil {
		return err
	}
	receipt, err := promotion.roles.PromoteApprovedWorkspace(ctx, workstation, source)
	if err != nil || !validReceipt(receipt, source.transferID, source.header) {
		return errors.Join(ErrWorkspaceTransfer, err)
	}
	return nil
}

type approvedScannerWorkspaceSource struct {
	scanner    session.Snapshot
	output     scan.ReportSanitizedOutput
	client     privatevmv1.ScannerGuestServiceClient
	header     transfer.Header
	transferID string
}

func newApprovedScannerWorkspaceSource(scanner session.Snapshot, report scan.ScanReport, client privatevmv1.ScannerGuestServiceClient) (*approvedScannerWorkspaceSource, error) {
	if err := report.Validate(); err != nil || !report.Complete || report.Result != "approved" || report.Policy != "safe" || report.SessionID != scanner.ID || len(report.SanitizedOutputs) != 1 || nilLikeHost(client) {
		return nil, ErrWorkspaceTransfer
	}
	output := report.SanitizedOutputs[0]
	digestBytes, err := hex.DecodeString(output.SHA256)
	if err != nil || len(digestBytes) != sha256.Size {
		clear(digestBytes)
		return nil, ErrWorkspaceTransfer
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	clear(digestBytes)
	header := transfer.Header{Name: output.LogicalName, Size: output.SizeBytes, SHA256: digest, MediaType: output.DetectedMIME}
	if output.OutputID == "" || header.Validate(8<<30) != nil {
		return nil, ErrWorkspaceTransfer
	}
	transferID, err := newPromotionTransferID()
	if err != nil {
		return nil, ErrWorkspaceTransfer
	}
	return &approvedScannerWorkspaceSource{scanner: scanner, output: output, client: client, header: header, transferID: transferID}, nil
}

func (source *approvedScannerWorkspaceSource) approvedWorkspaceImport(ctx context.Context) (WorkspaceImport, error) {
	if source == nil || ctx == nil {
		return WorkspaceImport{}, ErrWorkspaceTransfer
	}
	requestID, err := newGuestRequestID()
	if err != nil {
		return WorkspaceImport{}, ErrWorkspaceTransfer
	}
	requestContext := &privatevmv1.RequestContext{
		ApiVersion: &privatevmv1.ApiVersion{Major: 1, Minor: 0}, RequestId: requestID, SessionId: source.scanner.ID,
	}
	streamContext, cancel := context.WithCancel(ctx)
	stream, err := source.client.ExportApprovedFile(streamContext, &privatevmv1.ExportApprovedFileRequest{
		Context:  &privatevmv1.GuestContext{Context: requestContext, ExpectedRole: privatevmv1.GuestRole_GUEST_ROLE_SCANNER},
		OutputId: source.output.OutputID,
	}, grpc.MaxCallRecvMsgSize(transfer.DefaultMaxChunk+4096))
	if err != nil || stream == nil {
		cancel()
		return WorkspaceImport{}, errors.Join(ErrWorkspaceTransfer, err)
	}
	first, err := stream.Recv()
	begin := first.GetBegin()
	if err != nil || begin == nil || begin.GetTransferId() != source.output.OutputID || !sameRequestContext(begin.GetContext(), requestContext) {
		cancel()
		return WorkspaceImport{}, errors.Join(ErrWorkspaceTransfer, err)
	}
	actual, err := relayHeader(begin.GetDescriptor_())
	if err != nil || actual != source.header {
		cancel()
		return WorkspaceImport{}, ErrWorkspaceTransfer
	}
	count, complete := 1, false
	receive := func() (*privatevmv1.TransferFrame, error) {
		if complete || count >= maximumWorkspaceFrames {
			cancel()
			return nil, ErrWorkspaceTransfer
		}
		frame, receiveErr := stream.Recv()
		if receiveErr != nil || frame == nil {
			cancel()
			return nil, errors.Join(ErrWorkspaceTransfer, receiveErr)
		}
		count++
		if chunk := frame.GetChunk(); chunk != nil {
			if len(chunk.GetData()) == 0 || len(chunk.GetData()) > transfer.DefaultMaxChunk {
				clear(chunk.Data)
				cancel()
				return nil, ErrWorkspaceTransfer
			}
			return frame, nil
		}
		end := frame.GetEnd()
		if end == nil || end.GetTotalSize() != source.header.Size || !sameProtoHash(end.GetDigest(), source.header.SHA256) {
			cancel()
			return nil, ErrWorkspaceTransfer
		}
		extra, trailingErr := stream.Recv()
		if extra != nil {
			if chunk := extra.GetChunk(); chunk != nil {
				clear(chunk.Data)
			}
		}
		if !errors.Is(trailingErr, io.EOF) || extra != nil {
			cancel()
			return nil, ErrWorkspaceTransfer
		}
		complete = true
		cancel()
		return frame, nil
	}
	return WorkspaceImport{Begin: &privatevmv1.TransferBegin{
		TransferId: source.transferID, Descriptor_: cloneDescriptor(begin.GetDescriptor_()),
	}, Receive: receive, Close: cancel}, nil
}

func (*approvedScannerWorkspaceSource) privateVMScannerApproval() {}

func newPromotionTransferID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "transfer-" + hex.EncodeToString(value[:]), nil
}

func sameRequestContext(left, right *privatevmv1.RequestContext) bool {
	return left != nil && right != nil && left.GetApiVersion().GetMajor() == 1 && left.GetApiVersion().GetMinor() == 0 &&
		left.GetRequestId() == right.GetRequestId() && left.GetSessionId() == right.GetSessionId()
}

var _ ScannerApprovedWorkspaceSource = (*approvedScannerWorkspaceSource)(nil)
var _ ScannerPromotionRelay = (*WorkstationScannerPromotion)(nil)
