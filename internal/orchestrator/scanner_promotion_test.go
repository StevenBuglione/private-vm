package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc"
)

const (
	promotionScannerID     = "pvm-dddddddddddddddddddddddddddddddd"
	promotionWorkstationID = "pvm-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

type promotionScannerClient struct {
	privatevmv1.ScannerGuestServiceClient
	report      scan.ScanReport
	payload     []byte
	request     *privatevmv1.ExportApprovedFileRequest
	corruptEnd  bool
	trailing    bool
	exportError error
}

func (client *promotionScannerClient) ExportApprovedFile(_ context.Context, request *privatevmv1.ExportApprovedFileRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[privatevmv1.TransferFrame], error) {
	client.request = request
	if client.exportError != nil {
		return nil, client.exportError
	}
	output := client.report.SanitizedOutputs[0]
	digest := sha256.Sum256(client.payload)
	endDigest := digest
	if client.corruptEnd {
		endDigest[0] ^= 0xff
	}
	frames := []*privatevmv1.TransferFrame{
		{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{
			Context: cloneRequestContext(request.GetContext().GetContext()), TransferId: output.OutputID,
			Descriptor_: &privatevmv1.FileDescriptor{LogicalName: output.LogicalName, SizeBytes: uint64(len(client.payload)), DetectedMime: output.DetectedMIME, Digest: protoSHA256(digest)},
		}}},
		{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Sequence: 0, Data: append([]byte(nil), client.payload...)}}},
		{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{TotalSize: uint64(len(client.payload)), Digest: protoSHA256(endDigest)}}},
	}
	if client.trailing {
		frames = append(frames, &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Sequence: 1, Data: []byte("trailing")}}})
	}
	return &promotionScannerStream{frames: frames}, nil
}

type promotionScannerStream struct {
	grpc.ServerStreamingClient[privatevmv1.TransferFrame]
	frames []*privatevmv1.TransferFrame
	index  int
}

func (stream *promotionScannerStream) Recv() (*privatevmv1.TransferFrame, error) {
	if stream.index >= len(stream.frames) {
		return nil, io.EOF
	}
	frame := stream.frames[stream.index]
	stream.index++
	return frame, nil
}

type promotionWorkstationRelay struct {
	imported       []byte
	transferID     string
	corruptReceipt bool
}

func (*promotionWorkstationRelay) State(context.Context) (*privatevmv1.WorkspaceState, error) {
	return &privatevmv1.WorkspaceState{State: "READY"}, nil
}

func (relay *promotionWorkstationRelay) Import(_ context.Context, request WorkspaceImport) (*privatevmv1.TransferReceipt, error) {
	header, err := relayHeader(request.Begin.GetDescriptor_())
	if err != nil || request.Begin.GetContext() != nil || !strings.HasPrefix(request.Begin.GetTransferId(), "transfer-") {
		return nil, ErrWorkspaceTransfer
	}
	relay.transferID = request.Begin.GetTransferId()
	hasher := sha256.New()
	var total uint64
	var sequence uint64
	for count := 0; count < maximumWorkspaceFrames; count++ {
		frame, receiveErr := request.Receive()
		if receiveErr != nil || frame == nil {
			return nil, errors.Join(ErrWorkspaceTransfer, receiveErr)
		}
		if chunk := frame.GetChunk(); chunk != nil {
			if chunk.GetSequence() != sequence || len(chunk.GetData()) == 0 {
				return nil, ErrWorkspaceTransfer
			}
			_, _ = hasher.Write(chunk.GetData())
			relay.imported = append(relay.imported, chunk.GetData()...)
			total += uint64(len(chunk.GetData()))
			sequence++
			continue
		}
		end := frame.GetEnd()
		if end == nil || end.GetTotalSize() != total || total != header.Size {
			return nil, ErrWorkspaceTransfer
		}
		var digest [sha256.Size]byte
		copy(digest[:], hasher.Sum(nil))
		if !sameProtoHash(end.GetDigest(), digest) || digest != header.SHA256 {
			return nil, ErrWorkspaceTransfer
		}
		if relay.corruptReceipt {
			digest[0] ^= 0xff
		}
		return &privatevmv1.TransferReceipt{TransferId: request.Begin.GetTransferId(), Descriptor_: cloneDescriptor(request.Begin.GetDescriptor_()), ReceiverDigest: protoSHA256(digest)}, nil
	}
	return nil, ErrWorkspaceTransfer
}

func (*promotionWorkstationRelay) Export(context.Context, WorkspaceExport) (*privatevmv1.TransferReceipt, error) {
	return nil, ErrWorkstationUnavailable
}

func (*promotionWorkstationRelay) Verify(context.Context, string, *privatevmv1.Hash, *privatevmv1.Hash) (*privatevmv1.WorkspaceState, error) {
	return nil, ErrWorkstationUnavailable
}

type promotionHostRuntime struct {
	*fakeHostRuntime
	workstation WorkstationRelay
}

func (runtime *promotionHostRuntime) Workstation() (WorkstationRelay, error) {
	if runtime == nil || runtime.workstation == nil {
		return nil, ErrWorkstationUnavailable
	}
	return runtime.workstation, nil
}

func TestWorkstationScannerPromotionStreamsExactlyOneAuthenticatedOutputWithThreeHashes(t *testing.T) {
	payload := []byte("reconstructed scanner output")
	report := promotionReport(payload)
	scanner, workstation := promotionSnapshots()
	client := &promotionScannerClient{report: report, payload: payload}
	relay := &promotionWorkstationRelay{}
	promotion := promotionFixture(t, workstation, relay)

	if err := promotion.Promote(t.Context(), scanner, report, "workstation", workstation, client); err != nil {
		t.Fatal(err)
	}
	if client.request.GetOutputId() != report.SanitizedOutputs[0].OutputID || client.request.GetContext().GetExpectedRole() != privatevmv1.GuestRole_GUEST_ROLE_SCANNER ||
		client.request.GetContext().GetContext().GetSessionId() != scanner.ID {
		t.Fatalf("scanner request=%+v", client.request)
	}
	if string(relay.imported) != string(payload) || relay.transferID == "" || relay.transferID == report.SanitizedOutputs[0].OutputID {
		t.Fatalf("relay imported=%q transfer=%q", relay.imported, relay.transferID)
	}
}

func TestWorkstationScannerPromotionFailsClosedForUnapprovedFramingAndHashEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*scan.ScanReport, *promotionScannerClient, *promotionWorkstationRelay)
	}{
		{name: "more-than-selected-output", mutate: func(report *scan.ScanReport, _ *promotionScannerClient, _ *promotionWorkstationRelay) {
			second := report.SanitizedOutputs[0]
			second.OutputID = "scan-out-ffffffffffffffffffffffffffffffff"
			second.LogicalName = "second.safe.pdf"
			report.SanitizedOutputs = append(report.SanitizedOutputs, second)
		}},
		{name: "scanner-end-hash", mutate: func(_ *scan.ScanReport, client *promotionScannerClient, _ *promotionWorkstationRelay) {
			client.corruptEnd = true
		}},
		{name: "trailing-frame", mutate: func(_ *scan.ScanReport, client *promotionScannerClient, _ *promotionWorkstationRelay) {
			client.trailing = true
		}},
		{name: "workstation-receipt-hash", mutate: func(_ *scan.ScanReport, _ *promotionScannerClient, relay *promotionWorkstationRelay) {
			relay.corruptReceipt = true
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte("reconstructed scanner output")
			report := promotionReport(payload)
			client := &promotionScannerClient{report: report, payload: payload}
			relay := &promotionWorkstationRelay{}
			test.mutate(&report, client, relay)
			client.report = report
			scanner, workstation := promotionSnapshots()
			promotion := promotionFixture(t, workstation, relay)
			if err := promotion.Promote(t.Context(), scanner, report, "workstation", workstation, client); err == nil {
				t.Fatal("invalid promotion evidence returned success")
			}
		})
	}
}

func promotionFixture(t *testing.T, workstation session.Snapshot, relay WorkstationRelay) *WorkstationScannerPromotion {
	t.Helper()
	runtime := &promotionHostRuntime{fakeHostRuntime: &fakeHostRuntime{log: &hostTestLog{}}, workstation: relay}
	roles := &HostRoles{states: map[string]*hostRoleState{workstation.ID: {plan: session.LaunchPlan{Role: session.RoleWorkstation}, runtime: runtime}}}
	promotion, err := NewWorkstationScannerPromotion(roles)
	if err != nil {
		t.Fatal(err)
	}
	return promotion
}

func promotionSnapshots() (session.Snapshot, session.Snapshot) {
	created := time.Now().UTC().Add(-time.Minute)
	scanner := session.Snapshot{SchemaVersion: 1, ID: promotionScannerID, OwnerUID: 1000, Role: session.RoleScanner, Phase: session.PhaseActive, WorkflowState: "REPORT_COMPLETE", CreatedAt: created}
	workstation := session.Snapshot{SchemaVersion: 1, ID: promotionWorkstationID, OwnerUID: scanner.OwnerUID, Role: session.RoleWorkstation, Phase: session.PhaseActive, WorkflowState: "WORKING", CreatedAt: created.Add(time.Second)}
	return scanner, workstation
}

func promotionReport(payload []byte) scan.ScanReport {
	started := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Millisecond)
	completed := started.Add(5 * time.Minute)
	digest := sha256.Sum256(payload)
	return scan.ScanReport{
		SchemaVersion: scan.ScanReportSchemaVersion, SessionID: promotionScannerID, Policy: "safe",
		StartedAt: started, CompletedAt: completed, DurationMillis: uint64(completed.Sub(started) / time.Millisecond),
		Scanner:     scan.ReportScannerIdentity{ImageDigest: "sha256:" + strings.Repeat("a", 64), SourceCommit: strings.Repeat("b", 40), GuestdVersion: "1.0.0-rc.1"},
		Definitions: scan.ReportDefinitions{EngineVersion: "1.5.1", DatabaseVersion: "daily-28100", UpdatedAt: started.Add(-time.Hour), Official: true, Compatible: true},
		Isolation:   scan.ReportIsolation{NoNetwork: true, QuarantineReadOnly: true, MountOptions: []string{"nodev", "noexec", "nosuid", "ro"}},
		Phases:      scan.ReportPhases{DefinitionsVerified: true, OfflineVerified: true, InventoryComplete: true, MalwareScanComplete: true, ArchiveInspectionComplete: true, ReconstructionComplete: true, OutputRescanComplete: true},
		Inputs:      []scan.ReportInput{{LogicalName: "input.pdf", SizeBytes: 12, SHA256: strings.Repeat("c", 64), DetectedMIME: "application/pdf", ExtensionMIME: "application/pdf", ExtensionAgreement: true, ClamAVVerdict: "CLAMAV_CLEAN"}},
		Archives:    []scan.ReportArchive{}, Findings: []scan.Finding{},
		SanitizedOutputs: []scan.ReportSanitizedOutput{{OutputID: "scan-out-11111111111111111111111111111111", LogicalName: "input.safe.pdf", SourceSHA256: strings.Repeat("c", 64), SizeBytes: uint64(len(payload)), SHA256: hex.EncodeToString(digest[:]), DetectedMIME: "application/pdf", Transformation: "pdf-raster-rebuild-v1", RescanVerdict: "CLAMAV_CLEAN"}},
		Tools:            []scan.ToolEvidence{{Name: "clamav", Version: "1.5.1"}}, Result: "approved", Complete: true,
	}
}

func cloneRequestContext(value *privatevmv1.RequestContext) *privatevmv1.RequestContext {
	if value == nil {
		return nil
	}
	return &privatevmv1.RequestContext{ApiVersion: &privatevmv1.ApiVersion{Major: value.GetApiVersion().GetMajor(), Minor: value.GetApiVersion().GetMinor()}, RequestId: value.GetRequestId(), SessionId: value.GetSessionId()}
}

var _ privatevmv1.ScannerGuestServiceClient = (*promotionScannerClient)(nil)
var _ WorkstationRelay = (*promotionWorkstationRelay)(nil)
var _ HostRuntime = (*promotionHostRuntime)(nil)
