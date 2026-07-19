package orchestrator

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/usb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const approvedSourceTestSession = "pvm-0123456789abcdef0123456789abcdef"

func TestUSBScannerPromotionRegistersMACVerifiedReportOutputStreamOnce(t *testing.T) {
	data := []byte("reconstructed")
	digest := sha256.Sum256(data)
	report := approvedSourceScanReport(approvedSourceTestSession, digest, uint64(len(data)))
	stream := &approvedSourceTestStream{ctx: t.Context(), frames: approvedSourceFrames(report.SanitizedOutputs[0].OutputID, report.SanitizedOutputs[0].LogicalName, report.SanitizedOutputs[0].DetectedMIME, data, digest)}
	client := &approvedSourceScannerClient{stream: stream}
	registry := usb.NewApprovedSourceRegistry()
	promotion, err := NewUSBScannerPromotion(registry)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := session.Snapshot{ID: approvedSourceTestSession, OwnerUID: 1000, Role: session.RoleScanner, Phase: session.PhaseActive, WorkflowState: "REPORT_COMPLETE"}
	if err := promotion.Promote(t.Context(), snapshot, report, "usb", session.Snapshot{}, client); err != nil {
		t.Fatal(err)
	}
	selection := usb.SourceSelection{Role: usb.SourceScanner, SessionID: snapshot.ID, OutputID: report.SanitizedOutputs[0].OutputID}
	source, err := registry.OpenApproved(t.Context(), selection)
	if err != nil {
		t.Fatal(err)
	}
	output := source.Output()
	if output.SourceRole != usb.SourceScanner || !output.ReportAuthenticated || !output.ReportComplete || !output.PolicyApproved || !output.Reconstructed {
		t.Fatalf("scanner output evidence = %+v", output)
	}
	chunk, err := source.Next(t.Context())
	if err != nil || string(chunk.Data) != string(data) || chunk.Sequence != 0 {
		t.Fatalf("chunk=%q sequence=%d err=%v", chunk.Data, chunk.Sequence, err)
	}
	clear(chunk.Data)
	if _, err := source.Next(t.Context()); !errors.Is(err, io.EOF) {
		t.Fatalf("end error = %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if client.request == nil || client.request.GetOutputId() != selection.OutputID || client.request.GetContext().GetExpectedRole() != privatevmv1.GuestRole_GUEST_ROLE_SCANNER || client.request.GetContext().GetContext().GetSessionId() != snapshot.ID {
		t.Fatalf("scanner request = %+v", client.request)
	}
	if _, err := registry.OpenApproved(t.Context(), selection); err == nil {
		t.Fatal("scanner source reopened after one-use consumption")
	}
}

func TestUSBScannerPromotionRejectsAmbiguousReportOutputs(t *testing.T) {
	digest := sha256.Sum256([]byte("safe"))
	report := approvedSourceScanReport(approvedSourceTestSession, digest, 4)
	second := report.SanitizedOutputs[0]
	second.OutputID = "scan-out-" + strings.Repeat("f", 32)
	report.SanitizedOutputs = append(report.SanitizedOutputs, second)
	registry := usb.NewApprovedSourceRegistry()
	promotion, _ := NewUSBScannerPromotion(registry)
	err := promotion.Promote(t.Context(), session.Snapshot{ID: approvedSourceTestSession, Role: session.RoleScanner, Phase: session.PhaseActive}, report, "usb", session.Snapshot{}, &approvedSourceScannerClient{})
	if !errors.Is(err, ErrApprovedSourceUnavailable) {
		t.Fatalf("ambiguous report error = %v", err)
	}
}

func TestVerifiedWorkstationExportRegistersCurrentBoundedSource(t *testing.T) {
	data := []byte("workspace output")
	digest := sha256.Sum256(data)
	outputID := "output-" + strings.Repeat("a", 32)
	state := &privatevmv1.WorkspaceState{State: "READY", Entries: []*privatevmv1.WorkspaceEntry{{OutputId: outputID, SizeBytes: uint64(len(data)), Exported: true}}}
	relay := &approvedSourceWorkstationRelay{state: state, outputID: outputID, name: "result.txt", mediaType: "text/plain", data: data, digest: digest}
	runtime := &approvedSourceHostRuntime{relay: relay}
	snapshot := session.Snapshot{ID: approvedSourceTestSession, OwnerUID: 1000, Role: session.RoleWorkstation, Phase: session.PhaseActive, WorkflowState: "OUTPUT_VERIFIED"}
	roles := &HostRoles{states: map[string]*hostRoleState{snapshot.ID: {plan: session.LaunchPlan{Role: session.RoleWorkstation}, runtime: runtime}}}
	registry := usb.NewApprovedSourceRegistry()
	if err := roles.ConfigureApprovedSources(registry); err != nil {
		t.Fatal(err)
	}
	protoDigest := &privatevmv1.Hash{Algorithm: "sha256", Value: append([]byte(nil), digest[:]...)}
	verified, err := roles.VerifyWorkspaceExport(t.Context(), snapshot, outputID, protoDigest, protoDigest)
	if err != nil || verified.GetState() != "READY" {
		t.Fatalf("verified=%v err=%v", verified, err)
	}
	selection := usb.SourceSelection{Role: usb.SourceWorkstation, SessionID: snapshot.ID, OutputID: outputID}
	source, err := registry.OpenApproved(t.Context(), selection)
	if err != nil {
		t.Fatal(err)
	}
	output := source.Output()
	if output.SourceRole != usb.SourceWorkstation || !output.ExportStateAuthenticated || !output.ExportStateReady || output.LogicalName != "result.txt" {
		t.Fatalf("workstation output evidence = %+v", output)
	}
	chunk, err := source.Next(t.Context())
	if err != nil || string(chunk.Data) != string(data) {
		t.Fatalf("chunk=%q err=%v", chunk.Data, err)
	}
	clear(chunk.Data)
	if _, err := source.Next(t.Context()); !errors.Is(err, io.EOF) {
		t.Fatalf("end error = %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}

	// A later verified identity is still rejected at open if the guest marks it
	// changed before the one-use handoff begins.
	if _, err := roles.VerifyWorkspaceExport(t.Context(), snapshot, outputID, protoDigest, protoDigest); err != nil {
		t.Fatal(err)
	}
	relay.state = &privatevmv1.WorkspaceState{State: "CHANGED", Entries: []*privatevmv1.WorkspaceEntry{{OutputId: outputID, SizeBytes: uint64(len(data)), Exported: true, ChangedSinceExport: true}}}
	if _, err := registry.OpenApproved(t.Context(), selection); err == nil {
		t.Fatal("changed workstation output opened")
	}
}

type approvedSourceScannerClient struct {
	privatevmv1.ScannerGuestServiceClient
	stream  grpc.ServerStreamingClient[privatevmv1.TransferFrame]
	request *privatevmv1.ExportApprovedFileRequest
}

func (client *approvedSourceScannerClient) ExportApprovedFile(_ context.Context, request *privatevmv1.ExportApprovedFileRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[privatevmv1.TransferFrame], error) {
	client.request = request
	if client.stream == nil {
		return nil, ErrApprovedSourceUnavailable
	}
	return client.stream, nil
}

type approvedSourceTestStream struct {
	ctx    context.Context
	frames []*privatevmv1.TransferFrame
}

func (stream *approvedSourceTestStream) Recv() (*privatevmv1.TransferFrame, error) {
	if len(stream.frames) == 0 {
		return nil, io.EOF
	}
	frame := stream.frames[0]
	stream.frames = stream.frames[1:]
	return frame, nil
}
func (stream *approvedSourceTestStream) Header() (metadata.MD, error) { return nil, nil }
func (stream *approvedSourceTestStream) Trailer() metadata.MD         { return nil }
func (stream *approvedSourceTestStream) CloseSend() error             { return nil }
func (stream *approvedSourceTestStream) Context() context.Context     { return stream.ctx }
func (stream *approvedSourceTestStream) SendMsg(any) error            { return nil }
func (stream *approvedSourceTestStream) RecvMsg(any) error            { return nil }

type approvedSourceWorkstationRelay struct {
	state     *privatevmv1.WorkspaceState
	outputID  string
	name      string
	mediaType string
	data      []byte
	digest    [sha256.Size]byte
}

func (relay *approvedSourceWorkstationRelay) State(context.Context) (*privatevmv1.WorkspaceState, error) {
	return relay.state, nil
}
func (*approvedSourceWorkstationRelay) Import(context.Context, WorkspaceImport) (*privatevmv1.TransferReceipt, error) {
	return nil, ErrWorkstationUnavailable
}
func (relay *approvedSourceWorkstationRelay) Export(_ context.Context, export WorkspaceExport) (*privatevmv1.TransferReceipt, error) {
	descriptor := &privatevmv1.FileDescriptor{LogicalName: relay.name, SizeBytes: uint64(len(relay.data)), DetectedMime: relay.mediaType, Digest: &privatevmv1.Hash{Algorithm: "sha256", Value: append([]byte(nil), relay.digest[:]...)}}
	for _, frame := range approvedSourceFrames(relay.outputID, relay.name, relay.mediaType, relay.data, relay.digest) {
		if err := export.Send(frame); err != nil {
			return nil, err
		}
	}
	return &privatevmv1.TransferReceipt{TransferId: relay.outputID, Descriptor_: descriptor, ReceiverDigest: &privatevmv1.Hash{Algorithm: "sha256", Value: append([]byte(nil), relay.digest[:]...)}}, nil
}
func (relay *approvedSourceWorkstationRelay) Verify(_ context.Context, outputID string, daemonDigest, receiverDigest *privatevmv1.Hash) (*privatevmv1.WorkspaceState, error) {
	if outputID != relay.outputID || !sameProtoHash(daemonDigest, relay.digest) || !sameProtoHash(receiverDigest, relay.digest) {
		return nil, ErrWorkspaceTransfer
	}
	return relay.state, nil
}

type approvedSourceHostRuntime struct{ relay WorkstationRelay }

func (*approvedSourceHostRuntime) Stop(context.Context, bool) error { return nil }
func (*approvedSourceHostRuntime) Audit(context.Context) error      { return nil }
func (*approvedSourceHostRuntime) WorkspaceState(context.Context) (string, error) {
	return "READY", nil
}
func (*approvedSourceHostRuntime) Torrent() (TorrentRelay, error) { return nil, ErrHostRoleUnavailable }
func (runtime *approvedSourceHostRuntime) Workstation() (WorkstationRelay, error) {
	return runtime.relay, nil
}

func approvedSourceFrames(outputID, name, mediaType string, data []byte, digest [sha256.Size]byte) []*privatevmv1.TransferFrame {
	hash := func() *privatevmv1.Hash {
		return &privatevmv1.Hash{Algorithm: "sha256", Value: append([]byte(nil), digest[:]...)}
	}
	return []*privatevmv1.TransferFrame{
		{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{TransferId: outputID, Descriptor_: &privatevmv1.FileDescriptor{LogicalName: name, SizeBytes: uint64(len(data)), DetectedMime: mediaType, Digest: hash()}}}},
		{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Sequence: 0, Data: append([]byte(nil), data...)}}},
		{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{TotalSize: uint64(len(data)), Digest: hash()}}},
	}
}

func approvedSourceScanReport(sessionID string, digest [sha256.Size]byte, size uint64) scan.ScanReport {
	started := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Millisecond)
	completed := started.Add(5 * time.Minute)
	return scan.ScanReport{
		SchemaVersion: scan.ScanReportSchemaVersion, SessionID: sessionID, Policy: "safe",
		StartedAt: started, CompletedAt: completed, DurationMillis: 300000,
		Scanner:     scan.ReportScannerIdentity{ImageDigest: "sha256:" + strings.Repeat("a", 64), SourceCommit: strings.Repeat("b", 40), GuestdVersion: "1.0.0-test"},
		Definitions: scan.ReportDefinitions{EngineVersion: "1.5.1", DatabaseVersion: "fixture-definitions", UpdatedAt: started.Add(-time.Hour), Official: true, Compatible: true},
		Isolation:   scan.ReportIsolation{NoNetwork: true, QuarantineReadOnly: true, MountOptions: []string{"nodev", "noexec", "nosuid", "ro"}},
		Phases:      scan.ReportPhases{DefinitionsVerified: true, OfflineVerified: true, InventoryComplete: true, MalwareScanComplete: true, ArchiveInspectionComplete: true, ReconstructionComplete: true, OutputRescanComplete: true},
		Inputs:      []scan.ReportInput{{LogicalName: "fixture.pdf", SizeBytes: 12, SHA256: strings.Repeat("c", 64), DetectedMIME: "application/pdf", ExtensionMIME: "application/pdf", ExtensionAgreement: true, ClamAVVerdict: "CLAMAV_CLEAN"}},
		Archives:    []scan.ReportArchive{}, Findings: []scan.Finding{},
		SanitizedOutputs: []scan.ReportSanitizedOutput{{OutputID: "scan-out-" + strings.Repeat("d", 32), LogicalName: "fixture.safe.pdf", SourceSHA256: strings.Repeat("c", 64), SizeBytes: size, SHA256: hexDigest(digest), DetectedMIME: "application/pdf", Transformation: "pdf-raster-rebuild-v1", RescanVerdict: "CLAMAV_CLEAN"}},
		Tools:            []scan.ToolEvidence{{Name: "clamav", Version: "1.5.1"}}, Result: "approved", Complete: true,
	}
}

func hexDigest(digest [sha256.Size]byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, sha256.Size*2)
	for index, value := range digest {
		result[index*2] = alphabet[value>>4]
		result[index*2+1] = alphabet[value&0x0f]
	}
	return string(result)
}

var _ privatevmv1.ScannerGuestServiceClient = (*approvedSourceScannerClient)(nil)
var _ grpc.ServerStreamingClient[privatevmv1.TransferFrame] = (*approvedSourceTestStream)(nil)
var _ WorkstationRelay = (*approvedSourceWorkstationRelay)(nil)
var _ HostRuntime = (*approvedSourceHostRuntime)(nil)
var _ hostWorkstationRuntime = (*approvedSourceHostRuntime)(nil)
