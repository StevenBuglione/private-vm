package guest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/policy"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestScannerRPCUpdateRebootOfflineScanReconstructReportAndExport(t *testing.T) {
	baseTime := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	manager := scan.DefinitionManager{Now: func() time.Time { return baseTime.Add(time.Hour) }}
	store := &memoryScannerReceiptStore{}
	offlineBootStaged := false
	updateDefinitions := CoreScannerDefinitions{
		Manager: manager,
		Probe: bootProbeFunc(func(context.Context) (scan.BootEvidence, error) {
			return scan.BootEvidence{
				Phase: scan.PhaseUpdate, OverlayIdentity: "overlay-0123456789abcdef", VPNVerified: true,
				Interfaces: []scan.InterfaceEvidence{{Name: "eth0"}},
			}, nil
		}),
		Store: store, Stager: offlineBootStagerFunc(func(context.Context) error {
			store.mu.Lock()
			defer store.mu.Unlock()
			if !store.written {
				return errors.New("offline boot staged before receipt commit")
			}
			offlineBootStaged = true
			return nil
		}),
	}
	updateDefinitions.Manager.Updater = definitionUpdaterFunc(func(context.Context) (scan.DefinitionEvidence, error) {
		return scan.DefinitionEvidence{
			EngineVersion: "ClamAV-1.4.3", DatabaseVersion: "official-1234", UpdatedAt: baseTime,
			Official: true, Compatible: true, Complete: true,
		}, nil
	})

	updateToken := mustToken(t, 0x71)
	updateService := newScannerServiceForTest(t, updateToken, scannerTestAdapters{
		definitions: updateDefinitions,
		isolation:   unavailableScannerAdapters{}, inventory: unavailableScannerAdapters{},
		malware: unavailableScannerAdapters{}, reconstruction: &fakeScannerReconstruction{},
	})
	_, updateConnection := startScannerTestServer(t, updateService, updateToken)
	updateClient := privatevmv1.NewScannerGuestServiceClient(updateConnection)
	updated, err := updateClient.UpdateDefinitions(t.Context(), scannerRequest(""))
	if err != nil {
		t.Fatal(err)
	}
	if !updated.GetCurrent() || updated.GetDatabaseVersion() != "official-1234" || updated.GetUpdatedUnixSeconds() != baseTime.Unix() {
		t.Fatalf("definition status = %#v", updated)
	}
	if !offlineBootStaged {
		t.Fatal("offline boot was not staged after the receipt commit")
	}
	if _, err := updateClient.GetDefinitionsStatus(t.Context(), scannerRequest("")); err != nil {
		t.Fatalf("GetDefinitionsStatus() = %v", err)
	}

	quarantine := t.TempDir()
	source := []byte("authorized deterministic scanner fixture\n")
	if err := os.WriteFile(filepath.Join(quarantine, "document.txt"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	reconstruction := newFakeScannerReconstruction(source)
	offlineProbe := bootProbeFunc(func(context.Context) (scan.BootEvidence, error) {
		return scan.BootEvidence{
			Phase: scan.PhaseOffline, OverlayIdentity: "overlay-0123456789abcdef",
			Interfaces: []scan.InterfaceEvidence{{Name: "lo", Loopback: true}},
			Quarantine: scan.QuarantineEvidence{
				Attached: true, ReadOnly: true, MountOptions: []string{"ro", "nodev", "nosuid", "noexec"},
			},
		}, nil
	})
	offlineDefinitions := CoreScannerDefinitions{Manager: manager, Store: store}
	offlineIsolation := CoreScannerIsolation{Manager: manager, Probe: offlineProbe}
	clockCalls := 0
	offlineToken := mustToken(t, 0x72)
	offlineService := newScannerServiceForTest(t, offlineToken, scannerTestAdapters{
		definitions: offlineDefinitions, isolation: offlineIsolation,
		inventory:      CoreScannerInventory{RootPath: quarantine, Classifier: scan.ConservativeMIMEClassifier{}},
		malware:        CoreScannerMalware{RootPath: quarantine, Scanner: cleanContentScanner{}},
		reconstruction: reconstruction,
		now: func() time.Time {
			clockCalls++
			return baseTime.Add(time.Duration(clockCalls+2) * time.Hour)
		},
	})
	server, offlineConnection := startScannerTestServer(t, offlineService, offlineToken)
	services := server.GetServiceInfo()
	if len(services) != 2 {
		t.Fatalf("registered scanner services = %v", services)
	}
	if _, exists := services["privatevm.v1.ScannerGuestService"]; !exists {
		t.Fatal("scanner role service was not registered")
	}
	for _, forbidden := range []string{"privatevm.v1.WorkstationGuestService", "privatevm.v1.DownloaderGuestService", "privatevm.v1.ExporterGuestService"} {
		if _, exists := services[forbidden]; exists {
			t.Fatalf("cross-role service registered: %s", forbidden)
		}
	}
	offlineClient := privatevmv1.NewScannerGuestServiceClient(offlineConnection)
	statusResponse, err := offlineClient.VerifyOfflineMode(t.Context(), scannerRequest(""))
	if err != nil {
		t.Fatal(err)
	}
	if !statusResponse.GetNoNetwork() || !statusResponse.GetQuarantineReadOnly() {
		t.Fatalf("offline status = %#v", statusResponse)
	}

	inventoryStream, err := offlineClient.Inventory(t.Context(), scannerRequest("safe"))
	if err != nil {
		t.Fatal(err)
	}
	assertScanEvents(t, inventoryStream, "inventory", false)
	scanStream, err := offlineClient.Scan(t.Context(), scannerRequest("safe"))
	if err != nil {
		t.Fatal(err)
	}
	assertScanEvents(t, scanStream, "malware-scan", true)
	reconstructStream, err := offlineClient.Reconstruct(t.Context(), scannerRequest("safe"))
	if err != nil {
		t.Fatal(err)
	}
	assertScanEvents(t, reconstructStream, "reconstruction", true)

	envelope, err := offlineClient.GetScanReport(t.Context(), scannerRequest("safe"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := scan.VerifyApproval(scan.AuthenticatedReport{
		CanonicalJSON: envelope.GetCanonicalJson(), AuthenticationTag: envelope.GetAuthenticationTag(), Complete: envelope.GetComplete(),
	}, offlineToken.value)
	if err != nil {
		t.Fatalf("authenticated report did not verify: %v", err)
	}
	if report.Result != "approved" || len(report.Inputs) != 1 || len(report.SanitizedOutputs) != 1 || report.Inputs[0].ClamAVVerdict != "CLAMAV_CLEAN" {
		t.Fatalf("scan report = %#v", report)
	}

	exportStream, err := offlineClient.ExportApprovedFile(t.Context(), &privatevmv1.ExportApprovedFileRequest{
		Context: scannerRequest("").GetContext(), OutputId: report.SanitizedOutputs[0].OutputID,
	})
	if err != nil {
		t.Fatal(err)
	}
	var transferred []byte
	var begin *privatevmv1.TransferBegin
	var end *privatevmv1.TransferEnd
	for {
		frame, receiveErr := exportStream.Recv()
		if errors.Is(receiveErr, io.EOF) {
			break
		}
		if receiveErr != nil {
			t.Fatal(receiveErr)
		}
		switch {
		case frame.GetBegin() != nil:
			begin = frame.GetBegin()
		case frame.GetChunk() != nil:
			transferred = append(transferred, frame.GetChunk().GetData()...)
		case frame.GetEnd() != nil:
			end = frame.GetEnd()
		default:
			t.Fatal("export contained an empty frame")
		}
	}
	if begin == nil || end == nil || begin.GetTransferId() != report.SanitizedOutputs[0].OutputID ||
		begin.GetDescriptor_().GetLogicalName() != report.SanitizedOutputs[0].LogicalName ||
		!bytes.Equal(transferred, reconstruction.output) {
		t.Fatalf("export begin=%#v end=%#v bytes=%q", begin, end, transferred)
	}
	digest := sha256.Sum256(transferred)
	if end.GetTotalSize() != uint64(len(transferred)) || !slices.Equal(end.GetDigest().GetValue(), digest[:]) {
		t.Fatalf("export end = %#v", end)
	}

	_, err = privatevmv1.NewDownloaderGuestServiceClient(offlineConnection).GetDownloadStatus(t.Context(), &privatevmv1.TorrentRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("cross-role RPC code = %s, want Unimplemented", status.Code(err))
	}
	if err := offlineService.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := offlineService.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if reconstruction.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", reconstruction.cleanupCalls)
	}
}

func TestScannerRPCRejectsOutOfOrderPolicyChangeAndRedactsAdapterErrors(t *testing.T) {
	token := mustToken(t, 0x73)
	marker := "private-secret-file-name"
	definitions := CoreScannerDefinitions{
		Manager: scan.DefinitionManager{}, Store: &memoryScannerReceiptStore{},
		Probe:  bootProbeFunc(func(context.Context) (scan.BootEvidence, error) { return scan.BootEvidence{}, errors.New(marker) }),
		Stager: offlineBootStagerFunc(func(context.Context) error { return nil }),
	}
	service := newScannerServiceForTest(t, token, scannerTestAdapters{
		definitions: definitions, isolation: unavailableScannerAdapters{}, inventory: unavailableScannerAdapters{},
		malware: unavailableScannerAdapters{}, reconstruction: &fakeScannerReconstruction{},
	})
	_, connection := startScannerTestServer(t, service, token)
	client := privatevmv1.NewScannerGuestServiceClient(connection)

	scanStream, err := client.Scan(t.Context(), scannerRequest("safe"))
	if err == nil {
		_, err = scanStream.Recv()
	}
	assertScannerRPCError(t, err, codes.FailedPrecondition, "SCANNER_STATE_INVALID")

	_, err = client.UpdateDefinitions(t.Context(), scannerRequest(""))
	if err == nil {
		t.Fatal("UpdateDefinitions unexpectedly succeeded")
	}
	assertScannerRPCError(t, err, codes.Unavailable, "SCANNER_EVIDENCE_UNAVAILABLE")
	if strings.Contains(err.Error(), marker) {
		t.Fatal("scanner RPC error exposed wrapped adapter data")
	}
}

func TestScannerRPCCancellationTimeoutAndReconstructionCleanup(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		code codes.Code
		want string
	}{
		{name: "cancel", err: context.Canceled, code: codes.Canceled, want: "SCAN_CANCELLED"},
		{name: "timeout", err: context.DeadlineExceeded, code: codes.DeadlineExceeded, want: "SCAN_TIMEOUT"},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := mustToken(t, 0x74)
			service := newScannerServiceForTest(t, token, scannerTestAdapters{
				definitions: errorDefinitionAdapter{err: test.err}, isolation: unavailableScannerAdapters{},
				inventory: unavailableScannerAdapters{}, malware: unavailableScannerAdapters{}, reconstruction: &fakeScannerReconstruction{},
			})
			_, connection := startScannerTestServer(t, service, token)
			_, err := privatevmv1.NewScannerGuestServiceClient(connection).UpdateDefinitions(t.Context(), scannerRequest(""))
			assertScannerRPCError(t, err, test.code, test.want)
		})
	}

	token := mustToken(t, 0x75)
	reconstruction := &fakeScannerReconstruction{reconstructErr: context.Canceled}
	service := newScannerServiceForTest(t, token, scannerTestAdapters{
		definitions: unavailableScannerAdapters{}, isolation: unavailableScannerAdapters{},
		inventory: unavailableScannerAdapters{}, malware: unavailableScannerAdapters{}, reconstruction: reconstruction,
	})
	service.state = scannerStateScanComplete
	service.policyName = "safe"
	service.sessionID = testSessionID
	service.startedAt = time.Now().Add(-time.Second)
	service.inventory = scan.Inventory{Entries: []scan.InventoryEntry{{RelativePath: "fixture.txt", SizeBytes: 1, SHA256: strings.Repeat("1", 64), DetectedMIME: "text/plain"}}, TotalBytes: 1}
	service.scanSummary = scan.ScanSummary{Findings: []scan.Finding{{Code: "CLAMAV_CLEAN", Severity: scan.SeverityInfo, RelativePath: "fixture.txt", Detail: "complete"}}, ScannedFiles: 1, Complete: true}
	err := service.Reconstruct(scannerRequest("safe"), &scannerEventStream{ctx: t.Context()})
	assertScannerRPCError(t, err, codes.Canceled, "SCAN_CANCELLED")
	if reconstruction.cleanupCalls != 1 || service.state != scannerStateScanComplete {
		t.Fatalf("canceled reconstruction cleanup=%d state=%s", reconstruction.cleanupCalls, service.state)
	}
}

func TestScannerBlockingVerdictNeverInvokesReconstructionBackend(t *testing.T) {
	token := mustToken(t, 0x76)
	reconstruction := &fakeScannerReconstruction{}
	service := newScannerServiceForTest(t, token, scannerTestAdapters{
		definitions: unavailableScannerAdapters{}, isolation: unavailableScannerAdapters{},
		inventory: unavailableScannerAdapters{}, malware: unavailableScannerAdapters{}, reconstruction: reconstruction,
		now: func() time.Time { return time.Date(2026, 7, 19, 14, 0, 1, 0, time.UTC) },
	})
	service.state = scannerStateScanComplete
	service.policyName = "safe"
	service.sessionID = testSessionID
	service.startedAt = time.Date(2026, 7, 19, 14, 0, 0, 0, time.UTC)
	service.receipt = scan.UpdateReceipt{
		OverlayIdentity: "overlay-0123456789abcdef",
		Definitions: scan.DefinitionEvidence{
			EngineVersion: "ClamAV-1.4.3", DatabaseVersion: "official-1234",
			UpdatedAt: time.Date(2026, 7, 19, 13, 0, 0, 0, time.UTC), Official: true, Compatible: true, Complete: true,
		},
	}
	service.inventory = scan.Inventory{Entries: []scan.InventoryEntry{{
		RelativePath: "fixture.bin", SizeBytes: 1, SHA256: strings.Repeat("1", 64), DetectedMIME: "application/octet-stream",
	}}, TotalBytes: 1}
	service.scanSummary = scan.ScanSummary{
		Findings:     []scan.Finding{{Code: "MALWARE_DETECTED", Severity: scan.SeverityBlocking, RelativePath: "fixture.bin", Detail: "A fixture detection blocked promotion."}},
		ScannedFiles: 1, Complete: true,
	}
	stream := &scannerEventStream{ctx: t.Context()}
	if err := service.Reconstruct(scannerRequest("safe"), stream); err != nil {
		t.Fatal(err)
	}
	if reconstruction.reconstructCalls != 0 {
		t.Fatal("blocking malware verdict reached reconstruction backend")
	}
	if service.state != scannerStateReportComplete || len(stream.events) != 2 || stream.events[1].GetApproved() {
		t.Fatalf("blocking reconstruction state=%s events=%#v", service.state, stream.events)
	}
	report, err := scan.VerifyReport(service.report, token.value)
	if err != nil || report.Result != "rejected" || len(report.SanitizedOutputs) != 0 {
		t.Fatalf("blocking report=%#v err=%v", report, err)
	}
}

func TestValidateScanSummaryRejectsAmbiguousNonBlockingVerdict(t *testing.T) {
	inventory := scan.Inventory{Entries: []scan.InventoryEntry{{RelativePath: "fixture", SizeBytes: 1}}}
	summary := scan.ScanSummary{
		Findings:     []scan.Finding{{Code: "SCAN_WARNING", Severity: scan.SeverityWarning, RelativePath: "fixture", Detail: "ambiguous"}},
		ScannedFiles: 1, Complete: true,
	}
	if err := validateScanSummary(inventory, summary); scan.ErrorCode(err) != "SCAN_ERROR" {
		t.Fatalf("validateScanSummary() = %v", err)
	}
}

type scannerTestAdapters struct {
	definitions    ScannerDefinitionAdapter
	isolation      ScannerIsolationAdapter
	inventory      ScannerInventoryAdapter
	malware        ScannerMalwareAdapter
	reconstruction ScannerReconstructionAdapter
	now            func() time.Time
}

func newScannerServiceForTest(t *testing.T, token *Token, adapters scannerTestAdapters) *ScannerService {
	t.Helper()
	selectedPolicy := mustSafePolicy(t)
	identity := Identity{
		Role: session.RoleScanner, ImageDigest: "sha256:" + strings.Repeat("a", 64),
		SourceCommit: strings.Repeat("b", 40), BootNonce: append([]byte{1}, make([]byte, BootNonceSize-1)...),
		OSRelease: "26.05", GuestdVersion: "0.1.0-test",
	}
	service, err := NewScannerService(ScannerServiceConfig{
		Identity: identity, Definitions: adapters.definitions, Isolation: adapters.isolation,
		Inventory: adapters.inventory, Malware: adapters.malware, Reconstruction: adapters.reconstruction,
		Policies: ScannerPolicyResolverFunc(func(name string) (policy.Policy, error) {
			if name != "safe" {
				return policy.Policy{}, errors.New("unsupported fixture policy")
			}
			return selectedPolicy, nil
		}),
		Now: adapters.now,
	}, token)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func startScannerTestServer(t *testing.T, service *ScannerService, token *Token) (*grpc.Server, *grpc.ClientConn) {
	t.Helper()
	config := testConfig(t, session.RoleScanner, token)
	config.Identity = service.identity
	config.Scanner = service
	return startTestServer(t, config, token)
}

func scannerRequest(policyName string) *privatevmv1.ScannerRequest {
	return &privatevmv1.ScannerRequest{Context: helloRequest(session.RoleScanner, APIMajor, APIMinor).GetContext(), PolicyName: policyName}
}

type scanEventReceiver interface {
	Recv() (*privatevmv1.ScanEvent, error)
}

func assertScanEvents(t *testing.T, stream scanEventReceiver, operation string, approved bool) {
	t.Helper()
	var events []*privatevmv1.ScanEvent
	for {
		event, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
		encoded := event.String()
		if strings.Contains(encoded, "document.txt") || strings.Contains(encoded, strings.Repeat("1", 64)) {
			t.Fatalf("scan event exposed a filename or hash: %s", encoded)
		}
	}
	if len(events) < 2 || events[0].GetProgress().GetOperation() != operation || !events[len(events)-1].GetComplete() || events[len(events)-1].GetApproved() != approved {
		t.Fatalf("%s events = %#v", operation, events)
	}
}

func assertScannerRPCError(t *testing.T, err error, grpcCode codes.Code, stableCode string) {
	t.Helper()
	if status.Code(err) != grpcCode || !strings.Contains(err.Error(), stableCode) {
		t.Fatalf("scanner error = %v, want %s/%s", err, grpcCode, stableCode)
	}
	details := status.Convert(err).Details()
	if len(details) != 1 {
		t.Fatalf("scanner error details = %v", details)
	}
	detail, ok := details[0].(*privatevmv1.ErrorDetail)
	if !ok || detail.GetCode() != stableCode || detail.GetSafeMessage() == "" || detail.GetRemediation() == "" || detail.GetSessionState() == "" {
		t.Fatalf("scanner error detail = %#v", details[0])
	}
}

type memoryScannerReceiptStore struct {
	mu      sync.Mutex
	receipt scan.UpdateReceipt
	written bool
}

func (store *memoryScannerReceiptStore) Save(ctx context.Context, receipt scan.UpdateReceipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.receipt = receipt
	store.written = true
	return nil
}

func (store *memoryScannerReceiptStore) Load(ctx context.Context) (scan.UpdateReceipt, error) {
	if err := ctx.Err(); err != nil {
		return scan.UpdateReceipt{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.written {
		return scan.UpdateReceipt{}, errors.New("missing receipt")
	}
	return store.receipt, nil
}

type bootProbeFunc func(context.Context) (scan.BootEvidence, error)

func (function bootProbeFunc) Evidence(ctx context.Context) (scan.BootEvidence, error) {
	return function(ctx)
}

type offlineBootStagerFunc func(context.Context) error

func (function offlineBootStagerFunc) Stage(ctx context.Context) error {
	return function(ctx)
}

type definitionUpdaterFunc func(context.Context) (scan.DefinitionEvidence, error)

func (function definitionUpdaterFunc) Update(ctx context.Context) (scan.DefinitionEvidence, error) {
	return function(ctx)
}

type cleanContentScanner struct{}

func (cleanContentScanner) Scan(ctx context.Context, reader io.Reader, size uint64) (scan.ClamResult, error) {
	read, err := io.Copy(io.Discard, &io.LimitedReader{R: reader, N: int64(size) + 1})
	if err != nil || read != int64(size) {
		return scan.ClamResult{}, errors.New("fake scanner input mismatch")
	}
	if err := ctx.Err(); err != nil {
		return scan.ClamResult{}, err
	}
	return scan.ClamResult{Clean: true, Finding: scan.Finding{Code: "CLAMAV_CLEAN", Severity: scan.SeverityInfo, Detail: "Fake ClamAV completed the full stream."}}, nil
}

type fakeScannerReconstruction struct {
	output           []byte
	result           ScannerReconstruction
	reconstructErr   error
	reconstructCalls int
	cleanupErr       error
	cleanupCalls     int
	openCalls        int
}

func newFakeScannerReconstruction(source []byte) *fakeScannerReconstruction {
	output := append([]byte("sanitized:"), source...)
	digest := sha256.Sum256(output)
	sourceDigest := sha256.Sum256(source)
	return &fakeScannerReconstruction{
		output: output,
		result: ScannerReconstruction{
			Outputs: []scan.ReportSanitizedOutput{{
				OutputID: "scan-out-0123456789abcdef0123456789abcdef", LogicalName: "document-sanitized.txt",
				SourceSHA256: hex.EncodeToString(sourceDigest[:]), SizeBytes: uint64(len(output)), SHA256: hex.EncodeToString(digest[:]),
				DetectedMIME: "text/plain", Transformation: "utf8-validated", RescanVerdict: "CLAMAV_CLEAN",
			}},
			Tools:                     []scan.ToolEvidence{{Name: "fake-reconstructor", Version: "1.0"}},
			ArchiveInspectionComplete: true, ReconstructionComplete: true, OutputRescanComplete: true,
		},
	}
}

func (adapter *fakeScannerReconstruction) Reconstruct(context.Context, scan.Inventory, scan.ScanSummary, policy.Policy) (ScannerReconstruction, error) {
	adapter.reconstructCalls++
	if adapter.reconstructErr != nil {
		return ScannerReconstruction{}, adapter.reconstructErr
	}
	return cloneReconstruction(adapter.result), nil
}

func (adapter *fakeScannerReconstruction) OpenApproved(ctx context.Context, outputID string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(adapter.result.Outputs) == 0 || outputID != adapter.result.Outputs[0].OutputID {
		return nil, errors.New("unknown output")
	}
	adapter.openCalls++
	return io.NopCloser(bytes.NewReader(adapter.output)), nil
}

func (adapter *fakeScannerReconstruction) Cleanup(context.Context) error {
	adapter.cleanupCalls++
	return adapter.cleanupErr
}

type errorDefinitionAdapter struct{ err error }

func (adapter errorDefinitionAdapter) Update(context.Context) (scan.UpdateReceipt, error) {
	return scan.UpdateReceipt{}, adapter.err
}

func (adapter errorDefinitionAdapter) Status(context.Context) (scan.UpdateReceipt, error) {
	return scan.UpdateReceipt{}, adapter.err
}

type scannerEventStream struct {
	ctx    context.Context
	events []*privatevmv1.ScanEvent
}

func (stream *scannerEventStream) Send(event *privatevmv1.ScanEvent) error {
	stream.events = append(stream.events, event)
	return nil
}

func (stream *scannerEventStream) SetHeader(metadata.MD) error  { return nil }
func (stream *scannerEventStream) SendHeader(metadata.MD) error { return nil }
func (stream *scannerEventStream) SetTrailer(metadata.MD)       {}
func (stream *scannerEventStream) Context() context.Context     { return stream.ctx }
func (stream *scannerEventStream) SendMsg(any) error            { return nil }
func (stream *scannerEventStream) RecvMsg(any) error            { return io.EOF }

const safePolicyFixture = `
schema_version = 1
name = "safe"
mode = "safe"

[limits]
max_input_bytes = 1048576
max_single_file_bytes = 1048576
max_files = 32
max_archive_depth = 3
max_expansion_ratio = 100.0
max_expanded_bytes = 4194304
scan_timeout_seconds = 60

[rules]
reject_on_malware = true
reject_on_scan_error = true
reject_on_skipped_file = true
reject_encrypted_archives = true
block_executables = true
block_scripts = true
block_disk_images = true
sanitize_documents = true
reencode_media = true
strip_metadata = true
`

func mustSafePolicy(t *testing.T) policy.Policy {
	t.Helper()
	selected, err := policy.Decode(strings.NewReader(safePolicyFixture))
	if err != nil {
		t.Fatal(err)
	}
	return selected
}
