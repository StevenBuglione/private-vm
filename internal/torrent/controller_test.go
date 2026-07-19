package torrent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"github.com/StevenBuglione/private-vm/internal/secret"
)

const testHash = "0123456789abcdef0123456789abcdef01234567"
const testMagnetPrefix = "magnet:?" + "xt=urn:btih:"

func TestInputBoundsValidationRedactionAndDestruction(t *testing.T) {
	magnetBytes := []byte(testMagnetPrefix + testHash + "&dn=private")
	input, err := NewInput(InputMagnet, magnetBytes)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", input, input), testHash) {
		t.Fatal("input formatter disclosed a torrent identifier")
	}
	if _, err := json.Marshal(input); !errors.Is(err, secret.ErrSerialization) {
		t.Fatalf("MarshalJSON error = %v", err)
	}
	input.Destroy()
	if err := input.WithReader(t.Context(), func(context.Context, io.Reader) error { return nil }); err == nil {
		t.Fatal("destroyed input remained readable")
	}
	for _, invalid := range [][]byte{
		[]byte("https://example.invalid/file"),
		[]byte("magnet:?dn=no-exact-topic"),
		[]byte(testMagnetPrefix + "short"),
		[]byte(testMagnetPrefix + testHash + "&xt=urn:btih:" + testHash),
		[]byte(testMagnetPrefix + testHash + "\n"),
	} {
		if _, err := NewInput(InputMagnet, invalid); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid magnet accepted or misclassified: %v", err)
		}
	}
	if _, err := NewInput(InputMagnet, bytes.Repeat([]byte{'x'}, MaximumMagnetBytes+1)); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("oversized input error = %v", err)
	}
	metainfo, err := NewInput(InputMetainfo, []byte("d4:infode"))
	if err != nil {
		t.Fatal(err)
	}
	metainfo.Destroy()
}

func TestMetadataFirstSelectionDownloadSealAndDestroy(t *testing.T) {
	backend := &fakeBackend{metadata: []RawMetadata{
		{Available: false},
		{Available: true, DisplayName: "fixture", Files: []RawFile{
			{Index: 0, Path: "document.pdf", Size: 128 << 20},
			{Index: 1, Path: "tool.exe", Size: 64 << 20},
		}},
	}}
	quarantine := &fakeQuarantine{}
	controller := testController(t, backend, quarantine, true)
	input := mustInput(t)
	defer input.Destroy()
	metadata, err := controller.Add(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !metadata.PayloadPaused || backend.started || backend.pauseCalls < 2 || len(backend.selections) != 1 || len(backend.selections[0]) != 0 {
		t.Fatalf("metadata was not held payload-paused: metadata=%+v backend=%+v", metadata, backend)
	}
	if metadata.Files[1].SuspectedType != "executable" || len(metadata.Files[1].HazardCodes) == 0 {
		t.Fatalf("executable was not highlighted: %+v", metadata.Files[1])
	}
	if _, _, err := controller.Select(t.Context(), []uint32{1}); !errors.Is(err, ErrInvalidSelection) {
		t.Fatalf("safe executable selection error = %v", err)
	}
	selected, plan, err := controller.Select(t.Context(), []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	if selected.SelectedSizeBytes != 128<<20 || plan.QuarantineRequired <= selected.SelectedSizeBytes || len(backend.selections) != 2 {
		t.Fatalf("capacity plan = %+v metadata=%+v", plan, selected)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	backend.statuses = []ClientStatus{
		{State: ClientRunning, CompletedBytes: 32 << 20, TotalBytes: 128 << 20},
		{State: ClientComplete, CompletedBytes: 128 << 20, TotalBytes: 128 << 20},
	}
	var events []Status
	if err := controller.Monitor(t.Context(), func(status Status) error { events = append(events, status); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].State != StateDownloadComplete {
		t.Fatalf("download events = %+v", events)
	}
	backend.digests = []FileDigest{{Path: "document.pdf", SizeBytes: 128 << 20, SourceIndex: 0, SHA256: [32]byte{1}}}
	destroyer := &fakeDestroyer{}
	coordinator := &Coordinator{Controller: controller, Destroyer: destroyer}
	receipt, err := coordinator.SealAndDestroy(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.ScannerReady() || !quarantine.unmounted || !backend.shutdown || destroyer.calls != 1 {
		t.Fatalf("seal/destroy evidence incomplete: ready=%t quarantine=%+v backend=%+v destroy=%d", receipt.ScannerReady(), quarantine, backend, destroyer.calls)
	}
	receipt.Destroy()
}

func TestCapacityPathAndMetadataFailuresBlockBeforePayload(t *testing.T) {
	for name, raw := range map[string]RawMetadata{
		"payload already read": {Available: true, PayloadRead: 1, DisplayName: "fixture", Files: []RawFile{{Index: 0, Path: "ok.pdf", Size: 1}}},
		"traversal":            {Available: true, DisplayName: "fixture", Files: []RawFile{{Index: 0, Path: "../escape", Size: 1}}},
		"case collision":       {Available: true, DisplayName: "fixture", Files: []RawFile{{Index: 0, Path: "A.pdf", Size: 1}, {Index: 1, Path: "a.pdf", Size: 1}}},
	} {
		t.Run(name, func(t *testing.T) {
			backend := &fakeBackend{metadata: []RawMetadata{raw}}
			controller := testController(t, backend, &fakeQuarantine{}, true)
			input := mustInput(t)
			defer input.Destroy()
			if _, err := controller.Add(t.Context(), input); !errors.Is(err, ErrUnsafeMetadata) {
				t.Fatalf("unsafe metadata error = %v", err)
			}
			if backend.started {
				t.Fatal("payload started after unsafe metadata")
			}
		})
	}
	backend := &fakeBackend{metadata: []RawMetadata{{Available: true, DisplayName: "fixture", Files: []RawFile{{Index: 0, Path: "large.pdf", Size: 10 << 30}}}}}
	controller := testController(t, backend, &fakeQuarantine{}, true)
	controller.config.Budget.QuarantineAvailableBytes = 1
	input := mustInput(t)
	defer input.Destroy()
	if _, err := controller.Add(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if _, _, err := controller.Select(t.Context(), []uint32{0}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	if err := controller.Start(t.Context()); !errors.Is(err, ErrNotApproved) || backend.started {
		t.Fatalf("unapproved start = %v started=%t", err, backend.started)
	}
}

func TestCancellationTimeoutVPNLossAndCleanupRemainPaused(t *testing.T) {
	backend := &fakeBackend{metadata: []RawMetadata{{Available: true, DisplayName: "fixture", Files: []RawFile{{Index: 0, Path: "ok.pdf", Size: 128 << 20}}}}}
	controller := testController(t, backend, &fakeQuarantine{}, true)
	input := mustInput(t)
	defer input.Destroy()
	if _, err := controller.Add(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if _, _, err := controller.Select(t.Context(), []uint32{0}); err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := controller.OnVPNLoss(t.Context(), guestvpn.Status{}); err != nil {
		t.Fatal(err)
	}
	state, err := controller.Status(t.Context())
	if err != nil || state.State != StatePaused {
		t.Fatalf("VPN loss state = %+v err=%v", state, err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := controller.Monitor(cancelled, func(Status) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled monitor error = %v", err)
	}
	if backend.pauseCalls == 0 {
		t.Fatal("cancelled monitor did not attempt pause")
	}
	backend.failShutdown = true
	if err := controller.Close(t.Context()); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("cleanup error = %v", err)
	}
	backend.failShutdown = false
	if err := controller.Close(t.Context()); err != nil {
		t.Fatalf("cleanup retry = %v", err)
	}
}

func TestMetadataTimeoutHasStableErrorAndLeavesClientPaused(t *testing.T) {
	backend := &fakeBackend{metadata: []RawMetadata{{Available: false}}}
	controller, err := newController(backend, &fakeQuarantine{}, errorWaiter{err: context.DeadlineExceeded}, Config{
		MetadataTimeout: time.Minute,
		PollInterval:    time.Millisecond,
		StallTimeout:    time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	input := mustInput(t)
	defer input.Destroy()
	if _, err := controller.Add(t.Context(), input); !errors.Is(err, ErrMetadataUnavailable) || apperror.From(err).Code != "TORRENT_METADATA_TIMEOUT" {
		t.Fatalf("metadata timeout error = %v", err)
	}
	if backend.started || backend.pauseCalls == 0 {
		t.Fatalf("metadata timeout did not remain paused: %+v", backend)
	}
}

func TestCoordinatorRetriesDestroyAuditWithoutResealing(t *testing.T) {
	backend := &fakeBackend{
		metadata: []RawMetadata{{Available: true, DisplayName: "fixture", Files: []RawFile{{Index: 0, Path: "ok.pdf", Size: 128 << 20}}}},
		statuses: []ClientStatus{{State: ClientComplete, CompletedBytes: 128 << 20, TotalBytes: 128 << 20}},
		digests:  []FileDigest{{Path: "ok.pdf", SizeBytes: 128 << 20, SourceIndex: 0, SHA256: [32]byte{1}}},
	}
	controller := testController(t, backend, &fakeQuarantine{}, true)
	input := mustInput(t)
	defer input.Destroy()
	if _, err := controller.Add(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if _, _, err := controller.Select(t.Context(), []uint32{0}); err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := controller.Monitor(t.Context(), func(Status) error { return nil }); err != nil {
		t.Fatal(err)
	}
	destroyer := &fakeDestroyer{fail: true}
	coordinator := &Coordinator{Controller: controller, Destroyer: destroyer}
	if receipt, err := coordinator.SealAndDestroy(t.Context()); !errors.Is(err, ErrCleanupIncomplete) || receipt != nil {
		t.Fatalf("failed cleanup receipt=%+v err=%v", receipt, err)
	}
	destroyer.fail = false
	receipt, err := coordinator.SealAndDestroy(t.Context())
	if err != nil || !receipt.ScannerReady() || backend.verifyCalls != 1 {
		t.Fatalf("cleanup retry receipt=%+v err=%v verifyCalls=%d", receipt, err, backend.verifyCalls)
	}
}

func TestSealRetriesUnmountWithoutRestartingStoppedClient(t *testing.T) {
	backend := &fakeBackend{
		metadata: []RawMetadata{{Available: true, DisplayName: "fixture", Files: []RawFile{{Index: 0, Path: "ok.pdf", Size: 128 << 20}}}},
		statuses: []ClientStatus{{State: ClientComplete, CompletedBytes: 128 << 20, TotalBytes: 128 << 20}},
		digests:  []FileDigest{{Path: "ok.pdf", SizeBytes: 128 << 20, SourceIndex: 0, SHA256: [32]byte{1}}},
	}
	quarantine := &fakeQuarantine{failOnce: true}
	controller := testController(t, backend, quarantine, true)
	input := mustInput(t)
	defer input.Destroy()
	if _, err := controller.Add(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if _, _, err := controller.Select(t.Context(), []uint32{0}); err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := controller.Monitor(t.Context(), func(Status) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Seal(t.Context()); !errors.Is(err, ErrSealFailed) {
		t.Fatalf("first seal error = %v", err)
	}
	manifest, err := controller.Seal(t.Context())
	if err != nil || backend.verifyCalls != 1 || backend.shutdownCalls != 1 || quarantine.calls != 2 {
		t.Fatalf("seal retry err=%v verify=%d shutdown=%d unmount=%d", err, backend.verifyCalls, backend.shutdownCalls, quarantine.calls)
	}
	manifest.Destroy()
	if err := controller.Close(t.Context()); err != nil || backend.shutdownCalls != 1 {
		t.Fatalf("sealed close err=%v shutdown=%d", err, backend.shutdownCalls)
	}
}

func testController(t *testing.T, backend *fakeBackend, quarantine *fakeQuarantine, safe bool) *Controller {
	t.Helper()
	controller, err := newController(backend, quarantine, instantWaiter{}, Config{
		SafePolicy: safe, MetadataTimeout: time.Minute, PollInterval: time.Millisecond, StallTimeout: time.Minute,
		Budget: CapacityBudget{
			QuarantineAvailableBytes: 64 << 30, ScanAvailableBytes: 64 << 30, ReconstructionAvailable: 64 << 30,
			DestinationAvailable: 64 << 30, RootOverlayBudgetBytes: 8 << 30, ArchiveExpansionBytes: 4 << 30,
			ReconstructionBytes: 1 << 30, MaximumSelectedBytes: 32 << 30,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func mustInput(t *testing.T) *Input {
	t.Helper()
	input, err := NewInput(InputMagnet, []byte(testMagnetPrefix+testHash))
	if err != nil {
		t.Fatal(err)
	}
	return input
}

type instantWaiter struct{}

func (instantWaiter) Wait(ctx context.Context, _ time.Duration) error { return ctx.Err() }

type errorWaiter struct{ err error }

func (waiter errorWaiter) Wait(context.Context, time.Duration) error { return waiter.err }

type fakeBackend struct {
	mu            sync.Mutex
	metadata      []RawMetadata
	statuses      []ClientStatus
	selections    [][]uint32
	digests       []FileDigest
	pauseCalls    int
	verifyCalls   int
	started       bool
	shutdown      bool
	shutdownCalls int
	failShutdown  bool
}

func (backend *fakeBackend) AddPaused(context.Context, *Input) (Handle, error) {
	return NewHandle(testHash)
}
func (backend *fakeBackend) Metadata(context.Context, Handle) (RawMetadata, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.metadata) == 0 {
		return RawMetadata{}, nil
	}
	value := backend.metadata[0]
	backend.metadata = backend.metadata[1:]
	return value, nil
}
func (backend *fakeBackend) SetSelection(_ context.Context, _ Handle, indexes []uint32, _ uint32) error {
	backend.selections = append(backend.selections, append([]uint32(nil), indexes...))
	return nil
}
func (backend *fakeBackend) Start(context.Context, Handle) error { backend.started = true; return nil }
func (backend *fakeBackend) Pause(context.Context, Handle) error {
	backend.pauseCalls++
	backend.started = false
	return nil
}
func (backend *fakeBackend) Status(context.Context, Handle) (ClientStatus, error) {
	if len(backend.statuses) == 0 {
		return ClientStatus{}, context.Canceled
	}
	status := backend.statuses[0]
	backend.statuses = backend.statuses[1:]
	return status, nil
}
func (backend *fakeBackend) VerifyCompleted(context.Context, Handle, Metadata) ([]FileDigest, error) {
	backend.verifyCalls++
	return append([]FileDigest(nil), backend.digests...), nil
}
func (backend *fakeBackend) Shutdown(context.Context) error {
	backend.shutdownCalls++
	if backend.failShutdown {
		return errors.New("fixture")
	}
	backend.shutdown = true
	return nil
}

type fakeQuarantine struct {
	unmounted bool
	calls     int
	failOnce  bool
}

func (quarantine *fakeQuarantine) SyncAndUnmount(context.Context) error {
	quarantine.calls++
	if quarantine.failOnce {
		quarantine.failOnce = false
		return errors.New("fixture")
	}
	quarantine.unmounted = true
	return nil
}

type fakeDestroyer struct {
	calls int
	fail  bool
}

func (destroyer *fakeDestroyer) DestroyAndAudit(context.Context) error {
	destroyer.calls++
	if destroyer.fail {
		return errors.New("fixture")
	}
	return nil
}

func TestStableTorrentErrorsNeverContainInput(t *testing.T) {
	fixture := testMagnetPrefix + testHash
	for _, err := range []error{invalidInput(), inputTooLarge(), unsafeMetadata(), invalidSelection(), insufficientCapacity(), downloadFailed(), sealFailed(), cleanupIncomplete()} {
		application := apperror.From(err)
		if application.Code == "" || application.Remediation == "" || strings.Contains(application.Error()+application.Remediation, fixture) {
			t.Fatalf("unsafe torrent error = %+v", application)
		}
	}
}
