package usb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

type fakeApprovedSource struct {
	output   ApprovedOutput
	chunks   [][]byte
	index    int
	closeErr error
	closed   int
	next     func(context.Context) error
}

func (s *fakeApprovedSource) Output() ApprovedOutput { return s.output }
func (s *fakeApprovedSource) Next(ctx context.Context) (RelayChunk, error) {
	if s.next != nil {
		if err := s.next(ctx); err != nil {
			return RelayChunk{}, err
		}
	}
	if s.index >= len(s.chunks) {
		return RelayChunk{}, io.EOF
	}
	data := append([]byte(nil), s.chunks[s.index]...)
	chunk := RelayChunk{Sequence: uint64(s.index), Data: data}
	s.index++
	return chunk, nil
}
func (s *fakeApprovedSource) Close() error { s.closed++; return s.closeErr }

type fakeDestinationWriter struct {
	buffer       bytes.Buffer
	nextSequence uint64
	abortCalls   int
	commitErr    error
	received     Digest
	reread       Digest
	incomplete   bool
}

func (w *fakeDestinationWriter) WriteChunk(_ context.Context, sequence uint64, data []byte) error {
	if sequence != w.nextSequence {
		return errors.New("sequence")
	}
	w.nextSequence++
	_, err := w.buffer.Write(data)
	return err
}
func (w *fakeDestinationWriter) Commit(_ context.Context, total uint64, relay Digest) (DestinationEvidence, error) {
	w.received = relay
	rereadArray := sha256.Sum256(w.buffer.Bytes())
	w.reread = NewDigest(rereadArray)
	if w.incomplete {
		return DestinationEvidence{BytesWritten: total, ReceivedDigest: relay, RereadDigest: w.reread}, w.commitErr
	}
	return DestinationEvidence{
		BytesWritten: total, ReceivedDigest: relay, RereadDigest: w.reread,
		FileSynced: true, FilesystemSynced: true, AtomicRename: true,
	}, w.commitErr
}
func (w *fakeDestinationWriter) Abort(context.Context) error { w.abortCalls++; return nil }

type fakeDestination struct {
	writer        DestinationWriter
	beginErr      error
	finalizeErr   error
	finalizeCalls int
}

func (d *fakeDestination) Begin(context.Context, ApprovedOutput) (DestinationWriter, error) {
	return d.writer, d.beginErr
}
func (d *fakeDestination) Finalize(context.Context) (FinalizeEvidence, error) {
	d.finalizeCalls++
	return FinalizeEvidence{Unmounted: d.finalizeErr == nil, LUKSClosed: d.finalizeErr == nil}, d.finalizeErr
}

type fakeExportLifecycle struct {
	mu    sync.Mutex
	order []string
	fail  map[string]error
}

func (l *fakeExportLifecycle) step(name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.order = append(l.order, name)
	return l.fail[name]
}
func (l *fakeExportLifecycle) VerifyHostAndSourceIsolation(context.Context, Claim) error {
	return l.step("boundaries")
}
func (l *fakeExportLifecycle) BootNetworkless(context.Context) error       { return l.step("boot") }
func (l *fakeExportLifecycle) VerifyNoNetwork(context.Context) error       { return l.step("offline") }
func (l *fakeExportLifecycle) AttachExactUSB(context.Context, Claim) error { return l.step("attach") }
func (l *fakeExportLifecycle) InspectAttachedUSB(context.Context, Claim) error {
	return l.step("inspect")
}
func (l *fakeExportLifecycle) DetachUSB(context.Context) error    { return l.step("detach") }
func (l *fakeExportLifecycle) StopExporter(context.Context) error { return l.step("stop") }
func (l *fakeExportLifecycle) AuditAbsent(context.Context) error  { return l.step("audit") }

type exportFixture struct {
	operation   *ExportOperation
	source      *fakeApprovedSource
	destination *fakeDestination
	writer      *fakeDestinationWriter
	lifecycle   *fakeExportLifecycle
	handle      *fakeDeviceClaim
	events      *[]ExportEvent
}

func newExportFixture(t *testing.T, data []byte) exportFixture {
	t.Helper()
	handle := &fakeDeviceClaim{}
	manager, enrollment, _ := claimFixture(t, fakeDeviceClaimer{handle: handle})
	claim, err := manager.Claim(t.Context(), "pvm-session", 1000, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	source := &fakeApprovedSource{
		output: ApprovedOutput{
			SourceRole: SourceScanner,
			OutputID:   "output-opaque-01", LogicalName: "approved-output.pdf", MediaType: "application/pdf",
			Size: uint64(len(data)), SourceDigest: NewDigest(sum), ReportAuthenticated: true,
			ReportComplete: true, PolicyApproved: true, Reconstructed: true,
		},
		chunks: [][]byte{data[:len(data)/2], data[len(data)/2:]},
	}
	destination := &fakeDestination{writer: &fakeDestinationWriter{}}
	lifecycle := &fakeExportLifecycle{fail: make(map[string]error)}
	events := make([]ExportEvent, 0)
	operation, err := NewExportOperation(
		manager, lifecycle, destination,
		ExportOptions{MaxBytes: 1 << 20, Timeout: time.Minute, IdleTimeout: time.Second},
		claim.ID, "pvm-session", 1000, enrollment,
		func(event ExportEvent) error { events = append(events, event); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	return exportFixture{operation: operation, source: source, destination: destination, writer: destination.writer.(*fakeDestinationWriter), lifecycle: lifecycle, handle: handle, events: &events}
}

func TestExportOperationStreamsVerifiesAndCleans(t *testing.T) {
	fixture := newExportFixture(t, []byte("approved reconstructed output"))
	receipt, err := fixture.operation.Run(t.Context(), fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	reread, ok := fixture.operation.VerifiedRereadDigest()
	if !ok || !reread.Equal(fixture.source.output.SourceDigest) {
		t.Fatal("successful operation did not retain internal reread evidence")
	}
	wantOrder := []string{"boundaries", "boot", "offline", "attach", "inspect", "detach", "stop", "audit"}
	if !equalStrings(fixture.lifecycle.order, wantOrder) {
		t.Fatalf("lifecycle order %v, want %v", fixture.lifecycle.order, wantOrder)
	}
	if fixture.handle.releaseCalls != 1 || fixture.source.closed != 1 || fixture.destination.finalizeCalls != 1 {
		t.Fatalf("release=%d close=%d finalize=%d", fixture.handle.releaseCalls, fixture.source.closed, fixture.destination.finalizeCalls)
	}
	for index, event := range *fixture.events {
		if event.Sequence != uint64(index+1) {
			t.Fatalf("non-monotonic events: %#v", *fixture.events)
		}
	}
}

func TestExportRejectsScannerRelayHashMismatchAndCleans(t *testing.T) {
	fixture := newExportFixture(t, []byte("approved reconstructed output"))
	wrong := sha256.Sum256([]byte("different"))
	fixture.source.output.SourceDigest = NewDigest(wrong)
	_, err := fixture.operation.Run(t.Context(), fixture.source)
	var usbError *Error
	if !errors.As(err, &usbError) || usbError.Code != CodeHashMismatch {
		t.Fatalf("got %v", err)
	}
	if fixture.writer.abortCalls != 1 || fixture.destination.finalizeCalls != 1 || fixture.handle.releaseCalls != 1 {
		t.Fatal("hash failure did not clean all owned resources")
	}
}

func TestExportRejectsIncompleteReportBeforeBoot(t *testing.T) {
	fixture := newExportFixture(t, []byte("approved reconstructed output"))
	fixture.source.output.ReportComplete = false
	_, err := fixture.operation.Run(t.Context(), fixture.source)
	var usbError *Error
	if !errors.As(err, &usbError) || usbError.Code != CodeWriteFailed {
		t.Fatalf("got %v", err)
	}
	if !equalStrings(fixture.lifecycle.order, []string{"audit"}) || fixture.handle.releaseCalls != 1 {
		t.Fatalf("unsafe invalid-report lifecycle: %v release=%d", fixture.lifecycle.order, fixture.handle.releaseCalls)
	}
}

func TestExportRejectsInsufficientCapacity(t *testing.T) {
	fixture := newExportFixture(t, []byte("approved reconstructed output"))
	fixture.operation.enrollment.Identity.Capacity = 1
	_, err := fixture.operation.Run(t.Context(), fixture.source)
	var usbError *Error
	if !errors.As(err, &usbError) || usbError.Code != CodeTooSmall {
		t.Fatalf("got %v", err)
	}
}

func TestExportSourceCloseFailureIsBlocking(t *testing.T) {
	fixture := newExportFixture(t, []byte("approved reconstructed output"))
	fixture.source.closeErr = errors.New("fixture close failure")
	_, err := fixture.operation.Run(t.Context(), fixture.source)
	if err == nil || fixture.source.closed != 1 || fixture.writer.abortCalls != 1 || fixture.handle.releaseCalls != 1 {
		t.Fatalf("err=%v close=%d abort=%d release=%d", err, fixture.source.closed, fixture.writer.abortCalls, fixture.handle.releaseCalls)
	}
}

func TestExportBoundaryFailureNeverBootsOrAttaches(t *testing.T) {
	fixture := newExportFixture(t, []byte("approved reconstructed output"))
	fixture.lifecycle.fail["boundaries"] = errors.New("fixture isolation failure")
	_, err := fixture.operation.Run(t.Context(), fixture.source)
	if err == nil || !equalStrings(fixture.lifecycle.order, []string{"boundaries", "audit"}) || fixture.handle.releaseCalls != 1 {
		t.Fatalf("err=%v order=%v release=%d", err, fixture.lifecycle.order, fixture.handle.releaseCalls)
	}
}

func TestExportPartialLifecycleFailuresAreCleaned(t *testing.T) {
	tests := []struct {
		step string
		want []string
	}{
		{"boot", []string{"boundaries", "boot", "stop", "audit"}},
		{"offline", []string{"boundaries", "boot", "offline", "stop", "audit"}},
		{"attach", []string{"boundaries", "boot", "offline", "attach", "detach", "stop", "audit"}},
		{"inspect", []string{"boundaries", "boot", "offline", "attach", "inspect", "detach", "stop", "audit"}},
	}
	for _, test := range tests {
		t.Run(test.step, func(t *testing.T) {
			fixture := newExportFixture(t, []byte("approved reconstructed output"))
			fixture.lifecycle.fail[test.step] = errors.New("fixture failure")
			_, err := fixture.operation.Run(t.Context(), fixture.source)
			if err == nil || !equalStrings(fixture.lifecycle.order, test.want) || fixture.handle.releaseCalls != 1 {
				t.Fatalf("err=%v order=%v release=%d", err, fixture.lifecycle.order, fixture.handle.releaseCalls)
			}
		})
	}
}

func TestExportRejectsExporterRereadMismatch(t *testing.T) {
	fixture := newExportFixture(t, []byte("approved reconstructed output"))
	wrong := sha256.Sum256([]byte("tampered"))
	fixture.writer.incomplete = false
	// Supply a writer whose commit evidence is altered after receiving the
	// complete bounded stream.
	fixture.writer.commitErr = nil
	fixture.writer.reread = NewDigest(wrong)
	fixture.destination = &fakeDestination{writer: &rereadMismatchWriter{fakeDestinationWriter: fixture.writer, mismatch: NewDigest(wrong)}}
	fixture.operation.destination = fixture.destination
	_, err := fixture.operation.Run(t.Context(), fixture.source)
	var usbError *Error
	if !errors.As(err, &usbError) || usbError.Code != CodeHashMismatch {
		t.Fatalf("got %v", err)
	}
}

type rereadMismatchWriter struct {
	*fakeDestinationWriter
	mismatch Digest
}

func (w *rereadMismatchWriter) Commit(ctx context.Context, total uint64, relay Digest) (DestinationEvidence, error) {
	evidence, err := w.fakeDestinationWriter.Commit(ctx, total, relay)
	evidence.RereadDigest = w.mismatch
	return evidence, err
}

func TestExportTimeoutCleansWithoutDetachedWork(t *testing.T) {
	fixture := newExportFixture(t, []byte("approved reconstructed output"))
	fixture.operation.options.IdleTimeout = time.Millisecond
	fixture.source.next = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	_, err := fixture.operation.Run(t.Context(), fixture.source)
	if err == nil || fixture.handle.releaseCalls != 1 {
		t.Fatalf("err=%v release=%d", err, fixture.handle.releaseCalls)
	}
}

func TestExportCleanupFailureCanBeRetried(t *testing.T) {
	fixture := newExportFixture(t, []byte("approved reconstructed output"))
	wrong := sha256.Sum256([]byte("different"))
	fixture.source.output.SourceDigest = NewDigest(wrong)
	fixture.destination.finalizeErr = errors.New("fixture finalize failure")
	_, err := fixture.operation.Run(t.Context(), fixture.source)
	var usbError *Error
	if !errors.As(err, &usbError) || usbError.Code != CodeCleanupIncomplete {
		t.Fatalf("got %v", err)
	}
	if fixture.handle.releaseCalls != 0 {
		t.Fatal("claim released before dependent destination cleanup")
	}
	fixture.destination.finalizeErr = nil
	if err := fixture.operation.Cleanup(t.Context()); err != nil {
		t.Fatalf("cleanup retry failed: %v", err)
	}
	if fixture.handle.releaseCalls != 1 {
		t.Fatal("cleanup retry did not release claim")
	}
}
