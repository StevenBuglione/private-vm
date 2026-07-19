package usb

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
)

type workflowRuntime struct {
	destination *fakeDestination
	lifecycle   *fakeExportLifecycle
	enrollment  Enrollment
}

func (runtime *workflowRuntime) Prepare(_ context.Context, claim Claim, filesystem string, _ *secret.Bytes, _ func(PrepareEvent) error) (PrepareReceipt, error) {
	fingerprint, _ := runtime.enrollment.Identity.Fingerprint()
	return PrepareReceipt{SchemaVersion: PrepareSchemaVersion, EnrollmentID: claim.EnrollmentID, Filesystem: filesystem, CapacityBytes: runtime.enrollment.Identity.Capacity, Fingerprint: fingerprint, State: PrepareDestinationReady}, nil
}
func (runtime *workflowRuntime) VerifyHostAndSourceIsolation(ctx context.Context, claim Claim) error {
	return runtime.lifecycle.VerifyHostAndSourceIsolation(ctx, claim)
}
func (runtime *workflowRuntime) BootNetworkless(ctx context.Context) error {
	return runtime.lifecycle.BootNetworkless(ctx)
}
func (runtime *workflowRuntime) VerifyNoNetwork(ctx context.Context) error {
	return runtime.lifecycle.VerifyNoNetwork(ctx)
}
func (runtime *workflowRuntime) AttachExactUSB(ctx context.Context, claim Claim) error {
	return runtime.lifecycle.AttachExactUSB(ctx, claim)
}
func (runtime *workflowRuntime) InspectAttachedUSB(ctx context.Context, claim Claim) error {
	return runtime.lifecycle.InspectAttachedUSB(ctx, claim)
}
func (runtime *workflowRuntime) DetachUSB(ctx context.Context) error {
	return runtime.lifecycle.DetachUSB(ctx)
}
func (runtime *workflowRuntime) StopExporter(ctx context.Context) error {
	return runtime.lifecycle.StopExporter(ctx)
}
func (runtime *workflowRuntime) AuditAbsent(ctx context.Context) error {
	return runtime.lifecycle.AuditAbsent(ctx)
}
func (runtime *workflowRuntime) Begin(ctx context.Context, output ApprovedOutput) (DestinationWriter, error) {
	return runtime.destination.Begin(ctx, output)
}
func (runtime *workflowRuntime) Finalize(ctx context.Context) (FinalizeEvidence, error) {
	return runtime.destination.Finalize(ctx)
}

type workflowRuntimeCoordinator struct {
	runtime *workflowRuntime
	fail    error
}

func (coordinator *workflowRuntimeCoordinator) Preflight(ctx context.Context, _ session.Snapshot) error {
	return errors.Join(ctx.Err(), coordinator.fail)
}
func (*workflowRuntimeCoordinator) VerifyImage(context.Context, session.Snapshot) error { return nil }
func (*workflowRuntimeCoordinator) StorageAllocation(session.Snapshot) session.AllocateFunc {
	return func(context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		return func(context.Context) error { return nil }, func(context.Context) error { return nil }, nil
	}
}
func (*workflowRuntimeCoordinator) RuntimeAllocation(session.Snapshot, Claim, Enrollment) session.AllocateFunc {
	return func(context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		return func(context.Context) error { return nil }, func(context.Context) error { return nil }, nil
	}
}
func (coordinator *workflowRuntimeCoordinator) Runtime(string) (ExporterRuntime, error) {
	if coordinator.runtime == nil {
		return nil, errors.New("missing")
	}
	return coordinator.runtime, nil
}

func TestHostWorkflowPrepareExportAndSessionCleanup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	store, err := session.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewManager(store, session.DefaultMaxSessionsPerOwner)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := sessions.Create(1000, session.RoleExporter)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"PLANNED", "USB_IDENTIFIED", "USB_CLAIMED"} {
		snapshot, err = sessions.TransitionWorkflow(t.Context(), snapshot.ID, 1000, state)
		if err != nil {
			t.Fatal(err)
		}
	}
	claims, enrollment, _ := claimFixture(t, fakeDeviceClaimer{handle: &fakeDeviceClaim{}})
	claim, err := claims.Claim(t.Context(), snapshot.ID, 1000, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	registerClaimResource(t, sessions, claims, snapshot, claim)
	data := []byte("authenticated reconstructed output")
	digest := sha256.Sum256(data)
	source := &fakeApprovedSource{output: ApprovedOutput{SourceRole: SourceScanner, OutputID: "output-opaque-01", LogicalName: "approved.pdf", MediaType: "application/pdf", Size: uint64(len(data)), SourceDigest: NewDigest(digest), ReportAuthenticated: true, ReportComplete: true, PolicyApproved: true, Reconstructed: true}, chunks: [][]byte{data}}
	registry := NewApprovedSourceRegistry()
	selection := SourceSelection{Role: SourceScanner, SessionID: "pvm-00000000000000000000000000000000", OutputID: "output-opaque-01"}
	if err := registry.Register(selection, func(context.Context) (ApprovedSource, error) { return source, nil }); err != nil {
		t.Fatal(err)
	}
	runtime := &workflowRuntime{destination: &fakeDestination{writer: &fakeDestinationWriter{}}, lifecycle: &fakeExportLifecycle{fail: make(map[string]error)}, enrollment: enrollment}
	workflow, err := NewHostWorkflow(sessions, claims, &workflowRuntimeCoordinator{runtime: runtime}, registry)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	workflow.Now = func() time.Time { return now }
	plan, err := workflow.PlanPreparation(t.Context(), snapshot, claim.ID, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	passphrase, err := secret.New([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	defer passphrase.Destroy()
	receipt, err := workflow.Prepare(t.Context(), snapshot, claim.ID, enrollment, plan.Challenge, Confirmation{First: plan.FirstPrompt, Second: plan.SecondPrompt}, passphrase, &fakePrepareAuthorizer{})
	if err != nil || receipt.State != PrepareDestinationReady {
		t.Fatalf("prepare=%+v err=%v", receipt, err)
	}
	active, err := sessions.Get(snapshot.ID, 1000)
	if err != nil || active.Phase != session.PhaseActive {
		t.Fatalf("active=%+v err=%v", active, err)
	}
	exported, err := workflow.Export(t.Context(), active, claim.ID, selection, enrollment)
	if err != nil || exported.Validate() != nil {
		t.Fatalf("export=%+v err=%v", exported, err)
	}
	cleaned, err := sessions.Cleanup(t.Context(), snapshot.ID, 1000)
	if err != nil || cleaned.Phase != session.PhaseDestroyed {
		t.Fatalf("cleanup=%+v err=%v", cleaned, err)
	}
	if _, err := registry.OpenApproved(t.Context(), selection); err == nil {
		t.Fatal("one-use approved source reopened")
	}
}

func TestHostWorkflowCancellationBeforeRuntimeCleansClaim(t *testing.T) {
	root := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	store, _ := session.NewStore(root)
	sessions, _ := session.NewManager(store, session.DefaultMaxSessionsPerOwner)
	snapshot, _ := sessions.Create(1000, session.RoleExporter)
	for _, state := range []string{"PLANNED", "USB_IDENTIFIED", "USB_CLAIMED"} {
		snapshot, _ = sessions.TransitionWorkflow(t.Context(), snapshot.ID, 1000, state)
	}
	handle := &fakeDeviceClaim{}
	claims, enrollment, _ := claimFixture(t, fakeDeviceClaimer{handle: handle})
	claim, _ := claims.Claim(t.Context(), snapshot.ID, 1000, enrollment)
	registerClaimResource(t, sessions, claims, snapshot, claim)
	coordinator := &workflowRuntimeCoordinator{fail: context.Canceled}
	workflow, _ := NewHostWorkflow(sessions, claims, coordinator, NewApprovedSourceRegistry())
	plan, _ := workflow.PlanPreparation(t.Context(), snapshot, claim.ID, enrollment)
	passphrase, _ := secret.New([]byte("correct horse battery staple"))
	defer passphrase.Destroy()
	_, err := workflow.Prepare(t.Context(), snapshot, claim.ID, enrollment, plan.Challenge, Confirmation{First: plan.FirstPrompt, Second: plan.SecondPrompt}, passphrase, &fakePrepareAuthorizer{})
	if err == nil || handle.releaseCalls != 1 {
		t.Fatalf("err=%v releases=%d", err, handle.releaseCalls)
	}
	cleaned, _ := sessions.Get(snapshot.ID, 1000)
	if cleaned.Phase != session.PhaseDestroyed {
		t.Fatalf("phase=%s", cleaned.Phase)
	}
}

func TestHostWorkflowReportsIncompleteFailureCleanup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	store, _ := session.NewStore(root)
	sessions, _ := session.NewManager(store, session.DefaultMaxSessionsPerOwner)
	snapshot, _ := sessions.Create(1000, session.RoleExporter)
	for _, state := range []string{"PLANNED", "USB_IDENTIFIED", "USB_CLAIMED"} {
		snapshot, _ = sessions.TransitionWorkflow(t.Context(), snapshot.ID, 1000, state)
	}
	handle := &fakeDeviceClaim{releaseErr: errors.New("injected release failure")}
	claims, enrollment, _ := claimFixture(t, fakeDeviceClaimer{handle: handle})
	claim, _ := claims.Claim(t.Context(), snapshot.ID, 1000, enrollment)
	registerClaimResource(t, sessions, claims, snapshot, claim)
	workflow, _ := NewHostWorkflow(sessions, claims, &workflowRuntimeCoordinator{fail: context.Canceled}, NewApprovedSourceRegistry())
	plan, _ := workflow.PlanPreparation(t.Context(), snapshot, claim.ID, enrollment)
	passphrase, _ := secret.New([]byte("correct horse battery staple"))
	defer passphrase.Destroy()
	_, err := workflow.Prepare(t.Context(), snapshot, claim.ID, enrollment, plan.Challenge, Confirmation{First: plan.FirstPrompt, Second: plan.SecondPrompt}, passphrase, &fakePrepareAuthorizer{})
	if !errors.Is(err, session.ErrCleanupIncomplete) {
		t.Fatalf("cleanup failure was hidden: %v", err)
	}
	retained, getErr := sessions.Get(snapshot.ID, 1000)
	if getErr != nil || retained.Phase != session.PhaseDestroying {
		t.Fatalf("retryable cleanup owner was lost: snapshot=%+v err=%v", retained, getErr)
	}
}

func TestHostWorkflowRejectsChangedApprovedOutputIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	store, _ := session.NewStore(root)
	sessions, _ := session.NewManager(store, session.DefaultMaxSessionsPerOwner)
	snapshot, _ := sessions.Create(1000, session.RoleExporter)
	for _, state := range []string{"PLANNED", "USB_IDENTIFIED", "USB_CLAIMED"} {
		snapshot, _ = sessions.TransitionWorkflow(t.Context(), snapshot.ID, 1000, state)
	}
	claims, enrollment, _ := claimFixture(t, fakeDeviceClaimer{handle: &fakeDeviceClaim{}})
	claim, _ := claims.Claim(t.Context(), snapshot.ID, 1000, enrollment)
	registerClaimResource(t, sessions, claims, snapshot, claim)
	runtime := &workflowRuntime{destination: &fakeDestination{}, lifecycle: &fakeExportLifecycle{fail: make(map[string]error)}, enrollment: enrollment}
	coordinator := &workflowRuntimeCoordinator{runtime: runtime}
	workflow, _ := NewHostWorkflow(sessions, claims, coordinator, NewApprovedSourceRegistry())
	plan, _ := workflow.PlanPreparation(t.Context(), snapshot, claim.ID, enrollment)
	passphrase, _ := secret.New([]byte("correct horse battery staple"))
	defer passphrase.Destroy()
	if _, err := workflow.Prepare(t.Context(), snapshot, claim.ID, enrollment, plan.Challenge, Confirmation{First: plan.FirstPrompt, Second: plan.SecondPrompt}, passphrase, &fakePrepareAuthorizer{}); err != nil {
		t.Fatal(err)
	}
	active, _ := sessions.Get(snapshot.ID, 1000)
	selection := SourceSelection{Role: SourceScanner, SessionID: "pvm-22222222222222222222222222222222", OutputID: "output-expected-01"}
	source := &fakeApprovedSource{output: ApprovedOutput{SourceRole: SourceScanner, OutputID: "output-changed-01"}}
	registry := NewApprovedSourceRegistry()
	if err := registry.Register(selection, func(context.Context) (ApprovedSource, error) { return source, nil }); err != nil {
		t.Fatal(err)
	}
	workflow.Sources = registry
	if _, err := workflow.Export(t.Context(), active, claim.ID, selection, enrollment); err == nil || source.closed != 1 {
		t.Fatalf("changed output identity err=%v closes=%d", err, source.closed)
	}
}

func registerClaimResource(t *testing.T, sessions *session.Manager, claims *ClaimManager, snapshot session.Snapshot, claim Claim) {
	t.Helper()
	err := sessions.AcquireResource(t.Context(), snapshot.ID, snapshot.OwnerUID, "usb-claim", func(context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		return func(ctx context.Context) error {
				return claims.Release(ctx, claim.ID, snapshot.ID, snapshot.OwnerUID)
			}, func(ctx context.Context) error {
				return claims.AuditAbsent(ctx, claim.ID, snapshot.ID, snapshot.OwnerUID)
			}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

var _ ExporterRuntime = (*workflowRuntime)(nil)
var _ ExporterRuntimeCoordinator = (*workflowRuntimeCoordinator)(nil)
