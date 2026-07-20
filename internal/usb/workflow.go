package usb

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
)

var sourceOutputIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@+-]{7,127}$`)

// SourceRole is a closed semantic origin for an approved output. It cannot
// represent a host path, guest path, device node, QEMU argument, or mount.
type SourceRole string

const (
	SourceScanner     SourceRole = "scanner"
	SourceWorkstation SourceRole = "workstation"
)

type SourceSelection struct {
	Role      SourceRole
	SessionID string
	OutputID  string
}

func (selection SourceSelection) validate() error {
	if selection.Role != SourceScanner && selection.Role != SourceWorkstation {
		return errors.New("USB export source role is invalid")
	}
	if session.ValidateID(selection.SessionID) != nil || !sourceOutputIDPattern.MatchString(selection.OutputID) {
		return errors.New("USB export source selection is invalid")
	}
	return nil
}

// ApprovedSourceProvider opens only authenticated, report-approved scanner
// reconstruction or workstation Export output. Implementations must complete
// their own guest handshake and return the declared digest with the stream.
type ApprovedSourceProvider interface {
	OpenApproved(context.Context, SourceSelection) (ApprovedSource, error)
}

// ExporterRuntime is the already authenticated, networkless exporter. The
// same object owns preparation, the one destination stream, hot-unplug, QEMU
// stop, and final absence audit.
type ExporterRuntime interface {
	PrepareBackend
	ExportLifecycle
	Destination
}

// ExporterRuntimeCoordinator binds image verification, volatile storage, and
// the QEMU/VSOCK runtime into the session actor's resource registry.
type ExporterRuntimeCoordinator interface {
	Preflight(context.Context, session.Snapshot) error
	VerifyImage(context.Context, session.Snapshot) error
	StorageAllocation(session.Snapshot) session.AllocateFunc
	RuntimeAllocation(session.Snapshot, Claim, Enrollment) session.AllocateFunc
	Runtime(string) (ExporterRuntime, error)
}

// HostWorkflow is the production daemon USB-002/USB-003 semantic owner.
// Plans and runtime references exist only in daemon memory; durable state is
// limited to the non-secret enrollment record owned elsewhere.
type HostWorkflow struct {
	Sessions *session.Manager
	Claims   *ClaimManager
	Runtime  ExporterRuntimeCoordinator
	Sources  ApprovedSourceProvider
	Now      func() time.Time

	mu    sync.Mutex
	plans map[string]PreparePlan
}

// VerifiedExport is internal destination evidence. Its digest cannot be
// serialized or rendered and is returned only to the daemon transaction that
// performs the final workstation verification.
type VerifiedExport struct {
	Receipt      ExportReceipt
	RereadDigest Digest
}

func NewHostWorkflow(sessions *session.Manager, claims *ClaimManager, runtime ExporterRuntimeCoordinator, sources ApprovedSourceProvider) (*HostWorkflow, error) {
	if sessions == nil || claims == nil || runtime == nil || sources == nil {
		return nil, errors.New("USB host workflow composition is incomplete")
	}
	return &HostWorkflow{Sessions: sessions, Claims: claims, Runtime: runtime, Sources: sources, plans: make(map[string]PreparePlan)}, nil
}

func (workflow *HostWorkflow) PlanPreparation(ctx context.Context, snapshot session.Snapshot, claimID string, enrollment Enrollment) (PreparePlan, error) {
	if workflow == nil || snapshot.Role != session.RoleExporter || snapshot.Phase != session.PhaseCreated || snapshot.WorkflowState != "USB_CLAIMED" {
		return PreparePlan{}, newError(CodeIdentityMismatch, "The exporter is not ready for USB preparation.", "Create one fresh exporter session and claim the exact enrollment.", nil)
	}
	claim, err := workflow.Claims.Revalidate(ctx, claimID, snapshot.ID, snapshot.OwnerUID, enrollment)
	if err != nil {
		return PreparePlan{}, err
	}
	now := time.Now
	if workflow.Now != nil {
		now = workflow.Now
	}
	plan, err := NewPreparePlan(enrollment, claim.Device, now())
	if err != nil {
		return PreparePlan{}, err
	}
	workflow.mu.Lock()
	workflow.plans[snapshot.ID] = plan
	workflow.mu.Unlock()
	return plan, nil
}

func (workflow *HostWorkflow) Prepare(ctx context.Context, snapshot session.Snapshot, claimID string, enrollment Enrollment, challenge string, confirmation Confirmation, passphrase *secret.Bytes, authorizer PrepareAuthorizer) (PrepareReceipt, error) {
	if workflow == nil || passphrase == nil || authorizer == nil {
		return PrepareReceipt{}, errors.New("USB preparation composition is incomplete")
	}
	workflow.mu.Lock()
	plan, present := workflow.plans[snapshot.ID]
	workflow.mu.Unlock()
	if !present || plan.Challenge != challenge {
		return PrepareReceipt{}, newError(CodeConfirmation, "The USB preparation plan is missing or changed.", "Request a fresh plan and repeat both exact confirmations.", nil)
	}
	now := time.Now
	if workflow.Now != nil {
		now = workflow.Now
	}
	// Validate all user-controlled confirmation material before allocating or
	// attaching the exporter. PrepareCoordinator repeats this check immediately
	// before authorization and the destructive guest call.
	if err := plan.Validate(enrollment, confirmation, now()); err != nil {
		return PrepareReceipt{}, err
	}
	runtime, current, err := workflow.ensureRuntime(ctx, snapshot, claimID, enrollment)
	if err != nil {
		if cleanupErr := workflow.cleanupFailed(snapshot); cleanupErr != nil {
			return PrepareReceipt{}, cleanupErr
		}
		return PrepareReceipt{}, err
	}
	coordinator := PrepareCoordinator{Claims: workflow.Claims, Backend: runtime, Authorizer: authorizer, Now: now}
	receipt, err := coordinator.Prepare(ctx, claimID, current.ID, current.OwnerUID, enrollment, plan, confirmation, passphrase, func(PrepareEvent) error { return nil })
	if err != nil {
		if cleanupErr := workflow.cleanupFailed(current); cleanupErr != nil {
			return PrepareReceipt{}, cleanupErr
		}
		return PrepareReceipt{}, err
	}
	workflow.mu.Lock()
	delete(workflow.plans, snapshot.ID)
	workflow.mu.Unlock()
	return receipt, nil
}

func (workflow *HostWorkflow) Export(ctx context.Context, snapshot session.Snapshot, claimID string, selection SourceSelection, enrollment Enrollment) (ExportReceipt, error) {
	if workflow == nil || snapshot.Role != session.RoleExporter || snapshot.Phase != session.PhaseActive || selection.validate() != nil {
		return ExportReceipt{}, newError(CodeWriteFailed, "The approved USB export selection is invalid.", "Select one authenticated approved output and retry.", nil)
	}
	source, err := workflow.Sources.OpenApproved(ctx, selection)
	if err != nil || source == nil {
		return ExportReceipt{}, newError(CodeWriteFailed, "The approved output stream is unavailable.", "Keep the exporter session intact and reselect the approved output.", err)
	}
	output := source.Output()
	if output.SourceRole != selection.Role || output.OutputID != selection.OutputID {
		_ = source.Close()
		return ExportReceipt{}, newError(CodeWriteFailed, "The approved output identity changed before export.", "Destroy the exporter and reselect the authenticated output.", nil)
	}
	verified, err := workflow.exportSource(ctx, snapshot, claimID, pinnedApprovedSource{ApprovedSource: source, output: output}, enrollment)
	return verified.Receipt, err
}

// ExportWorkspaceDestination consumes the daemon's one-shot authenticated
// workstation source directly. It neither registers a second source nor
// stages bytes or a pathname on the host.
func (workflow *HostWorkflow) ExportWorkspaceDestination(ctx context.Context, snapshot session.Snapshot, claimID string, source ApprovedSource, enrollment Enrollment) (VerifiedExport, error) {
	if source == nil {
		return VerifiedExport{}, newError(CodeWriteFailed, "The workstation destination stream is unavailable.", "Keep the workstation dirty and clean the exporter before retrying.", nil)
	}
	output := source.Output()
	if output.SourceRole != SourceWorkstation || !output.ExportStateAuthenticated || !output.WorkspaceDestinationAuthorized || output.ExportStateReady {
		_ = source.Close()
		return VerifiedExport{}, newError(CodeWriteFailed, "The workstation destination source authorization is invalid.", "Keep the workstation dirty and retry through the declared destination command.", nil)
	}
	return workflow.exportSource(ctx, snapshot, claimID, pinnedApprovedSource{ApprovedSource: source, output: output}, enrollment)
}

func (workflow *HostWorkflow) exportSource(ctx context.Context, snapshot session.Snapshot, claimID string, source ApprovedSource, enrollment Enrollment) (VerifiedExport, error) {
	if workflow == nil || snapshot.Role != session.RoleExporter || snapshot.Phase != session.PhaseActive || snapshot.WorkflowState != "DESTINATION_PREPARED" || source == nil {
		if source != nil {
			_ = source.Close()
		}
		return VerifiedExport{}, newError(CodeWriteFailed, "The prepared USB destination is unavailable.", "Prepare exactly one exporter and retry without discarding the source.", nil)
	}
	runtime, err := workflow.Runtime.Runtime(snapshot.ID)
	if err != nil {
		_ = source.Close()
		return VerifiedExport{}, err
	}
	operation, err := NewExportOperation(workflow.Claims, runtime, runtime, ExportOptions{}, claimID, snapshot.ID, snapshot.OwnerUID, enrollment, func(ExportEvent) error { return nil })
	if err != nil {
		_ = source.Close()
		return VerifiedExport{}, err
	}
	receipt, err := operation.Run(ctx, source)
	if err != nil {
		return VerifiedExport{}, err
	}
	digest, ok := operation.VerifiedRereadDigest()
	if !ok || digest.IsZero() || receipt.Validate() != nil {
		return VerifiedExport{}, newError(CodeHashMismatch, "The exporter reread evidence is unavailable.", "Do not trust the destination; clean the exporter and retry.", nil)
	}
	return VerifiedExport{Receipt: receipt, RereadDigest: digest}, nil
}

// pinnedApprovedSource makes the authenticated metadata immutable for the
// complete relay even if an adapter has a stateful Output implementation.
type pinnedApprovedSource struct {
	ApprovedSource
	output ApprovedOutput
}

func (source pinnedApprovedSource) Output() ApprovedOutput { return source.output }

func (workflow *HostWorkflow) ensureRuntime(ctx context.Context, snapshot session.Snapshot, claimID string, enrollment Enrollment) (ExporterRuntime, session.Snapshot, error) {
	if snapshot.Phase == session.PhaseActive {
		runtime, err := workflow.Runtime.Runtime(snapshot.ID)
		return runtime, snapshot, err
	}
	if snapshot.Phase != session.PhaseCreated {
		return nil, snapshot, errors.New("exporter session phase is invalid")
	}
	if err := workflow.Runtime.Preflight(ctx, snapshot); err != nil {
		return nil, snapshot, err
	}
	current, err := workflow.Sessions.Transition(ctx, snapshot.ID, snapshot.OwnerUID, session.PhasePreflighted)
	if err != nil {
		return nil, snapshot, err
	}
	if err := workflow.Runtime.VerifyImage(ctx, current); err != nil {
		return nil, current, err
	}
	current, err = workflow.Sessions.Transition(ctx, snapshot.ID, snapshot.OwnerUID, session.PhaseImagesVerified)
	if err != nil {
		return nil, current, err
	}
	storage := workflow.Runtime.StorageAllocation(current)
	if storage == nil {
		return nil, current, errors.New("exporter storage allocation is unavailable")
	}
	if err := workflow.Sessions.AcquireResource(ctx, current.ID, current.OwnerUID, "exporter-storage", storage); err != nil {
		return nil, current, err
	}
	current, err = workflow.Sessions.Transition(ctx, current.ID, current.OwnerUID, session.PhaseStorageReady)
	if err != nil {
		return nil, current, err
	}
	claim, err := workflow.Claims.Revalidate(ctx, claimID, current.ID, current.OwnerUID, enrollment)
	if err != nil {
		return nil, current, err
	}
	allocation := workflow.Runtime.RuntimeAllocation(current, claim, enrollment)
	if allocation == nil {
		return nil, current, errors.New("exporter runtime allocation is unavailable")
	}
	if err := workflow.Sessions.AcquireResource(ctx, current.ID, current.OwnerUID, "exporter-runtime", allocation); err != nil {
		return nil, current, err
	}
	current, err = workflow.Sessions.Transition(ctx, current.ID, current.OwnerUID, session.PhaseActive)
	if err != nil {
		return nil, current, err
	}
	runtime, err := workflow.Runtime.Runtime(current.ID)
	return runtime, current, err
}

func (workflow *HostWorkflow) cleanupFailed(snapshot session.Snapshot) error {
	cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	destroyed, err := workflow.Sessions.Cleanup(cleanup, snapshot.ID, snapshot.OwnerUID)
	cancel()
	workflow.mu.Lock()
	delete(workflow.plans, snapshot.ID)
	workflow.mu.Unlock()
	if err != nil || destroyed.Phase != session.PhaseDestroyed {
		return errors.Join(session.ErrCleanupIncomplete, err)
	}
	return nil
}
