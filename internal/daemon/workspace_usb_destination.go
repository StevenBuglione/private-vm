package daemon

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"sync"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/usb"
)

const (
	maximumWorkspaceUSBDestinationBytes  = uint64(8 << 30)
	maximumWorkspaceUSBDestinationFrames = maximumWorkspaceUSBDestinationBytes/usb.MaximumRelayChunk + 2
	workspaceUSBSourceCloseTimeout       = 30 * time.Second
)

type workspaceUSBClaimResolver interface {
	RevalidateOnlySessionClaim(context.Context, string, uint32, usb.Enrollment) (usb.Claim, error)
}

type workspaceUSBEnrollmentLoader interface {
	Load(uint32) (usb.Enrollment, error)
}

type workspaceUSBExporter interface {
	ExportWorkspaceDestination(context.Context, session.Snapshot, string, usb.ApprovedSource, usb.Enrollment) (usb.VerifiedExport, error)
}

// ConfigureWorkspaceUSBDestination binds the semantic workstation export RPC
// to the same exact claim, enrollment and prepared exporter owners used by the
// production USB workflow. It is called once before the daemon starts serving.
func (s *Service) ConfigureWorkspaceUSBDestination() error {
	if s == nil || s.Sessions == nil || s.USBRegistry == nil || s.USBClaims == nil || s.USBWorkflows == nil {
		return errors.New("workspace USB destination composition is incomplete")
	}
	claims, claimsOK := s.USBClaims.(workspaceUSBClaimResolver)
	exporter, exporterOK := s.USBWorkflows.(workspaceUSBExporter)
	if !claimsOK || !exporterOK {
		return errors.New("workspace USB destination contracts are unavailable")
	}
	s.WorkspaceDestinations = &workspaceUSBProvider{service: s, enrollments: s.USBRegistry, claims: claims, exporter: exporter}
	return nil
}

type workspaceUSBProvider struct {
	service     *Service
	enrollments workspaceUSBEnrollmentLoader
	claims      workspaceUSBClaimResolver
	exporter    workspaceUSBExporter
}

func (provider *workspaceUSBProvider) Prepare(ctx context.Context, plan WorkspaceDestinationPlan) (WorkspaceDestinationTransaction, error) {
	if provider == nil || provider.service == nil || provider.service.Sessions == nil || provider.enrollments == nil || provider.claims == nil || provider.exporter == nil ||
		ctx == nil || plan.Destination != privatevmv1.WorkspaceExportDestination_WORKSPACE_EXPORT_DESTINATION_USB ||
		session.ValidateID(plan.SourceSession) != nil || !workspaceOutputIDPattern.MatchString(plan.OutputID) {
		return nil, errors.New("workspace USB destination plan is invalid")
	}
	candidates := make([]session.Snapshot, 0, 1)
	for _, candidate := range provider.service.Sessions.List(plan.OwnerUID) {
		if candidate.OwnerUID == plan.OwnerUID && candidate.Role == session.RoleExporter && candidate.Phase == session.PhaseActive && candidate.WorkflowState == "DESTINATION_PREPARED" {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) != 1 {
		return nil, errors.New("exactly one prepared exporter destination is required")
	}

	exporter := candidates[0]
	lock := provider.service.roleOperation(exporter.ID)
	lock.Lock()
	release := true
	defer func() {
		if release {
			lock.Unlock()
		}
	}()
	current, err := provider.service.Sessions.Get(exporter.ID, plan.OwnerUID)
	if err != nil || current.Role != session.RoleExporter || current.Phase != session.PhaseActive || current.WorkflowState != "DESTINATION_PREPARED" {
		return nil, errors.Join(errors.New("prepared exporter destination changed"), err)
	}
	enrollment, err := provider.enrollments.Load(plan.OwnerUID)
	if err != nil || enrollment.Validate() != nil {
		return nil, errors.Join(errors.New("prepared exporter enrollment is unavailable"), err)
	}
	claim, err := provider.claims.RevalidateOnlySessionClaim(ctx, current.ID, plan.OwnerUID, enrollment)
	if err != nil || claim.ID == "" || claim.SessionID != current.ID || claim.OwnerUID != plan.OwnerUID || claim.EnrollmentID != enrollment.EnrollmentID {
		return nil, errors.Join(errors.New("prepared exporter claim is unavailable"), err)
	}
	release = false
	return &workspaceUSBTransaction{
		service: provider.service, enrollments: provider.enrollments, claims: provider.claims, exporter: provider.exporter,
		snapshot: current, claim: claim, enrollment: enrollment, unlock: lock.Unlock,
		outputID: plan.OutputID,
	}, nil
}

type workspaceUSBTransaction struct {
	service     *Service
	enrollments workspaceUSBEnrollmentLoader
	claims      workspaceUSBClaimResolver
	exporter    workspaceUSBExporter
	snapshot    session.Snapshot
	claim       usb.Claim
	enrollment  usb.Enrollment
	outputID    string
	unlock      func()

	mu         sync.Mutex
	receiving  bool
	finished   bool
	cleaned    bool
	unlockOnce sync.Once
}

func (transaction *workspaceUSBTransaction) Receive(ctx context.Context, source WorkspaceDestinationSource) (WorkspaceDestinationReceipt, error) {
	if transaction == nil || ctx == nil || source == nil {
		return WorkspaceDestinationReceipt{}, errors.New("workspace USB transaction is incomplete")
	}
	transaction.mu.Lock()
	if transaction.receiving || transaction.finished {
		transaction.mu.Unlock()
		return WorkspaceDestinationReceipt{}, errors.New("workspace USB transaction is one-shot")
	}
	transaction.receiving = true
	transaction.mu.Unlock()

	currentEnrollment, err := transaction.enrollments.Load(transaction.snapshot.OwnerUID)
	if err != nil || !sameWorkspaceUSBEnrollment(transaction.enrollment, currentEnrollment) {
		return transaction.finishReceive(errors.Join(errors.New("workspace USB enrollment changed"), err), usb.VerifiedExport{})
	}
	currentClaim, err := transaction.claims.RevalidateOnlySessionClaim(ctx, transaction.snapshot.ID, transaction.snapshot.OwnerUID, currentEnrollment)
	if err != nil || currentClaim.ID != transaction.claim.ID || currentClaim.EnrollmentID != transaction.claim.EnrollmentID {
		return transaction.finishReceive(errors.Join(errors.New("workspace USB claim changed"), err), usb.VerifiedExport{})
	}
	approved, err := newWorkspaceUSBApprovedSource(ctx, transaction.outputID, source)
	if err != nil {
		return transaction.finishReceive(err, usb.VerifiedExport{})
	}
	verified, exportErr := transaction.exporter.ExportWorkspaceDestination(ctx, transaction.snapshot, transaction.claim.ID, approved, transaction.enrollment)
	if exportErr == nil {
		exportErr = transaction.recordSuccess(context.WithoutCancel(ctx), verified)
	}
	return transaction.finishReceive(exportErr, verified)
}

func (transaction *workspaceUSBTransaction) recordSuccess(ctx context.Context, verified usb.VerifiedExport) error {
	if verified.Receipt.Validate() != nil || verified.RereadDigest.IsZero() || !verified.Receipt.CleanupComplete {
		return errors.New("workspace USB exporter evidence is incomplete")
	}
	transitionCtx, cancel := context.WithTimeout(ctx, workspaceDestinationAbortTimeout)
	defer cancel()
	for _, state := range []string{"STREAMING", "STREAM_COMPLETE", "FLUSHED", "POST_WRITE_VERIFIED", "USB_UNMOUNTED", "USB_DETACHED", "EXPORTER_STOPPED"} {
		if _, err := transaction.service.Sessions.TransitionWorkflow(transitionCtx, transaction.snapshot.ID, transaction.snapshot.OwnerUID, state); err != nil {
			return err
		}
	}
	return nil
}

func (transaction *workspaceUSBTransaction) finishReceive(operationErr error, verified usb.VerifiedExport) (WorkspaceDestinationReceipt, error) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), workspaceDestinationAbortTimeout)
	cleanupErr := transaction.cleanup(cleanupCtx)
	cancel()
	transaction.releaseLock()
	transaction.mu.Lock()
	transaction.receiving = false
	transaction.finished = true
	transaction.mu.Unlock()
	if cleanupErr != nil {
		return WorkspaceDestinationReceipt{}, errors.Join(errors.New("workspace USB exporter cleanup incomplete"), cleanupErr)
	}
	if operationErr != nil {
		return WorkspaceDestinationReceipt{}, operationErr
	}
	digest, err := workspaceUSBProtoDigest(verified.RereadDigest)
	if err != nil {
		return WorkspaceDestinationReceipt{}, err
	}
	return WorkspaceDestinationReceipt{ReceiverDigest: digest, Persisted: true, Reread: true, CleanupComplete: true}, nil
}

func (transaction *workspaceUSBTransaction) Abort(ctx context.Context) error {
	if transaction == nil || ctx == nil {
		return errors.New("workspace USB abort is invalid")
	}
	err := transaction.cleanup(ctx)
	transaction.releaseLock()
	return err
}

func (transaction *workspaceUSBTransaction) cleanup(ctx context.Context) error {
	transaction.mu.Lock()
	if transaction.cleaned {
		transaction.mu.Unlock()
		return nil
	}
	transaction.mu.Unlock()
	destroyed, err := transaction.service.Sessions.Cleanup(ctx, transaction.snapshot.ID, transaction.snapshot.OwnerUID)
	if err != nil || destroyed.Phase != session.PhaseDestroyed {
		return errors.Join(session.ErrCleanupIncomplete, err)
	}
	transaction.mu.Lock()
	transaction.cleaned = true
	transaction.mu.Unlock()
	return nil
}

func (transaction *workspaceUSBTransaction) releaseLock() {
	transaction.unlockOnce.Do(func() {
		if transaction.unlock != nil {
			transaction.unlock()
		}
	})
}

func sameWorkspaceUSBEnrollment(left, right usb.Enrollment) bool {
	return left.Validate() == nil && right.Validate() == nil && left.SchemaVersion == right.SchemaVersion && left.EnrollmentID == right.EnrollmentID &&
		left.Label == right.Label && left.Filesystem == right.Filesystem && left.Identity.Matches(right.Identity)
}

type workspaceUSBFrameDelivery struct {
	frame    *privatevmv1.TransferFrame
	consumed chan struct{}
}

type workspaceUSBSourceCompletion struct {
	receipt *privatevmv1.TransferReceipt
	err     error
}

type workspaceUSBApprovedSource struct {
	mu sync.Mutex

	output     usb.ApprovedOutput
	frames     <-chan workspaceUSBFrameDelivery
	completion <-chan workspaceUSBSourceCompletion
	cancel     context.CancelFunc
	pending    chan struct{}
	sequence   uint64
	written    uint64
	framesSeen uint64
	ended      bool
	closed     bool
	closeErr   error
}

func newWorkspaceUSBApprovedSource(ctx context.Context, expectedOutputID string, source WorkspaceDestinationSource) (*workspaceUSBApprovedSource, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	frames := make(chan workspaceUSBFrameDelivery)
	completion := make(chan workspaceUSBSourceCompletion, 1)
	go func() {
		defer close(frames)
		receipt, err := source(streamCtx, func(frame *privatevmv1.TransferFrame) error {
			if frame == nil {
				return errors.New("workspace USB source emitted a nil frame")
			}
			delivery := workspaceUSBFrameDelivery{frame: frame, consumed: make(chan struct{})}
			select {
			case frames <- delivery:
			case <-streamCtx.Done():
				return streamCtx.Err()
			}
			// Once delivered, retain frame ownership until the exporter has
			// synchronously consumed it. This avoids a plaintext staging copy.
			<-delivery.consumed
			return nil
		})
		completion <- workspaceUSBSourceCompletion{receipt: receipt, err: err}
	}()

	first, ok, err := receiveWorkspaceUSBFrame(ctx, frames)
	if err != nil || !ok || first.frame == nil || first.frame.GetBegin() == nil {
		cancel()
		ackWorkspaceUSBFrame(first)
		return nil, errors.Join(errors.New("workspace USB source begin is unavailable"), err)
	}
	begin := first.frame.GetBegin()
	descriptor := begin.GetDescriptor_()
	digest, digestOK := workspaceUSBDigest(descriptor.GetDigest())
	output := usb.ApprovedOutput{
		SourceRole: usb.SourceWorkstation, OutputID: begin.GetTransferId(), LogicalName: descriptor.GetLogicalName(), MediaType: descriptor.GetDetectedMime(),
		Size: descriptor.GetSizeBytes(), SourceDigest: digest, ExportStateAuthenticated: true, WorkspaceDestinationAuthorized: true,
	}
	valid := begin.GetContext() == nil && begin.GetTransferId() == expectedOutputID && workspaceOutputIDPattern.MatchString(begin.GetTransferId()) && digestOK && output.Validate(maximumWorkspaceUSBDestinationBytes) == nil
	ackWorkspaceUSBFrame(first)
	if !valid {
		cancel()
		return nil, errors.New("workspace USB source descriptor is invalid")
	}
	return &workspaceUSBApprovedSource{output: output, frames: frames, completion: completion, cancel: cancel, framesSeen: 1}, nil
}

func (source *workspaceUSBApprovedSource) Output() usb.ApprovedOutput {
	if source == nil {
		return usb.ApprovedOutput{}
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.output
}

func (source *workspaceUSBApprovedSource) Next(ctx context.Context) (usb.RelayChunk, error) {
	if source == nil || ctx == nil {
		return usb.RelayChunk{}, errors.New("workspace USB source is unavailable")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed {
		return usb.RelayChunk{}, errors.New("workspace USB source is closed")
	}
	source.ackPending()
	if source.ended {
		return usb.RelayChunk{}, io.EOF
	}
	delivery, ok, err := receiveWorkspaceUSBFrame(ctx, source.frames)
	if err != nil || !ok || delivery.frame == nil {
		return usb.RelayChunk{}, errors.Join(errors.New("workspace USB source ended without complete evidence"), err)
	}
	source.framesSeen++
	if source.framesSeen > maximumWorkspaceUSBDestinationFrames {
		ackWorkspaceUSBFrame(delivery)
		source.cancel()
		return usb.RelayChunk{}, errors.New("workspace USB source frame bound exceeded")
	}
	if chunk := delivery.frame.GetChunk(); chunk != nil {
		if chunk.GetSequence() != source.sequence || len(chunk.GetData()) == 0 || len(chunk.GetData()) > usb.MaximumRelayChunk ||
			source.written > source.output.Size || uint64(len(chunk.GetData())) > source.output.Size-source.written {
			ackWorkspaceUSBFrame(delivery)
			source.cancel()
			return usb.RelayChunk{}, errors.New("workspace USB source chunk is invalid")
		}
		source.sequence++
		source.written += uint64(len(chunk.GetData()))
		source.pending = delivery.consumed
		return usb.RelayChunk{Sequence: chunk.GetSequence(), Data: chunk.Data}, nil
	}
	end := delivery.frame.GetEnd()
	validEnd := end != nil && end.GetTotalSize() == source.output.Size && source.written == source.output.Size && workspaceUSBDigestEqual(source.output.SourceDigest, end.GetDigest())
	ackWorkspaceUSBFrame(delivery)
	if !validEnd {
		source.cancel()
		return usb.RelayChunk{}, errors.New("workspace USB source end is invalid")
	}
	source.ended = true
	return usb.RelayChunk{}, io.EOF
}

func (source *workspaceUSBApprovedSource) Close() error {
	if source == nil {
		return nil
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed {
		return source.closeErr
	}
	source.closed = true
	source.ackPending()
	if !source.ended {
		source.cancel()
		source.closeErr = errors.New("workspace USB source closed before complete consumption")
		return source.closeErr
	}
	wait, cancel := context.WithTimeout(context.Background(), workspaceUSBSourceCloseTimeout)
	defer cancel()
	select {
	case <-wait.Done():
		source.closeErr = wait.Err()
	case completion := <-source.completion:
		if completion.err != nil || !validWorkspaceTransferReceipt(completion.receipt, source.output.OutputID) ||
			completion.receipt.GetDescriptor_().GetSizeBytes() != source.output.Size ||
			completion.receipt.GetDescriptor_().GetLogicalName() != source.output.LogicalName ||
			completion.receipt.GetDescriptor_().GetDetectedMime() != source.output.MediaType ||
			!workspaceUSBDigestEqual(source.output.SourceDigest, completion.receipt.GetReceiverDigest()) {
			source.closeErr = errors.Join(errors.New("workspace USB source receipt is invalid"), completion.err)
		}
	}
	source.cancel()
	return source.closeErr
}

func (source *workspaceUSBApprovedSource) ackPending() {
	if source.pending != nil {
		close(source.pending)
		source.pending = nil
	}
}

func receiveWorkspaceUSBFrame(ctx context.Context, frames <-chan workspaceUSBFrameDelivery) (workspaceUSBFrameDelivery, bool, error) {
	select {
	case <-ctx.Done():
		return workspaceUSBFrameDelivery{}, false, ctx.Err()
	case delivery, ok := <-frames:
		return delivery, ok, nil
	}
}

func ackWorkspaceUSBFrame(delivery workspaceUSBFrameDelivery) {
	if delivery.consumed != nil {
		close(delivery.consumed)
	}
}

func workspaceUSBDigest(value *privatevmv1.Hash) (usb.Digest, bool) {
	if value == nil || value.GetAlgorithm() != "sha256" || len(value.GetValue()) != sha256.Size {
		return usb.Digest{}, false
	}
	var fixed [sha256.Size]byte
	copy(fixed[:], value.GetValue())
	digest := usb.NewDigest(fixed)
	clear(fixed[:])
	return digest, true
}

func workspaceUSBDigestEqual(expected usb.Digest, value *privatevmv1.Hash) bool {
	if value == nil || value.GetAlgorithm() != "sha256" || len(value.GetValue()) != sha256.Size {
		return false
	}
	matched := false
	_ = expected.WithBytes(func(bytes []byte) error {
		matched = subtle.ConstantTimeCompare(bytes, value.GetValue()) == 1
		return nil
	})
	return matched
}

func workspaceUSBProtoDigest(value usb.Digest) (*privatevmv1.Hash, error) {
	var digest []byte
	err := value.WithBytes(func(bytes []byte) error {
		digest = append([]byte(nil), bytes...)
		return nil
	})
	if err != nil || len(digest) != sha256.Size {
		clear(digest)
		return nil, errors.New("workspace USB reread digest is invalid")
	}
	return &privatevmv1.Hash{Algorithm: "sha256", Value: digest}, nil
}

var _ WorkspaceDestinationProvider = (*workspaceUSBProvider)(nil)
var _ WorkspaceDestinationTransaction = (*workspaceUSBTransaction)(nil)
var _ usb.ApprovedSource = (*workspaceUSBApprovedSource)(nil)
