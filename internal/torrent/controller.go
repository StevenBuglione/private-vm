package torrent

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/StevenBuglione/private-vm/internal/guestvpn"
)

const (
	defaultMetadataTimeout = 2 * time.Minute
	defaultPollInterval    = time.Second
	defaultStallTimeout    = 5 * time.Minute
	maximumOperation       = 10 * time.Minute
	cleanupTimeout         = 30 * time.Second
)

type ClientState string

const (
	ClientMetadata ClientState = "metadata"
	ClientPaused   ClientState = "paused"
	ClientRunning  ClientState = "running"
	ClientComplete ClientState = "complete"
	ClientError    ClientState = "error"
)

type ClientStatus struct {
	State          ClientState
	CompletedBytes uint64
	TotalBytes     uint64
}

// Backend is the complete semantic qBittorrent boundary. It has no arbitrary
// URL, save-path, preference, command, or hook operation.
type Backend interface {
	AddPaused(context.Context, *Input) (Handle, error)
	Metadata(context.Context, Handle) (RawMetadata, error)
	SetSelection(context.Context, Handle, []uint32, uint32) error
	Start(context.Context, Handle) error
	Pause(context.Context, Handle) error
	Status(context.Context, Handle) (ClientStatus, error)
	VerifyCompleted(context.Context, Handle, Metadata) ([]FileDigest, error)
	Shutdown(context.Context) error
}

// Quarantine owns only guest-side sync and unmount. The host never mounts or
// parses this filesystem.
type Quarantine interface {
	SyncAndUnmount(context.Context) error
}

type Waiter interface {
	Wait(context.Context, time.Duration) error
}

type timerWaiter struct{}

func (timerWaiter) Wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type Config struct {
	SafePolicy      bool
	Budget          CapacityBudget
	MetadataTimeout time.Duration
	PollInterval    time.Duration
	StallTimeout    time.Duration
}

type Controller struct {
	mu         sync.Mutex
	backend    Backend
	quarantine Quarantine
	waiter     Waiter
	config     Config
	state      State
	handle     Handle
	metadata   Metadata
	plan       CapacityPlan
	progress   Progress
	manifest   Manifest
	clientDown bool
	closed     bool
}

func NewController(backend Backend, quarantine Quarantine, config Config) (*Controller, error) {
	return newController(backend, quarantine, timerWaiter{}, config)
}

func newController(backend Backend, quarantine Quarantine, waiter Waiter, config Config) (*Controller, error) {
	if nilLike(backend) || nilLike(quarantine) || nilLike(waiter) {
		return nil, invalidRequest()
	}
	if config.MetadataTimeout == 0 {
		config.MetadataTimeout = defaultMetadataTimeout
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.StallTimeout == 0 {
		config.StallTimeout = defaultStallTimeout
	}
	if config.MetadataTimeout < time.Second || config.MetadataTimeout > maximumOperation || config.PollInterval <= 0 ||
		config.PollInterval > time.Minute || config.StallTimeout < time.Second || config.StallTimeout > maximumOperation {
		return nil, invalidRequest()
	}
	return &Controller{backend: backend, quarantine: quarantine, waiter: waiter, config: config, state: StateEmpty}, nil
}

// Add transfers one protected input to qBittorrent paused, waits only for
// metadata, and rejects any evidence that payload bytes were read.
func (controller *Controller) Add(ctx context.Context, input *Input) (Metadata, error) {
	if controller == nil || ctx == nil || input == nil {
		return Metadata{}, invalidRequest()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.state != StateEmpty {
		return Metadata{}, invalidRequest()
	}
	operationCtx, cancel := boundedContext(ctx, controller.config.MetadataTimeout)
	defer cancel()
	handle, err := controller.backend.AddPaused(operationCtx, input)
	if err != nil || !handle.valid() {
		return Metadata{}, invalidInput()
	}
	controller.handle = handle
	controller.state = StateMetadataFetching
	for {
		if err := controller.backend.Pause(operationCtx, handle); err != nil {
			return Metadata{}, metadataUnavailable(err)
		}
		raw, err := controller.backend.Metadata(operationCtx, handle)
		if err != nil {
			return Metadata{}, metadataUnavailable(err)
		}
		if raw.PayloadRead != 0 {
			return Metadata{}, unsafeMetadata()
		}
		if raw.Available {
			metadata, err := validateMetadata(raw)
			if err != nil {
				return Metadata{}, err
			}
			if err := controller.backend.SetSelection(operationCtx, handle, nil, uint32(len(metadata.Files))); err != nil {
				return Metadata{}, metadataUnavailable(err)
			}
			controller.metadata = metadata
			controller.state = StateSelectionRequired
			return cloneMetadata(metadata), nil
		}
		if err := controller.waiter.Wait(operationCtx, controller.config.PollInterval); err != nil {
			return Metadata{}, metadataUnavailable(err)
		}
	}
}

func (controller *Controller) Metadata() (Metadata, error) {
	if controller == nil {
		return Metadata{}, invalidRequest()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.state == StateEmpty || controller.state == StateMetadataFetching {
		return Metadata{}, invalidRequest()
	}
	return cloneMetadata(controller.metadata), nil
}

func (controller *Controller) Select(ctx context.Context, indexes []uint32) (Metadata, CapacityPlan, error) {
	if controller == nil || ctx == nil {
		return Metadata{}, CapacityPlan{}, invalidRequest()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || (controller.state != StateSelectionRequired && controller.state != StateCapacityVerified) {
		return Metadata{}, CapacityPlan{}, invalidRequest()
	}
	metadata, plan, err := planSelection(controller.metadata, indexes, controller.config.Budget, controller.config.SafePolicy)
	if err != nil {
		return Metadata{}, CapacityPlan{}, err
	}
	operationCtx, cancel := boundedContext(ctx, 30*time.Second)
	defer cancel()
	if err := controller.backend.SetSelection(operationCtx, controller.handle, indexes, uint32(len(metadata.Files))); err != nil {
		return Metadata{}, CapacityPlan{}, invalidSelection()
	}
	controller.metadata = metadata
	controller.plan = plan
	controller.progress = Progress{TotalBytes: plan.SelectedBytes}
	controller.state = StateCapacityVerified
	return cloneMetadata(metadata), plan, nil
}

func (controller *Controller) Start(ctx context.Context) error {
	if controller == nil || ctx == nil {
		return invalidRequest()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || (controller.state != StateCapacityVerified && controller.state != StatePaused) || controller.plan.SelectedBytes == 0 {
		return notApproved()
	}
	operationCtx, cancel := boundedContext(ctx, 30*time.Second)
	defer cancel()
	if err := controller.backend.Start(operationCtx, controller.handle); err != nil {
		return downloadFailed()
	}
	controller.state = StateDownloading
	return nil
}

func (controller *Controller) Pause(ctx context.Context) error {
	if controller == nil || ctx == nil {
		return invalidRequest()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.pauseLocked(ctx)
}

func (controller *Controller) pauseLocked(ctx context.Context) error {
	if controller.closed || (controller.state != StateDownloading && controller.state != StatePaused) {
		return invalidRequest()
	}
	operationCtx, cancel := boundedContext(ctx, 30*time.Second)
	defer cancel()
	if err := controller.backend.Pause(operationCtx, controller.handle); err != nil {
		return downloadFailed()
	}
	controller.state = StatePaused
	return nil
}

// Monitor is a bounded synchronous progress stream. Cancellation, timeout,
// stalls and client errors all attempt an independent bounded pause before the
// method returns.
func (controller *Controller) Monitor(ctx context.Context, emit func(Status) error) error {
	if controller == nil || ctx == nil || emit == nil {
		return invalidRequest()
	}
	controller.mu.Lock()
	if controller.closed || controller.state != StateDownloading {
		controller.mu.Unlock()
		return notApproved()
	}
	controller.mu.Unlock()
	lastProgress := uint64(0)
	lastChange := time.Now()
	for {
		controller.mu.Lock()
		if controller.closed {
			controller.mu.Unlock()
			return invalidRequest()
		}
		if controller.state == StatePaused {
			controller.mu.Unlock()
			return vpnLost()
		}
		if controller.state != StateDownloading {
			controller.mu.Unlock()
			return notApproved()
		}
		handle := controller.handle
		status, err := controller.backend.Status(ctx, handle)
		if err != nil {
			controller.pauseAfterFailureLocked()
			controller.mu.Unlock()
			if isContextError(err) {
				return err
			}
			return downloadFailed()
		}
		if status.TotalBytes != controller.plan.SelectedBytes || status.CompletedBytes > status.TotalBytes {
			controller.pauseAfterFailureLocked()
			controller.mu.Unlock()
			return downloadFailed()
		}
		controller.progress = Progress{CompletedBytes: status.CompletedBytes, TotalBytes: status.TotalBytes}
		if status.CompletedBytes > lastProgress {
			lastProgress = status.CompletedBytes
			lastChange = time.Now()
		}
		if status.State == ClientError {
			controller.pauseAfterFailureLocked()
			controller.mu.Unlock()
			return downloadFailed()
		}
		safeStatus := controller.statusLocked(status.CompletedBytes, status.TotalBytes)
		if status.State == ClientComplete && status.CompletedBytes == status.TotalBytes {
			if err := controller.backend.Pause(ctx, handle); err != nil {
				controller.mu.Unlock()
				return downloadFailed()
			}
			controller.state = StateDownloadComplete
			safeStatus = controller.statusLocked(status.CompletedBytes, status.TotalBytes)
			controller.mu.Unlock()
			if err := emit(safeStatus); err != nil {
				return err
			}
			return nil
		}
		controller.mu.Unlock()
		if err := emit(safeStatus); err != nil {
			controller.mu.Lock()
			controller.pauseAfterFailureLocked()
			controller.mu.Unlock()
			return err
		}
		if time.Since(lastChange) >= controller.config.StallTimeout {
			controller.mu.Lock()
			controller.pauseAfterFailureLocked()
			controller.mu.Unlock()
			return downloadStalled()
		}
		if err := controller.waiter.Wait(ctx, controller.config.PollInterval); err != nil {
			controller.mu.Lock()
			controller.pauseAfterFailureLocked()
			controller.mu.Unlock()
			return err
		}
	}
}

func (controller *Controller) Status(ctx context.Context) (Status, error) {
	if controller == nil || ctx == nil {
		return Status{}, invalidRequest()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed {
		return Status{}, invalidRequest()
	}
	if controller.state != StateDownloading {
		return controller.statusLocked(controller.progress.CompletedBytes, controller.progress.TotalBytes), nil
	}
	status, err := controller.backend.Status(ctx, controller.handle)
	if err != nil {
		return Status{}, downloadFailed()
	}
	if status.TotalBytes != controller.plan.SelectedBytes || status.CompletedBytes > status.TotalBytes {
		return Status{}, downloadFailed()
	}
	controller.progress = Progress{CompletedBytes: status.CompletedBytes, TotalBytes: status.TotalBytes}
	return controller.statusLocked(status.CompletedBytes, status.TotalBytes), nil
}

// OnVPNLoss implements guestvpn.LossResponder. The kill switch remains owned
// by guestvpn; this method only forces qBittorrent to a paused state.
func (controller *Controller) OnVPNLoss(_ context.Context, _ guestvpn.Status) error {
	if controller == nil {
		return invalidRequest()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.state != StateDownloading {
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := controller.backend.Pause(cleanupCtx, controller.handle); err != nil {
		return downloadFailed()
	}
	controller.state = StatePaused
	return nil
}

func (controller *Controller) Seal(ctx context.Context) (Manifest, error) {
	if controller == nil || ctx == nil {
		return Manifest{}, invalidRequest()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || (controller.state != StateDownloadComplete && !(controller.state == StateSealing && controller.clientDown && len(controller.manifest.files) > 0)) {
		return Manifest{}, notApproved()
	}
	controller.state = StateSealing
	operationCtx, cancel := boundedContext(ctx, maximumOperation)
	defer cancel()
	if !controller.clientDown {
		files, err := controller.backend.VerifyCompleted(operationCtx, controller.handle, controller.metadata)
		if err != nil {
			controller.state = StateDownloadComplete
			return Manifest{}, sealFailed()
		}
		manifest, err := newManifest(files)
		clearManifest(files)
		if err != nil {
			controller.state = StateDownloadComplete
			return Manifest{}, err
		}
		if err := verifyManifestMatchesSelection(manifest, controller.metadata); err != nil {
			manifest.Destroy()
			controller.state = StateDownloadComplete
			return Manifest{}, err
		}
		if err := controller.backend.Shutdown(operationCtx); err != nil {
			manifest.Destroy()
			controller.state = StateDownloadComplete
			return Manifest{}, sealFailed()
		}
		controller.manifest.Destroy()
		controller.manifest = manifest
		controller.clientDown = true
	}
	if err := controller.quarantine.SyncAndUnmount(operationCtx); err != nil {
		return Manifest{}, sealFailed()
	}
	controller.state = StateSealed
	return cloneManifest(controller.manifest), nil
}

func (controller *Controller) Close(ctx context.Context) error {
	if controller == nil || ctx == nil {
		return invalidRequest()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed {
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	var cleanupErrors []error
	if controller.handle.valid() && controller.state != StateSealed {
		if err := controller.backend.Pause(cleanupCtx, controller.handle); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if !controller.clientDown {
		if err := controller.backend.Shutdown(cleanupCtx); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		} else {
			controller.clientDown = true
		}
	}
	if len(cleanupErrors) > 0 {
		return cleanupIncomplete()
	}
	controller.manifest.Destroy()
	controller.metadata = Metadata{}
	controller.plan = CapacityPlan{}
	controller.progress = Progress{}
	controller.handle = Handle{}
	controller.closed = true
	return nil
}

func (controller *Controller) pauseAfterFailureLocked() {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = controller.backend.Pause(cleanupCtx, controller.handle)
	controller.state = StatePaused
}

func (controller *Controller) statusLocked(completed, total uint64) Status {
	status := Status{SchemaVersion: 1, State: controller.state, Progress: Progress{CompletedBytes: completed, TotalBytes: total}}
	switch controller.state {
	case StateEmpty:
		status.Code, status.Remediation = "TORRENT_INPUT_REQUIRED", "Submit one bounded torrent source through the secure input path."
	case StateMetadataFetching:
		status.Code, status.Remediation = "TORRENT_METADATA_FETCHING", "Wait for bounded metadata retrieval while payload remains paused."
	case StateSelectionRequired:
		status.Code, status.Remediation = "TORRENT_SELECTION_REQUIRED", "Review hazards and explicitly select permitted files."
	case StateCapacityVerified:
		status.Code, status.Remediation = "TORRENT_CAPACITY_VERIFIED", "Start payload transfer only while the VPN remains verified."
	case StateDownloading:
		status.Code, status.Remediation = "TORRENT_DOWNLOADING", "Keep the VPN verified and continue bounded progress monitoring."
	case StatePaused:
		status.Code, status.Remediation = "TORRENT_DOWNLOAD_PAUSED", "Re-verify VPN health before an explicit resume."
	case StateDownloadComplete:
		status.Code, status.Remediation = "TORRENT_DOWNLOAD_COMPLETE", "Verify, sync, unmount, and seal quarantine before destroying the downloader."
	case StateSealing:
		status.Code, status.Remediation = "QUARANTINE_SEALING", "Keep scanner attachment blocked until sealing and downloader cleanup complete."
	case StateSealed:
		status.Code, status.Remediation = "QUARANTINE_SEALED", "Destroy and audit the downloader before scanner attachment."
	default:
		status.Code, status.Remediation = "TORRENT_STATE_INVALID", "Abort and clean the session."
	}
	return status
}

type DownloaderDestroyer interface {
	DestroyAndAudit(context.Context) error
}

type Coordinator struct {
	Controller *Controller
	Destroyer  DownloaderDestroyer
	mu         sync.Mutex
	receipt    *SealedReceipt
}

type SealedReceipt struct {
	manifest Manifest
	ready    bool
}

func (receipt *SealedReceipt) ScannerReady() bool { return receipt != nil && receipt.ready }

func (receipt *SealedReceipt) Destroy() {
	if receipt == nil {
		return
	}
	receipt.manifest.Destroy()
	receipt.ready = false
}

// SealAndDestroy is the host-orchestrator gate: it exposes a scanner-ready
// receipt only after guest sealing and an exact downloader absence audit.
func (coordinator *Coordinator) SealAndDestroy(ctx context.Context) (*SealedReceipt, error) {
	if coordinator == nil || coordinator.Controller == nil || nilLike(coordinator.Destroyer) || ctx == nil {
		return nil, invalidRequest()
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.receipt != nil && coordinator.receipt.ScannerReady() {
		return coordinator.receipt, nil
	}
	manifest, err := coordinator.Controller.sealedManifest()
	if err != nil {
		manifest, err = coordinator.Controller.Seal(ctx)
		if err != nil {
			return nil, err
		}
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := coordinator.Destroyer.DestroyAndAudit(cleanupCtx); err != nil {
		manifest.Destroy()
		return nil, cleanupIncomplete()
	}
	coordinator.receipt = &SealedReceipt{manifest: manifest, ready: true}
	return coordinator.receipt, nil
}

func (controller *Controller) sealedManifest() (Manifest, error) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.closed || controller.state != StateSealed || len(controller.manifest.files) == 0 {
		return Manifest{}, invalidRequest()
	}
	return cloneManifest(controller.manifest), nil
}

func verifyManifestMatchesSelection(manifest Manifest, metadata Metadata) error {
	selected := make(map[uint32]File)
	for _, file := range metadata.Files {
		if file.Selected {
			selected[file.Index] = file
		}
	}
	if len(selected) != len(manifest.files) {
		return sealFailed()
	}
	for _, file := range manifest.files {
		expected, ok := selected[file.SourceIndex]
		if !ok || expected.DisplayPath != file.Path || expected.SizeBytes != file.SizeBytes {
			return sealFailed()
		}
		delete(selected, file.SourceIndex)
	}
	if len(selected) != 0 {
		return sealFailed()
	}
	return nil
}

func cloneMetadata(metadata Metadata) Metadata {
	result := metadata
	result.Files = make([]File, len(metadata.Files))
	copy(result.Files, metadata.Files)
	for index := range result.Files {
		result.Files[index].HazardCodes = append([]string(nil), result.Files[index].HazardCodes...)
	}
	return result
}

func cloneManifest(manifest Manifest) Manifest {
	files := make([]FileDigest, len(manifest.files))
	copy(files, manifest.files)
	return Manifest{files: files}
}

func boundedContext(parent context.Context, maximum time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(maximum)
	if current, ok := parent.Deadline(); ok && current.Before(deadline) {
		return context.WithCancel(parent)
	}
	return context.WithDeadline(parent, deadline)
}

func nilLike(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ guestvpn.LossResponder = (*Controller)(nil)
