package usb

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	ExportReceiptSchemaVersion = 1
	MaximumRelayChunk          = 1 << 20
	maximumExportBytes         = 16 << 40
	maximumExportDuration      = 24 * time.Hour
	maximumIdleDuration        = 5 * time.Minute
)

type ApprovedOutput struct {
	SourceRole               SourceRole
	OutputID                 string
	LogicalName              string
	MediaType                string
	Size                     uint64
	SourceDigest             Digest
	ReportAuthenticated      bool
	ReportComplete           bool
	PolicyApproved           bool
	Reconstructed            bool
	ExportStateAuthenticated bool
	ExportStateReady         bool
}

func (o ApprovedOutput) Validate(maxBytes uint64) error {
	if len(o.OutputID) < 8 || len(o.OutputID) > 128 || strings.ContainsAny(o.OutputID, "\x00\r\n/\\") {
		return errors.New("approved output identifier is invalid")
	}
	if o.LogicalName == "" || len(o.LogicalName) > 255 || !utf8.ValidString(o.LogicalName) ||
		strings.ContainsAny(o.LogicalName, "\x00\r\n/\\") || o.LogicalName == "." || o.LogicalName == ".." {
		return errors.New("approved output logical name is invalid")
	}
	if o.MediaType == "" || len(o.MediaType) > 255 || strings.ContainsAny(o.MediaType, "\x00\r\n") {
		return errors.New("approved output media type is invalid")
	}
	if o.Size == 0 || o.Size > maxBytes || o.SourceDigest.IsZero() {
		return errors.New("approved output size or digest is invalid")
	}
	switch o.SourceRole {
	case SourceScanner:
		if !o.ReportAuthenticated || !o.ReportComplete || !o.PolicyApproved || !o.Reconstructed {
			return errors.New("approved scanner output lacks complete safe-policy evidence")
		}
	case SourceWorkstation:
		if !o.ExportStateAuthenticated || !o.ExportStateReady {
			return errors.New("workstation output lacks authenticated ready-state evidence")
		}
	default:
		return errors.New("approved output source role is invalid")
	}
	return nil
}

type RelayChunk struct {
	Sequence uint64
	Data     []byte
}

type ApprovedSource interface {
	Output() ApprovedOutput
	Next(context.Context) (RelayChunk, error)
	Close() error
}

type DestinationWriter interface {
	WriteChunk(context.Context, uint64, []byte) error
	Commit(context.Context, uint64, Digest) (DestinationEvidence, error)
	Abort(context.Context) error
}

type Destination interface {
	Begin(context.Context, ApprovedOutput) (DestinationWriter, error)
	Finalize(context.Context) (FinalizeEvidence, error)
}

type DestinationEvidence struct {
	BytesWritten     uint64
	ReceivedDigest   Digest
	RereadDigest     Digest
	FileSynced       bool
	FilesystemSynced bool
	AtomicRename     bool
}

type FinalizeEvidence struct {
	Unmounted  bool
	LUKSClosed bool
}

type ExportLifecycle interface {
	VerifyHostAndSourceIsolation(context.Context, Claim) error
	BootNetworkless(context.Context) error
	VerifyNoNetwork(context.Context) error
	AttachExactUSB(context.Context, Claim) error
	InspectAttachedUSB(context.Context, Claim) error
	DetachUSB(context.Context) error
	StopExporter(context.Context) error
	AuditAbsent(context.Context) error
}

type ExportOptions struct {
	MaxBytes    uint64
	Timeout     time.Duration
	IdleTimeout time.Duration
}

func (o ExportOptions) normalized() (ExportOptions, error) {
	if o.MaxBytes == 0 {
		o.MaxBytes = 4 << 30
	}
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Hour
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = 30 * time.Second
	}
	if o.MaxBytes > maximumExportBytes || o.Timeout <= 0 || o.Timeout > maximumExportDuration ||
		o.IdleTimeout <= 0 || o.IdleTimeout > maximumIdleDuration || o.IdleTimeout > o.Timeout {
		return ExportOptions{}, errors.New("USB export bounds are invalid")
	}
	return o, nil
}

type ExportState string

const (
	ExportPlanned           ExportState = "PLANNED"
	ExportClaimVerified     ExportState = "USB_CLAIMED"
	ExportBooting           ExportState = "EXPORTER_BOOTING"
	ExportNoNetworkVerified ExportState = "NO_NETWORK_VERIFIED"
	ExportUSBAttached       ExportState = "USB_ATTACHED"
	ExportStreaming         ExportState = "STREAMING"
	ExportStreamComplete    ExportState = "STREAM_COMPLETE"
	ExportFlushed           ExportState = "FLUSHED"
	ExportPostWriteVerified ExportState = "POST_WRITE_VERIFIED"
	ExportUSBUnmounted      ExportState = "USB_UNMOUNTED"
	ExportUSBDetached       ExportState = "USB_DETACHED"
	ExportExporterStopped   ExportState = "EXPORTER_STOPPED"
	ExportIncomplete        ExportState = "INCOMPLETE"
)

type ExportEvent struct {
	Sequence uint64
	State    ExportState
	Code     string
	Message  string
	Current  uint64
	Total    uint64
}

type ExportReceipt struct {
	SchemaVersion           int    `json:"schema_version"`
	EnrollmentID            string `json:"enrollment_id"`
	BytesWritten            uint64 `json:"bytes_written"`
	ScannerRelayHashEqual   bool   `json:"scanner_relay_hash_equal"`
	RelayExporterHashEqual  bool   `json:"relay_exporter_hash_equal"`
	ExporterRereadHashEqual bool   `json:"exporter_reread_hash_equal"`
	FileSynced              bool   `json:"file_synced"`
	FilesystemSynced        bool   `json:"filesystem_synced"`
	AtomicRename            bool   `json:"atomic_rename"`
	USBUnmounted            bool   `json:"usb_unmounted"`
	USBDetached             bool   `json:"usb_detached"`
	ExporterStopped         bool   `json:"exporter_stopped"`
	CleanupComplete         bool   `json:"cleanup_complete"`
}

type ExportOperation struct {
	mu sync.Mutex

	claims      *ClaimManager
	lifecycle   ExportLifecycle
	destination Destination
	options     ExportOptions
	claimID     string
	sessionID   string
	ownerUID    uint32
	enrollment  Enrollment
	events      func(ExportEvent) error
	sequence    uint64

	writer            DestinationWriter
	booted            bool
	attached          bool
	destinationOpened bool
	committed         bool
	finalized         bool
	detached          bool
	stopped           bool
	released          bool
	audited           bool
	running           bool
	finished          bool
}

func NewExportOperation(
	claims *ClaimManager,
	lifecycle ExportLifecycle,
	destination Destination,
	options ExportOptions,
	claimID string,
	sessionID string,
	ownerUID uint32,
	enrollment Enrollment,
	events func(ExportEvent) error,
) (*ExportOperation, error) {
	if claims == nil || lifecycle == nil || destination == nil || events == nil {
		return nil, errors.New("USB export operation is incomplete")
	}
	normalized, err := options.normalized()
	if err != nil {
		return nil, err
	}
	if err := enrollment.Validate(); err != nil {
		return nil, err
	}
	if claimID == "" || sessionID == "" {
		return nil, errors.New("USB export requires a claim and session")
	}
	return &ExportOperation{
		claims: claims, lifecycle: lifecycle, destination: destination,
		options: normalized, claimID: claimID, sessionID: sessionID,
		ownerUID: ownerUID, enrollment: enrollment, events: events,
	}, nil
}

func (o *ExportOperation) Run(ctx context.Context, source ApprovedSource) (receipt ExportReceipt, resultErr error) {
	o.mu.Lock()
	if o.running || o.finished {
		o.mu.Unlock()
		return ExportReceipt{}, errors.New("USB export operation cannot run twice")
	}
	o.running = true
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		o.running = false
		o.finished = true
		o.mu.Unlock()
	}()
	if source == nil {
		return o.fail(ctx, "An approved source is required.", nil)
	}
	sourceClosed := false
	defer func() {
		if !sourceClosed {
			_ = source.Close()
		}
	}()
	output := source.Output()
	if err := output.Validate(o.options.MaxBytes); err != nil {
		return o.fail(ctx, "The selected output is not eligible for safe USB export.", err)
	}
	if output.Size > o.enrollment.Identity.Capacity {
		return o.failAs(ctx, CodeTooSmall, "The enrolled USB is too small for the approved output.", "Use a larger enrolled device and repeat preparation before exporting.", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, o.options.Timeout)
	defer cancel()

	claim, err := o.claims.Revalidate(ctx, o.claimID, o.sessionID, o.ownerUID, o.enrollment)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if cleanupErr := o.cleanup(cleanupCtx, true); cleanupErr != nil {
			return ExportReceipt{}, cleanupErr
		}
		return ExportReceipt{}, err
	}
	if err := o.emit(ExportClaimVerified, "USB_CLAIM_VERIFIED", "The exact enrolled USB claim was revalidated.", 0, output.Size); err != nil {
		return o.fail(ctx, "Exporter event recording failed.", err)
	}
	if err := o.lifecycle.VerifyHostAndSourceIsolation(ctx, claim); err != nil {
		return o.fail(ctx, "USB role-boundary isolation verification failed.", err)
	}
	o.booted = true
	if err := o.lifecycle.BootNetworkless(ctx); err != nil {
		return o.fail(ctx, "The networkless exporter could not start.", err)
	}
	if err := o.emit(ExportBooting, "USB_EXPORTER_BOOTED", "The headless exporter started.", 0, output.Size); err != nil {
		return o.fail(ctx, "Exporter event recording failed.", err)
	}
	if err := o.lifecycle.VerifyNoNetwork(ctx); err != nil {
		return o.fail(ctx, "Exporter network isolation verification failed.", err)
	}
	if err := o.emit(ExportNoNetworkVerified, "USB_EXPORTER_OFFLINE", "The exporter has no network interface.", 0, output.Size); err != nil {
		return o.fail(ctx, "Exporter event recording failed.", err)
	}
	o.attached = true
	if err := o.lifecycle.AttachExactUSB(ctx, claim); err != nil {
		return o.fail(ctx, "The exact enrolled USB could not be attached.", err)
	}
	if err := o.lifecycle.InspectAttachedUSB(ctx, claim); err != nil {
		return o.fail(ctx, "Exporter USB identity verification failed.", err)
	}
	if err := o.emit(ExportUSBAttached, "USB_ATTACHED_EXACT", "The exporter verified the exact enrolled USB identity.", 0, output.Size); err != nil {
		return o.fail(ctx, "Exporter event recording failed.", err)
	}

	writer, err := o.destination.Begin(ctx, output)
	if writer != nil {
		o.writer = writer
		o.destinationOpened = true
	}
	if err != nil || writer == nil {
		return o.fail(ctx, "The exporter destination could not begin a bounded write.", err)
	}
	if err := o.emit(ExportStreaming, "USB_STREAMING", "The approved output stream is being relayed.", 0, output.Size); err != nil {
		return o.fail(ctx, "Exporter event recording failed.", err)
	}

	hasher := sha256.New()
	var written uint64
	var expectedSequence uint64
	for {
		chunkCtx, chunkCancel := context.WithTimeout(ctx, o.options.IdleTimeout)
		chunk, nextErr := source.Next(chunkCtx)
		chunkCancel()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return o.fail(ctx, "The approved source stream failed.", nextErr)
		}
		if chunk.Sequence != expectedSequence || len(chunk.Data) == 0 || len(chunk.Data) > MaximumRelayChunk ||
			written > output.Size || uint64(len(chunk.Data)) > output.Size-written {
			clear(chunk.Data)
			return o.fail(ctx, "The approved source stream violated its bounds.", nil)
		}
		writeCtx, writeCancel := context.WithTimeout(ctx, o.options.IdleTimeout)
		writeErr := writer.WriteChunk(writeCtx, chunk.Sequence, chunk.Data)
		writeCancel()
		if writeErr != nil {
			clear(chunk.Data)
			return o.fail(ctx, "The exporter rejected a bounded stream chunk.", writeErr)
		}
		_, _ = hasher.Write(chunk.Data)
		written += uint64(len(chunk.Data))
		expectedSequence++
		clear(chunk.Data)
		if err := o.emit(ExportStreaming, "USB_STREAM_PROGRESS", "The approved output stream is being relayed.", written, output.Size); err != nil {
			return o.fail(ctx, "Exporter event recording failed.", err)
		}
	}
	if written != output.Size {
		return o.fail(ctx, "The approved source stream ended before its declared size.", nil)
	}
	closeErr := source.Close()
	sourceClosed = true
	if closeErr != nil {
		return o.fail(ctx, "The approved source stream did not close cleanly.", closeErr)
	}
	var relayArray [32]byte
	copy(relayArray[:], hasher.Sum(nil))
	relayDigest := NewDigest(relayArray)
	clear(relayArray[:])
	if !output.SourceDigest.Equal(relayDigest) {
		return o.hashFailure(ctx, "The source and relay hashes do not agree.")
	}
	if err := o.emit(ExportStreamComplete, "USB_STREAM_COMPLETE", "The complete approved stream reached the exporter.", written, output.Size); err != nil {
		return o.fail(ctx, "Exporter event recording failed.", err)
	}
	commitCtx, commitCancel := context.WithTimeout(ctx, o.options.IdleTimeout)
	evidence, err := writer.Commit(commitCtx, written, relayDigest)
	commitCancel()
	if err != nil {
		return o.fail(ctx, "The exporter could not commit and reread the destination file.", err)
	}
	o.committed = true
	o.writer = nil
	if evidence.BytesWritten != written || !evidence.FileSynced || !evidence.FilesystemSynced || !evidence.AtomicRename {
		return o.fail(ctx, "The exporter did not return complete flush evidence.", nil)
	}
	if !relayDigest.Equal(evidence.ReceivedDigest) || !relayDigest.Equal(evidence.RereadDigest) {
		return o.hashFailure(ctx, "The relay and exporter reread hashes do not agree.")
	}
	if err := o.emit(ExportFlushed, "USB_FLUSHED", "The exporter fsynced the file and destination filesystem.", written, output.Size); err != nil {
		return o.fail(ctx, "Exporter event recording failed.", err)
	}
	if err := o.emit(ExportPostWriteVerified, "USB_POST_WRITE_VERIFIED", "Scanner, relay and exporter reread hashes agree.", written, output.Size); err != nil {
		return o.fail(ctx, "Exporter event recording failed.", err)
	}

	finalEvidence, err := o.destination.Finalize(ctx)
	if err != nil || !finalEvidence.Unmounted || !finalEvidence.LUKSClosed {
		return o.fail(ctx, "The exporter destination did not unmount and close cleanly.", err)
	}
	o.finalized = true
	o.destinationOpened = false
	if err := o.emit(ExportUSBUnmounted, "USB_UNMOUNTED", "The exporter unmounted and closed the encrypted destination.", written, output.Size); err != nil {
		return o.fail(ctx, "Exporter event recording failed.", err)
	}
	if err := o.lifecycle.DetachUSB(ctx); err != nil {
		return o.fail(ctx, "The USB could not be detached from the exporter.", err)
	}
	o.detached = true
	o.attached = false
	if err := o.emit(ExportUSBDetached, "USB_DETACHED", "The USB was detached from the exporter.", written, output.Size); err != nil {
		return o.fail(ctx, "Exporter event recording failed.", err)
	}
	if err := o.lifecycle.StopExporter(ctx); err != nil {
		return o.fail(ctx, "The exporter could not stop cleanly.", err)
	}
	o.stopped = true
	o.booted = false
	if err := o.emit(ExportExporterStopped, "USB_EXPORTER_STOPPED", "The exporter stopped after verification.", written, output.Size); err != nil {
		return o.fail(ctx, "Exporter event recording failed.", err)
	}
	if err := o.claims.Release(ctx, o.claimID, o.sessionID, o.ownerUID); err != nil {
		return o.fail(ctx, "The USB claim could not be released.", err)
	}
	o.released = true
	if err := o.lifecycle.AuditAbsent(ctx); err != nil {
		return o.fail(ctx, "USB exporter cleanup audit failed.", err)
	}
	o.audited = true
	return ExportReceipt{
		SchemaVersion: ExportReceiptSchemaVersion, EnrollmentID: o.enrollment.EnrollmentID,
		BytesWritten: written, ScannerRelayHashEqual: true,
		RelayExporterHashEqual: true, ExporterRereadHashEqual: true,
		FileSynced: true, FilesystemSynced: true, AtomicRename: true,
		USBUnmounted: true, USBDetached: true, ExporterStopped: true, CleanupComplete: true,
	}, nil
}

func (o *ExportOperation) Cleanup(ctx context.Context) error {
	return o.cleanup(ctx, false)
}

func (o *ExportOperation) cleanup(ctx context.Context, allowRunning bool) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.running && !allowRunning {
		return errors.New("USB export cleanup is owned by the active operation")
	}
	if o.writer != nil && !o.committed {
		if err := o.writer.Abort(ctx); err != nil {
			return newError(CodeCleanupIncomplete, "The exporter partial file could not be removed.", "Retry session cleanup before trusting or disconnecting the USB.", err)
		}
		o.writer = nil
	}
	if o.destinationOpened && !o.finalized {
		evidence, err := o.destination.Finalize(ctx)
		if err != nil || !evidence.Unmounted || !evidence.LUKSClosed {
			return newError(CodeCleanupIncomplete, "The exporter destination could not be unmounted and closed.", "Retry session cleanup before trusting or disconnecting the USB.", err)
		}
		o.destinationOpened = false
		o.finalized = true
	}
	if o.attached && !o.detached {
		if err := o.lifecycle.DetachUSB(ctx); err != nil {
			return newError(CodeCleanupIncomplete, "The USB could not be detached during cleanup.", "Retry session cleanup before disconnecting the USB.", err)
		}
		o.attached = false
		o.detached = true
	}
	if o.booted && !o.stopped {
		if err := o.lifecycle.StopExporter(ctx); err != nil {
			return newError(CodeCleanupIncomplete, "The exporter could not be stopped during cleanup.", "Retry session cleanup before disconnecting the USB.", err)
		}
		o.booted = false
		o.stopped = true
	}
	if !o.released {
		if err := o.claims.Release(ctx, o.claimID, o.sessionID, o.ownerUID); err != nil {
			return err
		}
		o.released = true
	}
	if !o.audited {
		if err := o.lifecycle.AuditAbsent(ctx); err != nil {
			return newError(CodeCleanupIncomplete, "USB exporter resources remain after cleanup.", "Retry session cleanup and keep the USB connected.", err)
		}
		o.audited = true
	}
	return nil
}

func (o *ExportOperation) fail(ctx context.Context, message string, cause error) (ExportReceipt, error) {
	return o.failAs(ctx, CodeWriteFailed, message, "Keep the USB connected, inspect it again, and retry only after cleanup succeeds.", cause)
}

func (o *ExportOperation) failAs(ctx context.Context, code ErrorCode, message, remediation string, cause error) (ExportReceipt, error) {
	_ = o.emit(ExportIncomplete, "USB_EXPORT_INCOMPLETE", "USB export is incomplete; do not trust the destination until a new verified export succeeds.", 0, 0)
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if cleanupErr := o.cleanup(cleanupCtx, true); cleanupErr != nil {
		return ExportReceipt{}, cleanupErr
	}
	return ExportReceipt{}, newError(code, message, remediation, cause)
}

func (o *ExportOperation) hashFailure(ctx context.Context, message string) (ExportReceipt, error) {
	_ = o.emit(ExportIncomplete, "USB_HASH_MISMATCH", "USB export hash verification failed; do not trust the destination.", 0, 0)
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if cleanupErr := o.cleanup(cleanupCtx, true); cleanupErr != nil {
		return ExportReceipt{}, cleanupErr
	}
	return ExportReceipt{}, newError(CodeHashMismatch, message, "Do not trust the destination; inspect it again and perform a new export.", nil)
}

func (o *ExportOperation) emit(state ExportState, code, message string, current, total uint64) error {
	if state == "" || strings.TrimSpace(code) == "" || strings.TrimSpace(message) == "" || current > total {
		return errors.New("invalid USB export event")
	}
	o.sequence++
	return o.events(ExportEvent{Sequence: o.sequence, State: state, Code: code, Message: message, Current: current, Total: total})
}

func (r ExportReceipt) Validate() error {
	if r.SchemaVersion != ExportReceiptSchemaVersion || !enrollmentIDPattern.MatchString(r.EnrollmentID) || r.BytesWritten == 0 ||
		!r.ScannerRelayHashEqual || !r.RelayExporterHashEqual || !r.ExporterRereadHashEqual ||
		!r.FileSynced || !r.FilesystemSynced || !r.AtomicRename || !r.USBUnmounted || !r.USBDetached ||
		!r.ExporterStopped || !r.CleanupComplete {
		return fmt.Errorf("USB export receipt is incomplete")
	}
	return nil
}
