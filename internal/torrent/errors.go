package torrent

import (
	"context"
	"errors"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

var (
	ErrInvalidRequest      = errors.New("invalid torrent request")
	ErrInvalidInput        = errors.New("invalid torrent input")
	ErrInputTooLarge       = errors.New("torrent input too large")
	ErrMetadataUnavailable = errors.New("torrent metadata unavailable")
	ErrUnsafeMetadata      = errors.New("unsafe torrent metadata")
	ErrInvalidSelection    = errors.New("invalid torrent selection")
	ErrCapacityEvidence    = errors.New("torrent capacity evidence unavailable")
	ErrCapacity            = errors.New("insufficient torrent capacity")
	ErrNotApproved         = errors.New("torrent payload not approved")
	ErrDownloadStalled     = errors.New("torrent download stalled")
	ErrDownloadFailed      = errors.New("torrent download failed")
	ErrVPNLost             = errors.New("torrent VPN lost")
	ErrSealFailed          = errors.New("quarantine seal failed")
	ErrCleanupIncomplete   = errors.New("downloader cleanup incomplete")
)

func invalidRequest() error {
	return apperror.Wrap("TORRENT_REQUEST_INVALID", exitcode.Torrent, "The torrent workflow request is invalid.", "Inspect the volatile downloader state and retry the permitted next transition.", ErrInvalidRequest)
}

func invalidInput() error {
	return apperror.Wrap("TORRENT_INPUT_INVALID", exitcode.Torrent, "The bounded torrent input is malformed.", "Supply one valid magnet URI through hidden terminal input or standard input, or one regular .torrent file.", ErrInvalidInput)
}

func inputTooLarge() error {
	return apperror.Wrap("TORRENT_INPUT_TOO_LARGE", exitcode.Torrent, "The torrent input exceeds its fixed size limit.", "Use a magnet no larger than 8 KiB or a .torrent file no larger than 16 MiB.", ErrInputTooLarge)
}

func metadataUnavailable(cause error) error {
	if errors.Is(cause, context.Canceled) {
		return cause
	}
	return apperror.Wrap("TORRENT_METADATA_TIMEOUT", exitcode.Torrent, "Torrent metadata was not obtained within the bounded planning window.", "Keep payload paused, verify VPN health, and retry with a valid source.", ErrMetadataUnavailable)
}

func unsafeMetadata() error {
	return apperror.Wrap("TORRENT_METADATA_UNSAFE", exitcode.Torrent, "Torrent metadata violates the path or file-count policy.", "Reject this torrent; do not download payload bytes from unsafe metadata.", ErrUnsafeMetadata)
}

func invalidSelection() error {
	return apperror.Wrap("TORRENT_SELECTION_INVALID", exitcode.Torrent, "The requested torrent file selection is invalid.", "Select each displayed file index at most once and exclude every blocked file.", ErrInvalidSelection)
}

func blockedType() error {
	return apperror.Wrap("TORRENT_EXECUTABLE_BLOCKED", exitcode.Torrent, "The safe policy blocks an executable, script, package, or disk image selection.", "Deselect blocked content; safe mode never promotes these file types.", ErrInvalidSelection)
}

func insufficientCapacity() error {
	return apperror.Wrap("TORRENT_CAPACITY_INSUFFICIENT", exitcode.Storage, "The selected torrent cannot fit every required encrypted workflow stage.", "Reduce the selection or provide more encrypted quarantine, scan, reconstruction, and destination capacity.", ErrCapacity)
}

func capacityEvidenceUnavailable() error {
	return apperror.Wrap("TORRENT_CAPACITY_EVIDENCE_UNAVAILABLE", exitcode.Storage, "Independent capacity evidence is unavailable for the complete torrent workflow.", "Select a supported downstream destination and retry after its scanner, reconstruction, and destination capacity can be verified.", ErrCapacityEvidence)
}

func notApproved() error {
	return apperror.Wrap("TORRENT_PAYLOAD_NOT_APPROVED", exitcode.Torrent, "Torrent payload transfer is not approved for the current state.", "Complete metadata review, explicit selection, and capacity verification before starting payload transfer.", ErrNotApproved)
}

func downloadStalled() error {
	return apperror.Wrap("TORRENT_DOWNLOAD_STALLED", exitcode.Torrent, "The torrent made no progress within the bounded stall window.", "Leave the payload paused, inspect VPN health, and explicitly retry or abort.", ErrDownloadStalled)
}

func downloadFailed() error {
	return apperror.Wrap("TORRENT_DOWNLOAD_FAILED", exitcode.Torrent, "The torrent client reported a bounded download failure.", "Keep quarantine sealed from later roles, destroy the downloader, and retry with a fresh session.", ErrDownloadFailed)
}

func vpnLost() error {
	return apperror.Wrap("TORRENT_VPN_LOST", exitcode.Network, "The verified VPN was lost and torrent transfer was paused.", "Keep the kill switch armed; re-verify the tunnel before an explicit resume.", ErrVPNLost)
}

func sealFailed() error {
	return apperror.Wrap("QUARANTINE_SEAL_FAILED", exitcode.Torrent, "The completed quarantine could not be verified and sealed.", "Do not attach quarantine to the scanner; retry bounded sealing or abort and clean the session.", ErrSealFailed)
}

func cleanupIncomplete() error {
	return apperror.Wrap("DOWNLOADER_CLEANUP_INCOMPLETE", exitcode.Cleanup, "The downloader was not proven destroyed after quarantine sealing.", "Keep scanner attachment blocked and retry the single cleanup owner until its absence audit passes.", ErrCleanupIncomplete)
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// NormalizeError converts package sentinels used at transport boundaries into
// the same stable, redacted application errors returned by the state machine.
func NormalizeError(err error) error {
	if err == nil || isContextError(err) {
		return err
	}
	var application *apperror.Error
	if errors.As(err, &application) {
		return application
	}
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return invalidRequest()
	case errors.Is(err, ErrInputTooLarge):
		return inputTooLarge()
	case errors.Is(err, ErrInvalidInput):
		return invalidInput()
	case errors.Is(err, ErrMetadataUnavailable):
		return metadataUnavailable(err)
	case errors.Is(err, ErrUnsafeMetadata):
		return unsafeMetadata()
	case errors.Is(err, ErrInvalidSelection):
		return invalidSelection()
	case errors.Is(err, ErrCapacity):
		return insufficientCapacity()
	case errors.Is(err, ErrCapacityEvidence):
		return capacityEvidenceUnavailable()
	case errors.Is(err, ErrNotApproved):
		return notApproved()
	case errors.Is(err, ErrDownloadStalled):
		return downloadStalled()
	case errors.Is(err, ErrDownloadFailed):
		return downloadFailed()
	case errors.Is(err, ErrVPNLost):
		return vpnLost()
	case errors.Is(err, ErrSealFailed):
		return sealFailed()
	case errors.Is(err, ErrCleanupIncomplete):
		return cleanupIncomplete()
	default:
		return apperror.From(err)
	}
}
