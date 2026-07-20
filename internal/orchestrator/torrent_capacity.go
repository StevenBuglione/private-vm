package orchestrator

import (
	"context"

	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/torrent"
)

// TorrentCapacitySource creates path-free downstream evidence from immutable,
// daemon-owned role plans. It is called for every selection attempt so changed
// evidence cannot be silently reused.
type TorrentCapacitySource interface {
	Evidence(context.Context, session.Snapshot, session.LaunchPlan, torrent.Destination) (torrent.CapacityEvidence, error)
}

// PlannedTorrentCapacitySource binds the exact scanner-image and destination
// plans selected by the production composition root. The quarantine filesystem
// is deliberately absent: its free bytes are measured in the downloader guest.
type PlannedTorrentCapacitySource struct {
	ScannerScratchBytes         uint64
	WorkstationDestinationBytes uint64
	USBDestinationBytes         uint64
	ArchiveExpansionBytes       uint64
	ReconstructionBytes         uint64
	MaximumSelectedBytes        uint64
}

func (source PlannedTorrentCapacitySource) Evidence(ctx context.Context, snapshot session.Snapshot, plan session.LaunchPlan, destination torrent.Destination) (torrent.CapacityEvidence, error) {
	if ctx == nil {
		return torrent.CapacityEvidence{}, torrent.ErrCapacityEvidence
	}
	if err := ctx.Err(); err != nil {
		return torrent.CapacityEvidence{}, err
	}
	if session.ValidateID(snapshot.ID) != nil || snapshot.Role != session.RoleDownloader || plan.Role != snapshot.Role ||
		plan.RootBytes == 0 || plan.ScratchBytes == 0 || source.ScannerScratchBytes == 0 ||
		source.ReconstructionBytes == 0 || source.MaximumSelectedBytes == 0 {
		return torrent.CapacityEvidence{}, torrent.ErrCapacityEvidence
	}
	destinationBytes := uint64(0)
	switch destination {
	case torrent.DestinationWorkstation:
		destinationBytes = source.WorkstationDestinationBytes
	case torrent.DestinationUSB:
		destinationBytes = source.USBDestinationBytes
	default:
		return torrent.CapacityEvidence{}, torrent.ErrCapacityEvidence
	}
	if destinationBytes == 0 {
		return torrent.CapacityEvidence{}, torrent.ErrCapacityEvidence
	}
	maximumSelected := minCapacity(source.MaximumSelectedBytes, plan.ScratchBytes)
	return torrent.CapacityEvidence{
		Destination:             destination,
		ScanAvailableBytes:      plan.ScratchBytes,
		ReconstructionAvailable: source.ScannerScratchBytes,
		DestinationAvailable:    destinationBytes,
		RootOverlayBudgetBytes:  plan.RootBytes,
		ArchiveExpansionBytes:   source.ArchiveExpansionBytes,
		ReconstructionBytes:     source.ReconstructionBytes,
		MaximumSelectedBytes:    maximumSelected,
	}, nil
}

func minCapacity(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}

var _ TorrentCapacitySource = PlannedTorrentCapacitySource{}
