package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/torrent"
)

func TestPlannedTorrentCapacitySourceUsesIndependentRoleEvidence(t *testing.T) {
	source := PlannedTorrentCapacitySource{
		ScannerReadOnlyBytes: 7 << 30, ScannerScratchBytes: 9 << 30, WorkstationDestinationBytes: 10 << 30,
		ArchiveExpansionBytes: 4 << 30, ReconstructionBytes: 1 << 30, MaximumOutputBytes: 512 << 20, MaximumSelectedBytes: 12 << 30,
	}
	snapshot := session.Snapshot{ID: hostRoleSessionID, Role: session.RoleDownloader}
	plan := session.LaunchPlan{Role: session.RoleDownloader, RootBytes: 7 << 30, ScratchBytes: 8 << 30}
	evidence, err := source.Evidence(t.Context(), snapshot, plan, torrent.DestinationWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.ScanAvailableBytes != 7<<30 || evidence.ReconstructionAvailable != 9<<30 ||
		evidence.DestinationAvailable != 10<<30 || evidence.RootOverlayBudgetBytes != 7<<30 ||
		evidence.MaximumSelectedBytes != 8<<30 {
		t.Fatalf("independent evidence = %+v", evidence)
	}

	changed := source
	changed.ScannerScratchBytes = 6 << 30
	changed.ScannerReadOnlyBytes = 3 << 30
	changed.WorkstationDestinationBytes = 5 << 30
	plan.ScratchBytes = 4 << 30
	updated, err := changed.Evidence(t.Context(), snapshot, plan, torrent.DestinationWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ScanAvailableBytes != 3<<30 || updated.ReconstructionAvailable != 6<<30 || updated.DestinationAvailable != 5<<30 || updated.MaximumSelectedBytes != 4<<30 {
		t.Fatalf("recalculated evidence = %+v", updated)
	}
}

func TestPlannedTorrentCapacitySourceFailsWithoutDeclaredAvailableDestination(t *testing.T) {
	source := PlannedTorrentCapacitySource{
		ScannerReadOnlyBytes: 7 << 30, ScannerScratchBytes: 9 << 30, WorkstationDestinationBytes: 10 << 30,
		ArchiveExpansionBytes: 4 << 30, ReconstructionBytes: 1 << 30, MaximumOutputBytes: 512 << 20, MaximumSelectedBytes: 12 << 30,
	}
	snapshot := session.Snapshot{ID: hostRoleSessionID, Role: session.RoleDownloader}
	plan := session.LaunchPlan{Role: session.RoleDownloader, RootBytes: 7 << 30, ScratchBytes: 8 << 30}
	for name, destination := range map[string]torrent.Destination{"missing": "", "unavailable usb": torrent.DestinationUSB} {
		t.Run(name, func(t *testing.T) {
			if _, err := source.Evidence(t.Context(), snapshot, plan, destination); !errors.Is(err, torrent.ErrCapacityEvidence) {
				t.Fatalf("destination error = %v", err)
			}
		})
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := source.Evidence(cancelled, snapshot, plan, torrent.DestinationWorkstation); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled evidence error = %v", err)
	}
}

func TestTorrentCapacityReceiptPreservesIndependentFields(t *testing.T) {
	evidence := torrent.CapacityEvidence{
		Destination:        torrent.DestinationWorkstation,
		ScanAvailableBytes: 7, ReconstructionAvailable: 11, DestinationAvailable: 13,
		RootOverlayBudgetBytes: 17, ArchiveExpansionBytes: 19, ReconstructionBytes: 23, MaximumSelectedBytes: 29,
		MaximumOutputBytes: 31,
	}
	receipt, err := torrentCapacityReceipt(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.GetSchemaVersion() != 1 || receipt.GetScanAvailableBytes() != 7 ||
		receipt.GetReconstructionAvailableBytes() != 11 || receipt.GetDestinationAvailableBytes() != 13 ||
		receipt.GetRootOverlayBudgetBytes() != 17 || receipt.GetArchiveExpansionBytes() != 19 ||
		receipt.GetReconstructionBytes() != 23 || receipt.GetMaximumSelectedBytes() != 29 || receipt.GetMaximumOutputBytes() != 31 {
		t.Fatalf("receipt = %+v", receipt)
	}
	evidence.DestinationAvailable = 0
	if _, err := torrentCapacityReceipt(evidence); !errors.Is(err, torrent.ErrCapacityEvidence) {
		t.Fatalf("zero destination evidence error = %v", err)
	}
}
