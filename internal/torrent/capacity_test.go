package torrent

import (
	"errors"
	"testing"
)

func TestCapacityPlanUsesTheMinimumIndependentStage(t *testing.T) {
	metadata := Metadata{PayloadPaused: true, Files: []File{{Index: 0, DisplayPath: "fixture.pdf", SizeBytes: 128 << 20}}}
	budget := CapacityBudget{
		QuarantineAvailableBytes: ^uint64(0), ScanAvailableBytes: ^uint64(0), ReconstructionAvailable: ^uint64(0),
		DestinationAvailable: ^uint64(0), RootOverlayBudgetBytes: 1 << 30, ArchiveExpansionBytes: 1 << 30,
		ReconstructionBytes: 128 << 20, MaximumOutputBytes: 64 << 20, MaximumSelectedBytes: 1 << 30,
	}
	_, plan, err := planSelection(metadata, []uint32{0}, budget, true)
	if err != nil {
		t.Fatal(err)
	}
	budget.QuarantineAvailableBytes = plan.QuarantineRequired
	budget.ScanAvailableBytes = plan.ScanRequired
	budget.ReconstructionAvailable = plan.ReconstructionNeed
	budget.DestinationAvailable = plan.DestinationRequired
	if _, _, err := planSelection(metadata, []uint32{0}, budget, true); err != nil {
		t.Fatalf("exact independent stage capacities failed: %v", err)
	}
	for name, reduce := range map[string]func(*CapacityBudget){
		"quarantine":     func(value *CapacityBudget) { value.QuarantineAvailableBytes-- },
		"scanner":        func(value *CapacityBudget) { value.ScanAvailableBytes-- },
		"reconstruction": func(value *CapacityBudget) { value.ReconstructionAvailable-- },
		"destination":    func(value *CapacityBudget) { value.DestinationAvailable-- },
	} {
		t.Run(name, func(t *testing.T) {
			insufficient := budget
			reduce(&insufficient)
			if _, _, err := planSelection(metadata, []uint32{0}, insufficient, true); !errors.Is(err, ErrCapacity) {
				t.Fatalf("stage error = %v", err)
			}
		})
	}
}

func TestCapacityPlanFailsClosedOnOverflow(t *testing.T) {
	metadata := Metadata{PayloadPaused: true, Files: []File{{Index: 0, DisplayPath: "fixture.pdf", SizeBytes: ^uint64(0)}}}
	budget := CapacityBudget{
		QuarantineAvailableBytes: ^uint64(0), ScanAvailableBytes: ^uint64(0), ReconstructionAvailable: ^uint64(0),
		DestinationAvailable: ^uint64(0), RootOverlayBudgetBytes: 1, ArchiveExpansionBytes: 1,
		ReconstructionBytes: 1, MaximumOutputBytes: 1, MaximumSelectedBytes: ^uint64(0),
	}
	if _, _, err := planSelection(metadata, []uint32{0}, budget, true); !errors.Is(err, ErrCapacity) {
		t.Fatalf("overflow error = %v", err)
	}
}
