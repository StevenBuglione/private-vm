package torrent

const (
	minimumSafetyMargin         = 4 << 30
	minimumQuarantineMargin     = 64 << 20
	minimumScanMargin           = 64 << 20
	minimumReconstructionMargin = 64 << 20
	minimumDestinationMargin    = 64 << 20
)

// PlanSelection evaluates one semantic selection against a fresh guest-side
// quarantine probe and daemon-attested downstream evidence.
func PlanSelection(metadata Metadata, indexes []uint32, evidence CapacityEvidence, quarantineAvailable uint64, safePolicy bool) (Metadata, CapacityPlan, error) {
	budget, err := evidence.budget(quarantineAvailable)
	if err != nil {
		return Metadata{}, CapacityPlan{}, err
	}
	return planSelection(metadata, indexes, budget, safePolicy)
}

func planSelection(metadata Metadata, indexes []uint32, budget CapacityBudget, safePolicy bool) (Metadata, CapacityPlan, error) {
	if !metadata.PayloadPaused || len(metadata.Files) == 0 || len(indexes) == 0 || len(indexes) > len(metadata.Files) ||
		budget.QuarantineAvailableBytes == 0 || budget.ScanAvailableBytes == 0 || budget.ReconstructionAvailable == 0 || budget.DestinationAvailable == 0 ||
		budget.RootOverlayBudgetBytes == 0 || budget.ReconstructionBytes == 0 || budget.MaximumOutputBytes == 0 || budget.MaximumSelectedBytes == 0 {
		return Metadata{}, CapacityPlan{}, invalidSelection()
	}
	selected := make(map[uint32]struct{}, len(indexes))
	copyMetadata := metadata
	copyMetadata.Files = make([]File, len(metadata.Files))
	copy(copyMetadata.Files, metadata.Files)
	copyMetadata.SelectedSizeBytes = 0
	archiveSelected := false
	for _, index := range indexes {
		if int(index) >= len(copyMetadata.Files) {
			return Metadata{}, CapacityPlan{}, invalidSelection()
		}
		if _, exists := selected[index]; exists {
			return Metadata{}, CapacityPlan{}, invalidSelection()
		}
		selected[index] = struct{}{}
		file := &copyMetadata.Files[index]
		if safePolicy && hasBlockedType(*file) {
			return Metadata{}, CapacityPlan{}, blockedType()
		}
		archiveSelected = archiveSelected || hasArchive(*file)
		var overflow bool
		copyMetadata.SelectedSizeBytes, overflow = checkedAdd(copyMetadata.SelectedSizeBytes, file.SizeBytes)
		if overflow {
			return Metadata{}, CapacityPlan{}, insufficientCapacity()
		}
		file.Selected = true
	}
	if copyMetadata.SelectedSizeBytes == 0 || copyMetadata.SelectedSizeBytes > budget.MaximumSelectedBytes {
		return Metadata{}, CapacityPlan{}, insufficientCapacity()
	}

	filesystemOverhead := copyMetadata.SelectedSizeBytes / 20
	if filesystemOverhead < 64<<20 {
		filesystemOverhead = 64 << 20
	}
	quarantineMargin := stageMargin(copyMetadata.SelectedSizeBytes, minimumQuarantineMargin)
	quarantineRequired, overflow := sum(copyMetadata.SelectedSizeBytes, filesystemOverhead, quarantineMargin)
	if overflow {
		return Metadata{}, CapacityPlan{}, insufficientCapacity()
	}
	expansion := uint64(0)
	if archiveSelected {
		expansion = budget.ArchiveExpansionBytes
		if expansion == 0 {
			return Metadata{}, CapacityPlan{}, insufficientCapacity()
		}
	}
	scanMargin := stageMargin(copyMetadata.SelectedSizeBytes, minimumScanMargin)
	scanRequired, overflow := sum(copyMetadata.SelectedSizeBytes, scanMargin)
	if overflow {
		return Metadata{}, CapacityPlan{}, insufficientCapacity()
	}
	reconstructionMargin := stageMargin(budget.ReconstructionBytes, minimumReconstructionMargin)
	reconstructionRequired, overflow := sum(expansion, budget.ReconstructionBytes, reconstructionMargin)
	if overflow {
		return Metadata{}, CapacityPlan{}, insufficientCapacity()
	}
	outputOverhead := budget.MaximumOutputBytes / 20
	if outputOverhead < 64<<20 {
		outputOverhead = 64 << 20
	}
	destinationMargin := stageMargin(budget.MaximumOutputBytes, minimumDestinationMargin)
	destinationRequired, overflow := sum(budget.MaximumOutputBytes, outputOverhead, destinationMargin)
	if overflow {
		return Metadata{}, CapacityPlan{}, insufficientCapacity()
	}
	safetyMargin := stageMargin(copyMetadata.SelectedSizeBytes, minimumSafetyMargin)
	sessionRequired, overflow := sum(budget.RootOverlayBudgetBytes, quarantineRequired, reconstructionRequired, safetyMargin)
	if overflow || quarantineRequired > budget.QuarantineAvailableBytes || scanRequired > budget.ScanAvailableBytes ||
		reconstructionRequired > budget.ReconstructionAvailable || destinationRequired > budget.DestinationAvailable {
		return Metadata{}, CapacityPlan{}, insufficientCapacity()
	}
	return copyMetadata, CapacityPlan{
		SelectedBytes: copyMetadata.SelectedSizeBytes, QuarantineRequired: quarantineRequired,
		ScanRequired: scanRequired, ReconstructionNeed: reconstructionRequired,
		DestinationRequired: destinationRequired, SessionRequired: sessionRequired, SafetyMargin: safetyMargin,
		QuarantineMargin: quarantineMargin, ScanMargin: scanMargin,
		ReconstructionMargin: reconstructionMargin, DestinationMargin: destinationMargin,
	}, nil
}

func stageMargin(value, minimum uint64) uint64 {
	margin := value / 10
	if margin < minimum {
		return minimum
	}
	return margin
}

func sum(values ...uint64) (uint64, bool) {
	var result uint64
	for _, value := range values {
		var overflow bool
		result, overflow = checkedAdd(result, value)
		if overflow {
			return 0, true
		}
	}
	return result, false
}
