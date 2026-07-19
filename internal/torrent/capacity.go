package torrent

const minimumSafetyMargin = 4 << 30

func planSelection(metadata Metadata, indexes []uint32, budget CapacityBudget, safePolicy bool) (Metadata, CapacityPlan, error) {
	if !metadata.PayloadPaused || len(metadata.Files) == 0 || len(indexes) == 0 || len(indexes) > len(metadata.Files) ||
		budget.QuarantineAvailableBytes == 0 || budget.ScanAvailableBytes == 0 || budget.ReconstructionAvailable == 0 || budget.DestinationAvailable == 0 ||
		budget.RootOverlayBudgetBytes == 0 || budget.ReconstructionBytes == 0 || budget.MaximumSelectedBytes == 0 {
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
	safetyMargin := copyMetadata.SelectedSizeBytes / 10
	if safetyMargin < minimumSafetyMargin {
		safetyMargin = minimumSafetyMargin
	}
	quarantineRequired, overflow := sum(copyMetadata.SelectedSizeBytes, filesystemOverhead, safetyMargin)
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
	scanRequired, overflow := sum(copyMetadata.SelectedSizeBytes, expansion, safetyMargin)
	if overflow {
		return Metadata{}, CapacityPlan{}, insufficientCapacity()
	}
	reconstructionRequired, overflow := sum(budget.ReconstructionBytes, safetyMargin)
	if overflow {
		return Metadata{}, CapacityPlan{}, insufficientCapacity()
	}
	destinationRequired, overflow := sum(budget.ReconstructionBytes, filesystemOverhead)
	if overflow {
		return Metadata{}, CapacityPlan{}, insufficientCapacity()
	}
	sessionRequired, overflow := sum(budget.RootOverlayBudgetBytes, quarantineRequired, expansion, reconstructionRequired, safetyMargin)
	if overflow || quarantineRequired > budget.QuarantineAvailableBytes || scanRequired > budget.ScanAvailableBytes ||
		reconstructionRequired > budget.ReconstructionAvailable || destinationRequired > budget.DestinationAvailable {
		return Metadata{}, CapacityPlan{}, insufficientCapacity()
	}
	return copyMetadata, CapacityPlan{
		SelectedBytes: copyMetadata.SelectedSizeBytes, QuarantineRequired: quarantineRequired,
		ScanRequired: scanRequired, ReconstructionNeed: reconstructionRequired,
		DestinationRequired: destinationRequired, SessionRequired: sessionRequired, SafetyMargin: safetyMargin,
	}, nil
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
