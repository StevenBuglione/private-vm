package storage

import "errors"

type ScratchMode string

const (
	ScratchModeRAM  ScratchMode = "tmpfs"
	ScratchModeLUKS ScratchMode = "luks2"
)

type HostCapacity struct {
	TotalRAMBytes     uint64
	AvailableRAMBytes uint64
	RuntimeFreeBytes  uint64
	ScratchFreeBytes  uint64
	RuntimeIsTmpfs    bool
	DiskBackedSwap    bool
}

type CapacityRequest struct {
	GuestRAMBytes       uint64
	ExpectedWritesBytes uint64
	SmallScratchMax     uint64
}

type CapacityPlan struct {
	Mode             ScratchMode
	HostReserveBytes uint64
	ReservedBytes    uint64
}

func PlanCapacity(host HostCapacity, request CapacityRequest) (CapacityPlan, error) {
	if host.DiskBackedSwap {
		return CapacityPlan{}, errors.New("disk-backed swap blocks volatile session planning")
	}
	if !host.RuntimeIsTmpfs {
		return CapacityPlan{}, errors.New("runtime directory is not on volatile tmpfs")
	}
	if host.TotalRAMBytes == 0 || request.GuestRAMBytes == 0 || request.ExpectedWritesBytes == 0 {
		return CapacityPlan{}, errors.New("capacity inputs must be non-zero")
	}
	reserve := host.TotalRAMBytes / 5
	if reserve < 4<<30 {
		reserve = 4 << 30
	}
	ramRequired, overflow := add3(request.GuestRAMBytes, request.ExpectedWritesBytes, reserve)
	if !overflow && request.ExpectedWritesBytes <= request.SmallScratchMax &&
		ramRequired <= host.AvailableRAMBytes && request.ExpectedWritesBytes <= host.RuntimeFreeBytes {
		return CapacityPlan{Mode: ScratchModeRAM, HostReserveBytes: reserve, ReservedBytes: request.ExpectedWritesBytes}, nil
	}
	if request.ExpectedWritesBytes <= host.ScratchFreeBytes {
		return CapacityPlan{Mode: ScratchModeLUKS, HostReserveBytes: reserve, ReservedBytes: request.ExpectedWritesBytes}, nil
	}
	return CapacityPlan{}, errors.New("neither volatile RAM nor encrypted disk scratch has sufficient capacity")
}

func add3(a, b, c uint64) (uint64, bool) {
	first := a + b
	if first < a {
		return 0, true
	}
	result := first + c
	return result, result < first
}
