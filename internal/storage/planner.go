package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

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

// CapacityPool owns one immutable capacity snapshot and serializes reservations
// made from it. A plan is not authorization to allocate until it has a live
// reservation from this pool.
type CapacityPool struct {
	mu           sync.Mutex
	host         HostCapacity
	reservations map[string]*CapacityReservation
	ramBytes     uint64
	runtimeBytes uint64
	scratchBytes uint64
}

type CapacityReservation struct {
	mu           sync.Mutex
	pool         *CapacityPool
	sessionID    string
	plan         CapacityPlan
	ramBytes     uint64
	runtimeBytes uint64
	scratchBytes uint64
	released     bool
}

func NewCapacityPool(host HostCapacity) (*CapacityPool, error) {
	if host.DiskBackedSwap || !host.RuntimeIsTmpfs || host.TotalRAMBytes == 0 || host.AvailableRAMBytes == 0 || host.AvailableRAMBytes > host.TotalRAMBytes || (host.RuntimeFreeBytes == 0 && host.ScratchFreeBytes == 0) {
		return nil, errors.New("capacity pool requires valid fail-closed host evidence")
	}
	return &CapacityPool{host: host, reservations: make(map[string]*CapacityReservation)}, nil
}

func (p *CapacityPool) Reserve(sessionID string, request CapacityRequest) (*CapacityReservation, error) {
	if p == nil || !storageSessionPattern.MatchString(sessionID) {
		return nil, errors.New("capacity reservation requires an internal session ID")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.reservations[sessionID]; exists {
		return nil, errors.New("capacity is already reserved for this session")
	}
	effective := p.host
	var ok bool
	if effective.AvailableRAMBytes, ok = subtractCapacity(effective.AvailableRAMBytes, p.ramBytes); !ok {
		return nil, errors.New("reserved memory exceeds the capacity snapshot")
	}
	if effective.RuntimeFreeBytes, ok = subtractCapacity(effective.RuntimeFreeBytes, p.runtimeBytes); !ok {
		return nil, errors.New("reserved runtime space exceeds the capacity snapshot")
	}
	if effective.ScratchFreeBytes, ok = subtractCapacity(effective.ScratchFreeBytes, p.scratchBytes); !ok {
		return nil, errors.New("reserved scratch space exceeds the capacity snapshot")
	}
	plan, err := PlanCapacity(effective, request)
	if err != nil {
		return nil, err
	}
	reservation := &CapacityReservation{pool: p, sessionID: sessionID, plan: plan, ramBytes: request.GuestRAMBytes}
	switch plan.Mode {
	case ScratchModeRAM:
		reservation.ramBytes, ok = addCapacity(reservation.ramBytes, request.ExpectedWritesBytes)
		if !ok {
			return nil, errors.New("capacity reservation overflow")
		}
		reservation.runtimeBytes = request.ExpectedWritesBytes
	case ScratchModeLUKS:
		reservation.scratchBytes = request.ExpectedWritesBytes
	default:
		return nil, errors.New("capacity planner returned an unsupported mode")
	}
	if p.ramBytes, ok = addCapacity(p.ramBytes, reservation.ramBytes); !ok {
		return nil, errors.New("memory reservation overflow")
	}
	if p.runtimeBytes, ok = addCapacity(p.runtimeBytes, reservation.runtimeBytes); !ok {
		p.ramBytes -= reservation.ramBytes
		return nil, errors.New("runtime reservation overflow")
	}
	if p.scratchBytes, ok = addCapacity(p.scratchBytes, reservation.scratchBytes); !ok {
		p.ramBytes -= reservation.ramBytes
		p.runtimeBytes -= reservation.runtimeBytes
		return nil, errors.New("scratch reservation overflow")
	}
	p.reservations[sessionID] = reservation
	return reservation, nil
}

func (r *CapacityReservation) Plan() CapacityPlan {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.plan
}

func (r *CapacityReservation) Destroy(context.Context) error {
	if r == nil || r.pool == nil {
		return errors.New("capacity reservation is invalid")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return nil
	}
	r.pool.mu.Lock()
	defer r.pool.mu.Unlock()
	current := r.pool.reservations[r.sessionID]
	if current != r || r.pool.ramBytes < r.ramBytes || r.pool.runtimeBytes < r.runtimeBytes || r.pool.scratchBytes < r.scratchBytes {
		return errors.New("capacity reservation ownership is inconsistent")
	}
	delete(r.pool.reservations, r.sessionID)
	r.pool.ramBytes -= r.ramBytes
	r.pool.runtimeBytes -= r.runtimeBytes
	r.pool.scratchBytes -= r.scratchBytes
	r.released = true
	return nil
}

func (r *CapacityReservation) Audit(context.Context) error {
	if r == nil || r.pool == nil {
		return errors.New("capacity reservation is invalid")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pool.mu.Lock()
	defer r.pool.mu.Unlock()
	if !r.released || r.pool.reservations[r.sessionID] == r {
		return errors.New("capacity reservation remains active")
	}
	return nil
}

func ProbeHostCapacity(runtimeRoot, scratchRoot string) (HostCapacity, error) {
	for _, path := range []string{runtimeRoot, scratchRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return HostCapacity{}, errors.New("capacity paths must be narrow clean absolute paths")
		}
	}
	total, available, err := readMemoryCapacity("/proc/meminfo")
	if err != nil {
		return HostCapacity{}, err
	}
	runtimeStat, err := secureStatfs(runtimeRoot)
	if err != nil {
		return HostCapacity{}, errors.New("runtime capacity is unavailable")
	}
	scratchStat, err := secureStatfs(scratchRoot)
	if err != nil {
		return HostCapacity{}, errors.New("encrypted scratch capacity is unavailable")
	}
	swaps, err := readBoundedCapacityFile("/proc/swaps", 64<<10)
	if err != nil {
		return HostCapacity{}, errors.New("host swap evidence is unavailable")
	}
	diskBackedSwap, err := parseDiskBackedSwap(swaps)
	if err != nil {
		return HostCapacity{}, err
	}
	return HostCapacity{
		TotalRAMBytes: total, AvailableRAMBytes: available,
		RuntimeFreeBytes: statfsAvailable(runtimeStat), ScratchFreeBytes: statfsAvailable(scratchStat),
		RuntimeIsTmpfs: runtimeStat.Type == unix.TMPFS_MAGIC,
		DiskBackedSwap: diskBackedSwap,
	}, nil
}

func PlanCapacity(host HostCapacity, request CapacityRequest) (CapacityPlan, error) {
	if host.DiskBackedSwap {
		return CapacityPlan{}, errors.New("disk-backed swap blocks volatile session planning")
	}
	if !host.RuntimeIsTmpfs {
		return CapacityPlan{}, errors.New("runtime directory is not on volatile tmpfs")
	}
	if host.TotalRAMBytes == 0 || host.AvailableRAMBytes == 0 || host.AvailableRAMBytes > host.TotalRAMBytes || request.GuestRAMBytes == 0 || request.ExpectedWritesBytes == 0 || request.SmallScratchMax == 0 {
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
	guestRequired, guestOK := addCapacity(request.GuestRAMBytes, reserve)
	if guestOK && guestRequired <= host.AvailableRAMBytes && request.ExpectedWritesBytes <= host.ScratchFreeBytes {
		return CapacityPlan{Mode: ScratchModeLUKS, HostReserveBytes: reserve, ReservedBytes: request.ExpectedWritesBytes}, nil
	}
	return CapacityPlan{}, errors.New("neither volatile RAM nor encrypted disk scratch has sufficient capacity")
}

func addCapacity(left, right uint64) (uint64, bool) {
	result := left + right
	return result, result >= left
}

func subtractCapacity(total, used uint64) (uint64, bool) {
	if used > total {
		return 0, false
	}
	return total - used, true
}

func add3(a, b, c uint64) (uint64, bool) {
	first := a + b
	if first < a {
		return 0, true
	}
	result := first + c
	return result, result < first
}

func readMemoryCapacity(path string) (uint64, uint64, error) {
	data, err := readBoundedCapacityFile(path, 64<<10)
	if err != nil {
		return 0, 0, errors.New("bounded host memory evidence is unavailable")
	}
	var total, available uint64
	var totalSeen, availableSeen bool
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] != "kB" {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil || value > ^uint64(0)/1024 {
			return 0, 0, errors.New("host memory evidence is malformed")
		}
		switch fields[0] {
		case "MemTotal:":
			if totalSeen {
				return 0, 0, errors.New("host memory evidence contains a duplicate total")
			}
			totalSeen = true
			total = value * 1024
		case "MemAvailable:":
			if availableSeen {
				return 0, 0, errors.New("host memory evidence contains a duplicate available value")
			}
			availableSeen = true
			available = value * 1024
		}
	}
	if total == 0 || available == 0 || available > total {
		return 0, 0, errors.New("host memory evidence is incomplete")
	}
	return total, available, nil
}

func statfsAvailable(stat unix.Statfs_t) uint64 {
	blockSize := uint64(stat.Bsize)
	if blockSize == 0 || stat.Bavail > ^uint64(0)/blockSize {
		return 0
	}
	return stat.Bavail * blockSize
}

func hasDiskBackedSwap(data []byte) bool {
	result, err := parseDiskBackedSwap(data)
	return err != nil || result
}

func parseDiskBackedSwap(data []byte) (bool, error) {
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return false, errors.New("host swap evidence is empty")
	}
	header := strings.Fields(lines[0])
	if len(header) < 5 || header[0] != "Filename" || header[1] != "Type" {
		return false, errors.New("host swap evidence header is malformed")
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 5 || !filepath.IsAbs(fields[0]) {
			return false, errors.New("host swap evidence entry is malformed")
		}
		name := strings.TrimPrefix(fields[0], "/dev/zram")
		if name == "" {
			return true, nil
		}
		if _, err := strconv.ParseUint(name, 10, 31); err != nil {
			return true, nil
		}
	}
	return false, nil
}

func secureStatfs(path string) (unix.Statfs_t, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return unix.Statfs_t{}, err
	}
	defer unix.Close(fd)
	var stat unix.Statfs_t
	if err := unix.Fstatfs(fd, &stat); err != nil {
		return unix.Statfs_t{}, err
	}
	return stat, nil
}

func readBoundedCapacityFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("capacity evidence exceeded its bound")
	}
	return data, nil
}
