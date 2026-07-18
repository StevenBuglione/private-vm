package qemu

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var cgroupSessionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,47}$`)

type CgroupLimits struct {
	MemoryBytes uint64
	VCPUs       uint32
	PIDs        uint32
}

type CgroupHandle interface {
	Path() string
	Cleanup(context.Context) error
}

type CgroupFactory interface {
	Place(context.Context, string, int, CgroupLimits) (CgroupHandle, error)
}

// FSCgroupFactory creates delegated child cgroups below private-vmd's current
// cgroup. The systemd unit must set Delegate=yes.
type FSCgroupFactory struct {
	Root string
}

func CurrentCgroupFactory() (FSCgroupFactory, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return FSCgroupFactory{}, fmt.Errorf("read daemon cgroup: %w", err)
	}
	var relative string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			relative = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if relative == "" || !filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return FSCgroupFactory{}, errors.New("daemon is not running in a valid cgroups v2 path")
	}
	return FSCgroupFactory{Root: filepath.Join("/sys/fs/cgroup", relative)}, nil
}

func (f FSCgroupFactory) Place(ctx context.Context, sessionID string, pid int, limits CgroupLimits) (CgroupHandle, error) {
	if !filepath.IsAbs(f.Root) || filepath.Clean(f.Root) != f.Root {
		return nil, errors.New("cgroup root must be a clean absolute path")
	}
	if !cgroupSessionPattern.MatchString(sessionID) || pid <= 1 {
		return nil, errors.New("invalid internal cgroup identity")
	}
	if limits.MemoryBytes < 512<<20 || limits.VCPUs < 1 || limits.VCPUs > 64 {
		return nil, errors.New("invalid cgroup resource limits")
	}
	if limits.PIDs == 0 {
		limits.PIDs = 256
	}
	path := filepath.Join(f.Root, "private-vm-"+sessionID+".scope")
	if err := os.Mkdir(path, 0o750); err != nil {
		return nil, fmt.Errorf("create delegated QEMU cgroup: %w", err)
	}
	handle := &fsCgroup{path: path}
	rollback := true
	defer func() {
		if rollback {
			_ = os.Remove(path)
		}
	}()
	settings := []struct{ name, value string }{
		{"memory.max", strconv.FormatUint(limits.MemoryBytes, 10)},
		{"memory.swap.max", "0"},
		{"pids.max", strconv.FormatUint(uint64(limits.PIDs), 10)},
		{"cpu.max", strconv.FormatUint(uint64(limits.VCPUs)*100000, 10) + " 100000"},
		// Move the process only after every controller limit is installed.
		{"cgroup.procs", strconv.Itoa(pid)},
	}
	for _, setting := range settings {
		name, value := setting.name, setting.value
		if err := os.WriteFile(filepath.Join(path, name), []byte(value), 0o600); err != nil {
			return nil, fmt.Errorf("configure delegated QEMU cgroup %s: %w", name, err)
		}
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	rollback = false
	return handle, nil
}

type fsCgroup struct {
	path string
}

func (c *fsCgroup) Path() string { return c.path }

func (c *fsCgroup) Cleanup(ctx context.Context) error {
	if _, err := os.Stat(c.path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := os.WriteFile(filepath.Join(c.path, "cgroup.kill"), []byte("1"), 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("kill delegated QEMU cgroup: %w", err)
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := os.Remove(c.path)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("remove delegated QEMU cgroup: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
