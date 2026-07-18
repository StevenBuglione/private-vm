package preflight

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	commandProbeLimit = 4 << 20
	tmpfsMagic        = 0x01021994
)

type Doctor struct {
	Strict bool
}

func (d Doctor) Run() Report {
	report := Report{SchemaVersion: 1}
	add := func(diag Diagnostic) {
		report.Diagnostics = append(report.Diagnostics, diag)
		if diag.Severity == SeverityBlocking {
			report.Runnable = false
		}
	}
	report.Runnable = true

	if runtime.GOOS != "linux" {
		add(blocking("HOST_OS_UNSUPPORTED", "private-vm requires Linux.", "Run on a supported NixOS, Fedora, Ubuntu, or Debian host."))
		return report
	}
	add(info("HOST_OS_LINUX", "Linux host detected."))

	checkFile(add, "/run/systemd/system", "SYSTEMD_REQUIRED", "systemd is not running.", "Boot the host with systemd as PID 1.")
	checkFile(add, "/sys/fs/cgroup/cgroup.controllers", "CGROUP_V2_REQUIRED", "cgroups v2 is unavailable.", "Enable the unified cgroups v2 hierarchy.")
	checkDevice(add, "/dev/kvm", true, "KVM_UNAVAILABLE", "KVM_PERMISSION_DENIED")
	checkDevice(add, "/dev/net/tun", true, "TUN_UNAVAILABLE", "TUN_PERMISSION_DENIED")
	checkDevice(add, "/dev/vhost-vsock", false, "VSOCK_UNAVAILABLE", "VSOCK_PERMISSION_DENIED")
	checkRuntimeFS(add)
	checkSwapAndResume(add)
	checkRootEncryption(add)
	checkCapacity(add)
	checkOrphans(add)

	required := []struct {
		name string
		code string
	}{
		{"qemu-system-x86_64", "QEMU_UNSUPPORTED"}, {"qemu-img", "QEMU_IMG_MISSING"},
		{"cryptsetup", "CRYPTSETUP_MISSING"}, {"nft", "NFTABLES_MISSING"}, {"ip", "IPROUTE2_MISSING"},
		{"mkfs.ext4", "EXT4_TOOLS_MISSING"}, {"remote-viewer", "SPICE_VIEWER_MISSING"}, {"usbguard", "USBGUARD_MISSING"},
	}
	paths := make(map[string]string, len(required))
	for _, item := range required {
		path, err := exec.LookPath(item.name)
		if err != nil {
			add(blocking(item.code, fmt.Sprintf("Required command %q was not found.", item.name), "Install the complete private-vm host package or NixOS module."))
			continue
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			add(blocking(item.code, fmt.Sprintf("Could not resolve %q to an absolute path.", item.name), "Reinstall the complete private-vm host package."))
			continue
		}
		paths[item.name] = absolute
	}
	if qemu := paths["qemu-system-x86_64"]; qemu != "" {
		checkQEMU(add, qemu)
	}

	return report
}

func checkFile(add func(Diagnostic), path, code, summary, remediation string) {
	if _, err := os.Stat(path); err != nil {
		add(blocking(code, summary, remediation))
	} else {
		add(info(strings.TrimSuffix(code, "_REQUIRED")+"_PRESENT", path+" is available."))
	}
}

func checkDevice(add func(Diagnostic), path string, writable bool, missingCode, permissionCode string) {
	if _, err := os.Stat(path); err != nil {
		add(blocking(missingCode, path+" is unavailable.", "Load the required kernel module and install the private-vm host integration."))
		return
	}
	flags := os.O_RDONLY
	if writable {
		flags = os.O_RDWR
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		add(blocking(permissionCode, "The current user cannot open "+path+".", "Install the host module and confirm group/device permissions."))
		return
	}
	_ = f.Close()
	add(info(strings.TrimSuffix(missingCode, "_UNAVAILABLE")+"_USABLE", path+" is usable."))
}

func checkRuntimeFS(add func(Diagnostic)) {
	var stat unix.Statfs_t
	if err := unix.Statfs("/run", &stat); err != nil {
		add(blocking("RUNTIME_NOT_TMPFS", "The /run filesystem could not be inspected.", "Ensure /run exists as a volatile tmpfs."))
		return
	}
	if uint64(stat.Type) != tmpfsMagic {
		add(blocking("RUNTIME_NOT_TMPFS", "/run is not tmpfs.", "Configure /run as a volatile tmpfs before starting private-vm."))
		return
	}
	add(info("RUNTIME_TMPFS_VERIFIED", "/run is a volatile tmpfs."))
}

func checkSwapAndResume(add func(Diagnostic)) {
	data, err := os.ReadFile("/proc/swaps")
	if err != nil {
		add(blocking("DISK_SWAP_STATUS_UNKNOWN", "Active swap could not be inspected.", "Make /proc/swaps readable and retry."))
	} else {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		diskSwap := false
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) > 0 && !strings.Contains(fields[0], "zram") {
				diskSwap = true
			}
		}
		if diskSwap {
			add(blocking("DISK_SWAP_ACTIVE", "Disk-backed swap is active.", "Disable disk swap; zram is permitted."))
		} else {
			add(info("DISK_SWAP_ABSENT", "No disk-backed swap is active."))
		}
	}
	cmdline, _ := os.ReadFile("/proc/cmdline")
	resume, _ := os.ReadFile("/sys/power/resume")
	configured := strings.Contains(" "+string(cmdline)+" ", " resume=") || (strings.TrimSpace(string(resume)) != "" && strings.TrimSpace(string(resume)) != "0:0")
	if configured {
		add(blocking("HIBERNATION_ENABLED", "A hibernation resume target is configured.", "Disable resume/hibernation before running private-vm."))
	} else {
		add(info("HIBERNATION_RESUME_ABSENT", "No hibernation resume target is configured."))
	}
}

func checkRootEncryption(add func(Diagnostic)) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		add(warning("HOST_ROOT_ENCRYPTION_UNKNOWN", "Root encryption evidence could not be inspected.", "Review host full-disk encryption; private-vm still encrypts its session scratch independently."))
		return
	}
	source := ""
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, " - ")
		if len(parts) != 2 {
			continue
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) > 4 && left[4] == "/" && len(right) > 1 {
			source = right[1]
			break
		}
	}
	if strings.HasPrefix(source, "/dev/mapper/") || strings.HasPrefix(source, "/dev/dm-") {
		add(info("HOST_ROOT_ENCRYPTION_EVIDENCE", "The root filesystem uses a device-mapper device."))
		return
	}
	add(warning("HOST_ROOT_UNENCRYPTED", "No host root-encryption evidence was found.", "Use full-disk encryption for defense in depth; private-vm session scratch remains independently encrypted."))
}

func checkCapacity(add func(Diagnostic)) {
	var sys unix.Sysinfo_t
	if err := unix.Sysinfo(&sys); err != nil {
		add(blocking("INSUFFICIENT_MEMORY", "Host memory could not be measured.", "Ensure the kernel exposes sysinfo and retry."))
	} else {
		available := uint64(sys.Freeram+sys.Bufferram) * uint64(sys.Unit)
		if available < 4<<30 {
			add(blocking("INSUFFICIENT_MEMORY", "Less than 4 GiB of host memory is currently available.", "Close applications or add memory before starting a VM."))
		} else {
			add(info("MEMORY_CAPACITY_PRESENT", "Host memory reserve is available."))
		}
	}
	path := nearestExisting("/var/lib/private-vm/scratch")
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil || stat.Bavail == 0 {
		add(blocking("INSUFFICIENT_SCRATCH", "Scratch capacity could not be verified.", "Ensure /var/lib/private-vm is on a filesystem with available space."))
	} else {
		add(info("SCRATCH_CAPACITY_PRESENT", "Scratch filesystem capacity is available."))
	}
}

func nearestExisting(path string) string {
	for {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		next := filepath.Dir(path)
		if next == path {
			return "/"
		}
		path = next
	}
}

func checkOrphans(add func(Diagnostic)) {
	entries, err := os.ReadDir("/run/private-vm")
	if errors.Is(err, os.ErrNotExist) {
		add(info("ORPHAN_RESOURCES_ABSENT", "No private-vm runtime resources exist."))
		return
	}
	if err != nil {
		add(warning("ORPHAN_STATUS_UNAVAILABLE", "Runtime resources could not be inspected.", "Query the installed daemon with private-vm session cleanup --all."))
		return
	}
	count := 0
	for _, entry := range entries {
		if entry.Name() != "control.sock" {
			count++
		}
	}
	if count > 0 {
		add(blocking("ORPHAN_CLEANUP_FAILED", "Potential private-vm runtime resources remain.", "Run private-vm session cleanup --all and retry doctor."))
	} else {
		add(info("ORPHAN_RESOURCES_ABSENT", "No orphan private-vm resources were found."))
	}
}

func checkQEMU(add func(Diagnostic), binary string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := boundedOutput(ctx, binary, "--version")
	if err != nil || !strings.Contains(string(version), "QEMU emulator version") {
		add(blocking("QEMU_UNSUPPORTED", "QEMU version probing failed.", "Install QEMU 9.2 or newer with SPICE and VSOCK support."))
		return
	}
	fields := strings.Fields(string(version))
	versionOK := false
	for i, field := range fields {
		if field == "version" && i+1 < len(fields) {
			parts := strings.Split(fields[i+1], ".")
			major, _ := strconv.Atoi(parts[0])
			versionOK = major >= 9
			break
		}
	}
	if !versionOK {
		add(blocking("QEMU_UNSUPPORTED", "QEMU is older than 9.2.", "Install a supported QEMU release."))
		return
	}
	machines, machineErr := boundedOutput(ctx, binary, "-machine", "help")
	devices, deviceErr := boundedOutput(ctx, binary, "-device", "help")
	spice, spiceErr := boundedOutput(ctx, binary, "-spice", "help")
	all := string(machines) + string(devices) + string(spice)
	for _, feature := range []string{"q35", "vhost-vsock", "virtio-net", "virtio-blk", "usb-host", "spice"} {
		if !strings.Contains(strings.ToLower(all), feature) {
			add(blocking("QEMU_UNSUPPORTED", "QEMU is missing required feature "+feature+".", "Install QEMU with KVM, SPICE, VSOCK, VirtIO and USB host support."))
			return
		}
	}
	if machineErr != nil || deviceErr != nil || spiceErr != nil {
		add(blocking("QEMU_UNSUPPORTED", "QEMU feature probing returned an error.", "Install the complete supported QEMU package."))
		return
	}
	add(info("QEMU_FEATURES_VERIFIED", "QEMU version and required features are present."))
}

func boundedOutput(ctx context.Context, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	var output limitWriter
	output.limit = commandProbeLimit
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	if output.exceeded {
		return output.Bytes(), errors.New("probe output exceeded limit")
	}
	return output.Bytes(), err
}

type limitWriter struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.Len()+len(p) > w.limit {
		remaining := w.limit - w.Len()
		if remaining > 0 {
			_, _ = w.Buffer.Write(p[:remaining])
		}
		w.exceeded = true
		return len(p), nil
	}
	return w.Buffer.Write(p)
}

func blocking(code, summary, remediation string) Diagnostic {
	return Diagnostic{Code: code, Severity: SeverityBlocking, Summary: summary, Remediation: remediation}
}
func warning(code, summary, remediation string) Diagnostic {
	return Diagnostic{Code: code, Severity: SeverityWarning, Summary: summary, Remediation: remediation, Overridable: true}
}
func info(code, summary string) Diagnostic {
	return Diagnostic{Code: code, Severity: SeverityInfo, Summary: summary}
}
