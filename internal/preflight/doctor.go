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
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	commandProbeLimit  = 4 << 20
	tmpfsMagic         = 0x01021994
	extFilesystemMagic = 0x0000ef53
	btrfsMagic         = 0x9123683e
	xfsMagic           = 0x58465342
)

type Doctor struct {
	Strict       bool
	installation *installationProbe
}

type probeCommand func(context.Context, string, ...string) ([]byte, error)

// installationProbe is injectable only for deterministic same-package tests.
// Production callers always receive the closed default paths and bounded
// command runner below.
type installationProbe struct {
	runtimeDirectory string
	controlSocket    string
	configFile       string
	policyFiles      []string
	systemctl        string
	ownerUID         uint32
	run              probeCommand
}

func (d Doctor) Run() Report {
	return d.RunContext(context.Background())
}

// RunContext executes the read-only diagnostic set under the caller's bounded
// lifetime. External probes inherit the context and every phase observes
// cancellation before continuing.
func (d Doctor) RunContext(ctx context.Context) Report {
	if ctx == nil {
		ctx = context.Background()
	}
	report := Report{SchemaVersion: 1}
	add := func(diag Diagnostic) {
		report.Diagnostics = append(report.Diagnostics, diag)
		if diag.Severity == SeverityBlocking {
			report.Runnable = false
		}
	}
	report.Runnable = true
	if ctx.Err() != nil {
		return report
	}

	if runtime.GOOS != "linux" {
		add(blocking("HOST_OS_UNSUPPORTED", "private-vm requires Linux.", "Run on a supported NixOS, Fedora, Ubuntu, or Debian host."))
		return report
	}
	add(info("HOST_OS_LINUX", "Linux host detected."))
	checkHostIdentity(add)

	checkFile(add, "/run/systemd/system", "SYSTEMD_REQUIRED", "systemd is not running.", "Boot the host with systemd as PID 1.")
	checkFile(add, "/sys/fs/cgroup/cgroup.controllers", "CGROUP_V2_REQUIRED", "cgroups v2 is unavailable.", "Enable the unified cgroups v2 hierarchy.")
	checkNetworkNamespace(add, "/proc/self/ns/net")
	checkControlDevice(add, "/dev/mapper/control", "DEVICE_MAPPER_UNAVAILABLE", "DEVICE_MAPPER_CONTROL_PRESENT", "Load dm_mod and expose the device-mapper control node.")
	checkControlDevice(add, "/dev/loop-control", "LOOP_CONTROL_UNAVAILABLE", "LOOP_CONTROL_PRESENT", "Load the loop module and expose /dev/loop-control.")
	checkDevice(add, "/dev/kvm", true, "KVM_UNAVAILABLE", "KVM_PERMISSION_DENIED")
	checkDevice(add, "/dev/net/tun", true, "TUN_UNAVAILABLE", "TUN_PERMISSION_DENIED")
	checkDevice(add, "/dev/vhost-vsock", false, "VSOCK_UNAVAILABLE", "VSOCK_PERMISSION_DENIED")
	checkRuntimeFS(add)
	checkIPv6Forwarding(add, "/proc/sys/net/ipv6/conf/all/forwarding")
	checkSwapAndResume(add)
	checkRootEncryption(add)
	checkCapacity(add)
	checkSparseCapability(add, "/var/lib/private-vm/scratch")
	checkOrphans(add)

	required := []struct {
		name string
		code string
	}{
		{"qemu-system-x86_64", "QEMU_UNSUPPORTED"}, {"qemu-img", "QEMU_IMG_MISSING"},
		{"cryptsetup", "CRYPTSETUP_MISSING"}, {"nft", "NFTABLES_MISSING"}, {"ip", "IPROUTE2_MISSING"},
		{"mkfs.ext4", "EXT4_TOOLS_MISSING"}, {"remote-viewer", "SPICE_VIEWER_MISSING"}, {"usbguard", "USBGUARD_MISSING"},
		{"pkcheck", "POLKIT_CHECK_MISSING"}, {"losetup", "LOSETUP_MISSING"},
	}
	paths := make(map[string]string, len(required))
	for _, item := range required {
		if ctx.Err() != nil {
			return report
		}
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
		checkQEMU(ctx, add, qemu)
	}
	checkHostToolCapabilities(ctx, add, paths, boundedOutput)
	checkInstalledIntegration(ctx, d.Strict, add, d.installation)

	return report
}

func checkHostIdentity(add func(Diagnostic)) {
	checkArchitecture(add, runtime.GOARCH)
	var identity unix.Utsname
	if err := unix.Uname(&identity); err != nil {
		add(blocking("KERNEL_STATUS_UNKNOWN", "The running Linux kernel identity could not be inspected.", "Boot a supported Linux kernel and make uname information available."))
		return
	}
	checkKernelRelease(add, unix.ByteSliceToString(identity.Release[:]))
}

func checkArchitecture(add func(Diagnostic), architecture string) {
	if architecture != "amd64" {
		add(blocking("HOST_ARCH_UNSUPPORTED", "The host architecture is outside the frozen v1 runtime contract.", "Use x86_64 Linux for private-vm v1."))
		return
	}
	add(info("HOST_ARCH_X86_64", "The host architecture is x86_64."))
}

func checkKernelRelease(add func(Diagnostic), release string) {
	base := strings.SplitN(strings.TrimSpace(release), "-", 2)[0]
	parts := strings.Split(base, ".")
	if len(parts) < 2 {
		add(blocking("KERNEL_STATUS_UNKNOWN", "The running Linux kernel version could not be parsed.", "Use Linux kernel 6.6 or newer with a canonical release identifier."))
		return
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil || major < 0 || minor < 0 {
		add(blocking("KERNEL_STATUS_UNKNOWN", "The running Linux kernel version could not be parsed.", "Use Linux kernel 6.6 or newer with a canonical release identifier."))
		return
	}
	if major < 6 || major == 6 && minor < 6 {
		add(blocking("KERNEL_UNSUPPORTED", "The running Linux kernel is older than 6.6.", "Boot Linux kernel 6.6 or newer."))
		return
	}
	add(info("KERNEL_VERSION_SUPPORTED", "The running Linux kernel is version 6.6 or newer."))
}

func checkNetworkNamespace(add func(Diagnostic), path string) {
	metadata, err := os.Lstat(path)
	if err != nil || metadata.Mode()&os.ModeSymlink == 0 {
		add(blocking("NETNS_UNAVAILABLE", "The current process network namespace identity is unavailable.", "Enable Linux network namespaces and expose /proc/self/ns/net."))
		return
	}
	target, err := os.Readlink(path)
	if err != nil || !strings.HasPrefix(target, "net:[") || !strings.HasSuffix(target, "]") {
		add(blocking("NETNS_UNAVAILABLE", "The current process network namespace identity is invalid.", "Enable Linux network namespaces and expose /proc/self/ns/net."))
		return
	}
	identifier := strings.TrimSuffix(strings.TrimPrefix(target, "net:["), "]")
	value, err := strconv.ParseUint(identifier, 10, 64)
	if err != nil || value == 0 {
		add(blocking("NETNS_UNAVAILABLE", "The current process network namespace identity is invalid.", "Enable Linux network namespaces and expose /proc/self/ns/net."))
		return
	}
	add(info("NETNS_PRESENT", "The current process has a Linux network namespace identity."))
}

func checkControlDevice(add func(Diagnostic), path, failureCode, successCode, remediation string) {
	metadata, err := os.Stat(path)
	if err != nil || !isCharacterDevice(metadata.Mode()) {
		add(blocking(failureCode, path+" is not an available character-device control node.", remediation))
		return
	}
	add(info(successCode, path+" is an available character-device control node."))
}

func isCharacterDevice(mode os.FileMode) bool {
	return mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0
}

type hostToolProbe struct {
	name        string
	arguments   []string
	markers     []string
	failureCode string
	successCode string
}

var hostToolProbes = []hostToolProbe{
	{name: "nft", arguments: []string{"--version"}, markers: []string{"nftables"}, failureCode: "NFTABLES_UNSUPPORTED", successCode: "NFTABLES_CAPABILITY_VERIFIED"},
	{name: "ip", arguments: []string{"-Version"}, markers: []string{"ip utility", "iproute2"}, failureCode: "IPROUTE2_UNSUPPORTED", successCode: "IPROUTE2_CAPABILITY_VERIFIED"},
	{name: "cryptsetup", arguments: []string{"--version"}, markers: []string{"cryptsetup"}, failureCode: "CRYPTSETUP_UNSUPPORTED", successCode: "CRYPTSETUP_CAPABILITY_VERIFIED"},
	{name: "losetup", arguments: []string{"--version"}, markers: []string{"losetup"}, failureCode: "LOSETUP_UNSUPPORTED", successCode: "LOSETUP_CAPABILITY_VERIFIED"},
	{name: "mkfs.ext4", arguments: []string{"-V"}, markers: []string{"mke2fs"}, failureCode: "EXT4_TOOLS_UNSUPPORTED", successCode: "EXT4_TOOLS_CAPABILITY_VERIFIED"},
	{name: "remote-viewer", arguments: []string{"--version"}, markers: []string{"remote viewer", "remote-viewer", "virt-viewer"}, failureCode: "SPICE_VIEWER_UNSUPPORTED", successCode: "SPICE_VIEWER_CAPABILITY_VERIFIED"},
	{name: "usbguard", arguments: []string{"--version"}, markers: []string{"usbguard"}, failureCode: "USBGUARD_UNSUPPORTED", successCode: "USBGUARD_CAPABILITY_VERIFIED"},
}

func checkHostToolCapabilities(ctx context.Context, add func(Diagnostic), paths map[string]string, run probeCommand) {
	for _, probe := range hostToolProbes {
		if ctx.Err() != nil {
			return
		}
		binary := paths[probe.name]
		if binary == "" {
			continue
		}
		if !runHostToolProbe(ctx, binary, probe, run) {
			add(blocking(probe.failureCode, "A required host tool failed its bounded read-only capability probe.", "Install the complete supported "+probe.name+" package and retry."))
			continue
		}
		if probe.name == "ip" {
			operation, cancel := context.WithTimeout(ctx, 3*time.Second)
			output, err := run(operation, binary, "netns", "list")
			cancel()
			clear(output)
			if err != nil {
				add(blocking(probe.failureCode, "iproute2 cannot inspect Linux network namespaces.", "Install iproute2 with network-namespace support and retry."))
				continue
			}
		}
		add(info(probe.successCode, "The required host tool passed its bounded read-only capability probe."))
	}
}

func runHostToolProbe(ctx context.Context, binary string, probe hostToolProbe, run probeCommand) bool {
	operation, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	output, err := run(operation, binary, probe.arguments...)
	if err != nil {
		clear(output)
		return false
	}
	matched := false
	for _, marker := range probe.markers {
		if containsASCIIFold(output, marker) {
			matched = true
			break
		}
	}
	clear(output)
	return matched
}

func containsASCIIFold(data []byte, lowercaseMarker string) bool {
	if len(lowercaseMarker) == 0 || len(data) < len(lowercaseMarker) {
		return false
	}
	for start := 0; start <= len(data)-len(lowercaseMarker); start++ {
		matched := true
		for offset := 0; offset < len(lowercaseMarker); offset++ {
			value := data[start+offset]
			if value >= 'A' && value <= 'Z' {
				value += 'a' - 'A'
			}
			if value != lowercaseMarker[offset] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func defaultInstallationProbe() *installationProbe {
	return &installationProbe{
		runtimeDirectory: "/run/private-vm",
		controlSocket:    "/run/private-vm/control.sock",
		configFile:       "/etc/private-vm/config.toml",
		policyFiles: []string{
			"/run/current-system/sw/share/polkit-1/actions/org.private-vm.policy",
			"/usr/share/polkit-1/actions/org.private-vm.policy",
		},
		ownerUID: 0,
		run:      boundedOutput,
	}
}

func checkInstalledIntegration(ctx context.Context, strict bool, add func(Diagnostic), probe *installationProbe) {
	if probe == nil {
		probe = defaultInstallationProbe()
	}
	run := probe.run
	if run == nil {
		run = boundedOutput
	}
	systemctl := probe.systemctl
	if systemctl == "" {
		resolved, err := exec.LookPath("systemctl")
		if err != nil {
			add(integrationFailure(strict, "SYSTEMCTL_MISSING", "systemctl is unavailable for installed-host verification.", "Install the complete host integration and rerun Doctor."))
		} else {
			systemctl, err = filepath.Abs(resolved)
			if err != nil {
				add(integrationFailure(strict, "SYSTEMCTL_MISSING", "systemctl could not be resolved safely.", "Reinstall the complete host integration and rerun Doctor."))
				systemctl = ""
			}
		}
	}
	if systemctl != "" {
		checkActiveUnit(ctx, strict, add, run, systemctl, "private-vmd.service", "PRIVATE_VMD_SERVICE_INACTIVE", "PRIVATE_VMD_SERVICE_ACTIVE")
		checkActiveUnit(ctx, strict, add, run, systemctl, "usbguard.service", "USBGUARD_SERVICE_INACTIVE", "USBGUARD_SERVICE_ACTIVE")
	}

	if err := verifyControlSocket(probe); err != nil {
		add(integrationFailure(strict, "CONTROL_SOCKET_INVALID", "The installed daemon control socket contract is not satisfied.", "Start private-vmd and verify /run/private-vm ownership and modes."))
	} else {
		add(info("CONTROL_SOCKET_VERIFIED", "The installed daemon control socket ownership and modes are valid."))
	}
	if err := verifyDaemonConfig(probe.configFile, probe.ownerUID); err != nil {
		add(integrationFailure(strict, "DAEMON_CONFIG_INVALID", "The installed daemon configuration ownership or mode is invalid.", "Reinstall the root-owned mode 0600 configuration and restart private-vmd."))
	} else {
		add(info("DAEMON_CONFIG_VERIFIED", "The installed daemon configuration ownership and mode are valid."))
	}
	if err := verifyPolkitPolicy(probe.policyFiles, probe.ownerUID); err != nil {
		add(integrationFailure(strict, "POLKIT_POLICY_INVALID", "The installed Polkit policy is missing, unsafe, or outside the one-action contract.", "Reinstall the host integration containing only org.private-vm.usb.prepare."))
	} else {
		add(info("POLKIT_POLICY_VERIFIED", "The installed Polkit policy contains only the USB prepare action."))
	}
}

func checkActiveUnit(ctx context.Context, strict bool, add func(Diagnostic), run probeCommand, systemctl, unit, failureCode, successCode string) {
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := run(operation, systemctl, "is-active", "--quiet", unit)
	clear(output)
	if err != nil {
		add(integrationFailure(strict, failureCode, "A required installed host service is inactive.", "Enable and start "+unit+", then rerun Doctor."))
		return
	}
	add(info(successCode, unit+" is active."))
}

func verifyControlSocket(probe *installationProbe) error {
	directory, err := os.Lstat(probe.runtimeDirectory)
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0o750 || !ownedBy(directory, probe.ownerUID) {
		return errors.New("runtime directory contract mismatch")
	}
	socket, err := os.Lstat(probe.controlSocket)
	if err != nil || socket.Mode()&os.ModeSocket == 0 || socket.Mode().Perm() != 0o660 || !ownedBy(socket, probe.ownerUID) {
		return errors.New("control socket contract mismatch")
	}
	directoryStat, directoryOK := directory.Sys().(*syscall.Stat_t)
	socketStat, socketOK := socket.Sys().(*syscall.Stat_t)
	if !directoryOK || !socketOK || directoryStat.Gid != socketStat.Gid {
		return errors.New("control socket group mismatch")
	}
	return nil
}

func verifyDaemonConfig(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ownedBy(info, ownerUID) {
		return errors.New("daemon configuration contract mismatch")
	}
	return nil
}

func verifyPolkitPolicy(candidates []string, ownerUID uint32) error {
	var selected string
	for _, candidate := range candidates {
		if _, err := os.Lstat(candidate); err == nil {
			selected = candidate
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("polkit policy inspection failed")
		}
	}
	if selected == "" {
		return errors.New("polkit policy is absent")
	}
	info, err := os.Lstat(selected)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, resolveErr := filepath.EvalSymlinks(selected)
		if resolveErr != nil || !strings.HasPrefix(resolved, "/nix/store/") {
			return errors.New("polkit policy symlink is outside the Nix store")
		}
		info, err = os.Stat(selected)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || !ownedBy(info, ownerUID) || info.Size() <= 0 || info.Size() > 1<<20 {
		return errors.New("polkit policy metadata is unsafe")
	}
	data, err := os.ReadFile(selected)
	if err != nil || bytes.Count(data, []byte("<action id=")) != 1 || !bytes.Contains(data, []byte(`<action id="org.private-vm.usb.prepare">`)) {
		return errors.New("polkit policy action contract mismatch")
	}
	return nil
}

func ownedBy(info os.FileInfo, ownerUID uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == ownerUID
}

func integrationFailure(strict bool, code, summary, remediation string) Diagnostic {
	if strict {
		return blocking(code, summary, remediation)
	}
	return warning(code, summary, remediation)
}

func checkIPv6Forwarding(add func(Diagnostic), path string) {
	value, err := os.ReadFile(path)
	if err != nil {
		add(blocking(
			"HOST_IPV6_FORWARDING_STATUS_UNKNOWN",
			"The host IPv6 forwarding prerequisite could not be inspected.",
			"Install the private-vm host integration, apply its sysctl configuration, and retry.",
		))
		return
	}
	if strings.TrimSpace(string(value)) != "1" {
		add(blocking(
			"HOST_IPV6_FORWARDING_DISABLED",
			"Host IPv6 forwarding is disabled.",
			"Enable net.ipv6.conf.all.forwarding through the private-vm host integration, reboot or apply the declarative configuration, and retry.",
		))
		return
	}
	add(info("HOST_IPV6_FORWARDING_VERIFIED", "The host IPv6 forwarding prerequisite is enabled."))
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

// checkSparseCapability derives read-only evidence from the filesystem type.
// Doctor intentionally does not create a probe file in scratch: even a
// temporary write would violate its no-mutation contract. Unknown filesystem
// types therefore fail closed instead of being guessed sparse-capable.
func checkSparseCapability(add func(Diagnostic), path string) {
	path = nearestExisting(path)
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		add(blocking("SPARSE_FILE_SUPPORT_UNKNOWN", "Scratch sparse-file capability could not be inspected without mutation.", "Place scratch on ext4, XFS, Btrfs or tmpfs and retry."))
		return
	}
	if !knownSparseFilesystem(stat.Type) {
		add(blocking("SPARSE_FILE_SUPPORT_UNKNOWN", "The scratch filesystem is not in the read-only sparse-capability allowlist.", "Place scratch on ext4, XFS, Btrfs or tmpfs; Doctor never writes a probe file."))
		return
	}
	add(info("SPARSE_FILE_SUPPORT_VERIFIED", "The scratch filesystem type has reviewed sparse-file semantics."))
}

func knownSparseFilesystem(filesystemType int64) bool {
	switch filesystemType {
	case extFilesystemMagic, btrfsMagic, xfsMagic, tmpfsMagic:
		return true
	default:
		return false
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

func checkQEMU(parent context.Context, add func(Diagnostic), binary string) {
	checkQEMUWithRunner(parent, add, binary, boundedOutput)
}

func checkQEMUWithRunner(parent context.Context, add func(Diagnostic), binary string, run probeCommand) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	version, err := run(ctx, binary, "--version")
	if err != nil || !strings.Contains(string(version), "QEMU emulator version") {
		clear(version)
		add(blocking("QEMU_UNSUPPORTED", "QEMU version probing failed.", "Install QEMU 9.2 or newer with SPICE and VSOCK support."))
		return
	}
	versionSupported := supportedQEMUVersion(string(version))
	clear(version)
	if !versionSupported {
		add(blocking("QEMU_UNSUPPORTED", "QEMU is older than 9.2.", "Install a supported QEMU release."))
		return
	}
	machines, machineErr := run(ctx, binary, "-machine", "help")
	devices, deviceErr := run(ctx, binary, "-device", "help")
	spice, _ := run(ctx, binary, "-spice", "help")
	featuresPresent := true
	for _, feature := range []string{"q35", "vhost-vsock", "virtio-net", "virtio-blk", "usb-host"} {
		if !containsASCIIFold(machines, feature) && !containsASCIIFold(devices, feature) {
			featuresPresent = false
			break
		}
	}
	spicePresent := containsASCIIFold(spice, "spice options:") && containsASCIIFold(spice, "unix=<") &&
		containsASCIIFold(spice, "disable-copy-paste=<") && containsASCIIFold(spice, "disable-agent-file-xfer=<")
	clear(machines)
	clear(devices)
	clear(spice)
	if !featuresPresent {
		add(blocking("QEMU_UNSUPPORTED", "QEMU is missing a required q35, VSOCK, VirtIO or USB-host feature.", "Install QEMU with KVM, SPICE, VSOCK, VirtIO and USB host support."))
		return
	}
	if machineErr != nil || deviceErr != nil || !spicePresent {
		add(blocking("QEMU_UNSUPPORTED", "QEMU feature probing returned an error.", "Install the complete supported QEMU package."))
		return
	}
	add(info("QEMU_FEATURES_VERIFIED", "QEMU version and required features are present."))
}

func supportedQEMUVersion(output string) bool {
	fields := strings.Fields(output)
	for index, field := range fields {
		if field != "version" || index+1 >= len(fields) {
			continue
		}
		parts := strings.Split(fields[index+1], ".")
		if len(parts) < 2 {
			return false
		}
		major, majorErr := strconv.Atoi(parts[0])
		minor, minorErr := strconv.Atoi(parts[1])
		return majorErr == nil && minorErr == nil && (major > 9 || major == 9 && minor >= 2)
	}
	return false
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
