package preflight

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorAlwaysReturnsDiagnostics(t *testing.T) {
	report := (Doctor{}).Run()
	if len(report.Diagnostics) == 0 {
		t.Fatal("expected at least one diagnostic")
	}
}

func TestCheckIPv6Forwarding(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		value    string
		missing  bool
		wantCode string
		severity Severity
	}{
		{name: "enabled", value: "1\n", wantCode: "HOST_IPV6_FORWARDING_VERIFIED", severity: SeverityInfo},
		{name: "disabled", value: "0\n", wantCode: "HOST_IPV6_FORWARDING_DISABLED", severity: SeverityBlocking},
		{name: "noncanonical", value: "2\n", wantCode: "HOST_IPV6_FORWARDING_DISABLED", severity: SeverityBlocking},
		{name: "unavailable", missing: true, wantCode: "HOST_IPV6_FORWARDING_STATUS_UNKNOWN", severity: SeverityBlocking},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "forwarding")
			if !test.missing {
				if err := os.WriteFile(path, []byte(test.value), 0o600); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
			}
			var diagnostics []Diagnostic
			checkIPv6Forwarding(func(diagnostic Diagnostic) {
				diagnostics = append(diagnostics, diagnostic)
			}, path)
			if len(diagnostics) != 1 || diagnostics[0].Code != test.wantCode || diagnostics[0].Severity != test.severity {
				t.Fatalf("diagnostics = %#v", diagnostics)
			}
		})
	}
}

func TestArchitectureAndKernelIdentityContract(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		check      func(func(Diagnostic))
		wantCode   string
		wantStatus Severity
	}{
		{name: "amd64", check: func(add func(Diagnostic)) { checkArchitecture(add, "amd64") }, wantCode: "HOST_ARCH_X86_64", wantStatus: SeverityInfo},
		{name: "arm64 outside v1", check: func(add func(Diagnostic)) { checkArchitecture(add, "arm64") }, wantCode: "HOST_ARCH_UNSUPPORTED", wantStatus: SeverityBlocking},
		{name: "minimum kernel", check: func(add func(Diagnostic)) { checkKernelRelease(add, "6.6.0") }, wantCode: "KERNEL_VERSION_SUPPORTED", wantStatus: SeverityInfo},
		{name: "new kernel suffix", check: func(add func(Diagnostic)) { checkKernelRelease(add, "6.18.12-custom") }, wantCode: "KERNEL_VERSION_SUPPORTED", wantStatus: SeverityInfo},
		{name: "old kernel", check: func(add func(Diagnostic)) { checkKernelRelease(add, "6.5.19") }, wantCode: "KERNEL_UNSUPPORTED", wantStatus: SeverityBlocking},
		{name: "malformed kernel", check: func(add func(Diagnostic)) { checkKernelRelease(add, "private") }, wantCode: "KERNEL_STATUS_UNKNOWN", wantStatus: SeverityBlocking},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var diagnostic Diagnostic
			test.check(func(value Diagnostic) { diagnostic = value })
			if diagnostic.Code != test.wantCode || diagnostic.Severity != test.wantStatus {
				t.Fatalf("diagnostic = %#v", diagnostic)
			}
		})
	}
}

func TestNetworkNamespaceIdentityIsReadOnlyAndStrict(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	valid := filepath.Join(root, "valid")
	if err := os.Symlink("net:[4026531840]", valid); err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(root, "invalid")
	if err := os.WriteFile(invalid, []byte("net:[1]"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, path, code string
		severity         Severity
	}{
		{name: "valid", path: valid, code: "NETNS_PRESENT", severity: SeverityInfo},
		{name: "regular file", path: invalid, code: "NETNS_UNAVAILABLE", severity: SeverityBlocking},
		{name: "missing", path: filepath.Join(root, "missing"), code: "NETNS_UNAVAILABLE", severity: SeverityBlocking},
	} {
		t.Run(test.name, func(t *testing.T) {
			var diagnostic Diagnostic
			checkNetworkNamespace(func(value Diagnostic) { diagnostic = value }, test.path)
			if diagnostic.Code != test.code || diagnostic.Severity != test.severity {
				t.Fatalf("diagnostic = %#v", diagnostic)
			}
		})
	}
}

func TestControlDeviceAndSparseFilesystemEvidence(t *testing.T) {
	t.Parallel()
	if !isCharacterDevice(os.ModeDevice|os.ModeCharDevice|0o600) || isCharacterDevice(os.ModeDevice|0o600) || isCharacterDevice(0o600) {
		t.Fatal("character-device mode classifier drifted")
	}
	for _, filesystemType := range []int64{extFilesystemMagic, btrfsMagic, xfsMagic, tmpfsMagic} {
		if !knownSparseFilesystem(filesystemType) {
			t.Fatalf("reviewed sparse filesystem %#x rejected", filesystemType)
		}
	}
	if knownSparseFilesystem(0x12345678) {
		t.Fatal("unknown filesystem guessed sparse-capable")
	}
}

func TestHostToolProbesUseOnlyBoundedReadOnlyOperations(t *testing.T) {
	t.Parallel()
	paths := make(map[string]string, len(hostToolProbes))
	outputs := make(map[string][]byte, len(hostToolProbes))
	for _, probe := range hostToolProbes {
		path := "/tools/" + probe.name
		paths[probe.name] = path
		outputs[path] = []byte(probe.markers[0] + " 1.0\n")
	}
	var calls [][]string
	run := func(_ context.Context, executable string, arguments ...string) ([]byte, error) {
		call := append([]string{executable}, arguments...)
		calls = append(calls, call)
		if executable == paths["ip"] && len(arguments) == 2 && arguments[0] == "netns" && arguments[1] == "list" {
			return nil, nil
		}
		return append([]byte(nil), outputs[executable]...), nil
	}
	var diagnostics []Diagnostic
	checkHostToolCapabilities(t.Context(), func(value Diagnostic) { diagnostics = append(diagnostics, value) }, paths, run)
	if len(diagnostics) != len(hostToolProbes) || len(calls) != len(hostToolProbes)+1 {
		t.Fatalf("diagnostics=%#v calls=%#v", diagnostics, calls)
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity != SeverityInfo {
			t.Fatalf("diagnostic = %#v", diagnostic)
		}
	}
	allowed := map[string]bool{
		"nft --version": true, "ip -Version": true, "ip netns list": true,
		"cryptsetup --version": true, "losetup --version": true,
		"mkfs.ext4 -V": true, "remote-viewer --version": true,
		"usbguard --version": true,
	}
	for _, call := range calls {
		key := filepath.Base(call[0])
		for _, argument := range call[1:] {
			key += " " + argument
		}
		if !allowed[key] {
			t.Fatalf("mutating or unreviewed probe invoked: %q", key)
		}
		delete(allowed, key)
	}
	if len(allowed) != 0 {
		t.Fatalf("required probes were skipped: %#v", allowed)
	}
}

func TestHostToolProbeClearsCapturedOutput(t *testing.T) {
	t.Parallel()
	output := []byte("nftables v1.1.6\n")
	probe := hostToolProbe{arguments: []string{"--version"}, markers: []string{"nftables"}}
	if !runHostToolProbe(t.Context(), "/tools/nft", probe, func(context.Context, string, ...string) ([]byte, error) {
		return output, nil
	}) {
		t.Fatal("valid bounded probe was rejected")
	}
	for index, value := range output {
		if value != 0 {
			t.Fatalf("captured output byte %d was not cleared", index)
		}
	}
}

func TestHostToolProbeFailuresAreBlockingAndRedacted(t *testing.T) {
	t.Parallel()
	paths := map[string]string{"nft": "/tools/nft"}
	var diagnostics []Diagnostic
	checkHostToolCapabilities(t.Context(), func(value Diagnostic) { diagnostics = append(diagnostics, value) }, paths,
		func(context.Context, string, ...string) ([]byte, error) {
			return []byte("private raw output"), errors.New("failed")
		})
	if len(diagnostics) != 1 || diagnostics[0].Code != "NFTABLES_UNSUPPORTED" || diagnostics[0].Severity != SeverityBlocking ||
		strings.Contains(diagnostics[0].Summary, "private") || strings.Contains(diagnostics[0].Summary, "raw output") {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestQEMUAcceptsIntentionalSpiceHelpExitAndRequiresUnixSecurityOptions(t *testing.T) {
	t.Parallel()
	outputs := map[string][]byte{
		"--version":     []byte("QEMU emulator version 10.2.4\n"),
		"-machine help": []byte("q35 Standard PC\n"),
		"-device help":  []byte("vhost-vsock virtio-net virtio-blk usb-host\n"),
		"-spice help":   []byte("spice options:\n  unix=<bool>\n  disable-copy-paste=<bool>\n  disable-agent-file-xfer=<bool>\n"),
	}
	run := func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		key := strings.Join(arguments, " ")
		if key == "-spice help" {
			return append([]byte(nil), outputs[key]...), errors.New("QEMU help exit status 1")
		}
		return append([]byte(nil), outputs[key]...), nil
	}
	var diagnostics []Diagnostic
	checkQEMUWithRunner(t.Context(), func(value Diagnostic) { diagnostics = append(diagnostics, value) }, "/tools/qemu-system-x86_64", run)
	if len(diagnostics) != 1 || diagnostics[0].Code != "QEMU_FEATURES_VERIFIED" || diagnostics[0].Severity != SeverityInfo {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}

	outputs["-spice help"] = []byte("spice options:\n  port=<num>\n")
	diagnostics = nil
	checkQEMUWithRunner(t.Context(), func(value Diagnostic) { diagnostics = append(diagnostics, value) }, "/tools/qemu-system-x86_64", run)
	if len(diagnostics) != 1 || diagnostics[0].Code != "QEMU_UNSUPPORTED" || diagnostics[0].Severity != SeverityBlocking {
		t.Fatalf("missing Unix SPICE controls diagnostics = %#v", diagnostics)
	}
}

func TestQEMUProbeClearsCapturedOutput(t *testing.T) {
	t.Parallel()
	outputs := map[string][]byte{
		"--version":     []byte("QEMU emulator version 10.2.4\n"),
		"-machine help": []byte("q35 Standard PC\n"),
		"-device help":  []byte("vhost-vsock virtio-net virtio-blk usb-host\n"),
		"-spice help":   []byte("spice options:\n  unix=<bool>\n  disable-copy-paste=<bool>\n  disable-agent-file-xfer=<bool>\n"),
	}
	checkQEMUWithRunner(t.Context(), func(Diagnostic) {}, "/tools/qemu-system-x86_64",
		func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
			return outputs[strings.Join(arguments, " ")], nil
		})
	for name, output := range outputs {
		for index, value := range output {
			if value != 0 {
				t.Fatalf("%s captured output byte %d was not cleared", name, index)
			}
		}
	}
}

func TestQEMUVersionFloorIsNinePointTwo(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		version string
		want    bool
	}{
		{version: "QEMU emulator version 9.1.9", want: false},
		{version: "QEMU emulator version 9.2.0", want: true},
		{version: "QEMU emulator version 10.2.4", want: true},
		{version: "QEMU emulator version 9", want: false},
		{version: "unexpected", want: false},
	} {
		if got := supportedQEMUVersion(test.version); got != test.want {
			t.Fatalf("supportedQEMUVersion(%q)=%t want %t", test.version, got, test.want)
		}
	}
}

func TestInstalledIntegrationStrictAndCompatibilityModes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		strict   bool
		severity Severity
	}{
		{name: "strict", strict: true, severity: SeverityBlocking},
		{name: "compatibility", strict: false, severity: SeverityWarning},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			probe := &installationProbe{
				runtimeDirectory: filepath.Join(root, "run"),
				controlSocket:    filepath.Join(root, "run", "control.sock"),
				configFile:       filepath.Join(root, "config.toml"),
				policyFiles:      []string{filepath.Join(root, "policy.xml")},
				systemctl:        "/usr/bin/systemctl",
				ownerUID:         uint32(os.Geteuid()),
				run: func(context.Context, string, ...string) ([]byte, error) {
					return nil, errors.New("inactive")
				},
			}
			var diagnostics []Diagnostic
			checkInstalledIntegration(t.Context(), test.strict, func(diagnostic Diagnostic) {
				diagnostics = append(diagnostics, diagnostic)
			}, probe)
			if len(diagnostics) != 5 {
				t.Fatalf("diagnostics = %#v", diagnostics)
			}
			for _, diagnostic := range diagnostics {
				if diagnostic.Severity != test.severity || diagnostic.Overridable != !test.strict {
					t.Fatalf("diagnostic = %#v", diagnostic)
				}
			}
		})
	}
}

func TestInstalledIntegrationVerifiesClosedContract(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	runtimeDirectory := filepath.Join(root, "run")
	if err := os.Mkdir(runtimeDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	controlSocket := filepath.Join(runtimeDirectory, "control.sock")
	listener, err := net.Listen("unix", controlSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(controlSocket, 0o660); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(root, "config.toml")
	if err := os.WriteFile(configFile, []byte("schema_version = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policyFile := filepath.Join(root, "policy.xml")
	if err := os.WriteFile(policyFile, []byte(`<policyconfig><action id="org.private-vm.usb.prepare"></action></policyconfig>`), 0o444); err != nil {
		t.Fatal(err)
	}
	var commands [][]string
	probe := &installationProbe{
		runtimeDirectory: runtimeDirectory,
		controlSocket:    controlSocket,
		configFile:       configFile,
		policyFiles:      []string{policyFile},
		systemctl:        "/usr/bin/systemctl",
		ownerUID:         uint32(os.Geteuid()),
		run: func(_ context.Context, executable string, arguments ...string) ([]byte, error) {
			commands = append(commands, append([]string{executable}, arguments...))
			return nil, nil
		},
	}
	var diagnostics []Diagnostic
	checkInstalledIntegration(t.Context(), true, func(diagnostic Diagnostic) {
		diagnostics = append(diagnostics, diagnostic)
	}, probe)
	if len(commands) != 2 || len(diagnostics) != 5 {
		t.Fatalf("commands=%#v diagnostics=%#v", commands, diagnostics)
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity != SeverityInfo {
			t.Fatalf("diagnostic = %#v", diagnostic)
		}
	}
	if commands[0][1] != "is-active" || commands[0][2] != "--quiet" || commands[0][3] != "private-vmd.service" ||
		commands[1][1] != "is-active" || commands[1][2] != "--quiet" || commands[1][3] != "usbguard.service" {
		t.Fatalf("unexpected service probes: %#v", commands)
	}
}

func TestInstalledPolicyRejectsAdditionalAction(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "policy.xml")
	data := `<policyconfig><action id="org.private-vm.usb.prepare"></action><action id="unexpected"></action></policyconfig>`
	if err := os.WriteFile(path, []byte(data), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := verifyPolkitPolicy([]string{path}, uint32(os.Geteuid())); err == nil {
		t.Fatal("additional Polkit action accepted")
	}
}
