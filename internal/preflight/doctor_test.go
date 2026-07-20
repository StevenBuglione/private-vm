package preflight

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
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
