package preflight

import (
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
