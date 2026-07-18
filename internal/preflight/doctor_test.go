package preflight

import "testing"

func TestDoctorAlwaysReturnsDiagnostics(t *testing.T) {
	report := (Doctor{}).Run()
	if len(report.Diagnostics) == 0 {
		t.Fatal("expected at least one diagnostic")
	}
}
