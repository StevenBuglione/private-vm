package scan

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

func TestAuthenticatedReportApprovesOnlyCompleteCanonicalEvidence(t *testing.T) {
	key := reportTestKey(t, 0x41)
	report := validApprovedReport()
	envelope, err := SignReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyApproval(envelope, key)
	if err != nil {
		t.Fatal(err)
	}
	if verified.SessionID != report.SessionID || !bytes.Equal(envelope.CanonicalJSON, mustCanonicalReport(t, report)) || len(envelope.AuthenticationTag) != ScanReportMACBytes {
		t.Fatalf("verified report/envelope mismatch: %+v", verified)
	}
	for _, forbidden := range []string{"magnet", "info_hash", "torrent_id"} {
		if strings.Contains(string(envelope.CanonicalJSON), forbidden) {
			t.Fatalf("canonical report contains forbidden torrent identifier field %q", forbidden)
		}
	}
}

func TestReportTamperingWrongKeyAndNonCanonicalJSONReject(t *testing.T) {
	key := reportTestKey(t, 0x42)
	envelope, err := SignReport(validApprovedReport(), key)
	if err != nil {
		t.Fatal(err)
	}

	tampered := envelope
	tampered.CanonicalJSON = append([]byte(nil), envelope.CanonicalJSON...)
	tampered.CanonicalJSON[len(tampered.CanonicalJSON)-2] ^= 1
	if _, err := VerifyReport(tampered, key); ErrorCode(err) != "REPORT_AUTHENTICATION_FAILED" {
		t.Fatalf("tampered report error = %v", err)
	}

	wrong := reportTestKey(t, 0x43)
	if _, err := VerifyReport(envelope, wrong); ErrorCode(err) != "REPORT_AUTHENTICATION_FAILED" {
		t.Fatalf("wrong key error = %v", err)
	}

	nonCanonical := append([]byte(" "), envelope.CanonicalJSON...)
	tag, err := reportMAC(key, nonCanonical)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReport(AuthenticatedReport{CanonicalJSON: nonCanonical, AuthenticationTag: tag, Complete: true}, key); ErrorCode(err) != "REPORT_INCOMPLETE" {
		t.Fatalf("noncanonical report error = %v", err)
	}
}

func TestIncompleteRejectedAndInvalidReportsCannotApprove(t *testing.T) {
	key := reportTestKey(t, 0x44)
	incomplete := validApprovedReport()
	incomplete.Result = "error"
	incomplete.Complete = false
	incomplete.Phases.OutputRescanComplete = false
	incomplete.SanitizedOutputs = nil
	envelope, err := SignReport(incomplete, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyApproval(envelope, key); ErrorCode(err) != "REPORT_INCOMPLETE" {
		t.Fatalf("incomplete approval error = %v", err)
	}

	invalids := []ScanReport{validApprovedReport(), validApprovedReport(), validApprovedReport(), validApprovedReport()}
	invalids[0].Inputs = append(invalids[0].Inputs, invalids[0].Inputs[0])
	invalids[1].Phases.MalwareScanComplete = false
	invalids[2].Findings = []Finding{{Code: "MALWARE_DETECTED", Severity: SeverityBlocking, RelativePath: "input.pdf", Detail: "blocked"}}
	invalids[3].SanitizedOutputs[0].RescanVerdict = "SKIPPED"
	for index, report := range invalids {
		if _, err := SignReport(report, key); ErrorCode(err) != "REPORT_INCOMPLETE" {
			t.Fatalf("invalid report %d error = %v", index, err)
		}
	}
}

func TestDestroyedReportKeyFailsClosed(t *testing.T) {
	key := reportTestKey(t, 0x45)
	key.Destroy()
	if _, err := SignReport(validApprovedReport(), key); ErrorCode(err) != "REPORT_KEY_UNAVAILABLE" {
		t.Fatalf("destroyed key error = %v", err)
	}
}

func validApprovedReport() ScanReport {
	started := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	return ScanReport{
		SchemaVersion:  ScanReportSchemaVersion,
		SessionID:      "pvm-11111111111111111111111111111111",
		Policy:         "safe",
		StartedAt:      started,
		CompletedAt:    started.Add(5 * time.Minute),
		DurationMillis: 300000,
		Scanner: ReportScannerIdentity{
			ImageDigest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			SourceCommit: "0123456789abcdef0123456789abcdef01234567", GuestdVersion: "1.0.0-rc.1",
		},
		Definitions: ReportDefinitions{
			EngineVersion: "1.5.1", DatabaseVersion: "daily-28100", UpdatedAt: started.Add(-time.Hour), Official: true, Compatible: true,
		},
		Isolation: ReportIsolation{NoNetwork: true, QuarantineReadOnly: true, MountOptions: []string{"nodev", "noexec", "nosuid", "ro"}},
		Phases: ReportPhases{
			DefinitionsVerified: true, OfflineVerified: true, InventoryComplete: true,
			MalwareScanComplete: true, ArchiveInspectionComplete: true,
			ReconstructionComplete: true, OutputRescanComplete: true,
		},
		Inputs: []ReportInput{{
			LogicalName: "input.pdf", SizeBytes: 12, SHA256: strings.Repeat("a", 64), DetectedMIME: "application/pdf",
			ExtensionMIME: "application/pdf", ExtensionAgreement: true, ClamAVVerdict: "CLAMAV_CLEAN",
		}},
		Archives: []ReportArchive{},
		Findings: []Finding{{Code: "PDF_ACTIVE_CONTENT_REMOVED", Severity: SeverityInfo, RelativePath: "input.pdf", Detail: "Output was rasterized and rebuilt."}},
		SanitizedOutputs: []ReportSanitizedOutput{{
			OutputID: "scan-out-22222222222222222222222222222222", LogicalName: "input.safe.pdf", SourceSHA256: strings.Repeat("a", 64),
			SizeBytes: 20, SHA256: strings.Repeat("c", 64), DetectedMIME: "application/pdf", Transformation: "pdf-raster-rebuild-v1", RescanVerdict: "CLAMAV_CLEAN",
		}},
		Tools:  []ToolEvidence{{Name: "clamav", Version: "1.5.1"}, {Name: "ghostscript-pdfimage24", Version: "10.05.1"}},
		Result: "approved", Complete: true,
	}
}

func reportTestKey(t *testing.T, fill byte) *secret.Bytes {
	t.Helper()
	key, err := secret.New(bytes.Repeat([]byte{fill}, ScanReportMACBytes))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	return key
}

func mustCanonicalReport(t *testing.T, report ScanReport) []byte {
	t.Helper()
	encoded, err := report.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
