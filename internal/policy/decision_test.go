package policy

import "testing"

func TestSafeRulesFailClosed(t *testing.T) {
	rules := Rules{
		validated:       true,
		rejectOnMalware: true, rejectOnScanError: true,
		rejectOnSkippedFile: true, rejectEncrypted: true,
		blockExecutables: true, blockScripts: true, blockDiskImages: true,
	}
	for name, summary := range map[string]ScanSummary{
		"malware":   {MalwareDetected: true},
		"error":     {ScanErrors: 1},
		"skipped":   {SkippedFiles: 1},
		"encrypted": {EncryptedFiles: 1},
		"blocked":   {BlockedTypes: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if rules.Approve(summary) {
				t.Fatal("expected rejection")
			}
		})
	}
	if !rules.Approve(ScanSummary{}) {
		t.Fatal("clean summary should approve")
	}
}

func TestRulesRejectUnvalidatedAndMalformedSummaries(t *testing.T) {
	if (Rules{}).Approve(ScanSummary{}) {
		t.Fatal("zero-value rules approved a summary")
	}
	rules := Rules{validated: true, rejectOnMalware: true, rejectOnScanError: true, rejectOnSkippedFile: true, rejectEncrypted: true}
	if rules.Approve(ScanSummary{ScanErrors: -1}) {
		t.Fatal("negative counter was accepted")
	}
	if rules.Approve(ScanSummary{Findings: []Finding{{Severity: FindingSeverity("unknown")}}}) {
		t.Fatal("unknown finding severity was accepted")
	}
}
