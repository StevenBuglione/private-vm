package policy

import "testing"

func TestSafeRulesFailClosed(t *testing.T) {
	rules := Rules{
		RejectOnMalware: true, RejectOnScanError: true,
		RejectOnSkippedFile: true, RejectEncrypted: true,
		BlockExecutables: true, BlockScripts: true, BlockDiskImages: true,
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
