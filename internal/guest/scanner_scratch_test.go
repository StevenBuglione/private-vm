package guest

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/scan"
)

func validScannerScratchEvidence(uid, gid uint32) scannerScratchEvidence {
	return scannerScratchEvidence{
		matches: 1, filesystem: "tmpfs", mountRoot: "/",
		options:    map[string]bool{"rw": true, "nosuid": true, "nodev": true, "noexec": true},
		totalBytes: 512 << 20, rootUID: 0, rootGID: 0, workerUID: uid, workerGID: gid,
		rootMode: 0o711, workerMode: 0o700, sameDevice: true, distinctNode: true,
	}
}

func TestProductionScannerScratchVerifierAcceptsExactBoundedEvidence(t *testing.T) {
	verifier := productionScannerScratchVerifier{
		mountRoot: "/run/private-vm/scanner-scratch", workerRoot: "/run/private-vm/scanner-scratch/worker",
		maximumBytes: 512 << 20, workerUID: 1000, workerGID: 1000,
		collect: func(context.Context, productionScannerScratchVerifier) (scannerScratchEvidence, error) {
			return validScannerScratchEvidence(1000, 1000), nil
		},
	}
	if err := verifier.Verify(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestProductionScannerScratchVerifierFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*scannerScratchEvidence)
		err    error
	}{
		{name: "missing", mutate: func(value *scannerScratchEvidence) { value.matches = 0 }},
		{name: "ambiguous", mutate: func(value *scannerScratchEvidence) { value.matches = 2 }},
		{name: "wrong-filesystem", mutate: func(value *scannerScratchEvidence) { value.filesystem = "ext4" }},
		{name: "malformed", err: errors.New("malformed mount evidence")},
		{name: "oversized", mutate: func(value *scannerScratchEvidence) { value.totalBytes++ }},
		{name: "executable", mutate: func(value *scannerScratchEvidence) { value.options["noexec"] = false; value.options["exec"] = true }},
		{name: "worker-mode", mutate: func(value *scannerScratchEvidence) { value.workerMode = 0o755 }},
		{name: "wrong-device", mutate: func(value *scannerScratchEvidence) { value.sameDevice = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := productionScannerScratchVerifier{
				mountRoot: "/run/private-vm/scanner-scratch", workerRoot: "/run/private-vm/scanner-scratch/worker",
				maximumBytes: 512 << 20, workerUID: 1000, workerGID: 1000,
				collect: func(context.Context, productionScannerScratchVerifier) (scannerScratchEvidence, error) {
					evidence := validScannerScratchEvidence(1000, 1000)
					if test.mutate != nil {
						test.mutate(&evidence)
					}
					return evidence, test.err
				},
			}
			if code := scan.ErrorCode(verifier.Verify(t.Context())); code != "SCANNER_SCRATCH_UNVERIFIED" {
				t.Fatalf("scratch error code = %q", code)
			}
		})
	}
}

func TestProductionScannerScratchVerifierPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	verifier := productionScannerScratchVerifier{
		mountRoot: "/run/private-vm/scanner-scratch", workerRoot: "/run/private-vm/scanner-scratch/worker",
		maximumBytes: 512 << 20, workerUID: 1000, workerGID: 1000,
	}
	if err := verifier.Verify(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestScannerNixScratchContract(t *testing.T) {
	data, err := os.ReadFile("../../nix/guests/scanner.nix")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		`TemporaryFileSystem = [`,
		`/run/private-vm/scanner-scratch:rw,nosuid,nodev,noexec,size=512M,mode=0711,uid=0,gid=0`,
		`install -d -m 0700 -o private-vm-scanner -g private-vm-scanner /run/private-vm/scanner-scratch/worker`,
		`systemd.services.private-vm-guestd.serviceConfig.MemoryMax = "3G";`,
		`MemoryMax = "2G";`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("scanner.nix lacks contract %q", required)
		}
	}
	if strings.Contains(source, `MemoryMax = "6G";`) {
		t.Fatal("scanner memory ceiling exceeds its 4 GiB VM")
	}
}
