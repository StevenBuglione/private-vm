package guest

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/policy"
	"github.com/StevenBuglione/private-vm/internal/scan"
)

type recordingScannerCommand struct {
	calls  [][]string
	output []byte
	err    error
}

type failedStartScannerCommand struct {
	calls [][]string
	cause error
}

func (command *failedStartScannerCommand) Run(_ context.Context, path string, arguments []string, _ uint64) ([]byte, error) {
	command.calls = append(command.calls, append([]string{path}, arguments...))
	if slices.Contains(arguments, "start") {
		return nil, command.cause
	}
	return nil, nil
}

func (command *recordingScannerCommand) Run(_ context.Context, path string, arguments []string, _ uint64) ([]byte, error) {
	call := append([]string{path}, arguments...)
	command.calls = append(command.calls, call)
	if slices.Contains(arguments, "--version") {
		return bytes.Clone(command.output), command.err
	}
	return nil, command.err
}

func TestProductionDefinitionUpdaterUsesOnlyFixedUnitsAndCompleteOfficialEvidence(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 20, 0, 0, 0, time.UTC)
	for _, name := range []string{"main.cvd", "daily.cld", "bytecode.cvd"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("verified-definition-fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	command := &recordingScannerCommand{output: []byte("ClamAV 1.4.3/27660/Sun Jul 19 00:00:00 2026\n")}
	updater := productionDefinitionUpdater{
		command: command, systemctl: "/fixed/systemctl", clamscan: "/fixed/clamscan",
		databaseDirectory: directory, now: func() time.Time { return now },
	}
	evidence, err := updater.Update(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Official || !evidence.Compatible || !evidence.Complete || evidence.EngineVersion != "1.4.3" || evidence.DatabaseVersion != "27660" {
		t.Fatalf("definition evidence = %#v", evidence)
	}
	want := [][]string{
		{"/fixed/systemctl", "start", "private-vm-scanner-definitions-update.service"},
		{"/fixed/clamscan", "--version"},
		{"/fixed/systemctl", "restart", "clamav-daemon.service"},
	}
	if !slices.EqualFunc(command.calls, want, func(left, right []string) bool { return slices.Equal(left, right) }) {
		t.Fatalf("fixed command sequence = %#v", command.calls)
	}
}

func TestProductionDefinitionUpdaterUsesOldestRequiredDatabaseTimestamp(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 20, 0, 0, 0, time.UTC)
	ages := map[string]time.Duration{
		"main.cvd":     -time.Hour,
		"daily.cld":    -48 * time.Hour,
		"bytecode.cvd": -time.Minute,
	}
	for name, age := range ages {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("verified-definition-fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, now.Add(age), now.Add(age)); err != nil {
			t.Fatal(err)
		}
	}
	updater := productionDefinitionUpdater{
		command:   &recordingScannerCommand{output: []byte("ClamAV 1.4.3/27660/Sun Jul 19 00:00:00 2026\n")},
		systemctl: "/fixed/systemctl", clamscan: "/fixed/clamscan",
		databaseDirectory: directory, now: func() time.Time { return now },
	}
	evidence, err := updater.Update(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(-48 * time.Hour); !evidence.UpdatedAt.Equal(want) {
		t.Fatalf("required definition timestamp = %s, want %s", evidence.UpdatedAt, want)
	}
	manager := scan.DefinitionManager{Now: func() time.Time { return now }}
	if code := scan.ErrorCode(manager.ValidateCurrent(evidence)); code != "SCANNER_DEFINITIONS_STALE" {
		t.Fatalf("stale required daily database was not blocking: %s", code)
	}
}

func TestProductionDefinitionUpdaterStopsFixedUnitAfterFailureCancellationAndTimeout(t *testing.T) {
	for _, test := range []struct {
		name  string
		cause error
	}{{"failure", errors.New("injected")}, {"cancellation", context.Canceled}, {"timeout", context.DeadlineExceeded}} {
		t.Run(test.name, func(t *testing.T) {
			command := &failedStartScannerCommand{cause: test.cause}
			updater := productionDefinitionUpdater{command: command, systemctl: "/fixed/systemctl", clamscan: "/fixed/clamscan", now: time.Now}
			_, err := updater.Update(t.Context())
			if scan.ErrorCode(err) != "SCANNER_UPDATE_FAILED" || len(command.calls) != 2 || !slices.Equal(command.calls[1], []string{"/fixed/systemctl", "stop", "private-vm-scanner-definitions-update.service"}) {
				t.Fatalf("failure cleanup calls=%#v err=%v", command.calls, err)
			}
		})
	}
}

func TestProductionUpdateBootProbeRequiresScopedVPNMarkerAndPersistsOverlayIdentity(t *testing.T) {
	directory := t.TempDir()
	phase := filepath.Join(directory, "phase.json")
	if err := os.WriteFile(phase, []byte(`{"schema_version":1,"role":"scanner","phase":"definitions-update","network_device_policy":"proton-only","quarantine_device_policy":"forbidden","definitions_update":"enabled"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := &productionScannerBootProbe{
		phasePath: phase, stateDirectory: directory,
		quarantineRoot: filepath.Join(directory, "absent-mount"), quarantineDevice: filepath.Join(directory, "absent-device"),
	}
	unverified, err := probe.Evidence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if unverified.VPNVerified || unverified.Phase != scan.PhaseUpdate || unverified.OverlayIdentity == "" {
		t.Fatalf("unverified update evidence = %#v", unverified)
	}
	verified, err := probe.Evidence(scannerVPNVerifiedContext(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	if !verified.VPNVerified || verified.OverlayIdentity != unverified.OverlayIdentity {
		t.Fatalf("verified update evidence = %#v", verified)
	}
}

type productionCleanScanner struct{}

func (productionCleanScanner) Scan(ctx context.Context, reader io.Reader, expected uint64) (scan.ClamResult, error) {
	written, err := io.Copy(io.Discard, io.LimitReader(reader, int64(expected)+1))
	if err != nil || uint64(written) != expected || ctx.Err() != nil {
		return scan.ClamResult{}, context.Canceled
	}
	return scan.ClamResult{Clean: true, Finding: scan.Finding{Code: "CLAMAV_CLEAN", Severity: scan.SeverityInfo, Detail: "complete"}}, nil
}

func TestProductionReconstructionApprovesOneTextOutputAndCleansIt(t *testing.T) {
	parent := productionTmpfs(t)
	quarantine := t.TempDir()
	if err := os.WriteFile(filepath.Join(quarantine, "document.txt"), []byte("one\r\ntwo\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	selected, err := policy.Load(filepath.Join("..", "..", "examples", "policy.safe.toml"))
	if err != nil {
		t.Fatal(err)
	}
	classifier := scan.ConservativeMIMEClassifier{}
	inventory, err := scan.BuildInventory(t.Context(), quarantine, scan.InventoryLimits{
		MaxFiles: selected.Limits().MaxFiles(), MaxInputBytes: selected.Limits().MaxInputBytes(),
	}, classifier)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := scan.ScanInventory(t.Context(), inventory, func(ctx context.Context, entry scan.InventoryEntry) (io.ReadCloser, error) {
		return scan.OpenInventoryEntry(ctx, quarantine, entry)
	}, productionCleanScanner{})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &productionScannerReconstruction{
		root: quarantine,
		sandbox: scan.ExtractionSandbox{
			ParentPath: parent, Tmpfs: true, PrivateMountNamespace: true, WorkerUID: os.Geteuid(), WorkerGID: os.Getegid(),
		},
		classifier: classifier, scanner: productionCleanScanner{}, outputs: make(map[string]*scan.ReconstructedOutput),
	}
	result, err := adapter.Reconstruct(t.Context(), inventory, summary, selected)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outputs) != 1 || len(result.Findings) != 0 || !result.OutputRescanComplete {
		t.Fatalf("reconstruction = %#v", result)
	}
	reader, err := adapter.OpenApproved(t.Context(), result.Outputs[0].OutputID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil || string(data) != "one\ntwo\n" {
		t.Fatalf("sanitized output = %q err=%v close=%v", data, err, closeErr)
	}
	if err := adapter.Cleanup(t.Context()); err != nil || len(adapter.outputs) != 0 {
		t.Fatal("volatile reconstruction cleanup did not converge")
	}
}

func TestProductionArchiveTraversalBecomesBlockingCompleteFinding(t *testing.T) {
	parent := productionTmpfs(t)
	quarantine := t.TempDir()
	path := filepath.Join(quarantine, "payload.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	member, err := archive.Create("../escape.txt")
	if err == nil {
		_, err = member.Write([]byte("blocked"))
	}
	if closeArchiveErr := archive.Close(); err == nil {
		err = closeArchiveErr
	}
	if closeFileErr := file.Close(); err == nil {
		err = closeFileErr
	}
	if err != nil {
		t.Fatal(err)
	}
	selected, err := policy.Load(filepath.Join("..", "..", "examples", "policy.safe.toml"))
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := scan.BuildInventory(t.Context(), quarantine, scan.InventoryLimits{MaxFiles: 10, MaxInputBytes: 1 << 20}, scan.ConservativeMIMEClassifier{})
	if err != nil {
		t.Fatal(err)
	}
	summary, err := scan.ScanInventory(t.Context(), inventory, func(ctx context.Context, entry scan.InventoryEntry) (io.ReadCloser, error) {
		return scan.OpenInventoryEntry(ctx, quarantine, entry)
	}, productionCleanScanner{})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &productionScannerReconstruction{
		root: quarantine, sandbox: scan.ExtractionSandbox{ParentPath: parent, Tmpfs: true, PrivateMountNamespace: true, WorkerUID: os.Geteuid(), WorkerGID: os.Getegid()},
		classifier: scan.ConservativeMIMEClassifier{}, scanner: productionCleanScanner{}, outputs: make(map[string]*scan.ReconstructedOutput),
	}
	result, err := adapter.Reconstruct(t.Context(), inventory, summary, selected)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outputs) != 0 || len(result.Findings) != 1 || result.Findings[0].Severity != scan.SeverityBlocking || !strings.HasPrefix(result.Findings[0].Code, "ARCHIVE_") {
		t.Fatalf("archive rejection = %#v", result)
	}
}

func productionTmpfs(t *testing.T) string {
	t.Helper()
	parent := "/dev/shm"
	if info, err := os.Stat(parent); err != nil || !info.IsDir() {
		t.Skip("tmpfs test parent unavailable")
	}
	directory, err := os.MkdirTemp(parent, "private-vm-scanner-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}
