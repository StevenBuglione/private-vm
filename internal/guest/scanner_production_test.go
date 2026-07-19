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
	calls     [][]string
	cause     error
	stopCause error
}

func (command *failedStartScannerCommand) Run(_ context.Context, path string, arguments []string, _ uint64) ([]byte, error) {
	command.calls = append(command.calls, append([]string{path}, arguments...))
	if slices.Contains(arguments, "start") {
		return nil, command.cause
	}
	if slices.Contains(arguments, "stop") {
		return nil, command.stopCause
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

func TestProductionOfflineBootStagerUsesOnlyFixedUnit(t *testing.T) {
	command := &recordingScannerCommand{}
	stager := productionScannerOfflineBootStager{command: command, systemctl: "/fixed/systemctl"}
	if err := stager.Stage(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"/fixed/systemctl", "start", productionScannerOfflineUnit}}
	if !slices.EqualFunc(command.calls, want, func(left, right []string) bool { return slices.Equal(left, right) }) {
		t.Fatalf("fixed command sequence = %#v", command.calls)
	}
}

func TestProductionOfflineBootStagerCleansFailureCancellationAndTimeout(t *testing.T) {
	for _, test := range []struct {
		name     string
		cause    error
		wantCode string
	}{
		{name: "failure", cause: errors.New("injected"), wantCode: "SCANNER_OFFLINE_BOOT_STAGE_FAILED"},
		{name: "cancellation", cause: context.Canceled},
		{name: "timeout", cause: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := &failedStartScannerCommand{cause: test.cause}
			stager := productionScannerOfflineBootStager{command: command, systemctl: "/fixed/systemctl"}
			err := stager.Stage(t.Context())
			if test.wantCode != "" {
				if scan.ErrorCode(err) != test.wantCode {
					t.Fatalf("Stage() error = %v", err)
				}
			} else if !errors.Is(err, test.cause) {
				t.Fatalf("Stage() error = %v, want %v", err, test.cause)
			}
			if len(command.calls) != 2 || !slices.Equal(command.calls[1], []string{"/fixed/systemctl", "stop", productionScannerOfflineUnit}) {
				t.Fatalf("failure cleanup calls = %#v", command.calls)
			}
		})
	}
}

func TestProductionOfflineBootStagerFailsClosedWhenCleanupCannotConverge(t *testing.T) {
	command := &failedStartScannerCommand{cause: errors.New("start failed"), stopCause: errors.New("stop failed")}
	stager := productionScannerOfflineBootStager{command: command, systemctl: "/fixed/systemctl"}
	if err := stager.Stage(t.Context()); scan.ErrorCode(err) != "SCANNER_OFFLINE_BOOT_STAGE_CLEANUP_INCOMPLETE" {
		t.Fatalf("Stage() error = %v", err)
	}
}

func TestProductionUpdateBootProbeRequiresScopedVPNMarkerAndPersistsOverlayIdentity(t *testing.T) {
	directory := t.TempDir()
	phase := filepath.Join(directory, "phase.json")
	bootMode := filepath.Join(directory, "boot-mode")
	if err := os.WriteFile(phase, []byte(`{"schema_version":1,"role":"scanner","phase":"definitions-update","network_device_policy":"proton-only","quarantine_device_policy":"forbidden","definitions_update":"enabled"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bootMode, []byte("definitions-update"), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := &productionScannerBootProbe{
		phasePath: phase, bootModePath: bootMode, stateDirectory: directory,
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

func TestProductionBootProbeRejectsMissingUnknownAndMismatchedQEMUMode(t *testing.T) {
	directory := t.TempDir()
	phase := filepath.Join(directory, "phase.json")
	if err := os.WriteFile(phase, []byte(`{"schema_version":1,"role":"scanner","phase":"definitions-update","network_device_policy":"proton-only","quarantine_device_policy":"forbidden","definitions_update":"enabled"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		mode *string
	}{
		{name: "missing"},
		{name: "unknown", mode: stringPointer("arbitrary")},
		{name: "mismatch", mode: stringPointer("scan-offline")},
	} {
		t.Run(test.name, func(t *testing.T) {
			bootMode := filepath.Join(t.TempDir(), "boot-mode")
			if test.mode != nil {
				if err := os.WriteFile(bootMode, []byte(*test.mode), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			probe := &productionScannerBootProbe{
				phasePath: phase, bootModePath: bootMode, stateDirectory: directory,
				quarantineRoot: filepath.Join(directory, "absent-mount"), quarantineDevice: filepath.Join(directory, "absent-device"),
			}
			if _, err := probe.Evidence(t.Context()); scan.ErrorCode(err) != "SCANNER_BOOT_MODE_MISMATCH" {
				t.Fatalf("Evidence() error = %v", err)
			}
		})
	}
}

func TestScannerBootModeAcceptsOnlyExactQEMUStringEncoding(t *testing.T) {
	for _, test := range []struct {
		name    string
		content []byte
		want    string
	}{
		{name: "raw", content: []byte("scan-offline"), want: "scan-offline"},
		{name: "qemu-nul", content: append([]byte("definitions-update"), 0), want: "definitions-update"},
		{name: "newline", content: []byte("scan-offline\n")},
		{name: "two-nuls", content: append([]byte("scan-offline"), 0, 0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "boot-mode")
			if err := os.WriteFile(path, test.content, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := loadScannerBootMode(path)
			if test.want == "" {
				if err == nil {
					t.Fatalf("loadScannerBootMode() = %q", got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("loadScannerBootMode() = %q, %v", got, err)
			}
		})
	}
}

func stringPointer(value string) *string { return &value }

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

func TestProductionArchiveRecursivelyScansReconstructsAndCleans(t *testing.T) {
	inner := productionZIPBytes(t, map[string][]byte{"document.txt": []byte("one\r\ntwo\r\n")})
	outer := productionZIPBytes(t, map[string][]byte{"nested.zip": inner})
	adapter, inventory, summary, selected, parent := productionArchiveFixture(t, "payload.zip", outer, productionCleanScanner{})

	result, err := adapter.Reconstruct(t.Context(), inventory, summary, selected)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Outputs) != 1 || len(result.Findings) != 0 || len(result.Archives) != 2 {
		t.Fatalf("recursive reconstruction = %#v", result)
	}
	depths := []uint32{result.Archives[0].Depth, result.Archives[1].Depth}
	slices.Sort(depths)
	if !slices.Equal(depths, []uint32{0, 1}) {
		t.Fatalf("archive depths = %v", depths)
	}
	reader, err := adapter.OpenApproved(t.Context(), result.Outputs[0].OutputID)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || string(data) != "one\ntwo\n" {
		t.Fatalf("archive output = %q read=%v close=%v", data, readErr, closeErr)
	}
	assertNoProductionExtractions(t, parent)
	if err := adapter.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cleanup entries=%v err=%v", entries, err)
	}
}

func TestProductionArchiveContainmentFailuresAreCompleteAndCleaned(t *testing.T) {
	encrypted := productionZIPBytes(t, map[string][]byte{"document.txt": []byte("text")})
	markProductionZIPEncrypted(t, encrypted)
	bomb := productionZIPBytes(t, map[string][]byte{"document.txt": bytes.Repeat([]byte("A"), 256<<10)})
	nested := productionZIPBytes(t, map[string][]byte{"document.txt": []byte("text")})
	for depth := 0; depth < 5; depth++ {
		nested = productionZIPBytes(t, map[string][]byte{"nested.zip": nested})
	}
	typeMismatch := productionZIPBytes(t, map[string][]byte{"document.pdf": []byte("plain text")})
	traversal := productionZIPBytes(t, map[string][]byte{"../escape.txt": []byte("blocked")})

	for _, test := range []struct {
		name    string
		payload []byte
		code    string
	}{
		{"traversal", traversal, "ARCHIVE_PATH_UNSAFE"},
		{"encrypted", encrypted, "ARCHIVE_ENCRYPTED"},
		{"bomb", bomb, "ARCHIVE_LIMIT_REACHED"},
		{"nested-limit", nested, "ARCHIVE_LIMIT_REACHED"},
		{"type-mismatch", typeMismatch, "TYPE_MISMATCH"},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, inventory, summary, selected, parent := productionArchiveFixture(t, "payload.zip", test.payload, productionCleanScanner{})
			result, err := adapter.Reconstruct(t.Context(), inventory, summary, selected)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Outputs) != 0 || !hasProductionFinding(result.Findings, test.code) {
				t.Fatalf("containment result = %#v", result)
			}
			assertNoProductionExtractions(t, parent)
			if err := adapter.Cleanup(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type productionScannerFunc func(context.Context, io.Reader, uint64) (scan.ClamResult, error)

func (function productionScannerFunc) Scan(ctx context.Context, reader io.Reader, expected uint64) (scan.ClamResult, error) {
	return function(ctx, reader, expected)
}

func TestProductionArchiveCancellationAndTimeoutRemoveExtraction(t *testing.T) {
	payload := productionZIPBytes(t, map[string][]byte{"document.txt": []byte("bounded")})
	for _, test := range []struct {
		name string
		run  func(*testing.T, *productionScannerReconstruction, scan.Inventory, scan.ScanSummary, policy.Policy) error
	}{
		{"cancellation", func(t *testing.T, adapter *productionScannerReconstruction, inventory scan.Inventory, summary scan.ScanSummary, selected policy.Policy) error {
			ctx, cancel := context.WithCancel(t.Context())
			adapter.scanner = productionScannerFunc(func(context.Context, io.Reader, uint64) (scan.ClamResult, error) {
				cancel()
				return scan.ClamResult{}, context.Canceled
			})
			_, err := adapter.Reconstruct(ctx, inventory, summary, selected)
			return err
		}},
		{"timeout", func(t *testing.T, adapter *productionScannerReconstruction, inventory scan.Inventory, summary scan.ScanSummary, selected policy.Policy) error {
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			called := false
			adapter.scanner = productionScannerFunc(func(ctx context.Context, _ io.Reader, _ uint64) (scan.ClamResult, error) {
				called = true
				<-ctx.Done()
				return scan.ClamResult{}, ctx.Err()
			})
			_, err := adapter.Reconstruct(ctx, inventory, summary, selected)
			if !called {
				t.Fatal("deadline expired before the extracted member scan began")
			}
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, inventory, summary, selected, parent := productionArchiveFixture(t, "payload.zip", payload, productionCleanScanner{})
			err := test.run(t, adapter, inventory, summary, selected)
			if test.name == "cancellation" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation error = %v", err)
			}
			if test.name == "timeout" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("timeout error = %v", err)
			}
			assertNoProductionExtractions(t, parent)
			if len(adapter.outputs) != 0 {
				t.Fatal("failed recursive scan retained an output")
			}
		})
	}
}

func productionArchiveFixture(t *testing.T, name string, payload []byte, memberScanner ScannerContentScanner) (*productionScannerReconstruction, scan.Inventory, scan.ScanSummary, policy.Policy, string) {
	t.Helper()
	parent := productionTmpfs(t)
	quarantine := t.TempDir()
	if err := os.WriteFile(filepath.Join(quarantine, name), payload, 0o600); err != nil {
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
		classifier: classifier, scanner: memberScanner, outputs: make(map[string]*scan.ReconstructedOutput),
	}
	return adapter, inventory, summary, selected, parent
}

func productionZIPBytes(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0o600)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(members[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func markProductionZIPEncrypted(t *testing.T, archive []byte) {
	t.Helper()
	local := bytes.Index(archive, []byte("PK\x03\x04"))
	central := bytes.Index(archive, []byte("PK\x01\x02"))
	if local < 0 || central < 0 {
		t.Fatal("ZIP headers missing")
	}
	archive[local+6] |= 1
	archive[central+8] |= 1
}

func hasProductionFinding(findings []scan.Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code && finding.Severity == scan.SeverityBlocking {
			return true
		}
	}
	return false
}

func assertNoProductionExtractions(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "private-vm-extract-") {
			t.Fatalf("extraction remains after recursive processing: %s", entry.Name())
		}
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
