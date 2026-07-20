package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/buildinfo"
	"github.com/StevenBuglione/private-vm/internal/config"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"github.com/StevenBuglione/private-vm/internal/preflight"
)

type invocation struct {
	id     CommandID
	intent Intent
}

type recordingInvoker struct {
	mu     sync.Mutex
	calls  []invocation
	invoke func(context.Context, CommandID, Intent) (Result, error)
}

func (invoker *recordingInvoker) Invoke(ctx context.Context, id CommandID, intent Intent) (Result, error) {
	invoker.mu.Lock()
	invoker.calls = append(invoker.calls, invocation{id: id, intent: intent})
	invoker.mu.Unlock()
	if invoker.invoke != nil {
		return invoker.invoke(ctx, id, intent)
	}
	return Result{Code: CodeAcknowledged, Data: AcknowledgementPayload{Message: "accepted"}}, nil
}

func TestVersionCommandAndRootAliasHaveIdenticalMachineOutput(t *testing.T) {
	dependencies := func(stdout, stderr *bytes.Buffer) Dependencies {
		return Dependencies{
			Stdout: stdout, Stderr: stderr,
			BuildInfo: func() buildinfo.Info {
				return buildinfo.Info{Version: "1.2.3", Commit: "abc", Date: "2026-07-18T00:00:00Z", Dirty: "false", GoVersion: "go1.26.5", OS: "linux", Arch: "amd64"}
			},
		}
	}
	var commandOut, commandErr bytes.Buffer
	if code := New(dependencies(&commandOut, &commandErr)).Execute(context.Background(), []string{"version", "--json"}); code != exitcode.OK {
		t.Fatalf("version code=%d stderr=%q", code, commandErr.String())
	}
	var aliasOut, aliasErr bytes.Buffer
	if code := New(dependencies(&aliasOut, &aliasErr)).Execute(context.Background(), []string{"--version", "--json"}); code != exitcode.OK {
		t.Fatalf("alias code=%d stderr=%q", code, aliasErr.String())
	}
	if commandOut.String() != aliasOut.String() || commandErr.Len() != 0 || aliasErr.Len() != 0 {
		t.Fatalf("command=%q/%q alias=%q/%q", commandOut.String(), commandErr.String(), aliasOut.String(), aliasErr.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(commandOut.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["code"] != "VERSION_REPORTED" || envelope["ok"] != true || len(envelope) != 4 {
		t.Fatalf("unexpected envelope: %#v", envelope)
	}
}

func TestCompleteDocumentedCommandSurface(t *testing.T) {
	app := New(Dependencies{})
	paths := []string{
		"init", "version", "doctor",
		"plan workstation", "plan torrent",
		"desktop start", "desktop connect", "desktop status", "desktop stop", "desktop restart-viewer", "desktop bundles list", "desktop bundles inspect",
		"workspace import", "workspace inbox", "workspace list", "workspace inspect", "workspace export", "workspace verify", "workspace discard",
		"torrent start", "torrent add", "torrent metadata", "torrent select", "torrent plan", "torrent download", "torrent pause", "torrent resume", "torrent status", "torrent complete",
		"scan start", "scan status", "scan report", "scan approve", "scan reject",
		"vpn import", "vpn inspect", "vpn test", "vpn rotate", "vpn remove",
		"usb list", "usb inspect", "usb enroll", "usb prepare", "usb export", "usb verify", "usb forget",
		"images list", "images sync", "images pull", "images verify", "images inspect", "images build", "images test", "images prune",
		"session list", "session status", "session report", "session stop", "session abort", "session cleanup",
		"policy list", "policy show", "policy validate",
		"run workstation", "run torrent", "run scanner",
		"system status", "system install", "system uninstall", "system diagnostics",
		"completion bash", "completion zsh", "completion fish",
	}
	for _, path := range paths {
		command, remaining, err := app.root.Find(strings.Fields(path))
		if err != nil || command == app.root || command.CommandPath() != "private-vm "+path || len(remaining) != 0 {
			t.Errorf("path %q: command=%q remaining=%v err=%v", path, command.CommandPath(), remaining, err)
		}
	}
	if command, _, err := app.root.Find([]string{"config"}); err == nil && command != app.root {
		t.Fatal("undocumented config command is public")
	}
	for _, forbidden := range []string{"magnet", "private-key", "wireguard-key", "password"} {
		if app.root.PersistentFlags().Lookup(forbidden) != nil {
			t.Fatalf("sensitive global flag %q exists", forbidden)
		}
		visitCommands(app.root, func(command *cobra.Command) {
			if command.Flags().Lookup(forbidden) != nil {
				t.Errorf("sensitive flag %q exists on %s", forbidden, command.CommandPath())
			}
		})
	}
}

func visitCommands(command *cobra.Command, visit func(*cobra.Command)) {
	visit(command)
	for _, child := range command.Commands() {
		visitCommands(child, visit)
	}
}

func TestGlobalFlagsAndRootOnlyVersion(t *testing.T) {
	app := New(Dependencies{})
	for _, name := range []string{"config", "json", "no-color", "non-interactive", "timeout", "log-level", "strict"} {
		if app.root.PersistentFlags().Lookup(name) == nil {
			t.Errorf("missing global flag --%s", name)
		}
	}
	if app.root.Flags().Lookup("version") == nil {
		t.Fatal("missing root --version flag")
	}
	var stdout, stderr bytes.Buffer
	code := New(Dependencies{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"desktop", "--version"})
	if code != exitcode.Usage {
		t.Fatalf("subcommand --version code=%d output=%q/%q", code, stdout.String(), stderr.String())
	}
}

func TestCLIConfigLayerIsLoadedBeforeDispatch(t *testing.T) {
	const selectedPath = "/tmp/private-vm-selected-config.toml"
	invoker := &recordingInvoker{}
	var gotPath string
	var gotOverrides config.Overrides
	load := func(path string, overrides config.Overrides) (config.Config, error) {
		gotPath, gotOverrides = path, overrides
		return config.Defaults(), nil
	}
	code := New(Dependencies{Invoker: invoker, LoadConfig: load}).Execute(
		context.Background(),
		[]string{"desktop", "start", "--config", selectedPath, "--strict=false"},
	)
	if code != exitcode.OK || gotPath != selectedPath || gotOverrides.Strict == nil || *gotOverrides.Strict {
		t.Fatalf("code=%d path=%q overrides=%#v", code, gotPath, gotOverrides)
	}
	if len(invoker.calls) != 1 {
		t.Fatalf("dispatch calls=%#v", invoker.calls)
	}
	intent, ok := invoker.calls[0].intent.(WorkstationIntent)
	if !ok || intent.Bundle != "development" || intent.Memory != "4294967296B" || intent.CPUs != 2 {
		t.Fatalf("configuration defaults did not reach dispatch: %#v", invoker.calls[0].intent)
	}
}

func TestCLIUsesProductionSelectedConfigForWorkstationDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selected.toml")
	if err := os.WriteFile(path, []byte(`
schema_version = 1
[desktop]
bundle = "basic"
audio = true
memory_bytes = 2147483648
vcpus = 1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	invoker := &recordingInvoker{}
	code := New(Dependencies{Invoker: invoker}).Execute(
		context.Background(), []string{"desktop", "start", "--config", path},
	)
	if code != exitcode.OK || len(invoker.calls) != 1 {
		t.Fatalf("code=%d calls=%#v", code, invoker.calls)
	}
	want := WorkstationIntent{Bundle: "basic", Audio: true, Memory: "2147483648B", CPUs: 1}
	if !reflect.DeepEqual(invoker.calls[0].intent, want) {
		t.Fatalf("got=%#v want=%#v", invoker.calls[0].intent, want)
	}
}

func TestAbsentStrictFlagDoesNotOverrideLayerAndDoctorUsesSnapshot(t *testing.T) {
	configuration, err := config.Decode(strings.NewReader("schema_version=1\nstrict=false\n"))
	if err != nil {
		t.Fatal(err)
	}
	var gotOverrides config.Overrides
	var doctorStrict bool
	code := New(Dependencies{
		LoadConfig: func(_ string, overrides config.Overrides) (config.Config, error) {
			gotOverrides = overrides
			return configuration, nil
		},
		Doctor: func(_ context.Context, strict bool) preflight.Report {
			doctorStrict = strict
			return preflight.Report{Runnable: true}
		},
	}).Execute(context.Background(), []string{"doctor"})
	if code != exitcode.OK || gotOverrides.Strict != nil || doctorStrict {
		t.Fatalf("code=%d overrides=%#v doctorStrict=%v", code, gotOverrides, doctorStrict)
	}
}

func TestConfigFailureIsRedactedStableExitEleven(t *testing.T) {
	for _, machine := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		args := []string{"doctor"}
		if machine {
			args = append(args, "--json")
		}
		code := New(Dependencies{
			Stdout: &stdout,
			Stderr: &stderr,
			LoadConfig: func(string, config.Overrides) (config.Config, error) {
				return config.Config{}, &config.Error{
					Code: "CONFIG_PARSE", Message: "The configuration is invalid.",
					Remediation: "Compare it with the installed example.",
				}
			},
		}).Execute(context.Background(), args)
		if code != exitcode.Configuration || stdout.Len() != 0 ||
			!strings.Contains(stderr.String(), "CONFIG_PARSE") {
			t.Fatalf("machine=%v code=%d stdout=%q stderr=%q", machine, code, stdout.String(), stderr.String())
		}
		if machine && !json.Valid(stderr.Bytes()) {
			t.Fatalf("invalid JSON error: %q", stderr.String())
		}
	}

	const marker = "SENSITIVE-CONFIG-MARKER"
	invoker := &recordingInvoker{}
	var stdout, stderr bytes.Buffer
	code := New(Dependencies{
		Stdout: &stdout, Stderr: &stderr, Invoker: invoker,
		LoadConfig: func(string, config.Overrides) (config.Config, error) {
			return config.Config{}, errors.New(marker)
		},
	}).Execute(context.Background(), []string{"init", "--json"})
	if code != exitcode.Configuration || stdout.Len() != 0 || !json.Valid(stderr.Bytes()) ||
		strings.Contains(stderr.String(), marker) || len(invoker.calls) != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q calls=%#v", code, stdout.String(), stderr.String(), invoker.calls)
	}
}

func TestReferenceCommandsDoNotLoadConfiguration(t *testing.T) {
	load := func(string, config.Overrides) (config.Config, error) {
		t.Fatal("reference command loaded configuration")
		return config.Config{}, errors.New("unreachable")
	}
	for _, args := range [][]string{{"version"}, {"--version"}, {"completion", "bash"}, {"--help"}} {
		if code := New(Dependencies{LoadConfig: load}).Execute(context.Background(), args); code != exitcode.OK {
			t.Fatalf("args=%v code=%d", args, code)
		}
	}
}

func TestJSONRejectsHumanOnlyHelpAndCompletion(t *testing.T) {
	for _, args := range [][]string{
		{"--json"},
		{"--json", "--help"},
		{"version", "--help", "--json"},
		{"completion", "bash", "--json"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := New(Dependencies{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), args)
			if code != exitcode.Usage || stdout.Len() != 0 || !json.Valid(stderr.Bytes()) {
				t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
			}
		})
	}
	var stdout, stderr bytes.Buffer
	code := New(Dependencies{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"version", "--help", "--help=false", "--json"})
	if code != exitcode.OK || !json.Valid(stdout.Bytes()) || stderr.Len() != 0 {
		t.Fatalf("final false help flag code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunAliasesUseSameSemanticDispatch(t *testing.T) {
	const session = "pvm-11111111111111111111111111111111"
	tests := []struct {
		name      string
		canonical []string
		alias     []string
	}{
		{name: "workstation", canonical: []string{"desktop", "start", "--bundle", "office", "--audio", "--memory", "4GiB", "--cpus", "2"}, alias: []string{"run", "workstation", "--bundle", "office", "--audio", "--memory", "4GiB", "--cpus", "2"}},
		{name: "scanner", canonical: []string{"scan", "start", "--session", session}, alias: []string{"run", "scanner", "--session", session}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invoke := func(args []string) invocation {
				invoker := &recordingInvoker{}
				code := New(Dependencies{Invoker: invoker}).Execute(context.Background(), args)
				if code != exitcode.OK || len(invoker.calls) != 1 {
					t.Fatalf("args=%v code=%d calls=%#v", args, code, invoker.calls)
				}
				return invoker.calls[0]
			}
			canonical, alias := invoke(test.canonical), invoke(test.alias)
			if canonical.id != alias.id || !reflect.DeepEqual(canonical.intent, alias.intent) {
				t.Fatalf("canonical=%#v alias=%#v", canonical, alias)
			}
		})
	}
}

func TestValidatedParametersReachSemanticInvoker(t *testing.T) {
	const session = "pvm-11111111111111111111111111111111"
	tests := []struct {
		name string
		args []string
		want Intent
	}{
		{name: "plan workstation", args: []string{"plan", "workstation", "--bundle", "office"}, want: PlanWorkstationIntent{Bundle: "office"}},
		{name: "plan torrent", args: []string{"plan", "torrent", "--policy", "safe", "--destination", "usb"}, want: PlanTorrentIntent{Policy: "safe", Destination: "usb"}},
		{name: "optional session", args: []string{"desktop", "status", "--session", session}, want: SessionIntent{SessionID: session}},
		{name: "desktop stop", args: []string{"desktop", "stop", "--session", session, "--discard"}, want: DesktopStopIntent{SessionID: session, Discard: true}},
		{name: "bundle", args: []string{"desktop", "bundles", "inspect", "office"}, want: BundleIntent{Name: "office"}},
		{name: "workspace path", args: []string{"workspace", "import", "/tmp/input", "--session", session}, want: WorkspacePathIntent{SessionID: session, Path: "/tmp/input"}},
		{name: "workspace export", args: []string{"workspace", "export", "output-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--to", "usb", "--session", session}, want: WorkspaceExportIntent{SessionID: session, Destination: "usb", OutputID: "output-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{name: "workspace verify", args: []string{"workspace", "verify", "--export", "export-1"}, want: WorkspaceVerifyIntent{ExportID: "export-1"}},
		{name: "workspace discard", args: []string{"workspace", "discard", "--all", "--session", session}, want: WorkspaceDiscardIntent{SessionID: session, All: true}},
		{name: "torrent start", args: []string{"torrent", "start", "--policy", "quarantine"}, want: TorrentIntent{Policy: "quarantine"}},
		{name: "torrent input", args: []string{"torrent", "add", "--torrent-file", "/tmp/input.torrent"}, want: TorrentInputIntent{TorrentFile: "/tmp/input.torrent"}},
		{name: "torrent selection", args: []string{"torrent", "select", "--files", "1,2,4", "--destination", "workstation"}, want: TorrentSelectionIntent{Files: []uint32{1, 2, 4}, Destination: "workstation"}},
		{name: "scanner approval", args: []string{"scan", "approve", "--session", session, "--to", "usb"}, want: ScanApprovalIntent{SessionID: session, To: "usb"}},
		{name: "vpn import", args: []string{"vpn", "import", "--from-file", "/tmp/profile.conf"}, want: VPNImportIntent{ProfileName: "proton-p2p", FromFile: "/tmp/profile.conf"}},
		{name: "usb device", args: []string{"usb", "enroll", "--device", "usbdev-0123456789abcdef"}, want: USBDeviceIntent{DeviceID: "usbdev-0123456789abcdef", Label: "PRIVATE_VM_TRANSFER"}},
		{name: "usb prepare", args: []string{"usb", "prepare", "--format", "luks2-ext4"}, want: USBPrepareIntent{Format: "luks2-ext4"}},
		{name: "usb export", args: []string{"usb", "export", "--session", session, "--claim", "usbclaim-0123456789abcdef0123456789abcdef", "--scanner-session", "pvm-22222222222222222222222222222222", "--output", "output-opaque-01"}, want: USBExportIntent{ExporterSession: session, ClaimID: "usbclaim-0123456789abcdef0123456789abcdef", SourceSession: "pvm-22222222222222222222222222222222", OutputID: "output-opaque-01"}},
		{name: "image selection", args: []string{"images", "sync", "--role", "workstation", "--bundle", "basic"}, want: ImageSelectionIntent{Role: "workstation", Bundle: "basic"}},
		{name: "image test", args: []string{"images", "test", "ghcr.io/example/image@sha256:abc", "--backend", "qemu"}, want: ImageTestIntent{Reference: "ghcr.io/example/image@sha256:abc", Backend: "qemu"}},
		{name: "session report", args: []string{"session", "report", "--session", session, "--export", "/tmp/report.json"}, want: SessionReportIntent{SessionID: session, ExportPath: "/tmp/report.json"}},
		{name: "session cleanup", args: []string{"session", "cleanup", "--all"}, want: SessionCleanupIntent{All: true}},
		{name: "policy name", args: []string{"policy", "show", "safe"}, want: PolicyNameIntent{Name: "safe"}},
		{name: "policy file", args: []string{"policy", "validate", "/tmp/policy.toml"}, want: PolicyFileIntent{Path: "/tmp/policy.toml"}},
		{name: "system install", args: []string{"system", "install", "--dry-run"}, want: SystemInstallIntent{DryRun: true}},
		{name: "system diagnostics", args: []string{"system", "diagnostics", "--export", "/tmp/diagnostics.json"}, want: SystemDiagnosticsIntent{ExportPath: "/tmp/diagnostics.json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invoker := &recordingInvoker{}
			if code := New(Dependencies{Invoker: invoker}).Execute(context.Background(), test.args); code != exitcode.OK {
				t.Fatalf("args=%v code=%d", test.args, code)
			}
			if len(invoker.calls) != 1 || !reflect.DeepEqual(invoker.calls[0].intent, test.want) {
				t.Fatalf("got=%#v want=%#v", invoker.calls, test.want)
			}
		})
	}
}

func TestFailClosedUnimplementedCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := New(Dependencies{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"init", "--json"})
	if code != exitcode.Runtime || stdout.Len() != 0 || !strings.Contains(stderr.String(), `"code":"NOT_IMPLEMENTED"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestUnknownSyntaxNeverEchoesCallerInput(t *testing.T) {
	const marker = "MAGNET-OR-KEY-MUST-NOT-APPEAR"
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "unknown command human", args: []string{"unknown-" + marker}},
		{name: "unknown command JSON", args: []string{"--json", "unknown-" + marker}},
		{name: "unknown option human", args: []string{"init", "--unknown-" + marker}},
		{name: "unknown option JSON", args: []string{"--json", "init", "--unknown-" + marker}},
		{name: "unknown option trailing JSON", args: []string{"init", "--unknown-" + marker, "--json"}},
		{name: "invalid value trailing JSON", args: []string{"init", "--timeout", marker, "--json"}},
		{name: "repeated mode trailing JSON", args: []string{"init", "--json=false", "--unknown-" + marker, "--json"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := New(Dependencies{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), test.args)
			if code != exitcode.Usage || strings.Contains(stdout.String(), marker) || strings.Contains(stderr.String(), marker) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if strings.HasSuffix(test.name, "JSON") && !json.Valid(stderr.Bytes()) {
				t.Fatalf("machine error is not JSON: %q", stderr.String())
			}
		})
	}
}

func TestMachineModePrescanRespectsArgumentTerminator(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := New(Dependencies{Stdout: &stdout, Stderr: &stderr}).Execute(context.Background(), []string{"init", "--", "--json"})
	if code != exitcode.Usage || json.Valid(stderr.Bytes()) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestDoctorRendersReportAndReturnsPreflightFailure(t *testing.T) {
	var strict bool
	var stdout, stderr bytes.Buffer
	app := New(Dependencies{
		Stdout: &stdout, Stderr: &stderr,
		Doctor: func(_ context.Context, value bool) preflight.Report {
			strict = value
			return preflight.Report{SchemaVersion: 1, Runnable: false, Diagnostics: []preflight.Diagnostic{{Code: "DISK_SWAP_ACTIVE", Severity: preflight.SeverityBlocking, Summary: "Disk swap is active.", Remediation: "Disable it."}}}
		},
	})
	code := app.Execute(context.Background(), []string{"doctor", "--strict", "--json"})
	if code != exitcode.Preflight || !strict || !strings.Contains(stdout.String(), `"code":"DOCTOR_REPORT"`) || !strings.Contains(stderr.String(), `"code":"HOST_PREFLIGHT_FAILED"`) {
		t.Fatalf("code=%d strict=%t stdout=%q stderr=%q", code, strict, stdout.String(), stderr.String())
	}
}

func TestRepairSafeFailsWithoutCallingDoctor(t *testing.T) {
	called := false
	app := New(Dependencies{Doctor: func(context.Context, bool) preflight.Report { called = true; return preflight.Report{Runnable: true} }})
	if code := app.Execute(context.Background(), []string{"doctor", "--repair-safe"}); code != exitcode.Preflight || called {
		t.Fatalf("code=%d doctor-called=%t", code, called)
	}
}

func TestInvocationCancellationTimeoutAndInternalFailure(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		invoker := &recordingInvoker{invoke: func(ctx context.Context, _ CommandID, _ Intent) (Result, error) {
			<-ctx.Done()
			return Result{}, ctx.Err()
		}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if code := New(Dependencies{Invoker: invoker}).Execute(ctx, []string{"init"}); code != exitcode.Cancelled {
			t.Fatalf("code=%d", code)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		invoker := &recordingInvoker{invoke: func(ctx context.Context, _ CommandID, _ Intent) (Result, error) {
			<-ctx.Done()
			return Result{}, ctx.Err()
		}}
		if code := New(Dependencies{Invoker: invoker}).Execute(context.Background(), []string{"init", "--timeout", "1ms"}); code != exitcode.Runtime {
			t.Fatalf("code=%d", code)
		}
	})
	t.Run("late success after timeout", func(t *testing.T) {
		invoker := &recordingInvoker{invoke: func(ctx context.Context, _ CommandID, _ Intent) (Result, error) {
			<-ctx.Done()
			return Result{Code: CodeAcknowledged, Data: AcknowledgementPayload{Message: "late"}}, nil
		}}
		if code := New(Dependencies{Invoker: invoker}).Execute(context.Background(), []string{"init", "--timeout", "1ms"}); code != exitcode.Runtime {
			t.Fatalf("code=%d", code)
		}
	})
	t.Run("internal", func(t *testing.T) {
		invoker := &recordingInvoker{invoke: func(context.Context, CommandID, Intent) (Result, error) {
			return Result{}, errors.New("private internal detail")
		}}
		var stdout, stderr bytes.Buffer
		code := New(Dependencies{Stdout: &stdout, Stderr: &stderr, Invoker: invoker}).Execute(context.Background(), []string{"init", "--json"})
		if code != exitcode.Internal || strings.Contains(stderr.String(), "private internal detail") {
			t.Fatalf("code=%d stderr=%q", code, stderr.String())
		}
	})
	t.Run("malformed application error", func(t *testing.T) {
		invoker := &recordingInvoker{invoke: func(context.Context, CommandID, Intent) (Result, error) {
			return Result{}, apperror.New("bad code", 99, "unsafe", "unsafe")
		}}
		var stdout, stderr bytes.Buffer
		code := New(Dependencies{Stdout: &stdout, Stderr: &stderr, Invoker: invoker}).Execute(context.Background(), []string{"init", "--json"})
		if code != exitcode.Internal || !strings.Contains(stderr.String(), `"code":"INTERNAL_ERROR"`) {
			t.Fatalf("code=%d stderr=%q", code, stderr.String())
		}
	})
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{name: "wrapped cancellation", err: errors.Join(errors.New("inner"), context.Canceled), want: exitcode.Cancelled},
		{name: "wrapped deadline", err: errors.Join(errors.New("inner"), context.DeadlineExceeded), want: exitcode.Runtime},
	} {
		t.Run(test.name, func(t *testing.T) {
			invoker := &recordingInvoker{invoke: func(context.Context, CommandID, Intent) (Result, error) {
				return Result{}, test.err
			}}
			if code := New(Dependencies{Invoker: invoker}).Execute(context.Background(), []string{"init"}); code != test.want {
				t.Fatalf("code=%d want=%d", code, test.want)
			}
		})
	}
}

func TestDoctorHonorsCancellationAndTimeout(t *testing.T) {
	for _, test := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		args []string
		want int
	}{
		{name: "cancelled", ctx: func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}
		}, args: []string{"doctor"}, want: exitcode.Cancelled},
		{name: "timeout", ctx: func() (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		}, args: []string{"doctor", "--timeout", "1ms"}, want: exitcode.Runtime},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.ctx()
			defer cancel()
			var stdout bytes.Buffer
			app := New(Dependencies{
				Stdout: &stdout,
				Doctor: func(ctx context.Context, _ bool) preflight.Report {
					<-ctx.Done()
					return preflight.Report{SchemaVersion: 1, Runnable: true}
				},
			})
			if code := app.Execute(ctx, test.args); code != test.want || stdout.Len() != 0 {
				t.Fatalf("code=%d want=%d stdout=%q", code, test.want, stdout.String())
			}
		})
	}
}

func TestCommandValidationFailuresAreUsageErrors(t *testing.T) {
	tests := [][]string{
		{"plan", "workstation"},
		{"desktop", "start", "--cpus", "0"},
		{"workspace", "export"},
		{"torrent", "add"},
		{"torrent", "add", "--magnet-stdin", "--torrent-file", "/tmp/a"},
		{"torrent", "select", "--files", "1,1"},
		{"torrent", "select", "--files", "1"},
		{"scan", "start"},
		{"vpn", "import", "--non-interactive"},
		{"usb", "prepare", "--format", "luks2-ext4", "--non-interactive"},
		{"images", "build"},
		{"session", "cleanup", "--session", "pvm-11111111111111111111111111111111", "--all"},
		{"system", "install"},
		{"init", "unexpected"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			if code := New(Dependencies{}).Execute(context.Background(), args); code != exitcode.Usage {
				t.Fatalf("args=%v code=%d", args, code)
			}
		})
	}
}

func TestInvokerReceivesBoundedContext(t *testing.T) {
	invoker := &recordingInvoker{invoke: func(ctx context.Context, _ CommandID, _ Intent) (Result, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > time.Second {
			t.Fatalf("unexpected deadline: %v %t", deadline, ok)
		}
		return Result{Code: CodeAcknowledged, Data: AcknowledgementPayload{Message: "ok"}}, nil
	}}
	if code := New(Dependencies{Invoker: invoker}).Execute(context.Background(), []string{"init", "--timeout", "1s"}); code != exitcode.OK {
		t.Fatalf("code=%d", code)
	}
}
