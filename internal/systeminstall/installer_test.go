package systeminstall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeProbe struct {
	uid       int
	err       error
	active    bool
	activeErr error
}

func (probe fakeProbe) EffectiveUID() int                    { return probe.uid }
func (probe fakeProbe) Validate(context.Context, bool) error { return probe.err }
func (probe fakeProbe) DaemonActive(context.Context) (bool, error) {
	return probe.active, probe.activeErr
}

type fakeActions struct {
	activateErr   error
	deactivateErr error
	reloadErr     error
	activations   int
	deactivations int
	reloads       int
}

func (actions *fakeActions) Activate(context.Context) error {
	actions.activations++
	return actions.activateErr
}

func (actions *fakeActions) Deactivate(context.Context) error {
	actions.deactivations++
	return actions.deactivateErr
}

func (actions *fakeActions) Reload(context.Context) error {
	actions.reloads++
	return actions.reloadErr
}

func TestInstallAndUninstallPreserveConfigurationAndState(t *testing.T) {
	bundle := makeBundle(t)
	root := t.TempDir()
	configPath := underRoot(root, "/etc/private-vm/config.toml")
	mustWrite(t, configPath, []byte("operator-config\n"), 0o600)
	cacheSentinel := underRoot(root, "/var/lib/private-vm/images/sentinel")
	mustWrite(t, cacheSentinel, []byte("cache\n"), 0o600)
	actions := &fakeActions{}
	installer := Installer{BundleRoot: bundle, Root: root, Probe: fakeProbe{uid: 0}, Actions: actions}

	plan, err := installer.PlanInstall(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasChange(plan, OperationPreserve, "/etc/private-vm/config.toml") ||
		!hasChange(plan, OperationEnable, "private-vmd.service") {
		t.Fatalf("install plan omitted preservation or service activation: %#v", plan)
	}
	if _, err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if actions.activations != 1 || actions.deactivations != 0 {
		t.Fatalf("unexpected action calls: %#v", actions)
	}
	if value := mustRead(t, configPath); value != "operator-config\n" {
		t.Fatalf("configuration replaced: %q", value)
	}
	if _, err := os.Stat(underRoot(root, "/usr/bin/private-vm")); err != nil {
		t.Fatalf("CLI was not installed: %v", err)
	}

	uninstallPlan, err := installer.PlanUninstall(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasChange(uninstallPlan, OperationPreserve, "/etc/private-vm/config.toml") {
		t.Fatalf("uninstall plan does not preserve config: %#v", uninstallPlan)
	}
	if _, err := installer.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if actions.deactivations != 1 {
		t.Fatalf("service deactivation calls=%d", actions.deactivations)
	}
	if actions.reloads != 1 {
		t.Fatalf("post-removal reload calls=%d", actions.reloads)
	}
	for _, path := range []string{"/usr/bin/private-vm", InstalledManifest} {
		if _, err := os.Stat(underRoot(root, path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("managed path remains after uninstall: %s err=%v", path, err)
		}
	}
	if mustRead(t, configPath) != "operator-config\n" || mustRead(t, cacheSentinel) != "cache\n" {
		t.Fatal("uninstall changed preserved configuration or cache")
	}
}

func TestUpgradeReplacesManagedFilesAndPreservesOperatorState(t *testing.T) {
	root := t.TempDir()
	actions := &fakeActions{}
	installer := Installer{BundleRoot: makeBundleVersion(t, "1.0.0-rc.1"), Root: root, Probe: fakeProbe{uid: 0}, Actions: actions}
	if _, err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	configPath := underRoot(root, "/etc/private-vm/config.toml")
	mustWrite(t, configPath, []byte("operator-config\n"), 0o600)
	cacheSentinel := underRoot(root, "/var/lib/private-vm/images/sentinel")
	mustWrite(t, cacheSentinel, []byte("cache\n"), 0o600)

	upgrade := makeBundleVersion(t, "1.0.0-rc.2")
	mustWrite(t, filepath.Join(upgrade, "private-vm"), []byte("upgraded-cli\n"), 0o755)
	rewriteBundleManifest(t, upgrade, "1.0.0-rc.2")
	installer.BundleRoot = upgrade
	plan, err := installer.PlanInstall(context.Background())
	if err != nil || !hasChange(plan, OperationReplace, "/usr/bin/private-vm") || !hasChange(plan, OperationPreserve, "/etc/private-vm/config.toml") {
		t.Fatalf("upgrade plan=%#v err=%v", plan, err)
	}
	if _, err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mustRead(t, underRoot(root, "/usr/bin/private-vm")) != "upgraded-cli\n" ||
		mustRead(t, configPath) != "operator-config\n" || mustRead(t, cacheSentinel) != "cache\n" {
		t.Fatal("upgrade did not replace only managed immutable content")
	}
	if actions.activations != 2 || actions.deactivations != 0 {
		t.Fatalf("unexpected upgrade activation sequence: %#v", actions)
	}
	assertNoTransactionFiles(t, root)
}

func TestUninstallReloadFailureRestoresManagedInstallation(t *testing.T) {
	root := t.TempDir()
	actions := &fakeActions{}
	installer := Installer{BundleRoot: makeBundle(t), Root: root, Probe: fakeProbe{uid: 0}, Actions: actions}
	if _, err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	installedCLI := mustRead(t, underRoot(root, "/usr/bin/private-vm"))
	actions.reloadErr = errors.New("injected reload failure")
	if _, err := installer.Uninstall(context.Background()); err == nil {
		t.Fatal("uninstall reload failure was accepted")
	}
	if mustRead(t, underRoot(root, "/usr/bin/private-vm")) != installedCLI {
		t.Fatal("uninstall rollback did not restore managed content")
	}
	if _, err := os.Stat(underRoot(root, InstalledManifest)); err != nil {
		t.Fatalf("uninstall rollback did not restore manifest: %v", err)
	}
	if actions.deactivations != 1 || actions.reloads != 1 || actions.activations != 2 {
		t.Fatalf("unexpected uninstall rollback actions: %#v", actions)
	}
	assertNoTransactionFiles(t, root)
}

func TestActivationFailureRollsBackEveryManagedFile(t *testing.T) {
	bundle := makeBundle(t)
	root := t.TempDir()
	existing := underRoot(root, "/usr/bin/private-vm")
	mustWrite(t, existing, []byte("previous\n"), 0o755)
	actions := &fakeActions{activateErr: errors.New("injected")}
	installer := Installer{BundleRoot: bundle, Root: root, Probe: fakeProbe{uid: 0}, Actions: actions}
	if _, err := installer.Install(context.Background()); err == nil {
		t.Fatal("activation failure was accepted")
	}
	if value := mustRead(t, existing); value != "previous\n" {
		t.Fatalf("previous binary was not restored: %q", value)
	}
	if _, err := os.Stat(underRoot(root, InstalledManifest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("installed manifest remained after rollback: %v", err)
	}
	if actions.activations != 1 || actions.deactivations != 1 {
		t.Fatalf("activation rollback was incomplete: %#v", actions)
	}
	assertNoTransactionFiles(t, root)
}

func TestTamperedBundleAndInstalledFileFailBeforeMutation(t *testing.T) {
	bundle := makeBundle(t)
	root := t.TempDir()
	actions := &fakeActions{}
	installer := Installer{BundleRoot: bundle, Root: root, Probe: fakeProbe{uid: 0}, Actions: actions}
	mustWrite(t, filepath.Join(bundle, "README.md"), []byte("tampered\n"), 0o444)
	if _, err := installer.Install(context.Background()); err == nil {
		t.Fatal("tampered bundle was accepted")
	}
	if actions.activations != 0 {
		t.Fatal("tampered bundle reached activation")
	}

	bundle = makeBundle(t)
	installer.BundleRoot = bundle
	if _, err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, underRoot(root, "/usr/bin/private-vm"), []byte("tampered-installed\n"), 0o755)
	if _, err := installer.Uninstall(context.Background()); err == nil {
		t.Fatal("tampered installed file was accepted")
	}
	if actions.deactivations != 0 {
		t.Fatal("tampered installation reached service deactivation")
	}
}

func TestCancellationAndNonRootFailBeforeActivation(t *testing.T) {
	bundle := makeBundle(t)
	for _, test := range []struct {
		name     string
		ctx      context.Context
		uid      int
		probeErr error
	}{
		{"cancelled", cancelledContext(), 0, nil},
		{"timeout", context.Background(), 0, context.DeadlineExceeded},
		{"non-root", context.Background(), 1000, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			actions := &fakeActions{}
			installer := Installer{BundleRoot: bundle, Root: t.TempDir(), Probe: fakeProbe{uid: test.uid, err: test.probeErr}, Actions: actions}
			if _, err := installer.Install(test.ctx); err == nil {
				t.Fatal("unsafe install request succeeded")
			}
			if actions.activations != 0 {
				t.Fatal("failed request reached activation")
			}
		})
	}
}

func TestActiveDaemonBlocksInstallAndUpgradeBeforeMutation(t *testing.T) {
	actions := &fakeActions{}
	installer := Installer{
		BundleRoot: makeBundle(t), Root: t.TempDir(),
		Probe: fakeProbe{uid: 0, active: true}, Actions: actions,
	}
	if _, err := installer.Install(context.Background()); err == nil {
		t.Fatal("active daemon was accepted")
	}
	if actions.activations != 0 || actions.deactivations != 0 {
		t.Fatalf("blocked upgrade reached system action: %#v", actions)
	}
}

func TestManifestRejectsUnknownDuplicateAndSymbolicContent(t *testing.T) {
	bundle := makeBundle(t)
	manifestPath := filepath.Join(bundle, "manifest.json")
	original := mustRead(t, manifestPath)
	unknown := strings.Replace(original, `"product":"private-vm"`, `"product":"private-vm","credential":"forbidden"`, 1)
	mustWrite(t, manifestPath, []byte(unknown), 0o444)
	if _, _, err := LoadManifest(bundle); err == nil {
		t.Fatal("unknown manifest field was accepted")
	}
	duplicate := strings.Replace(original, `"product":"private-vm"`, `"product":"private-vm","product":"private-vm"`, 1)
	mustWrite(t, manifestPath, []byte(duplicate), 0o444)
	if _, _, err := LoadManifest(bundle); err == nil {
		t.Fatal("duplicate manifest field was accepted")
	}
	mustWrite(t, manifestPath, []byte(original), 0o444)
	if err := os.Remove(filepath.Join(bundle, "README.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("LICENSE", filepath.Join(bundle, "README.md")); err != nil {
		t.Fatal(err)
	}
	manifest, _, err := LoadManifest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBundle(context.Background(), bundle, manifest); err == nil {
		t.Fatal("symbolic bundle content was accepted")
	}
}

func makeBundle(t *testing.T) string {
	return makeBundleVersion(t, "1.0.0-rc.1")
}

func makeBundleVersion(t *testing.T, version string) string {
	t.Helper()
	root := t.TempDir()
	for index, template := range fileTemplates {
		value := []byte("private-vm fixture " + template.source + " " + string(rune('a'+index)) + "\n")
		mustWrite(t, filepath.Join(root, filepath.FromSlash(template.source)), value, os.FileMode(template.mode))
	}
	rewriteBundleManifest(t, root, version)
	return root
}

func rewriteBundleManifest(t *testing.T, root, version string) {
	t.Helper()
	manifest, err := BuildManifest(context.Background(), root, version)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "manifest.json"), encoded, 0o444)
}

func underRoot(root, absolute string) string {
	return filepath.Join(root, strings.TrimPrefix(absolute, "/"))
}

func mustWrite(t *testing.T, path string, value []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, value, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func hasChange(plan Plan, operation Operation, path string) bool {
	for _, change := range plan.Changes {
		if change.Operation == operation && change.Path == path {
			return true
		}
	}
	return false
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func assertNoTransactionFiles(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), ".private-vm-") {
			t.Errorf("transaction file remains: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestManifestWireIsClosed(t *testing.T) {
	bundle := makeBundle(t)
	manifest, raw, err := LoadManifest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if manifest.Product != "private-vm" || len(decoded) != 6 {
		t.Fatalf("unexpected manifest: %#v", decoded)
	}
}
