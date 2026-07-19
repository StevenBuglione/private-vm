package systeminstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

type Operation string

const (
	OperationCreate   Operation = "create"
	OperationReplace  Operation = "replace"
	OperationPreserve Operation = "preserve"
	OperationRemove   Operation = "remove"
	OperationGroup    Operation = "ensure-group"
	OperationEnable   Operation = "enable-service"
	OperationDisable  Operation = "disable-service"
)

var ErrRollbackIncomplete = errors.New("installation rollback is incomplete")

type Change struct {
	Operation Operation
	Path      string
}

type Plan struct {
	Action  string
	Version string
	Changes []Change
}

// HostProbe is immutable host evidence gathered before any mutation.
type HostProbe interface {
	Validate(context.Context, bool) error
	EffectiveUID() int
	DaemonActive(context.Context) (bool, error)
}

// Actions is the exact systemd/sysusers/tmpfiles boundary. It deliberately has
// no generic command method.
type Actions interface {
	Activate(context.Context) error
	Deactivate(context.Context) error
	Reload(context.Context) error
}

type Installer struct {
	BundleRoot string
	Root       string
	Probe      HostProbe
	Actions    Actions
}

// NewDefault returns the production generic-archive installer. It discovers
// the bundle beside the running CLI; an already-installed CLI can still use
// the fixed installed manifest for uninstall.
func NewDefault() Installer {
	executable, err := os.Executable()
	if err != nil {
		executable = "/invalid/private-vm"
	}
	return Installer{
		BundleRoot: filepath.Dir(executable),
		Root:       "/",
		Probe:      defaultProbe{},
		Actions:    systemActions{},
	}
}

func (installer Installer) PlanInstall(ctx context.Context) (Plan, error) {
	if err := installer.validate(ctx, true); err != nil {
		return Plan{}, err
	}
	manifest, _, err := LoadManifest(installer.BundleRoot)
	if err != nil {
		return Plan{}, err
	}
	if err := verifyBundle(ctx, installer.BundleRoot, manifest); err != nil {
		return Plan{}, err
	}
	active, err := installer.Probe.DaemonActive(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Plan{}, err
		}
		return Plan{}, errors.New("daemon activity could not be verified")
	}
	if active {
		return Plan{}, errors.New("active daemon prevents install or upgrade")
	}
	changes := []Change{{Operation: OperationGroup, Path: "private-vm"}}
	for _, file := range manifest.Files {
		target, pathErr := installer.target(file.Destination)
		if pathErr != nil {
			return Plan{}, pathErr
		}
		operation, inspectErr := plannedWrite(target, file.Preserve, installer.Root == "/")
		if inspectErr != nil {
			return Plan{}, inspectErr
		}
		changes = append(changes, Change{Operation: operation, Path: file.Destination})
	}
	manifestTarget, err := installer.target(InstalledManifest)
	if err != nil {
		return Plan{}, err
	}
	operation, err := plannedWrite(manifestTarget, false, installer.Root == "/")
	if err != nil {
		return Plan{}, err
	}
	changes = append(changes, Change{Operation: operation, Path: InstalledManifest})
	changes = append(changes, Change{Operation: OperationEnable, Path: "private-vmd.service"})
	return Plan{Action: "install", Version: manifest.Version, Changes: changes}, nil
}

func (installer Installer) Install(ctx context.Context) (Plan, error) {
	plan, err := installer.PlanInstall(ctx)
	if err != nil {
		return Plan{}, err
	}
	if installer.Probe.EffectiveUID() != 0 {
		return Plan{}, errors.New("installation requires root")
	}
	manifest, manifestBytes, err := LoadManifest(installer.BundleRoot)
	if err != nil {
		return Plan{}, err
	}
	txn := fileTransaction{installer: installer}
	for _, file := range manifest.Files {
		if err := ctx.Err(); err != nil {
			return Plan{}, rollbackFailure(err, txn.rollback())
		}
		if err := txn.install(file); err != nil {
			return Plan{}, rollbackFailure(err, txn.rollback())
		}
	}
	if err := txn.installBytes(InstalledManifest, 0o444, false, manifestBytes); err != nil {
		return Plan{}, rollbackFailure(err, txn.rollback())
	}
	if err := installer.Actions.Activate(ctx); err != nil {
		rollbackErr := errors.Join(installer.Actions.Deactivate(context.Background()), txn.rollback())
		primary := error(errors.New("host integration activation failed"))
		if ctx.Err() != nil {
			primary = ctx.Err()
		}
		return Plan{}, rollbackFailure(primary, rollbackErr)
	}
	if err := txn.commit(); err != nil {
		return Plan{}, fmt.Errorf("%w: installation rollback files remain", ErrRollbackIncomplete)
	}
	return plan, nil
}

func (installer Installer) PlanUninstall(ctx context.Context) (Plan, error) {
	if err := installer.validate(ctx, false); err != nil {
		return Plan{}, err
	}
	manifestPath, err := installer.target(InstalledManifest)
	if err != nil {
		return Plan{}, err
	}
	manifest, _, err := loadManifestFile(manifestPath)
	if err != nil {
		return Plan{}, errors.New("installed manifest is unavailable")
	}
	if err := installer.verifyInstalled(ctx, manifest); err != nil {
		return Plan{}, err
	}
	changes := []Change{{Operation: OperationDisable, Path: "private-vmd.service"}}
	for _, file := range manifest.Files {
		if file.Preserve {
			changes = append(changes, Change{Operation: OperationPreserve, Path: file.Destination})
			continue
		}
		changes = append(changes, Change{Operation: OperationRemove, Path: file.Destination})
	}
	changes = append(changes, Change{Operation: OperationRemove, Path: InstalledManifest})
	return Plan{Action: "uninstall", Version: manifest.Version, Changes: changes}, nil
}

func (installer Installer) Uninstall(ctx context.Context) (Plan, error) {
	plan, err := installer.PlanUninstall(ctx)
	if err != nil {
		return Plan{}, err
	}
	if installer.Probe.EffectiveUID() != 0 {
		return Plan{}, errors.New("uninstallation requires root")
	}
	manifestPath, _ := installer.target(InstalledManifest)
	manifest, _, err := loadManifestFile(manifestPath)
	if err != nil {
		return Plan{}, err
	}
	if err := installer.Actions.Deactivate(ctx); err != nil {
		if ctx.Err() != nil {
			return Plan{}, ctx.Err()
		}
		return Plan{}, errors.New("host integration deactivation failed")
	}
	txn := removalTransaction{installer: installer}
	for _, file := range manifest.Files {
		if file.Preserve {
			continue
		}
		if err := ctx.Err(); err != nil {
			rollbackErr := errors.Join(txn.rollback(), installer.Actions.Activate(context.Background()))
			return Plan{}, rollbackFailure(err, rollbackErr)
		}
		if err := txn.remove(file.Destination); err != nil {
			rollbackErr := errors.Join(txn.rollback(), installer.Actions.Activate(context.Background()))
			return Plan{}, rollbackFailure(err, rollbackErr)
		}
	}
	if err := txn.remove(InstalledManifest); err != nil {
		rollbackErr := errors.Join(txn.rollback(), installer.Actions.Activate(context.Background()))
		return Plan{}, rollbackFailure(err, rollbackErr)
	}
	if err := installer.Actions.Reload(ctx); err != nil {
		rollbackErr := errors.Join(txn.rollback(), installer.Actions.Activate(context.Background()))
		if ctx.Err() != nil {
			return Plan{}, rollbackFailure(ctx.Err(), rollbackErr)
		}
		return Plan{}, rollbackFailure(errors.New("systemd reload after removal failed"), rollbackErr)
	}
	if err := txn.commit(); err != nil {
		return Plan{}, fmt.Errorf("%w: removed-file rollback data remains", ErrRollbackIncomplete)
	}
	return plan, nil
}

func (installer Installer) validate(ctx context.Context, requireKVM bool) error {
	if ctx == nil || installer.BundleRoot == "" || installer.Root == "" || installer.Probe == nil || installer.Actions == nil {
		return errors.New("installer configuration is invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := installer.Probe.Validate(ctx, requireKVM); err != nil {
		return fmt.Errorf("host is unsupported: %w", err)
	}
	rootInfo, err := os.Lstat(installer.Root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("installation root is unsafe")
	}
	if installer.Root == "/" {
		stat, ok := rootInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || rootInfo.Mode().Perm()&0o022 != 0 {
			return errors.New("installation root ownership or mode is unsafe")
		}
	}
	bundleInfo, err := os.Lstat(installer.BundleRoot)
	if err != nil || !bundleInfo.IsDir() || bundleInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("bundle root is unsafe")
	}
	return nil
}

func (installer Installer) verifyInstalled(ctx context.Context, manifest Manifest) error {
	for _, file := range manifest.Files {
		if file.Preserve {
			continue
		}
		target, err := installer.target(file.Destination)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(installer.Root, target)
		if err != nil {
			return errors.New("installed path is invalid")
		}
		info, err := os.Lstat(target)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != os.FileMode(file.Mode) {
			return errors.New("installed file mode or type verification failed")
		}
		size, digest, err := hashRegularFile(ctx, installer.Root, filepath.ToSlash(relative), MaximumBundleFile)
		if err != nil || size != file.Size || digest != file.SHA256 {
			return errors.New("installed file verification failed")
		}
	}
	return nil
}

func (installer Installer) target(destination string) (string, error) {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return "", errors.New("installation destination is invalid")
	}
	relative := strings.TrimPrefix(destination, string(filepath.Separator))
	target := filepath.Join(installer.Root, relative)
	back, err := filepath.Rel(installer.Root, target)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return "", errors.New("installation destination escapes root")
	}
	return target, nil
}

func plannedWrite(path string, preserve, requireRoot bool) (Operation, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return OperationCreate, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("installation target is unsafe")
	}
	if requireRoot {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm()&0o022 != 0 {
			return "", errors.New("installation target ownership or links are unsafe")
		}
	}
	if preserve {
		return OperationPreserve, nil
	}
	return OperationReplace, nil
}

type installedChange struct {
	target  string
	backup  string
	created bool
}

type fileTransaction struct {
	installer   Installer
	changes     []installedChange
	createdDirs []string
}

func (txn *fileTransaction) install(file File) error {
	target, err := txn.installer.target(file.Destination)
	if err != nil {
		return err
	}
	operation, err := plannedWrite(target, file.Preserve, txn.installer.Root == "/")
	if err != nil {
		return err
	}
	if operation == OperationPreserve {
		return nil
	}
	source := filepath.Join(txn.installer.BundleRoot, filepath.FromSlash(file.Source))
	input, err := os.Open(source)
	if err != nil {
		return errors.New("verified bundle file could not be reopened")
	}
	defer input.Close()
	pathInfo, statErr := os.Lstat(source)
	openedInfo, openedErr := input.Stat()
	if statErr != nil || openedErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(pathInfo, openedInfo) {
		return errors.New("verified bundle file identity changed")
	}
	limited := io.LimitReader(input, file.Size+1)
	hash := sha256.New()
	if err := txn.installReader(file.Destination, os.FileMode(file.Mode), file.Preserve, io.TeeReader(limited, hash), file.Size); err != nil {
		return err
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != file.SHA256 {
		return errors.New("verified bundle file changed during copy")
	}
	return nil
}

func (txn *fileTransaction) installBytes(destination string, mode os.FileMode, preserve bool, value []byte) error {
	return txn.installReader(destination, mode, preserve, bytes.NewReader(value), int64(len(value)))
}

func (txn *fileTransaction) installReader(destination string, mode os.FileMode, preserve bool, input io.Reader, expected int64) error {
	target, err := txn.installer.target(destination)
	if err != nil {
		return err
	}
	operation, err := plannedWrite(target, preserve, txn.installer.Root == "/")
	if err != nil {
		return err
	}
	if operation == OperationPreserve {
		return nil
	}
	createdDirs, err := ensureParents(txn.installer.Root, filepath.Dir(target))
	if err != nil {
		return err
	}
	txn.createdDirs = append(txn.createdDirs, createdDirs...)
	staged, err := os.CreateTemp(filepath.Dir(target), ".private-vm-install-*")
	if err != nil {
		return errors.New("installation staging failed")
	}
	stagedPath := staged.Name()
	ok := false
	defer func() {
		_ = staged.Close()
		if !ok {
			_ = os.Remove(stagedPath)
		}
	}()
	written, err := io.CopyN(staged, input, expected)
	if err != nil || written != expected {
		return errors.New("installation staging copy failed")
	}
	var extra [1]byte
	if count, readErr := input.Read(extra[:]); count != 0 || (readErr != nil && readErr != io.EOF) {
		return errors.New("installation source changed during copy")
	}
	if err := staged.Chmod(mode); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return errors.New("installation staging could not be committed")
	}
	change := installedChange{target: target, created: operation == OperationCreate}
	if operation == OperationReplace {
		backup, backupErr := reserveBackup(target)
		if backupErr != nil {
			return backupErr
		}
		if renameErr := os.Rename(target, backup); renameErr != nil {
			_ = os.Remove(backup)
			return errors.New("existing installation file could not be staged for rollback")
		}
		change.backup = backup
	}
	if err := os.Rename(stagedPath, target); err != nil {
		if change.backup != "" {
			_ = os.Rename(change.backup, target)
		}
		return errors.New("installation file could not be published")
	}
	ok = true
	txn.changes = append(txn.changes, change)
	return nil
}

func (txn *fileTransaction) rollback() error {
	var rollbackErrors []error
	for index := len(txn.changes) - 1; index >= 0; index-- {
		change := txn.changes[index]
		if err := os.Remove(change.target); err != nil && !errors.Is(err, os.ErrNotExist) {
			rollbackErrors = append(rollbackErrors, err)
		}
		if change.backup != "" {
			if err := os.Rename(change.backup, change.target); err != nil {
				rollbackErrors = append(rollbackErrors, err)
			}
		}
	}
	for index := len(txn.createdDirs) - 1; index >= 0; index-- {
		if err := os.Remove(txn.createdDirs[index]); err != nil && !errors.Is(err, os.ErrNotExist) {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	return errors.Join(rollbackErrors...)
}

func (txn *fileTransaction) commit() error {
	var cleanupErrors []error
	for _, change := range txn.changes {
		if change.backup != "" {
			if err := os.Remove(change.backup); err != nil && !errors.Is(err, os.ErrNotExist) {
				cleanupErrors = append(cleanupErrors, err)
			}
		}
	}
	return errors.Join(cleanupErrors...)
}

type removedChange struct {
	target string
	backup string
}

type removalTransaction struct {
	installer Installer
	changes   []removedChange
}

func (txn *removalTransaction) remove(destination string) error {
	target, err := txn.installer.target(destination)
	if err != nil {
		return err
	}
	operation, err := plannedWrite(target, false, txn.installer.Root == "/")
	if err != nil || operation != OperationReplace {
		return errors.New("installed removal target is unsafe")
	}
	backup, err := reserveBackup(target)
	if err != nil {
		return err
	}
	if err := os.Rename(target, backup); err != nil {
		_ = os.Remove(backup)
		return errors.New("installed file could not be staged for removal")
	}
	txn.changes = append(txn.changes, removedChange{target: target, backup: backup})
	return nil
}

func (txn *removalTransaction) rollback() error {
	var rollbackErrors []error
	for index := len(txn.changes) - 1; index >= 0; index-- {
		if err := os.Rename(txn.changes[index].backup, txn.changes[index].target); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	return errors.Join(rollbackErrors...)
}

func (txn *removalTransaction) commit() error {
	var cleanupErrors []error
	for _, change := range txn.changes {
		if err := os.Remove(change.backup); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	return errors.Join(cleanupErrors...)
}

func rollbackFailure(primary, rollback error) error {
	if rollback == nil {
		return primary
	}
	return errors.Join(primary, ErrRollbackIncomplete)
}

func reserveBackup(target string) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(target), ".private-vm-rollback-*")
	if err != nil {
		return "", errors.New("rollback staging failed")
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", errors.New("rollback staging failed")
	}
	if err := os.Remove(path); err != nil {
		return "", errors.New("rollback staging failed")
	}
	return path, nil
}

func ensureParents(root, directory string) ([]string, error) {
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("installation parent escapes root")
	}
	current := root
	var created []string
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "." || component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			if mkdirErr := os.Mkdir(current, 0o755); mkdirErr != nil {
				return created, errors.New("installation parent could not be created")
			}
			created = append(created, current)
			continue
		}
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return created, errors.New("installation parent is unsafe")
		}
		if root == "/" {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
				return created, errors.New("installation parent ownership or mode is unsafe")
			}
		}
	}
	return created, nil
}

func SortChanges(changes []Change) []Change {
	copyOfChanges := append([]Change(nil), changes...)
	sort.SliceStable(copyOfChanges, func(left, right int) bool {
		if copyOfChanges[left].Path == copyOfChanges[right].Path {
			return copyOfChanges[left].Operation < copyOfChanges[right].Operation
		}
		return copyOfChanges[left].Path < copyOfChanges[right].Path
	})
	return copyOfChanges
}

type defaultProbe struct{}

func (defaultProbe) EffectiveUID() int { return os.Geteuid() }

func (defaultProbe) DaemonActive(ctx context.Context) (bool, error) {
	return systemdUnitActive(ctx, "private-vmd.service")
}

func (defaultProbe) Validate(ctx context.Context, requireKVM bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("unsupported operating system or architecture")
	}
	for _, required := range []string{"/run/systemd/system", "/sys/fs/cgroup/cgroup.controllers"} {
		if _, err := os.Stat(required); err != nil {
			return fmt.Errorf("required host facility is unavailable")
		}
	}
	if !requireKVM {
		return nil
	}
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return errors.New("KVM is unavailable to the installer")
	}
	if err := kvm.Close(); err != nil {
		return errors.New("KVM probe could not be closed")
	}
	return nil
}
