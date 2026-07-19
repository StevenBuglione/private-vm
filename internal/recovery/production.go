package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/StevenBuglione/private-vm/internal/session"
	"golang.org/x/sys/unix"
)

// StartupRegistry serializes recovery claims before the ordinary session
// manager exists. Creating the manager only after recovery succeeds is the
// admission barrier; no live session can race one of these claims.
type StartupRegistry struct {
	mu     sync.Mutex
	claims map[string]struct{}
}

func NewStartupRegistry() *StartupRegistry {
	return &StartupRegistry{claims: make(map[string]struct{})}
}

func (registry *StartupRegistry) ClaimRecovery(ctx context.Context, id string) (RecoveryClaim, error) {
	if registry == nil || session.ValidateID(id) != nil {
		return nil, errors.New("startup recovery claim is invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.claims[id]; exists {
		return nil, ErrActiveOwner
	}
	registry.claims[id] = struct{}{}
	return &startupClaim{registry: registry, id: id}, nil
}

type startupClaim struct {
	once     sync.Once
	registry *StartupRegistry
	id       string
}

func (claim *startupClaim) Release() {
	if claim == nil {
		return
	}
	claim.once.Do(func() {
		claim.registry.mu.Lock()
		delete(claim.registry.claims, claim.id)
		claim.registry.mu.Unlock()
	})
}

// VolatileKeyEvidence implements the v1 key-loss proof: LUKS keys have no
// restore path, and the fresh daemon receives no prior memfd. A non-empty
// on-disk secrets directory is therefore unexpected and returns Unknown.
type VolatileKeyEvidence struct {
	RuntimeRoot string
	DaemonUID   uint32
	DaemonGID   uint32
}

func (evidence VolatileKeyEvidence) State(ctx context.Context, id string) (KeyState, error) {
	if err := ctx.Err(); err != nil {
		return KeyUnknown, err
	}
	if session.ValidateID(id) != nil || !narrowAbsolute(evidence.RuntimeRoot) {
		return KeyUnknown, errors.New("volatile key evidence request is invalid")
	}
	secrets := filepath.Join(evidence.RuntimeRoot, id, "secrets")
	info, err := os.Lstat(secrets)
	if errors.Is(err, fs.ErrNotExist) {
		return KeyUnavailable, nil
	}
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return KeyUnknown, errors.New("volatile secrets directory identity is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != evidence.DaemonUID || stat.Gid != evidence.DaemonGID {
		return KeyUnknown, errors.New("volatile secrets directory owner is unsafe")
	}
	entries, err := os.ReadDir(secrets)
	if err != nil || len(entries) != 0 {
		return KeyUnknown, errors.New("unexpected key material remains in volatile storage")
	}
	return KeyUnavailable, nil
}

// FilesystemBaseAuditor captures a bounded aggregate of the verified image
// cache identities. Image verification remains the launch boundary; this seal
// proves recovery itself did not replace or rewrite those immutable objects.
type FilesystemBaseAuditor struct {
	Root       string
	OwnerUID   uint32
	MaxEntries int
	MaxDepth   int
}

func (auditor FilesystemBaseAuditor) Snapshot(ctx context.Context) (BaseImageSeal, error) {
	if !narrowAbsolute(auditor.Root) {
		return BaseImageSeal{}, errors.New("base-image audit root is invalid")
	}
	maximumEntries := auditor.MaxEntries
	if maximumEntries == 0 {
		maximumEntries = linuxInventoryLimit
	}
	maximumDepth := auditor.MaxDepth
	if maximumDepth == 0 {
		maximumDepth = 4
	}
	if maximumEntries < 1 || maximumEntries > linuxInventoryLimit || maximumDepth < 1 || maximumDepth > 8 {
		return BaseImageSeal{}, errors.New("base-image audit bounds are invalid")
	}
	rootInfo, err := os.Lstat(auditor.Root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0o022 != 0 || fileOwner(rootInfo) != auditor.OwnerUID {
		return BaseImageSeal{}, errors.New("base-image audit root identity is unsafe")
	}
	type item struct {
		path     string
		identity string
	}
	items := make([]item, 0)
	err = filepath.WalkDir(auditor.Root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("base-image audit enumeration failed")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(auditor.Root, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, "../") {
			return errors.New("base-image audit path escaped its root")
		}
		depth := 0
		if relative != "." {
			depth = strings.Count(relative, string(filepath.Separator)) + 1
		}
		if depth > maximumDepth {
			return errors.New("base-image audit depth exceeded its bound")
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) || info.Mode().Perm()&0o022 != 0 || (info.Mode().IsRegular() && info.Mode().Perm()&0o200 != 0) || fileOwner(info) != auditor.OwnerUID {
			return errors.New("base-image audit entry identity is unsafe")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (info.Mode().IsRegular() && stat.Nlink != 1) {
			return errors.New("base-image audit entry links are unsafe")
		}
		items = append(items, item{path: relative, identity: syscallStatIdentity(stat)})
		if len(items) > maximumEntries {
			return errors.New("base-image audit entry count exceeded its bound")
		}
		return nil
	})
	if err != nil {
		return BaseImageSeal{}, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].path < items[j].path })
	digest := sha256.New()
	for _, item := range items {
		_, _ = digest.Write([]byte(item.path))
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(item.identity))
		_, _ = digest.Write([]byte{0})
	}
	return BaseImageSeal{Count: uint32(len(items)), Fingerprint: fmt.Sprintf("%x", digest.Sum(nil))}, nil
}

func (auditor FilesystemBaseAuditor) Verify(ctx context.Context, expected BaseImageSeal) error {
	current, err := auditor.Snapshot(ctx)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("immutable base-image aggregate changed")
	}
	return nil
}

func fileOwner(info os.FileInfo) uint32 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ^uint32(0)
	}
	return stat.Uid
}

func syscallStatIdentity(stat *syscall.Stat_t) string {
	return strings.Join([]string{
		fmt.Sprint(stat.Dev), fmt.Sprint(stat.Ino), fmt.Sprint(stat.Mode),
		fmt.Sprint(stat.Uid), fmt.Sprint(stat.Gid), fmt.Sprint(stat.Nlink),
		fmt.Sprint(stat.Size), fmt.Sprint(stat.Mtim.Sec), fmt.Sprint(stat.Mtim.Nsec),
		fmt.Sprint(stat.Ctim.Sec), fmt.Sprint(stat.Ctim.Nsec),
	}, "\x00")
}

// WriteReportAtomic publishes only the closed recovery report to a volatile
// mode-0600 file. It never serializes candidates, locators or wrapped causes.
func WriteReportAtomic(path string, report Report) error {
	if !narrowAbsolute(path) || len(path) > 4096 || !strings.HasPrefix(filepath.Base(path), "private-vm-recovery-") || filepath.Ext(path) != ".json" {
		return errors.New("recovery report path is invalid")
	}
	data, err := json.Marshal(report)
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		return errors.New("recovery report encoding failed or exceeded its bound")
	}
	data = append(data, '\n')
	parent := filepath.Dir(path)
	parentFD, err := unix.Openat2(unix.AT_FDCWD, parent, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return errors.New("recovery report parent is unavailable")
	}
	defer unix.Close(parentFD)
	var finalStat unix.Stat_t
	if err := unix.Fstatat(parentFD, filepath.Base(path), &finalStat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if finalStat.Mode&unix.S_IFMT != unix.S_IFREG || finalStat.Mode&0o7777 != 0o600 || finalStat.Nlink != 1 || finalStat.Uid != uint32(os.Geteuid()) || finalStat.Gid != uint32(os.Getegid()) {
			return errors.New("existing recovery report identity is unsafe")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return errors.New("existing recovery report could not be inspected")
	}
	temporary := "." + filepath.Base(path) + ".tmp"
	if err := removeOwnedReportTemp(parentFD, temporary); err != nil {
		return err
	}
	fd, err := unix.Openat(parentFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("create recovery report staging file failed")
	}
	file := os.NewFile(uintptr(fd), "private-vm-recovery-report")
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = unix.Unlinkat(parentFD, temporary, 0)
		}
	}()
	if err := file.Chown(os.Geteuid(), os.Getegid()); err != nil {
		return errors.New("set recovery report owner failed")
	}
	if _, err := file.Write(data); err != nil {
		return errors.New("write recovery report failed")
	}
	if err := file.Sync(); err != nil || file.Close() != nil {
		return errors.New("synchronize recovery report failed")
	}
	if err := unix.Renameat(parentFD, temporary, parentFD, filepath.Base(path)); err != nil {
		return errors.New("publish recovery report failed")
	}
	if err := unix.Fsync(parentFD); err != nil {
		return errors.New("synchronize recovery report directory failed")
	}
	success = true
	return nil
}

func removeOwnedReportTemp(parentFD int, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return errors.New("stale recovery report staging identity is unsafe")
	}
	if err := unix.Unlinkat(parentFD, name, 0); err != nil {
		return errors.New("remove stale recovery report staging file failed")
	}
	return nil
}
