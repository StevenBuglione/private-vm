//go:build linux

package recovery

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/StevenBuglione/private-vm/internal/session"
	"golang.org/x/sys/unix"
)

const (
	linuxInventoryLimit = 4096
	linuxLoopLimit      = 256
	linuxEvidenceLimit  = 4096
)

var (
	loopDeviceName = regexp.MustCompile(`^loop[0-9]+$`)
	dmDeviceName   = regexp.MustCompile(`^dm-[0-9]+$`)
)

// ToolRunner is the narrow recovery command boundary. Implementations receive
// only a package-selected operation and a previously revalidated typed locator.
// Output is neither required nor accepted by recovery.
type ToolRunner interface {
	Run(context.Context, string, ...string) error
}

// MountCleaner is the typed outer-mount cleanup boundary.
type MountCleaner interface {
	Unmount(string, int) error
}

// LinuxBackendConfig names only trusted installation roots and fixed tools.
// Alternate proc/sys/dev roots exist solely for isolated source tests.
type LinuxBackendConfig struct {
	Store         *session.Store
	ScratchRoot   string
	DaemonUID     uint32
	DaemonGID     uint32
	ControlGID    uint32
	Cryptsetup    string
	Losetup       string
	Runner        ToolRunner
	Mounter       MountCleaner
	MountInfoPath string
	SysBlockRoot  string
	DevRoot       string
	DevMapperRoot string
	MaxCandidates int
	MaxLoops      int
}

// LinuxBackend inventories and removes the filesystem and outer-storage
// resources whose exact identities can be reconstructed without a surviving
// daemon handle. An advanced volatile session is deliberately not recoverable:
// its journal does not yet contain the process/network/VSOCK/USB identities
// required to mutate those resources safely.
type LinuxBackend struct {
	config   LinuxBackendConfig
	unsafe   map[string]struct{}
	observed map[string]Candidate
}

func NewLinuxBackend(config LinuxBackendConfig) (*LinuxBackend, error) {
	if config.Store == nil || config.Runner == nil || config.Mounter == nil {
		return nil, errors.New("linux recovery requires a volatile store, typed runner, and mount cleaner")
	}
	if config.DaemonUID != uint32(os.Geteuid()) || config.DaemonGID != uint32(os.Getegid()) {
		return nil, errors.New("linux recovery daemon identity does not match the running process")
	}
	if config.ScratchRoot == "" || !narrowAbsolute(config.ScratchRoot) {
		return nil, errors.New("linux recovery scratch root is invalid")
	}
	if config.Store.Root() == config.ScratchRoot || strings.HasPrefix(config.ScratchRoot+"/", config.Store.Root()+"/") || strings.HasPrefix(config.Store.Root()+"/", config.ScratchRoot+"/") {
		return nil, errors.New("linux recovery roots must be disjoint")
	}
	for label, path := range map[string]string{"cryptsetup": config.Cryptsetup, "losetup": config.Losetup} {
		if !narrowAbsolute(path) || filepath.Base(path) != label {
			return nil, errors.New("linux recovery tool path is invalid")
		}
	}
	if config.MountInfoPath == "" {
		config.MountInfoPath = "/proc/self/mountinfo"
	}
	if config.SysBlockRoot == "" {
		config.SysBlockRoot = "/sys/class/block"
	}
	if config.DevRoot == "" {
		config.DevRoot = "/dev"
	}
	if config.DevMapperRoot == "" {
		config.DevMapperRoot = "/dev/mapper"
	}
	for _, path := range []string{config.MountInfoPath, config.SysBlockRoot, config.DevRoot, config.DevMapperRoot} {
		if !narrowAbsolute(path) {
			return nil, errors.New("linux recovery evidence path is invalid")
		}
	}
	if config.MaxCandidates == 0 {
		config.MaxCandidates = linuxInventoryLimit
	}
	if config.MaxLoops == 0 {
		config.MaxLoops = linuxLoopLimit
	}
	if config.MaxCandidates < 1 || config.MaxCandidates > linuxInventoryLimit || config.MaxLoops < 1 || config.MaxLoops > linuxLoopLimit {
		return nil, errors.New("linux recovery inventory bounds are invalid")
	}
	return &LinuxBackend{config: config, unsafe: make(map[string]struct{}), observed: make(map[string]Candidate)}, nil
}

func (backend *LinuxBackend) Inventory(ctx context.Context) ([]Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	backend.unsafe = make(map[string]struct{})
	backend.observed = make(map[string]Candidate)

	ids, err := backend.config.Store.ListIDsForRecovery(backend.config.ControlGID)
	if err != nil {
		return nil, errors.New("volatile recovery inventory failed")
	}
	candidates := make([]Candidate, 0, len(ids))
	for _, id := range ids {
		snapshot, loadErr := backend.config.Store.Load(id)
		if loadErr != nil {
			return nil, errors.New("volatile recovery record validation failed")
		}
		if phaseMayOwnPrivilegedResources(snapshot.Phase) {
			backend.unsafe[id] = struct{}{}
		}
		sockets, socketErr := backend.inventorySockets(id)
		if socketErr != nil {
			return nil, socketErr
		}
		candidates = append(candidates, sockets...)
		candidate, candidateErr := backend.pathCandidate(id, KindRuntimePath, OriginVolatileRecord, filepath.Join(backend.config.Store.Root(), id), unix.S_IFDIR, 0o700)
		if candidateErr != nil {
			return nil, candidateErr
		}
		candidates = append(candidates, candidate)
	}

	storage, err := backend.inventoryScratch(ctx)
	if err != nil {
		return nil, err
	}
	candidates = append(candidates, storage...)
	if len(candidates) > backend.config.MaxCandidates {
		return nil, errors.New("linux recovery candidate limit exceeded")
	}
	for _, candidate := range candidates {
		key := linuxCandidateKey(candidate)
		if _, duplicate := backend.observed[key]; duplicate {
			return nil, errors.New("linux recovery inventory returned a duplicate")
		}
		backend.observed[key] = candidate
	}
	return candidates, nil
}

func phaseMayOwnPrivilegedResources(phase session.Phase) bool {
	switch phase {
	case session.PhaseCreated, session.PhasePreflighted, session.PhaseImagesVerified, session.PhaseDestroyed:
		return false
	default:
		return true
	}
}

func (backend *LinuxBackend) RevalidateOwned(ctx context.Context, candidate Candidate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, blocked := backend.unsafe[candidate.SessionID]; blocked {
		return errors.New("advanced recovery lacks exact process, network, VSOCK, and USB ownership evidence")
	}
	observed, ok := backend.observed[linuxCandidateKey(candidate)]
	if !ok || observed.Identity != candidate.Identity || observed.Locator != candidate.Locator {
		return errors.New("recovery candidate was not produced by the current bounded inventory")
	}
	current, err := backend.inspectCandidate(candidate)
	if err != nil {
		return err
	}
	if current != candidate.Identity {
		return errors.New("recovery candidate identity changed")
	}
	return nil
}

func (backend *LinuxBackend) Cleanup(ctx context.Context, candidate Candidate) error {
	if err := backend.RevalidateOwned(ctx, candidate); err != nil {
		return err
	}
	switch candidate.Kind {
	case KindQMPSocket, KindSPICESocket:
		return unlinkExact(candidate.Locator, candidate.Identity)
	case KindMount:
		return backend.config.Mounter.Unmount(candidate.Locator, 0)
	case KindMapper:
		return backend.config.Runner.Run(ctx, backend.config.Cryptsetup, "close", candidate.Locator)
	case KindLoop:
		return backend.config.Runner.Run(ctx, backend.config.Losetup, "--detach", candidate.Locator)
	case KindCiphertext:
		return unlinkExact(candidate.Locator, candidate.Identity)
	case KindRuntimePath:
		return backend.config.Store.Remove(candidate.SessionID)
	default:
		return errors.New("linux recovery resource class has no proven cleanup adapter")
	}
}

func (backend *LinuxBackend) AuditAbsent(ctx context.Context, candidate Candidate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	present, err := backend.candidatePresent(candidate)
	if err != nil {
		return err
	}
	if present {
		return errors.New("recovery resource remains present")
	}
	return nil
}

func (backend *LinuxBackend) AuditSessionAbsent(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, blocked := backend.unsafe[id]; blocked {
		return errors.New("advanced session absence is not proven")
	}
	if _, err := os.Lstat(filepath.Join(backend.config.Store.Root(), id)); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("volatile session path remains or cannot be audited")
	}
	if _, err := os.Lstat(filepath.Join(backend.config.ScratchRoot, id+".luks")); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("session ciphertext remains or cannot be audited")
	}
	loops, err := backend.loopsForCiphertext(filepath.Join(backend.config.ScratchRoot, id+".luks"))
	if err != nil || len(loops) != 0 {
		return errors.New("session loop-device absence is not proven")
	}
	if present, err := pathExists(filepath.Join(backend.config.DevMapperRoot, id)); err != nil || present {
		return errors.New("session mapper absence is not proven")
	}
	if mount, err := backend.mountFor(id); err != nil || mount != nil {
		return errors.New("session outer-mount absence is not proven")
	}
	return nil
}

func (backend *LinuxBackend) inventorySockets(id string) ([]Candidate, error) {
	var result []Candidate
	for _, descriptor := range []struct {
		directory string
		name      string
		kind      Kind
	}{{"qmp", "qmp.sock", KindQMPSocket}, {"spice", "spice.sock", KindSPICESocket}} {
		path := filepath.Join(backend.config.Store.Root(), id, descriptor.directory, descriptor.name)
		present, err := pathExists(path)
		if err != nil {
			return nil, errors.New("runtime socket inventory failed")
		}
		if !present {
			continue
		}
		candidate, err := backend.pathCandidate(id, descriptor.kind, OriginVolatileRecord, path, unix.S_IFSOCK, 0o600)
		if err != nil {
			return nil, err
		}
		result = append(result, candidate)
	}
	return result, nil
}

func (backend *LinuxBackend) inventoryScratch(ctx context.Context) ([]Candidate, error) {
	root, err := openOwnedDirectory(backend.config.ScratchRoot, backend.config.DaemonUID, backend.config.DaemonGID, 0o700)
	if err != nil {
		return nil, errors.New("scratch recovery root is unavailable or unsafe")
	}
	defer root.Close()
	entries, err := root.Readdir(-1)
	if err != nil || len(entries) > backend.config.MaxCandidates+1 {
		return nil, errors.New("scratch recovery inventory failed or exceeded its bound")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	markerSeen := false
	var result []Candidate
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Name() == ".private-vm-no-backup" {
			if err := verifyScratchMarker(filepath.Join(backend.config.ScratchRoot, entry.Name()), backend.config.DaemonUID, backend.config.DaemonGID); err != nil {
				return nil, err
			}
			markerSeen = true
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".luks") {
			return nil, errors.New("scratch recovery root contains an unexpected entry")
		}
		id := strings.TrimSuffix(entry.Name(), ".luks")
		if session.ValidateID(id) != nil {
			return nil, errors.New("scratch recovery entry has an invalid session identity")
		}
		ciphertext := filepath.Join(backend.config.ScratchRoot, entry.Name())
		candidate, err := backend.pathCandidate(id, KindCiphertext, OriginScratch, ciphertext, unix.S_IFREG, 0o600)
		if err != nil {
			return nil, err
		}
		result = append(result, candidate)
		loops, err := backend.loopsForCiphertext(ciphertext)
		if err != nil || len(loops) > 1 {
			return nil, errors.New("ciphertext loop-device ownership is missing or ambiguous")
		}
		if len(loops) == 1 {
			loop, err := backend.loopCandidate(id, loops[0], ciphertext)
			if err != nil {
				return nil, err
			}
			result = append(result, loop)
			mapper, present, err := backend.mapperCandidate(id, loops[0])
			if err != nil {
				return nil, err
			}
			if present {
				result = append(result, mapper)
			}
		} else if present, err := pathExists(filepath.Join(backend.config.DevMapperRoot, id)); err != nil || present {
			return nil, errors.New("device mapper exists without a proven ciphertext loop")
		}
		mount, present, err := backend.mountCandidate(id)
		if err != nil {
			return nil, err
		}
		if present {
			result = append(result, mount)
		}
	}
	if !markerSeen {
		return nil, errors.New("scratch backup-exclusion evidence is missing")
	}
	return result, nil
}

func (backend *LinuxBackend) pathCandidate(id string, kind Kind, origin Origin, path string, expectedType uint32, mode uint32) (Candidate, error) {
	stat, err := lstatOwned(path, backend.config.DaemonUID, backend.config.DaemonGID, expectedType, mode)
	if err != nil {
		return Candidate{}, errors.New("recovery path identity is unsafe")
	}
	if expectedType == unix.S_IFREG && (stat.Nlink != 1 || stat.Size <= 0) {
		return Candidate{}, errors.New("recovery file identity is unsafe")
	}
	return newLinuxCandidate(id, kind, origin, path, statIdentity(stat))
}

func (backend *LinuxBackend) loopCandidate(id, loopPath, ciphertext string) (Candidate, error) {
	stat, err := lstatTrustedBlock(loopPath)
	if err != nil {
		return Candidate{}, errors.New("loop device identity is unsafe")
	}
	backing, err := readBounded(filepath.Join(backend.config.SysBlockRoot, filepath.Base(loopPath), "loop", "backing_file"), linuxEvidenceLimit)
	if err != nil || filepath.Clean(strings.TrimSpace(string(backing))) != ciphertext {
		return Candidate{}, errors.New("loop device no longer backs the exact ciphertext")
	}
	return newLinuxCandidate(id, KindLoop, OriginKernel, loopPath, statIdentity(stat)+"\x00"+ciphertext)
}

func (backend *LinuxBackend) mapperCandidate(id, loopPath string) (Candidate, bool, error) {
	mapperPath := filepath.Join(backend.config.DevMapperRoot, id)
	present, err := pathExists(mapperPath)
	if err != nil || !present {
		return Candidate{}, false, err
	}
	resolved, err := filepath.EvalSymlinks(mapperPath)
	if err != nil || filepath.Dir(resolved) != backend.config.DevRoot || !dmDeviceName.MatchString(filepath.Base(resolved)) {
		return Candidate{}, false, errors.New("device mapper target is invalid")
	}
	stat, err := lstatTrustedBlock(resolved)
	if err != nil {
		return Candidate{}, false, errors.New("device mapper block identity is unsafe")
	}
	dm := filepath.Base(resolved)
	name, err := readBounded(filepath.Join(backend.config.SysBlockRoot, dm, "dm", "name"), 128)
	if err != nil || strings.TrimSpace(string(name)) != id {
		return Candidate{}, false, errors.New("device mapper name does not match the session")
	}
	slaves, err := os.ReadDir(filepath.Join(backend.config.SysBlockRoot, dm, "slaves"))
	if err != nil || len(slaves) != 1 || slaves[0].Name() != filepath.Base(loopPath) {
		return Candidate{}, false, errors.New("device mapper backing does not match the exact loop")
	}
	candidate, err := newLinuxCandidate(id, KindMapper, OriginKernel, id, statIdentity(stat)+"\x00"+dm+"\x00"+loopPath)
	return candidate, true, err
}

func (backend *LinuxBackend) mountCandidate(id string) (Candidate, bool, error) {
	mount, err := backend.mountFor(id)
	if err != nil || mount == nil {
		return Candidate{}, false, err
	}
	candidate, err := newLinuxCandidate(id, KindMount, OriginKernel, mount.point, mount.identity())
	return candidate, true, err
}

func (backend *LinuxBackend) inspectCandidate(candidate Candidate) (Identity, error) {
	switch candidate.Kind {
	case KindQMPSocket:
		current, err := backend.pathCandidate(candidate.SessionID, candidate.Kind, candidate.Origin, candidate.Locator, unix.S_IFSOCK, 0o600)
		return current.Identity, err
	case KindSPICESocket:
		current, err := backend.pathCandidate(candidate.SessionID, candidate.Kind, candidate.Origin, candidate.Locator, unix.S_IFSOCK, 0o600)
		return current.Identity, err
	case KindRuntimePath:
		current, err := backend.pathCandidate(candidate.SessionID, candidate.Kind, candidate.Origin, candidate.Locator, unix.S_IFDIR, 0o700)
		return current.Identity, err
	case KindCiphertext:
		current, err := backend.pathCandidate(candidate.SessionID, candidate.Kind, candidate.Origin, candidate.Locator, unix.S_IFREG, 0o600)
		return current.Identity, err
	case KindLoop:
		current, err := backend.loopCandidate(candidate.SessionID, candidate.Locator, filepath.Join(backend.config.ScratchRoot, candidate.SessionID+".luks"))
		return current.Identity, err
	case KindMapper:
		loops, err := backend.loopsForCiphertext(filepath.Join(backend.config.ScratchRoot, candidate.SessionID+".luks"))
		if err != nil || len(loops) != 1 {
			return Identity{}, errors.New("mapper loop ownership is not exact")
		}
		current, present, err := backend.mapperCandidate(candidate.SessionID, loops[0])
		if err != nil || !present {
			return Identity{}, errors.New("mapper identity is unavailable")
		}
		return current.Identity, nil
	case KindMount:
		current, present, err := backend.mountCandidate(candidate.SessionID)
		if err != nil || !present {
			return Identity{}, errors.New("outer mount identity is unavailable")
		}
		return current.Identity, nil
	default:
		return Identity{}, errors.New("linux recovery cannot revalidate this resource class")
	}
}

func (backend *LinuxBackend) candidatePresent(candidate Candidate) (bool, error) {
	switch candidate.Kind {
	case KindQMPSocket, KindSPICESocket, KindRuntimePath, KindCiphertext:
		return pathExists(candidate.Locator)
	case KindLoop:
		loops, err := backend.loopsForCiphertext(filepath.Join(backend.config.ScratchRoot, candidate.SessionID+".luks"))
		if err != nil {
			return false, err
		}
		for _, loop := range loops {
			if loop == candidate.Locator {
				return true, nil
			}
		}
		return false, nil
	case KindMapper:
		return pathExists(filepath.Join(backend.config.DevMapperRoot, candidate.SessionID))
	case KindMount:
		mount, err := backend.mountFor(candidate.SessionID)
		return mount != nil, err
	default:
		return false, errors.New("linux recovery cannot audit this resource class")
	}
}

func (backend *LinuxBackend) loopsForCiphertext(ciphertext string) ([]string, error) {
	entries, err := os.ReadDir(backend.config.SysBlockRoot)
	if err != nil {
		return nil, errors.New("loop-device inventory is unavailable")
	}
	loopsSeen := 0
	var result []string
	for _, entry := range entries {
		if !loopDeviceName.MatchString(entry.Name()) {
			continue
		}
		loopsSeen++
		if loopsSeen > backend.config.MaxLoops {
			return nil, errors.New("loop-device inventory exceeded its bound")
		}
		backing, readErr := readBounded(filepath.Join(backend.config.SysBlockRoot, entry.Name(), "loop", "backing_file"), linuxEvidenceLimit)
		if errors.Is(readErr, fs.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return nil, errors.New("loop-device backing evidence is unavailable")
		}
		if filepath.Clean(strings.TrimSpace(string(backing))) == ciphertext {
			result = append(result, filepath.Join(backend.config.DevRoot, entry.Name()))
		}
	}
	sort.Strings(result)
	return result, nil
}

type mountIdentity struct {
	id, parent, device, root, point, options, filesystem, source, super string
}

func (mount mountIdentity) identity() string {
	return strings.Join([]string{mount.id, mount.parent, mount.device, mount.root, mount.point, mount.options, mount.filesystem, mount.source, mount.super}, "\x00")
}

func (backend *LinuxBackend) mountFor(id string) (*mountIdentity, error) {
	data, err := readBounded(backend.config.MountInfoPath, 4<<20)
	if err != nil {
		return nil, errors.New("mount inventory is unavailable")
	}
	wantPoint := filepath.Join(backend.config.Store.Root(), id, "mount")
	wantSource := filepath.Join(backend.config.DevMapperRoot, id)
	var found *mountIdentity
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || len(fields) != separator+4 {
			return nil, errors.New("mount inventory record is malformed")
		}
		if fields[4] != wantPoint {
			continue
		}
		if found != nil || fields[separator+1] != "ext4" || fields[separator+2] != wantSource {
			return nil, errors.New("outer mount identity is missing or ambiguous")
		}
		options := strings.Split(fields[5], ",")
		for _, required := range []string{"nodev", "noexec", "nosuid"} {
			if !contains(options, required) {
				return nil, errors.New("outer mount security options are incomplete")
			}
		}
		found = &mountIdentity{id: fields[0], parent: fields[1], device: fields[2], root: fields[3], point: fields[4], options: fields[5], filesystem: fields[separator+1], source: fields[separator+2], super: fields[separator+3]}
	}
	return found, nil
}

func newLinuxCandidate(id string, kind Kind, origin Origin, locator, evidence string) (Candidate, error) {
	digest := sha256.Sum256([]byte(string(kind) + "\x00" + id + "\x00" + locator + "\x00" + evidence))
	return Candidate{SessionID: id, Kind: kind, Origin: origin, Locator: locator, Identity: Identity{Fingerprint: fmt.Sprintf("%x", digest[:]), OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid())}}, nil
}

func statIdentity(stat unix.Stat_t) string {
	return strings.Join([]string{
		strconv.FormatUint(uint64(stat.Dev), 10), strconv.FormatUint(stat.Ino, 10),
		strconv.FormatUint(uint64(stat.Mode), 10), strconv.FormatUint(uint64(stat.Uid), 10),
		strconv.FormatUint(uint64(stat.Gid), 10), strconv.FormatUint(stat.Nlink, 10),
		strconv.FormatInt(stat.Size, 10), strconv.FormatInt(stat.Mtim.Sec, 10),
		strconv.FormatInt(stat.Mtim.Nsec, 10), strconv.FormatInt(stat.Ctim.Sec, 10),
		strconv.FormatInt(stat.Ctim.Nsec, 10),
	}, "\x00")
}

func lstatOwned(path string, uid, gid uint32, expectedType uint32, expectedMode uint32) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return stat, err
	}
	if stat.Mode&unix.S_IFMT != expectedType || stat.Uid != uid || stat.Gid != gid {
		return stat, errors.New("resource type or owner is unsafe")
	}
	if expectedMode != 0 && stat.Mode&0o7777 != expectedMode {
		return stat, errors.New("resource mode is unsafe")
	}
	return stat, nil
}

func lstatTrustedBlock(path string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return stat, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFBLK || stat.Uid != 0 {
		return stat, errors.New("block resource type or owner is unsafe")
	}
	return stat, nil
}

func openOwnedDirectory(path string, uid, gid uint32, mode uint32) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != mode || stat.Uid != uid || stat.Gid != gid {
		unix.Close(fd)
		return nil, errors.New("directory identity is unsafe")
	}
	return os.NewFile(uintptr(fd), "private-vm-recovery-directory"), nil
}

func verifyScratchMarker(path string, uid, gid uint32) error {
	stat, err := lstatOwned(path, uid, gid, unix.S_IFREG, 0o600)
	if err != nil || stat.Nlink != 1 || stat.Size != int64(len("private-vm-ephemeral-scratch-v1")) {
		return errors.New("scratch backup-exclusion marker identity is invalid")
	}
	data, err := readBounded(path, 128)
	if err != nil || string(data) != "private-vm-ephemeral-scratch-v1" {
		return errors.New("scratch backup-exclusion marker content is invalid")
	}
	return nil
}

func unlinkExact(path string, identity Identity) error {
	parentPath, name := filepath.Dir(path), filepath.Base(path)
	parent, err := unix.Openat2(unix.AT_FDCWD, parentPath, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return errors.New("open recovery resource parent failed")
	}
	defer unix.Close(parent)
	var stat unix.Stat_t
	if err := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return errors.New("inspect recovery resource before deletion failed")
	}
	// The caller already compared its complete candidate fingerprint. Pin the
	// opened parent and require the same daemon owner immediately at unlink.
	if stat.Uid != identity.OwnerUID || stat.Gid != identity.OwnerGID {
		return errors.New("recovery resource owner changed before deletion")
	}
	if err := unix.Unlinkat(parent, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return errors.New("remove exact recovery resource failed")
	}
	return nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("recovery evidence exceeded its bound or could not be read")
	}
	return data, nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func narrowAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && len(path) <= 4096
}

func linuxCandidateKey(candidate Candidate) string {
	return candidate.SessionID + "\x00" + string(candidate.Kind) + "\x00" + candidate.Locator
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// OSRecoveryRunner executes only fixed verified tools with a minimal
// environment and discards all output so external diagnostics cannot escape.
type OSRecoveryRunner struct{}

func (OSRecoveryRunner) Run(ctx context.Context, path string, arguments ...string) error {
	if !narrowAbsolute(path) {
		return errors.New("recovery executable path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("recovery executable identity is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("recovery executable owner is unsafe")
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"LANG=C.UTF-8"}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil {
		return errors.New("typed recovery command failed")
	}
	return nil
}

// UnixMountCleaner never performs a recursive or lazy unmount.
type UnixMountCleaner struct{}

func (UnixMountCleaner) Unmount(path string, flags int) error {
	if !narrowAbsolute(path) || flags != 0 {
		return errors.New("recovery unmount request is invalid")
	}
	return unix.Unmount(path, flags)
}
