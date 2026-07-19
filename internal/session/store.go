package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	runtimeRootMode = 0o750
	sessionDirMode  = 0o700
	metadataMode    = 0o600
	controlSockMode = 0o660
	maxMetadataSize = 1 << 20
)

var sessionIDPattern = regexp.MustCompile(`^pvm-[a-f0-9]{32}$`)

var documentedSessionDirectories = map[string]struct{}{
	"qmp": {}, "spice": {}, "events": {}, "secrets": {}, "mount": {}, "locks": {},
}

// ValidateID accepts only daemon-generated opaque v1 session identifiers.
func ValidateID(id string) error {
	if !sessionIDPattern.MatchString(id) {
		return errors.New("invalid internal session identifier")
	}
	return nil
}

// Store owns redacted session journals beneath one already trusted volatile
// runtime root. All operations are serialized and dirfd-relative. The recorded
// root identity prevents a pathname replacement from redirecting a later
// operation to an attacker-controlled directory.
type Store struct {
	root string
	uid  uint32
	gid  uint32
	dev  uint64
	ino  uint64
	mu   sync.Mutex
}

func NewStore(root string) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, errors.New("runtime root must be a clean, non-root absolute path")
	}

	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	fd, created, err := openOrCreateRuntimeRoot(root, uid, gid)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		if created {
			_ = removeCreatedRuntimeRoot(root)
		}
		return nil, fmt.Errorf("inspect runtime root: %w", err)
	}
	if err := verifyOwnedDirectory("runtime root", &stat, uid, gid, runtimeRootMode); err != nil {
		if created {
			_ = removeCreatedRuntimeRoot(root)
		}
		return nil, err
	}

	return &Store{root: root, uid: uid, gid: gid, dev: uint64(stat.Dev), ino: stat.Ino}, nil
}

func (s *Store) Root() string { return s.root }

func (s *Store) Create(snapshot Snapshot) (returnErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := encodeSnapshot(snapshot)
	if err != nil {
		return err
	}
	rootFD, err := s.openRoot()
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)

	if err := unix.Mkdirat(rootFD, snapshot.ID, sessionDirMode); err != nil {
		return fmt.Errorf("create volatile session directory: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			if err := rollbackSessionCreate(rootFD, snapshot.ID); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("roll back volatile session creation: %w", err))
			}
		}
	}()

	sessionFD, err := openDirectoryAt(rootFD, snapshot.ID)
	if err != nil {
		return fmt.Errorf("open new volatile session directory: %w", err)
	}
	if err := setOwnedMode(sessionFD, s.uid, s.gid, sessionDirMode); err != nil {
		unix.Close(sessionFD)
		return fmt.Errorf("secure volatile session directory: %w", err)
	}
	if err := s.saveAt(sessionFD, data); err != nil {
		unix.Close(sessionFD)
		return err
	}
	if err := unix.Close(sessionFD); err != nil {
		return fmt.Errorf("close volatile session directory: %w", err)
	}
	if err := syncFD(rootFD, "runtime root"); err != nil {
		return err
	}
	if err := s.verifyRootPathIdentity(); err != nil {
		return err
	}
	rollback = false
	return nil
}

func (s *Store) Save(snapshot Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := encodeSnapshot(snapshot)
	if err != nil {
		return err
	}
	rootFD, err := s.openRoot()
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	sessionFD, err := s.openSession(rootFD, snapshot.ID)
	if err != nil {
		return err
	}
	defer unix.Close(sessionFD)
	return s.saveAt(sessionFD, data)
}

// Load reads and strictly validates one bounded redacted journal. It rejects
// unknown or duplicate JSON fields, trailing data, incomplete saves, unsafe
// paths, and snapshots whose internal identity or event chain is inconsistent.
func (s *Store) Load(id string) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ValidateID(id); err != nil {
		return Snapshot{}, err
	}
	rootFD, err := s.openRoot()
	if err != nil {
		return Snapshot{}, err
	}
	defer unix.Close(rootFD)
	snapshot, err := s.loadAt(rootFD, id)
	if err != nil {
		return Snapshot{}, err
	}
	if err := s.verifyRootPathIdentity(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ValidateID(id); err != nil {
		return err
	}
	rootFD, err := s.openRoot()
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)

	sessionFD, err := s.openSession(rootFD, id)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(sessionFD)
	entries, err := verifySessionEntries(sessionFD, s.uid, s.gid, true, false)
	if err != nil {
		return err
	}

	removing := ".removing-" + id
	if err := ensureMissingAt(rootFD, removing); err != nil {
		return err
	}
	if err := unix.Renameat(rootFD, id, rootFD, removing); err != nil {
		return fmt.Errorf("isolate volatile session directory for removal: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = unix.Renameat(rootFD, removing, rootFD, id)
			_ = unix.Fsync(rootFD)
		}
	}()
	if err := syncFD(rootFD, "runtime root after session isolation"); err != nil {
		return err
	}
	if err := s.verifyRootPathIdentity(); err != nil {
		return err
	}

	for _, name := range entries {
		if err := unix.Unlinkat(sessionFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove volatile session record: %w", err)
		}
	}
	if err := unix.Unlinkat(rootFD, removing, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove volatile session directory: %w", err)
	}
	rollback = false
	if err := syncFD(rootFD, "runtime root after session removal"); err != nil {
		return err
	}
	return s.verifyRootPathIdentity()
}

func (s *Store) ListIDs() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rootFD, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	entries, err := readDirectoryNames(rootFD)
	if err != nil {
		return nil, fmt.Errorf("list volatile session root: %w", err)
	}
	ids := make([]string, 0, len(entries))
	for _, name := range entries {
		if name == "control.sock" {
			if err := s.verifyControlSocket(rootFD); err != nil {
				return nil, err
			}
			continue
		}
		if err := ValidateID(name); err != nil {
			return nil, fmt.Errorf("unexpected path in volatile session root: %s", name)
		}
		if _, err := s.loadAt(rootFD, name); err != nil {
			return nil, fmt.Errorf("validate volatile session %s: %w", name, err)
		}
		ids = append(ids, name)
	}
	sort.Strings(ids)
	if err := s.verifyRootPathIdentity(); err != nil {
		return nil, err
	}
	return ids, nil
}

func (s *Store) saveAt(sessionFD int, data []byte) error {
	if err := s.verifySessionFD(sessionFD); err != nil {
		return err
	}
	entries, err := verifySessionEntries(sessionFD, s.uid, s.gid, true, true)
	if err != nil {
		return err
	}
	for _, name := range entries {
		if name == ".metadata.tmp" {
			if err := unix.Unlinkat(sessionFD, name, 0); err != nil {
				return fmt.Errorf("remove incomplete volatile session record: %w", err)
			}
		}
	}

	fd, err := unix.Openat(sessionFD, ".metadata.tmp", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, metadataMode)
	if err != nil {
		return fmt.Errorf("create volatile session record: %w", err)
	}
	tmpExists := true
	defer func() {
		_ = unix.Close(fd)
		if tmpExists {
			_ = unix.Unlinkat(sessionFD, ".metadata.tmp", 0)
		}
	}()
	if err := setOwnedMode(fd, s.uid, s.gid, metadataMode); err != nil {
		return fmt.Errorf("secure volatile session record: %w", err)
	}
	file := os.NewFile(uintptr(fd), ".metadata.tmp")
	if file == nil {
		return errors.New("wrap volatile session record descriptor")
	}
	if err := writeAll(file, data); err != nil {
		return fmt.Errorf("write volatile session record: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync volatile session record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close volatile session record: %w", err)
	}
	fd = -1

	if err := s.verifyRootPathIdentity(); err != nil {
		return err
	}
	if err := unix.Renameat(sessionFD, ".metadata.tmp", sessionFD, "metadata.json"); err != nil {
		return fmt.Errorf("install volatile session record: %w", err)
	}
	tmpExists = false
	if err := syncFD(sessionFD, "volatile session directory"); err != nil {
		return err
	}
	if err := s.verifyRootPathIdentity(); err != nil {
		return err
	}
	return nil
}

func (s *Store) loadAt(rootFD int, id string) (Snapshot, error) {
	sessionFD, err := s.openSession(rootFD, id)
	if err != nil {
		return Snapshot{}, err
	}
	defer unix.Close(sessionFD)
	entries, err := verifySessionEntries(sessionFD, s.uid, s.gid, false, true)
	if err != nil {
		return Snapshot{}, err
	}
	if !containsName(entries, "metadata.json") {
		return Snapshot{}, errors.New("volatile session directory does not contain metadata.json")
	}

	fd, err := openRegularAt(sessionFD, "metadata.json", s.uid, s.gid, metadataMode)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open volatile session record: %w", err)
	}
	file := os.NewFile(uintptr(fd), "metadata.json")
	if file == nil {
		unix.Close(fd)
		return Snapshot{}, errors.New("wrap volatile session record descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Snapshot{}, fmt.Errorf("inspect volatile session record: %w", err)
	}
	if info.Size() < 1 || info.Size() > maxMetadataSize {
		return Snapshot{}, errors.New("volatile session record size is outside the allowed range")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxMetadataSize+1))
	if err != nil {
		return Snapshot{}, fmt.Errorf("read volatile session record: %w", err)
	}
	if len(data) > maxMetadataSize {
		return Snapshot{}, errors.New("volatile session record exceeds 1 MiB")
	}
	snapshot, err := decodeSnapshot(data, id)
	if err != nil {
		return Snapshot{}, fmt.Errorf("decode volatile session record: %w", err)
	}
	return snapshot, nil
}

func (s *Store) openRoot() (int, error) {
	fd, err := openAbsoluteDirectory(s.root)
	if err != nil {
		return -1, fmt.Errorf("open runtime root: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("inspect runtime root: %w", err)
	}
	if err := verifyOwnedDirectory("runtime root", &stat, s.uid, s.gid, runtimeRootMode); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if uint64(stat.Dev) != s.dev || stat.Ino != s.ino {
		unix.Close(fd)
		return -1, errors.New("runtime root identity changed")
	}
	return fd, nil
}

func (s *Store) verifyRootPathIdentity() error {
	fd, err := s.openRoot()
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func (s *Store) openSession(rootFD int, id string) (int, error) {
	if err := ValidateID(id); err != nil {
		return -1, err
	}
	fd, err := openDirectoryAt(rootFD, id)
	if err != nil {
		return -1, fmt.Errorf("open volatile session directory: %w", err)
	}
	if err := s.verifySessionFD(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (s *Store) verifySessionFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect volatile session directory: %w", err)
	}
	return verifyOwnedDirectory("volatile session directory", &stat, s.uid, s.gid, sessionDirMode)
}

func (s *Store) verifyControlSocket(rootFD int) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(rootFD, "control.sock", &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("inspect daemon control socket: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Uid != s.uid || stat.Gid != s.gid || stat.Mode&0o7777 != controlSockMode {
		return errors.New("daemon control socket has an unsafe type, owner, group, or mode")
	}
	return nil
}

func openOrCreateRuntimeRoot(root string, uid, gid uint32) (fd int, created bool, err error) {
	fd, err = openAbsoluteDirectory(root)
	if err == nil {
		return fd, false, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return -1, false, fmt.Errorf("open runtime root: %w", err)
	}

	parentPath, name := filepath.Dir(root), filepath.Base(root)
	parentFD, err := openAbsoluteDirectory(parentPath)
	if err != nil {
		return -1, false, fmt.Errorf("open runtime root parent: %w", err)
	}
	defer unix.Close(parentFD)
	if err := verifyTrustedParent(parentFD, uid); err != nil {
		return -1, false, err
	}
	if err := unix.Mkdirat(parentFD, name, runtimeRootMode); err != nil {
		return -1, false, fmt.Errorf("create runtime root: %w", err)
	}
	created = true
	rollback := true
	defer func() {
		if rollback {
			_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
			_ = unix.Fsync(parentFD)
		}
	}()
	fd, err = openDirectoryAt(parentFD, name)
	if err != nil {
		return -1, true, fmt.Errorf("open new runtime root: %w", err)
	}
	if err := setOwnedMode(fd, uid, gid, runtimeRootMode); err != nil {
		unix.Close(fd)
		return -1, true, fmt.Errorf("secure runtime root: %w", err)
	}
	if err := syncFD(parentFD, "runtime root parent"); err != nil {
		unix.Close(fd)
		return -1, true, err
	}
	rollback = false
	return fd, true, nil
}

func openAbsoluteDirectory(path string) (int, error) {
	baseFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(baseFD)
	relative := strings.TrimPrefix(path, "/")
	if relative == "" {
		relative = "."
	}
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	}
	return unix.Openat2(baseFD, relative, how)
}

func openDirectoryAt(parentFD int, name string) (int, error) {
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	}
	return unix.Openat2(parentFD, name, how)
}

func openRegularAt(parentFD int, name string, uid, gid uint32, mode uint32) (int, error) {
	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	}
	fd, err := unix.Openat2(parentFD, name, how)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return -1, err
	}
	if err := verifyOwnedRegular("volatile session record", &stat, uid, gid, mode); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func verifyOwnedDirectory(label string, stat *unix.Stat_t, uid, gid uint32, mode uint32) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s is not a real directory", label)
	}
	if stat.Uid != uid || stat.Gid != gid {
		return fmt.Errorf("%s owner or group does not match the daemon", label)
	}
	if stat.Mode&0o7777 != mode {
		return fmt.Errorf("%s mode must be exactly %04o", label, mode)
	}
	return nil
}

func verifyOwnedRegular(label string, stat *unix.Stat_t, uid, gid uint32, mode uint32) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return fmt.Errorf("%s is not a singly-linked regular file", label)
	}
	if stat.Uid != uid || stat.Gid != gid {
		return fmt.Errorf("%s owner or group does not match the daemon", label)
	}
	if stat.Mode&0o7777 != mode {
		return fmt.Errorf("%s mode must be exactly %04o", label, mode)
	}
	return nil
}

func verifyTrustedParent(fd int, uid uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect runtime root parent: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || (stat.Uid != uid && stat.Uid != 0) {
		return errors.New("runtime root parent is not a trusted directory")
	}
	if stat.Mode&0o022 != 0 && !(stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0) {
		return errors.New("runtime root parent is writable by an untrusted group or user")
	}
	return nil
}

func setOwnedMode(fd int, uid, gid uint32, mode uint32) error {
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return err
	}
	return unix.Fchmod(fd, mode)
}

func verifySessionEntries(sessionFD int, uid, gid uint32, allowTemp, allowResourceDirectories bool) ([]string, error) {
	entries, err := readDirectoryNames(sessionFD)
	if err != nil {
		return nil, fmt.Errorf("read volatile session directory: %w", err)
	}
	for _, name := range entries {
		if _, documented := documentedSessionDirectories[name]; documented && allowResourceDirectories {
			var stat unix.Stat_t
			if err := unix.Fstatat(sessionFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return nil, fmt.Errorf("inspect volatile session resource directory: %w", err)
			}
			if err := verifyOwnedDirectory("volatile session resource directory", &stat, uid, gid, sessionDirMode); err != nil {
				return nil, err
			}
			continue
		}
		if name != "metadata.json" && !(allowTemp && name == ".metadata.tmp") {
			return nil, fmt.Errorf("unexpected path in volatile session directory: %s", name)
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(sessionFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return nil, fmt.Errorf("inspect volatile session record: %w", err)
		}
		if err := verifyOwnedRegular("volatile session record", &stat, uid, gid, metadataMode); err != nil {
			return nil, err
		}
	}
	sort.Strings(entries)
	return entries, nil
}

func containsName(names []string, expected string) bool {
	for _, name := range names {
		if name == expected {
			return true
		}
	}
	return false
}

func readDirectoryNames(fd int) ([]string, error) {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), "directory")
	if file == nil {
		unix.Close(duplicate)
		return nil, errors.New("wrap directory descriptor")
	}
	defer file.Close()
	return file.Readdirnames(-1)
}

func ensureMissingAt(parentFD int, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect removal staging path: %w", err)
	}
	return errors.New("volatile session removal staging path already exists")
}

func rollbackSessionCreate(rootFD int, id string) error {
	sessionFD, err := openDirectoryAt(rootFD, id)
	if err == nil {
		for _, name := range []string{".metadata.tmp", "metadata.json"} {
			_ = unix.Unlinkat(sessionFD, name, 0)
		}
		_ = unix.Close(sessionFD)
	}
	removeErr := unix.Unlinkat(rootFD, id, unix.AT_REMOVEDIR)
	if errors.Is(removeErr, unix.ENOENT) {
		removeErr = nil
	}
	return errors.Join(removeErr, unix.Fsync(rootFD))
}

func removeCreatedRuntimeRoot(root string) error {
	parentFD, err := openAbsoluteDirectory(filepath.Dir(root))
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	return unix.Unlinkat(parentFD, filepath.Base(root), unix.AT_REMOVEDIR)
}

func syncFD(fd int, label string) error {
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync %s: %w", label, err)
	}
	return nil
}

func writeAll(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func encodeSnapshot(snapshot Snapshot) ([]byte, error) {
	if err := validateSnapshot(snapshot); err != nil {
		return nil, err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("encode volatile session record: %w", err)
	}
	if len(data) > maxMetadataSize {
		return nil, errors.New("volatile session record exceeds 1 MiB")
	}
	return data, nil
}

func decodeSnapshot(data []byte, expectedID string) (Snapshot, error) {
	if err := rejectDuplicateJSONFields(data); err != nil {
		return Snapshot{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Snapshot{}, err
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	if snapshot.ID != expectedID {
		return Snapshot{}, errors.New("volatile session record identity does not match its directory")
	}
	return snapshot, nil
}

func rejectDuplicateJSONFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("volatile session record exceeds the JSON nesting limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("volatile session record has a non-string object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("volatile session record contains duplicate field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("volatile session record has an unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("volatile session record has an unterminated array")
		}
	default:
		return errors.New("volatile session record has an invalid JSON delimiter")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("volatile session record contains trailing JSON data")
		}
		return err
	}
	return nil
}
