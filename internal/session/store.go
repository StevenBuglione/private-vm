package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

var sessionIDPattern = regexp.MustCompile(`^pvm-[a-f0-9]{32}$`)

// ValidateID accepts only daemon-generated opaque v1 session identifiers.
func ValidateID(id string) error {
	if !sessionIDPattern.MatchString(id) {
		return errors.New("invalid internal session identifier")
	}
	return nil
}

type Store struct {
	root string
}

func NewStore(root string) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("runtime root must be a clean absolute path")
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("create runtime root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect runtime root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("runtime root is not a real directory")
	}
	return &Store{root: root}, nil
}

func (s *Store) Root() string { return s.root }

func (s *Store) Create(snapshot Snapshot) error {
	dir, err := s.sessionDir(snapshot.ID)
	if err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("create volatile session directory: %w", err)
	}
	if err := s.Save(snapshot); err != nil {
		_ = os.Remove(dir)
		return err
	}
	return nil
}

func (s *Store) Save(snapshot Snapshot) error {
	dir, err := s.sessionDir(snapshot.ID)
	if err != nil {
		return err
	}
	if err := verifyDirectory(dir); err != nil {
		return err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode volatile session record: %w", err)
	}
	if len(data) > 1<<20 {
		return errors.New("volatile session record exceeds 1 MiB")
	}
	tmp := filepath.Join(dir, ".metadata.tmp")
	final := filepath.Join(dir, "metadata.json")
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create volatile session record: %w", err)
	}
	removeTmp := true
	defer func() {
		_ = file.Close()
		if removeTmp {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write volatile session record: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync volatile session record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close volatile session record: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("install volatile session record: %w", err)
	}
	removeTmp = false
	return syncDirectory(dir)
}

func (s *Store) Remove(id string) error {
	dir, err := s.sessionDir(id)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read volatile session directory: %w", err)
	}
	for _, entry := range entries {
		if entry.Name() != "metadata.json" && entry.Name() != ".metadata.tmp" {
			return fmt.Errorf("unexpected path in volatile session directory: %s", entry.Name())
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove volatile session record: %w", err)
		}
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove volatile session directory: %w", err)
	}
	return syncDirectory(s.root)
}

func (s *Store) ListIDs() ([]string, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("list volatile session root: %w", err)
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() && sessionIDPattern.MatchString(entry.Name()) {
			ids = append(ids, entry.Name())
		}
	}
	return ids, nil
}

func (s *Store) sessionDir(id string) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.root, id), nil
}

func verifyDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect volatile session directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("volatile session path is not a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("volatile session directory permissions are too broad")
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}
