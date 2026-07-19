package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const storeTestID = "pvm-0123456789abcdef0123456789abcdef"

func TestStoreCreateLoadSaveRemove(t *testing.T) {
	store := newTestStore(t)
	snapshot := newTestSnapshot(t, storeTestID)
	if err := store.Create(snapshot); err != nil {
		t.Fatal(err)
	}

	assertPathMode(t, store.Root(), runtimeRootMode)
	assertPathMode(t, filepath.Join(store.Root(), snapshot.ID), sessionDirMode)
	assertPathMode(t, filepath.Join(store.Root(), snapshot.ID, "metadata.json"), metadataMode)
	assertPathOwner(t, filepath.Join(store.Root(), snapshot.ID, "metadata.json"))

	loaded, err := store.Load(snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != snapshot.ID || loaded.Sequence != snapshot.Sequence || loaded.Role != snapshot.Role {
		t.Fatalf("unexpected loaded snapshot: %#v", loaded)
	}
	ids, err := store.ListIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != snapshot.ID {
		t.Fatalf("unexpected session IDs: %v", ids)
	}

	if err := store.Save(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(snapshot.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(snapshot.ID); err != nil {
		t.Fatalf("idempotent removal failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.Root(), snapshot.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed session path remains: %v", err)
	}
}

func TestStoreRejectsSymlinkedAndMagicLinkRoots(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(base, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(filepath.Join(linkedParent, "runtime")); err == nil {
		t.Fatal("expected symlinked runtime ancestor to be rejected")
	}

	parent, err := os.Open(realParent)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	magicRoot := filepath.Join("/proc/self/fd", fileDescriptorString(parent), "runtime")
	if _, err := NewStore(magicRoot); err == nil {
		t.Fatal("expected procfs magic-link runtime ancestor to be rejected")
	}
}

func TestStoreFailsClosedAfterRuntimeRootReplacement(t *testing.T) {
	store := newTestStore(t)
	snapshot := newTestSnapshot(t, storeTestID)
	if err := store.Create(snapshot); err != nil {
		t.Fatal(err)
	}
	original := store.Root() + ".original"
	if err := os.Rename(store.Root(), original); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(store.Root(), runtimeRootMode); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(snapshot); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("expected runtime-root identity rejection, got %v", err)
	}
}

func TestStoreRejectsUnsafeModesAndSymlinkedMetadata(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "runtime")
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := NewStore(root); err == nil || !strings.Contains(err.Error(), "mode must be exactly") {
			t.Fatalf("expected exact root-mode rejection, got %v", err)
		}
	})

	t.Run("session", func(t *testing.T) {
		store := newTestStore(t)
		snapshot := newTestSnapshot(t, storeTestID)
		if err := store.Create(snapshot); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(store.Root(), snapshot.ID)
		if err := os.Chmod(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(snapshot.ID); err == nil || !strings.Contains(err.Error(), "mode must be exactly") {
			t.Fatalf("expected exact session-mode rejection, got %v", err)
		}
	})

	t.Run("metadata", func(t *testing.T) {
		store := newTestStore(t)
		snapshot := newTestSnapshot(t, storeTestID)
		if err := store.Create(snapshot); err != nil {
			t.Fatal(err)
		}
		metadata := filepath.Join(store.Root(), snapshot.ID, "metadata.json")
		if err := os.Chmod(metadata, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(snapshot.ID); err == nil || !strings.Contains(err.Error(), "mode must be exactly") {
			t.Fatalf("expected exact metadata-mode rejection, got %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		store := newTestStore(t)
		snapshot := newTestSnapshot(t, storeTestID)
		if err := store.Create(snapshot); err != nil {
			t.Fatal(err)
		}
		metadata := filepath.Join(store.Root(), snapshot.ID, "metadata.json")
		if err := os.Remove(metadata); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("{}"), metadataMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, metadata); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(snapshot.ID); err == nil {
			t.Fatal("expected symlinked metadata to be rejected")
		}
	})
}

func TestStoreStrictJournalValidation(t *testing.T) {
	tests := map[string]func([]byte) []byte{
		"unknown field": func(data []byte) []byte {
			var value map[string]any
			if err := json.Unmarshal(data, &value); err != nil {
				t.Fatal(err)
			}
			value["unexpected"] = true
			result, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			return result
		},
		"duplicate field": func(data []byte) []byte {
			return bytes.Replace(data, []byte(`{"schema_version":1`), []byte(`{"schema_version":1,"schema_version":1`), 1)
		},
		"trailing value": func(data []byte) []byte { return append(data, []byte(` {}`)...) },
		"malformed":      func(data []byte) []byte { return data[:len(data)-1] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store := newTestStore(t)
			snapshot := newTestSnapshot(t, storeTestID)
			if err := store.Create(snapshot); err != nil {
				t.Fatal(err)
			}
			metadata := filepath.Join(store.Root(), snapshot.ID, "metadata.json")
			data, err := os.ReadFile(metadata)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(metadata, mutate(data), metadataMode); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(snapshot.ID); err == nil {
				t.Fatal("expected invalid journal to be rejected")
			}
		})
	}

	t.Run("oversized", func(t *testing.T) {
		store := newTestStore(t)
		snapshot := newTestSnapshot(t, storeTestID)
		if err := store.Create(snapshot); err != nil {
			t.Fatal(err)
		}
		metadata := filepath.Join(store.Root(), snapshot.ID, "metadata.json")
		if err := os.WriteFile(metadata, bytes.Repeat([]byte{'x'}, maxMetadataSize+1), metadataMode); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(snapshot.ID); err == nil || !strings.Contains(err.Error(), "size") {
			t.Fatalf("expected oversized journal rejection, got %v", err)
		}
	})
}

func TestStoreRejectsUnexpectedEntriesWithoutPartialRemoval(t *testing.T) {
	store := newTestStore(t)
	snapshot := newTestSnapshot(t, storeTestID)
	if err := store.Create(snapshot); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(store.Root(), snapshot.ID)
	unexpected := filepath.Join(dir, "unexpected")
	if err := os.WriteFile(unexpected, []byte("blocked"), metadataMode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(snapshot.ID); err == nil {
		t.Fatal("expected load to reject unexpected directory entry")
	}
	if err := store.Remove(snapshot.ID); err == nil {
		t.Fatal("expected remove to reject unexpected directory entry")
	}
	if _, err := os.Stat(filepath.Join(dir, "metadata.json")); err != nil {
		t.Fatalf("metadata changed during rejected remove: %v", err)
	}
	if _, err := os.Stat(unexpected); err != nil {
		t.Fatalf("unexpected entry changed during rejected remove: %v", err)
	}
}

func TestStoreAllowsDocumentedResourceDirectoriesButRequiresCleanupBeforeRemove(t *testing.T) {
	store := newTestStore(t)
	snapshot := newTestSnapshot(t, storeTestID)
	if err := store.Create(snapshot); err != nil {
		t.Fatal(err)
	}
	resourceDirectory := filepath.Join(store.Root(), snapshot.ID, "qmp")
	if err := os.Mkdir(resourceDirectory, sessionDirMode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(snapshot.ID); err != nil {
		t.Fatalf("documented resource directory blocked journal load: %v", err)
	}
	if err := store.Save(snapshot); err != nil {
		t.Fatalf("documented resource directory blocked journal save: %v", err)
	}
	if err := store.Remove(snapshot.ID); err == nil {
		t.Fatal("expected remaining resource directory to block record removal")
	}
	if err := os.Remove(resourceDirectory); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(snapshot.ID); err != nil {
		t.Fatalf("remove after resource cleanup: %v", err)
	}
}

func TestStoreRecoversVerifiedIncompleteSave(t *testing.T) {
	store := newTestStore(t)
	snapshot := newTestSnapshot(t, storeTestID)
	if err := store.Create(snapshot); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(store.Root(), snapshot.ID, ".metadata.tmp")
	if err := os.WriteFile(temporary, []byte("incomplete"), metadataMode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(snapshot.ID); err == nil {
		t.Fatal("expected an incomplete save to block journal loading")
	}
	if err := store.Save(snapshot); err != nil {
		t.Fatalf("recover verified incomplete save: %v", err)
	}
	if _, err := os.Stat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("incomplete temporary journal remains: %v", err)
	}
}

func TestStoreCreateValidatesBeforeAllocating(t *testing.T) {
	store := newTestStore(t)
	snapshot := newTestSnapshot(t, storeTestID)
	snapshot.SchemaVersion = 2
	if err := store.Create(snapshot); err == nil {
		t.Fatal("expected invalid snapshot to be rejected")
	}
	if _, err := os.Stat(filepath.Join(store.Root(), snapshot.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid create allocated a session directory: %v", err)
	}
}

func TestStoreAllowsOnlyExactControlSocketAtRoot(t *testing.T) {
	store := newTestStore(t)
	listener, err := net.Listen("unix", filepath.Join(store.Root(), "control.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(filepath.Join(store.Root(), "control.sock"), controlSockMode); err != nil {
		t.Fatal(err)
	}
	if ids, err := store.ListIDs(); err != nil || len(ids) != 0 {
		t.Fatalf("exact control socket was not accepted: ids=%v err=%v", ids, err)
	}
	if err := os.Chmod(filepath.Join(store.Root(), "control.sock"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListIDs(); err == nil {
		t.Fatal("expected unsafe control socket mode to be rejected")
	}
}

func FuzzDecodeVolatileSessionJournal(f *testing.F) {
	const id = "pvm-0123456789abcdef0123456789abcdef"
	session, err := newOwned(id, 1000, RoleWorkstation, time.Unix(1, 0))
	if err != nil {
		f.Fatal(err)
	}
	seed, err := json.Marshal(session.Snapshot())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{"schema_version":1,"schema_version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxMetadataSize+1 {
			return
		}
		_, _ = decodeSnapshot(data, id)
	})
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newTestSnapshot(t *testing.T, id string) Snapshot {
	t.Helper()
	session, err := newOwned(id, uint32(os.Geteuid()), RoleWorkstation, time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return session.Snapshot()
}

func assertPathMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != mode {
		t.Fatalf("%s mode is %04o, want %04o", path, info.Mode().Perm(), mode)
	}
}

func assertPathOwner(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("file stat did not expose Unix ownership")
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		t.Fatalf("%s owner is %d:%d, want %d:%d", path, stat.Uid, stat.Gid, os.Geteuid(), os.Getegid())
	}
}

func fileDescriptorString(file *os.File) string {
	return strconv.FormatUint(uint64(file.Fd()), 10)
}
