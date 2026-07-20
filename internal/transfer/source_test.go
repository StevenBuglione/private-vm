package transfer

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceStreamsSameDescriptorBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.bin")
	want := bytes.Repeat([]byte("a"), DefaultMaxChunk+17)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := OpenSource(t.Context(), path, uint64(len(want)))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var got []byte
	if err := source.Stream(t.Context(), func(_ uint64, data []byte) error {
		got = append(got, data...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("streamed bytes differ")
	}
	if err := source.Stream(t.Context(), func(uint64, []byte) error { return nil }); err == nil {
		t.Fatal("source was reusable")
	}
}

func TestSourceRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSource(t.Context(), link, 1); err == nil {
		t.Fatal("symbolic link was accepted")
	}
}

func TestSourceRejectsSymlinkInParent(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(realParent, "input")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(root, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSource(t.Context(), filepath.Join(linkedParent, "input"), 1); err == nil {
		t.Fatal("source beneath a symbolic-link parent was accepted")
	}
}

func TestSourceDescriptorSurvivesParentPathReplacement(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "selected")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "input")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := OpenSource(t.Context(), path, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	moved := filepath.Join(root, "moved")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	var received []byte
	if err := source.Stream(t.Context(), func(_ uint64, data []byte) error {
		received = append(received, data...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if string(received) != "original" {
		t.Fatalf("stream followed replacement path: %q", received)
	}
}

func TestSourceDetectsChangeAfterPreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := OpenSource(t.Context(), path, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := os.WriteFile(path, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := source.Stream(t.Context(), func(uint64, []byte) error { return nil }); err == nil {
		t.Fatal("changed source was accepted")
	}
}
