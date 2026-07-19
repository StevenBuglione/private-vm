//go:build linux

package torrent

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFilesystemVerifierHashesOnlyExactRegularSelectedFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("synthetic quarantine fixture")
	path := filepath.Join(root, "nested", "document.pdf")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	verifier, err := newFilesystemVerifier(root)
	if err != nil {
		t.Fatal(err)
	}
	metadata := Metadata{
		SelectedSizeBytes: uint64(len(payload)),
		Files: []File{
			{Index: 0, DisplayPath: "nested/document.pdf", SizeBytes: uint64(len(payload)), Selected: true},
			{Index: 1, DisplayPath: "not-selected.txt", SizeBytes: 9},
		},
	}
	files, err := verifier.Verify(t.Context(), metadata)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(payload)
	if len(files) != 1 || files[0].Path != "nested/document.pdf" || files[0].SizeBytes != uint64(len(payload)) || files[0].SHA256 != expected {
		t.Fatalf("verified files = %+v", files)
	}
	clearManifest(files)
}

func TestFilesystemVerifierRejectsSymlinksAndHardlinks(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, string){
		"symlink": func(t *testing.T, root string) {
			t.Helper()
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, "payload.pdf")); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, root string) {
			t.Helper()
			path := filepath.Join(root, "payload.pdf")
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(path, filepath.Join(root, "second-link")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			prepare(t, root)
			verifier, err := newFilesystemVerifier(root)
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifier.Verify(context.Background(), Metadata{
				SelectedSizeBytes: 1,
				Files:             []File{{Index: 0, DisplayPath: "payload.pdf", SizeBytes: 1, Selected: true}},
			})
			if !errors.Is(err, ErrSealFailed) {
				t.Fatalf("unsafe entry error = %v", err)
			}
		})
	}
}
