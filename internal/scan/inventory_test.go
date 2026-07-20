//go:build linux

package scan

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestBuildInventoryHashesAndRecordsTypeMismatch(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "document.pdf"), []byte("plain text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inventory, err := BuildInventory(t.Context(), root, InventoryLimits{MaxFiles: 10, MaxInputBytes: 1024}, ConservativeMIMEClassifier{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Entries) != 1 || inventory.TotalBytes != 11 {
		t.Fatalf("unexpected inventory: %+v", inventory)
	}
	entry := inventory.Entries[0]
	if entry.RelativePath != "nested/document.pdf" || entry.DetectedMIME != "text/plain" || entry.ExtensionMIME != "application/pdf" || entry.ExtensionAgreement {
		t.Fatalf("unexpected entry: %+v", entry)
	}
	if len(entry.SHA256) != 64 || entry.Device == 0 || entry.Inode == 0 {
		t.Fatalf("missing identity: %+v", entry)
	}
}

func TestBuildInventoryRejectsLinksAndSpecialFiles(t *testing.T) {
	for _, test := range []struct {
		name string
		make func(*testing.T, string)
		code string
	}{
		{"symlink", func(t *testing.T, root string) {
			if err := os.Symlink("target", filepath.Join(root, "link")); err != nil {
				t.Fatal(err)
			}
		}, "SCAN_SYMLINK_REJECTED"},
		{"hardlink", func(t *testing.T, root string) {
			first := filepath.Join(root, "first")
			if err := os.WriteFile(first, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(first, filepath.Join(root, "second")); err != nil {
				t.Fatal(err)
			}
		}, "SCAN_HARDLINK_REJECTED"},
		{"fifo", func(t *testing.T, root string) {
			if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "SCAN_SPECIAL_FILE_REJECTED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.make(t, root)
			_, err := BuildInventory(t.Context(), root, InventoryLimits{MaxFiles: 10, MaxInputBytes: 1024}, ConservativeMIMEClassifier{})
			if ErrorCode(err) != test.code {
				t.Fatalf("code = %s, error = %v", ErrorCode(err), err)
			}
		})
	}
}

func TestBuildInventoryLimitsCancellationAndClassifierFailure(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "one"), []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildInventory(t.Context(), root, InventoryLimits{MaxFiles: 1, MaxInputBytes: 3}, ConservativeMIMEClassifier{}); ErrorCode(err) != "SCAN_LIMIT_REACHED" {
		t.Fatalf("byte limit error = %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := BuildInventory(cancelled, root, InventoryLimits{MaxFiles: 1, MaxInputBytes: 4}, ConservativeMIMEClassifier{}); ErrorCode(err) != "SCAN_CANCELLED" {
		t.Fatalf("cancellation error = %v", err)
	}
	failing := MIMEClassifierFunc(func(context.Context, []byte) (string, error) { return "", os.ErrInvalid })
	if _, err := BuildInventory(t.Context(), root, InventoryLimits{MaxFiles: 1, MaxInputBytes: 4}, failing); ErrorCode(err) != "SCAN_TYPE_IDENTIFICATION_FAILED" {
		t.Fatalf("classifier error = %v", err)
	}
}
