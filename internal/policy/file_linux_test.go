//go:build linux

package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxPolicyFileTrustAndTypes(t *testing.T) {
	directory := t.TempDir()
	safe := filepath.Join(directory, "safe.toml")
	if err := os.WriteFile(safe, []byte(readExample(t, "policy.safe.toml")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(safe); err != nil {
		t.Fatalf("safe policy failed: %v", err)
	}
	for _, mode := range []os.FileMode{0o622, 0o700} {
		if err := os.Chmod(safe, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(safe); Code(err) != "POLICY_READ" {
			t.Fatalf("mode %o returned %v", mode, err)
		}
	}
	if _, err := Load(directory); Code(err) != "POLICY_READ" {
		t.Fatalf("directory returned %v", err)
	}
	fifo := filepath.Join(directory, "blocked.toml")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := Load(fifo); Code(err) != "POLICY_READ" {
		t.Fatalf("FIFO returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("FIFO refusal was not nonblocking: %s", elapsed)
	}
}

func TestPolicyFilesystemAllowlistFailsClosed(t *testing.T) {
	for _, filesystemType := range []int64{unix.EXT4_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC} {
		if !localPolicyFilesystem(filesystemType) {
			t.Fatalf("local filesystem %#x was rejected", filesystemType)
		}
	}
	for _, filesystemType := range []int64{unix.FUSE_SUPER_MAGIC, unix.NFS_SUPER_MAGIC, unix.CEPH_SUPER_MAGIC, unix.AFS_SUPER_MAGIC} {
		if localPolicyFilesystem(filesystemType) {
			t.Fatalf("remote/userspace filesystem %#x was accepted", filesystemType)
		}
	}
}

func TestPolicyFileSizeErrorIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.toml")
	if err := os.WriteFile(path, make([]byte, maximumPolicySize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if Code(err) != "POLICY_TOO_LARGE" {
		t.Fatalf("got %v, want POLICY_TOO_LARGE", err)
	}
}
