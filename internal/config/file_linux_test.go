//go:build linux

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxConfigFileTrustAndTypes(t *testing.T) {
	directory := t.TempDir()
	safe := filepath.Join(directory, "safe.toml")
	writeConfig(t, safe, "schema_version=1\n")
	loader := defaultLoader()
	load := func(path string, trust FileTrust) error {
		_, err := loader.Load(LoadOptions{System: FileLayer{Path: path, Required: true, Trust: trust}})
		return err
	}
	if err := load(safe, TrustUser); err != nil {
		t.Fatalf("safe user file failed: %v", err)
	}

	link := filepath.Join(directory, "ordinary-link.toml")
	if err := os.Symlink(safe, link); err != nil {
		t.Fatal(err)
	}
	if err := load(link, TrustUser); err != nil {
		t.Fatalf("safe ordinary symlink needed by NixOS failed: %v", err)
	}

	file, err := os.Open(safe)
	if err != nil {
		t.Fatal(err)
	}
	magic := fmt.Sprintf("/proc/self/fd/%d", file.Fd())
	if err := load(magic, TrustUser); errorCode(err) != "CONFIG_READ" {
		t.Fatalf("magic link returned %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []os.FileMode{0o622, 0o700} {
		if err := os.Chmod(safe, mode); err != nil {
			t.Fatal(err)
		}
		if err := load(safe, TrustUser); errorCode(err) != "CONFIG_READ" {
			t.Fatalf("mode %o returned %v", mode, err)
		}
	}
	if err := os.Chmod(safe, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := load(directory, TrustAny); errorCode(err) != "CONFIG_READ" {
		t.Fatalf("directory returned %v", err)
	}

	fifo := filepath.Join(directory, "blocked.toml")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := load(fifo, TrustAny); errorCode(err) != "CONFIG_READ" {
		t.Fatalf("FIFO returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("FIFO refusal was not nonblocking: %s", elapsed)
	}

	if os.Geteuid() != 0 {
		if err := load(safe, TrustSystem); errorCode(err) != "CONFIG_READ" {
			t.Fatalf("non-root system file returned %v", err)
		}
	}
}

func TestConfigurationFilesystemAllowlistFailsClosed(t *testing.T) {
	for _, filesystemType := range []int64{unix.EXT4_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC} {
		if !localConfigurationFilesystem(filesystemType) {
			t.Fatalf("local filesystem %#x was rejected", filesystemType)
		}
	}
	for _, filesystemType := range []int64{unix.FUSE_SUPER_MAGIC, unix.NFS_SUPER_MAGIC, unix.CEPH_SUPER_MAGIC, unix.AFS_SUPER_MAGIC} {
		if localConfigurationFilesystem(filesystemType) {
			t.Fatalf("remote/userspace filesystem %#x was accepted", filesystemType)
		}
	}
}

func TestConfigFileSizeErrorIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.toml")
	writeConfig(t, path, string(make([]byte, maximumConfigBytes+1)))
	_, err := defaultLoader().Load(LoadOptions{User: FileLayer{Path: path, Required: true, Trust: TrustUser}})
	assertConfigCode(t, err, "CONFIG_TOO_LARGE")
}
