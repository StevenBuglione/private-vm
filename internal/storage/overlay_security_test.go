package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestActiveImageLeaseBlocksQEMUImgAndOverlayRemoval(t *testing.T) {
	outer := filepath.Join(t.TempDir(), "outer")
	if err := os.Mkdir(outer, 0o700); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "base.qcow2")
	if err := os.WriteFile(base, []byte("base"), 0o444); err != nil {
		t.Fatal(err)
	}
	registry := NewImageUseRegistry()
	manager := OverlayManager{QEMUImg: "/usr/bin/qemu-img", Runner: &overlayRunner{base: base}, Registry: registry}
	handle, err := manager.Create(context.Background(), outer, base, "root-workstation.qcow2")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := handle.Activate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(context.Background(), outer, base, "root-downloader.qcow2"); err == nil {
		t.Fatal("qemu-img touched a base image while its QEMU lease was active")
	}
	if err := handle.Destroy(context.Background()); err == nil {
		t.Fatal("active root overlay was removed")
	}
	if err := lease.Destroy(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Destroy(); err != nil {
		t.Fatalf("image lease release is not idempotent: %v", err)
	}
	if err := handle.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOverlayCleanupRefusesIdentityReplacement(t *testing.T) {
	outer := filepath.Join(t.TempDir(), "outer")
	if err := os.Mkdir(outer, 0o700); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "base.qcow2")
	if err := os.WriteFile(base, []byte("base"), 0o444); err != nil {
		t.Fatal(err)
	}
	manager := OverlayManager{QEMUImg: "/usr/bin/qemu-img", Runner: &overlayRunner{base: base}, Registry: NewImageUseRegistry()}
	handle, err := manager.Create(context.Background(), outer, base, "root-scanner.qcow2")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(handle.Path()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(handle.Path(), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := handle.Destroy(context.Background()); err == nil {
		t.Fatal("replacement overlay was unlinked")
	}
	if data, err := os.ReadFile(handle.Path()); err != nil || string(data) != "replacement" {
		t.Fatal("replacement overlay did not remain untouched")
	}
}

func TestOverlayCreationDetectsBaseReplacement(t *testing.T) {
	outer := filepath.Join(t.TempDir(), "outer")
	if err := os.Mkdir(outer, 0o700); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "base.qcow2")
	if err := os.WriteFile(base, []byte("base"), 0o444); err != nil {
		t.Fatal(err)
	}
	runner := &overlayRunner{base: base, replaceOnBaseInfo: true}
	manager := OverlayManager{QEMUImg: "/usr/bin/qemu-img", Runner: runner, Registry: NewImageUseRegistry()}
	if _, err := manager.Create(context.Background(), outer, base, "root-exporter.qcow2"); err == nil {
		t.Fatal("base replacement during qemu-img inspection unexpectedly passed")
	}
	if _, err := os.Lstat(filepath.Join(outer, "root-exporter.qcow2")); !os.IsNotExist(err) {
		t.Fatalf("failed base verification left an overlay: %v", err)
	}
}
