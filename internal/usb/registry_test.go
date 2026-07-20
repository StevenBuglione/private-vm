package usb

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func registryFixture(t *testing.T, device Device) (*Registry, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "enrollments")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	stores, err := NewOwnerStores(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(Enumerator{Source: staticSource{devices: []Device{device}}}, stores)
	if err != nil {
		t.Fatal(err)
	}
	return registry, root
}

type contextSource struct{}

func (contextSource) Snapshot(ctx context.Context) ([]Device, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestRegistryDiscoveryTimeoutIsBounded(t *testing.T) {
	root := filepath.Join(t.TempDir(), "enrollments")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	stores, err := NewOwnerStores(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(Enumerator{Source: contextSource{}}, stores)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	if _, err := registry.List(ctx, uint32(os.Geteuid())); err == nil {
		t.Fatal("timed-out discovery succeeded")
	}
}

func TestRegistryOwnerEnrollmentLifecycle(t *testing.T) {
	device := validDevice()
	registry, root := registryFixture(t, device)
	owner := uint32(os.Geteuid())
	listed, err := registry.List(t.Context(), owner)
	if err != nil || len(listed) != 1 || !listed[0].Selectable {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	if listed[0].BlockPath != device.BlockPath || listed[0].Serial != device.Identity.Serial || listed[0].USBGuardHash != device.Identity.USBGuardHash {
		t.Fatal("explicit review omitted exact transient identity")
	}
	enrolled, err := registry.Enroll(t.Context(), owner, device.DeviceID, DefaultEnrollmentLabel, false)
	if err != nil || !enrolled.Verified || enrolled.BlockPath != device.BlockPath {
		t.Fatalf("enroll=%+v err=%v", enrolled, err)
	}
	ownerDirectory := filepath.Join(root, strconv.FormatUint(uint64(owner), 10))
	info, err := os.Stat(ownerDirectory)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("owner directory mode=%v err=%v", info, err)
	}
	info, err = os.Stat(filepath.Join(ownerDirectory, enrollmentFileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode=%v err=%v", info, err)
	}
	record, err := os.ReadFile(filepath.Join(ownerDirectory, enrollmentFileName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(record, []byte(device.BlockPath)) {
		t.Fatal("transient kernel path persisted in enrollment")
	}
	verified, err := registry.Verify(t.Context(), owner)
	if err != nil || !verified.Verified {
		t.Fatalf("verify=%+v err=%v", verified, err)
	}
	if err := registry.Forget(t.Context(), owner); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Load(owner); err == nil {
		t.Fatal("forgotten enrollment loaded")
	}
}

func TestRegistryRejectsPortBindingCancellationAndUnsafeStore(t *testing.T) {
	device := validDevice()
	device.Identity.Serial = ""
	device.DeviceID = snapshotDeviceID(device.Identity, device.Bus, device.Address, device.BlockPath)
	registry, root := registryFixture(t, device)
	owner := uint32(os.Geteuid())
	if _, err := registry.Enroll(t.Context(), owner, device.DeviceID, DefaultEnrollmentLabel, false); err == nil {
		t.Fatal("serial-less enrollment accepted without port binding")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := registry.Enroll(canceled, owner, device.DeviceID, DefaultEnrollmentLabel, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled enroll=%v", err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Enroll(t.Context(), owner, device.DeviceID, DefaultEnrollmentLabel, true); err == nil {
		t.Fatal("unsafe enrollment root accepted")
	}
}
