package vpn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

func TestMemoryStoreImportResolveRotateRemove(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	source := newProfileSecret(t, validProfile(false, "vpn.proton.test:51820"))
	status, err := store.Import("proton-p2p", source)
	source.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	if !status.Present || status.Generation == 0 || status.Rotation != RotationResolutionNeeded || status.Profile == nil {
		t.Fatalf("unexpected import status: %#v", status)
	}
	oldProfile := store.profiles["proton-p2p"].profile
	if err := store.WithResolvedConfig(context.Background(), "proton-p2p", status.Generation, ResolvedEndpoint{address: netip.MustParseAddr("198.51.100.90"), port: 51820}, func(context.Context, io.Reader) error { return nil }); !errors.Is(err, ErrProfileNotReady) {
		t.Fatalf("pre-resolution delivery error = %v", err)
	}

	resolver := NewEndpointResolverWithLookup(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.90")}, nil
	}))
	resolved, current, err := store.Resolve(context.Background(), "proton-p2p", resolver)
	if err != nil || len(resolved) != 1 || current.Rotation != RotationCurrent || current.Code != "VPN_PROFILE_CURRENT" {
		t.Fatalf("Resolve() = %#v, %#v, %v", resolved, current, err)
	}
	var size int
	err = store.WithResolvedConfig(context.Background(), "proton-p2p", current.Generation, resolved[0], func(_ context.Context, reader io.Reader) error {
		value, err := io.ReadAll(reader)
		size = len(value)
		clear(value)
		return err
	})
	if err != nil || size == 0 || size > MaximumProfileBytes {
		t.Fatalf("WithResolvedConfig size=%d error=%v", size, err)
	}

	replacement := newProfileSecret(t, validProfile(false, "198.51.100.91:51820"))
	rotated, err := store.Import("proton-p2p", replacement)
	replacement.Destroy()
	if err != nil || rotated.Generation <= current.Generation || rotated.Rotation != RotationResolutionNeeded {
		t.Fatalf("rotation status = %#v, %v", rotated, err)
	}
	if _, err := oldProfile.Inspect(); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("replaced profile remained live: %v", err)
	}
	if err := store.WithResolvedConfig(context.Background(), "proton-p2p", current.Generation, resolved[0], func(context.Context, io.Reader) error { return nil }); !errors.Is(err, ErrProfileRotated) {
		t.Fatalf("stale generation error = %v", err)
	}

	store.Remove("proton-p2p")
	store.Remove("proton-p2p")
	missing := store.Inspect("proton-p2p")
	if missing.Present || missing.Rotation != RotationNotImported || missing.Code != "VPN_PROFILE_NOT_IMPORTED" {
		t.Fatalf("missing status = %#v", missing)
	}
}

func TestMemoryStoreFailedResolutionRequiresRotation(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	source := newProfileSecret(t, validProfile(false, "stale.proton.test:51820"))
	_, err := store.Import("proton-p2p", source)
	source.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewEndpointResolverWithLookup(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("synthetic stale endpoint")
	}))
	_, status, err := store.Resolve(context.Background(), "proton-p2p", resolver)
	if !errors.Is(err, ErrEndpointUnresolved) || status.Rotation != RotationRequired || status.Code != "VPN_PROFILE_ROTATION_REQUIRED" {
		t.Fatalf("failed resolution = %#v, %v", status, err)
	}
}

func TestMemoryStoreFailedImportIsAtomic(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	source := newProfileSecret(t, validProfile(false, "vpn.proton.test:51820"))
	original, err := store.Import("proton-p2p", source)
	source.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := secret.New([]byte("not a WireGuard profile"))
	if err != nil {
		t.Fatal(err)
	}
	defer invalid.Destroy()
	if _, err := store.Import("proton-p2p", invalid); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("invalid replacement error = %v", err)
	}
	current := store.Inspect("proton-p2p")
	if !current.Present || current.Generation != original.Generation || current.Rotation != original.Rotation {
		t.Fatalf("failed import changed live generation: before=%#v after=%#v", original, current)
	}
}

func TestMemoryStoreCancellationDoesNotInventStaleness(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	source := newProfileSecret(t, validProfile(false, "vpn.proton.test:51820"))
	_, err := store.Import("proton-p2p", source)
	source.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, status, err := store.Resolve(ctx, "proton-p2p", NewEndpointResolver())
	if !errors.Is(err, context.Canceled) || status.Rotation != RotationResolutionNeeded {
		t.Fatalf("canceled resolution = %#v, %v", status, err)
	}
}

func TestMemoryStoreCloseDestroysAndBlocksRestore(t *testing.T) {
	store := NewMemoryStore()
	source := newProfileSecret(t, validProfile(false, "vpn.proton.test:51820"))
	if _, err := store.Import("proton-p2p", source); err != nil {
		t.Fatal(err)
	}
	owned := store.profiles["proton-p2p"].profile
	source.Destroy()
	store.Close()
	store.Close()
	if status := store.Inspect("proton-p2p"); status.Present {
		t.Fatalf("closed store retained profile: %#v", status)
	}
	if _, err := owned.Inspect(); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("closed store left profile live: %v", err)
	}
	replacement := newProfileSecret(t, validProfile(false, "vpn.proton.test:51820"))
	defer replacement.Destroy()
	if _, err := store.Import("proton-p2p", replacement); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("closed-store import error = %v", err)
	}
}

func TestMemoryStoreProfileCountIsBounded(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	for index := 0; index < maximumStoredProfiles; index++ {
		source := newProfileSecret(t, validProfile(false, "vpn.proton.test:51820"))
		_, err := store.Import(fmt.Sprintf("profile-%d", index), source)
		source.Destroy()
		if err != nil {
			t.Fatal(err)
		}
	}
	source := newProfileSecret(t, validProfile(false, "vpn.proton.test:51820"))
	defer source.Destroy()
	if _, err := store.Import("one-too-many", source); !errors.Is(err, ErrProfileLimit) {
		t.Fatalf("profile limit error = %v", err)
	}
}

func TestStatusSchemaIsRedacted(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	source := newProfileSecret(t, validProfile(false, "vpn.proton.test:51820"))
	if _, err := store.Import("proton-p2p", source); err != nil {
		t.Fatal(err)
	}
	source.Destroy()
	encoded, err := json.Marshal(store.Inspect("proton-p2p"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte(encodedKey(0x11)), []byte("vpn.proton.test"), []byte("10.2.0.1"), []byte("198.51.100")} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatal("status JSON disclosed profile material")
		}
	}
}

func newProfileSecret(t *testing.T, input string) *secret.Bytes {
	t.Helper()
	raw := []byte(input)
	value, err := secret.New(raw)
	clear(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
