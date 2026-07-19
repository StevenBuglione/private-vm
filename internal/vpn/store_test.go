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
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

const testOwner = uint32(1000)

func TestMemoryStorePlanBindsOwnerNameGenerationEpochAndEndpoints(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	status := importFixtureProfile(t, store, testOwner, "proton-p2p", validProfile(false, "vpn.proton.test:51820"))
	if !status.Present || status.Generation == 0 || status.Rotation != RotationResolutionNeeded || status.Profile == nil {
		t.Fatalf("unexpected import status: %#v", status)
	}
	oldProfile := store.profiles[profileKey{owner: testOwner, name: "proton-p2p"}].profile
	if other := store.Inspect(testOwner+1, "proton-p2p"); other.Present {
		t.Fatal("another owner could inspect the imported profile")
	}

	resolver := NewEndpointResolverWithLookup(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")}, nil
	}))
	plan, current, err := store.Resolve(context.Background(), testOwner, "proton-p2p", resolver)
	if err != nil || plan == nil || current.Rotation != RotationCurrent || current.Code != "VPN_PROFILE_CURRENT" {
		t.Fatalf("Resolve() = %v, %#v, %v", plan, current, err)
	}

	var endpoints []netip.Addr
	var rendered []byte
	err = store.UsePlan(context.Background(), testOwner, "proton-p2p", plan, func(view ResolvedProfile) error {
		if err := view.Endpoints(context.Background(), func(address netip.Addr, port uint16) error {
			if port != 51820 {
				t.Fatalf("endpoint port = %d", port)
			}
			endpoints = append(endpoints, address)
			return nil
		}); err != nil {
			return err
		}
		return view.WithGuestConfig(context.Background(), func(_ context.Context, reader io.Reader) error {
			var readErr error
			rendered, readErr = io.ReadAll(reader)
			return readErr
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rendered)
	if len(endpoints) != 2 || !bytes.Contains(rendered, []byte("Endpoint = 1.1.1.1:51820")) {
		t.Fatal("firewall endpoint set and deterministic guest endpoint did not come from one plan")
	}

	secondPlan, _, err := store.Resolve(context.Background(), testOwner, "proton-p2p", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UsePlan(context.Background(), testOwner, "proton-p2p", plan, func(ResolvedProfile) error { return nil }); !errors.Is(err, ErrProfileRotated) {
		t.Fatalf("re-resolution did not invalidate old plan: %v", err)
	}
	if err := store.UsePlan(context.Background(), testOwner+1, "proton-p2p", secondPlan, func(ResolvedProfile) error { return nil }); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("cross-owner plan error = %v", err)
	}

	importFixtureProfile(t, store, testOwner, "second", validProfile(false, "one.one.one.one:51820"))
	otherPlan, _, err := store.Resolve(context.Background(), testOwner, "second", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UsePlan(context.Background(), testOwner, "proton-p2p", otherPlan, func(ResolvedProfile) error { return nil }); !errors.Is(err, ErrProfileRotated) {
		t.Fatalf("same-port cross-profile plan substitution error = %v", err)
	}

	replacement := importFixtureProfile(t, store, testOwner, "proton-p2p", validProfile(false, "1.0.0.1:51820"))
	if replacement.Generation <= current.Generation || replacement.Rotation != RotationResolutionNeeded {
		t.Fatalf("rotation status = %#v", replacement)
	}
	if _, err := oldProfile.Inspect(); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("replaced profile remained live: %v", err)
	}
	if err := store.UsePlan(context.Background(), testOwner, "proton-p2p", secondPlan, func(ResolvedProfile) error { return nil }); !errors.Is(err, ErrProfileRotated) {
		t.Fatalf("rotation did not invalidate plan: %v", err)
	}

	store.Remove(testOwner, "proton-p2p")
	store.Remove(testOwner, "proton-p2p")
	if missing := store.Inspect(testOwner, "proton-p2p"); missing.Present || missing.Rotation != RotationNotImported {
		t.Fatalf("missing status = %#v", missing)
	}
}

func TestResolvedProfileCannotEscapeUsePlanScope(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	importFixtureProfile(t, store, testOwner, "proton-p2p", validProfile(false, "1.1.1.1:51820"))
	plan, _, err := store.Resolve(context.Background(), testOwner, "proton-p2p", NewEndpointResolver())
	if err != nil {
		t.Fatal(err)
	}

	callbackFailure := errors.New("synthetic callback failure")
	var escaped ResolvedProfile
	err = store.UsePlan(context.Background(), testOwner, "proton-p2p", plan, func(view ResolvedProfile) error {
		escaped = view
		if err := view.Endpoints(context.Background(), func(netip.Addr, uint16) error { return nil }); err != nil {
			return err
		}
		return callbackFailure
	})
	if !errors.Is(err, callbackFailure) {
		t.Fatalf("UsePlan callback error = %v", err)
	}
	if err := escaped.Endpoints(context.Background(), func(netip.Addr, uint16) error { return nil }); !errors.Is(err, ErrProfileRotated) {
		t.Fatalf("escaped endpoint view error = %v", err)
	}
	if err := escaped.WithGuestConfig(context.Background(), func(context.Context, io.Reader) error { return nil }); !errors.Is(err, ErrProfileRotated) {
		t.Fatalf("escaped config view error = %v", err)
	}
}

func TestMemoryStoreGenerationsAreOwnerLocal(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	firstOwner := importFixtureProfile(t, store, testOwner, "first", validProfile(false, "1.1.1.1:51820"))
	otherOwner := importFixtureProfile(t, store, testOwner+1, "first", validProfile(false, "1.0.0.1:51820"))
	secondForFirstOwner := importFixtureProfile(t, store, testOwner, "second", validProfile(false, "8.8.8.8:51820"))
	if firstOwner.Generation != 1 || otherOwner.Generation != 1 || secondForFirstOwner.Generation != 2 {
		t.Fatalf("owner-local generations = %d, %d, %d", firstOwner.Generation, otherOwner.Generation, secondForFirstOwner.Generation)
	}
}

func TestFailedResolutionInvalidatesPlanAndRequiresRotation(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	importFixtureProfile(t, store, testOwner, "proton-p2p", validProfile(false, "stale.proton.test:51820"))
	good := NewEndpointResolverWithLookup(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}))
	plan, _, err := store.Resolve(context.Background(), testOwner, "proton-p2p", good)
	if err != nil {
		t.Fatal(err)
	}
	failed := NewEndpointResolverWithLookup(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("synthetic stale endpoint")
	}))
	_, status, err := store.Resolve(context.Background(), testOwner, "proton-p2p", failed)
	if !errors.Is(err, ErrEndpointUnresolved) || status.Rotation != RotationRequired || status.Code != "VPN_PROFILE_ROTATION_REQUIRED" {
		t.Fatalf("failed resolution = %#v, %v", status, err)
	}
	if err := store.UsePlan(context.Background(), testOwner, "proton-p2p", plan, func(ResolvedProfile) error { return nil }); !errors.Is(err, ErrProfileRotated) {
		t.Fatalf("failed resolution left prior plan valid: %v", err)
	}
}

func TestNonCooperativeResolverDoesNotFreezeStoreMutationOrClose(t *testing.T) {
	store := NewMemoryStore()
	importFixtureProfile(t, store, testOwner, "blocked", validProfile(false, "vpn.proton.test:51820"))
	entered := make(chan struct{})
	release := make(chan struct{})
	resolver := NewEndpointResolverWithLookup(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		close(entered)
		<-release // deliberately violates the injected-adapter context contract
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}))
	done := make(chan error, 1)
	go func() {
		_, _, err := store.Resolve(context.Background(), testOwner, "blocked", resolver)
		done <- err
	}()
	<-entered

	otherSource := newProfileSecret(t, validProfile(false, "1.0.0.1:51820"))
	defer otherSource.Destroy()
	mutationDone := make(chan error, 1)
	go func() {
		_, err := store.Import(testOwner, "other", otherSource)
		if err != nil {
			mutationDone <- err
			return
		}
		store.Remove(testOwner, "other")
		store.Close()
		mutationDone <- nil
	}()
	select {
	case err := <-mutationDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("non-cooperative resolver froze import/remove/close")
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("resolve after concurrent close error = %v", err)
	}
}

func TestMemoryStoreFailedImportIsAtomicAndLimitsAreBounded(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	original := importFixtureProfile(t, store, testOwner, "proton-p2p", validProfile(false, "vpn.proton.test:51820"))
	invalid, err := secret.New([]byte("not a WireGuard profile"))
	if err != nil {
		t.Fatal(err)
	}
	defer invalid.Destroy()
	if _, err := store.Import(testOwner, "proton-p2p", invalid); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("invalid replacement error = %v", err)
	}
	if current := store.Inspect(testOwner, "proton-p2p"); current.Generation != original.Generation {
		t.Fatal("failed import changed live generation")
	}
	for index := 1; index < maximumProfilesPerOwner; index++ {
		importFixtureProfile(t, store, testOwner, fmt.Sprintf("profile-%d", index), validProfile(false, "vpn.proton.test:51820"))
	}
	source := newProfileSecret(t, validProfile(false, "vpn.proton.test:51820"))
	defer source.Destroy()
	if _, err := store.Import(testOwner, "one-too-many", source); !errors.Is(err, ErrProfileLimit) {
		t.Fatalf("profile limit error = %v", err)
	}
}

func TestCloseDestroysProfilesPlansAndBlocksRestore(t *testing.T) {
	store := NewMemoryStore()
	importFixtureProfile(t, store, testOwner, "proton-p2p", validProfile(false, "vpn.proton.test:51820"))
	owned := store.profiles[profileKey{owner: testOwner, name: "proton-p2p"}].profile
	resolver := NewEndpointResolverWithLookup(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}))
	plan, _, err := store.Resolve(context.Background(), testOwner, "proton-p2p", resolver)
	if err != nil {
		t.Fatal(err)
	}
	concrete := plan.(*resolutionPlan)
	store.Close()
	store.Close()
	if _, err := owned.Inspect(); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("closed store left profile live: %v", err)
	}
	if err := store.UsePlan(context.Background(), testOwner, "proton-p2p", plan, func(ResolvedProfile) error { return nil }); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("closed store plan error = %v", err)
	}
	if concrete.owner != 0 || concrete.name != "" || concrete.generation != 0 || concrete.epoch != 0 || len(concrete.endpoints) != 0 {
		t.Fatal("closed store retained invalidated plan material")
	}
	replacement := newProfileSecret(t, validProfile(false, "vpn.proton.test:51820"))
	defer replacement.Destroy()
	if _, err := store.Import(testOwner, "proton-p2p", replacement); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("closed-store import error = %v", err)
	}
}

func TestStatusAndOpaquePlanFormattingAreRedacted(t *testing.T) {
	store := NewMemoryStore()
	defer store.Close()
	importFixtureProfile(t, store, testOwner, "proton-p2p", validProfile(false, "vpn.proton.test:51820"))
	resolver := NewEndpointResolverWithLookup(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}))
	plan, _, err := store.Resolve(context.Background(), testOwner, "proton-p2p", resolver)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(store.Inspect(testOwner, "proton-p2p"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte(encodedKey(0x11)), []byte("vpn.proton.test"), []byte("10.2.0.1"), []byte("1.1.1.1")} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatal("status JSON disclosed profile material")
		}
	}
	concrete := plan.(*resolutionPlan)
	var resolved ResolvedProfile
	if err := store.UsePlan(context.Background(), testOwner, "proton-p2p", plan, func(view ResolvedProfile) error {
		resolved = view
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []any{*concrete, concrete, resolved} {
		for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X"} {
			if got := fmt.Sprintf(verb, subject); got != redactedPlan {
				t.Fatalf("plan formatting %s = %q", verb, got)
			}
		}
		if _, err := json.Marshal(subject); !errors.Is(err, secret.ErrSerialization) {
			t.Fatalf("plan JSON error = %v", err)
		}
	}
}

func importFixtureProfile(t *testing.T, store *MemoryStore, owner uint32, name, input string) Status {
	t.Helper()
	source := newProfileSecret(t, input)
	status, err := store.Import(owner, name, source)
	source.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	return status
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
