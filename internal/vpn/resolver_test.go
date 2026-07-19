package vpn

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/apperror"
)

type lookupFunc func(context.Context, string, string) ([]netip.Addr, error)

func (fn lookupFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return fn(ctx, network, host)
}

func TestEndpointResolverReturnsBoundedSortedPublicAddresses(t *testing.T) {
	profile := mustParseProfile(t, validProfile(false, "vpn.proton.test:51820"))
	defer profile.Destroy()
	resolver := NewEndpointResolverWithLookup(lookupFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != "vpn.proton.test." {
			t.Fatal("resolver received an unexpected request")
		}
		return []netip.Addr{
			netip.MustParseAddr("2606:4700:4700::1111"),
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("1.1.1.1"),
		}, nil
	}))
	resolved, err := resolver.resolve(context.Background(), profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 || resolved[0].address != netip.MustParseAddr("1.1.1.1") || resolved[1].port != 51820 {
		t.Fatalf("unexpected resolved endpoint set: %#v", resolved)
	}
}

func TestEndpointResolverLiteralDoesNotCallDNS(t *testing.T) {
	profile := mustParseProfile(t, validProfile(false, "1.0.0.1:443"))
	defer profile.Destroy()
	resolver := NewEndpointResolverWithLookup(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("literal endpoint used DNS")
		return nil, nil
	}))
	resolved, err := resolver.resolve(context.Background(), profile)
	if err != nil || len(resolved) != 1 || resolved[0].address != netip.MustParseAddr("1.0.0.1") || resolved[0].port != 443 {
		t.Fatalf("Resolve() = %#v, %v", resolved, err)
	}
}

func TestEndpointResolverFailureIsActionableAndRedacted(t *testing.T) {
	profile := mustParseProfile(t, validProfile(false, "vpn.proton.test:51820"))
	defer profile.Destroy()
	cases := map[string]lookupFunc{
		"lookup failure": func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("resolver disclosed vpn.proton.test")
		},
		"unsafe address": func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		"mapped public address": func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("::ffff:1.1.1.1")}, nil
		},
		"too many": func(context.Context, string, string) ([]netip.Addr, error) {
			values := make([]netip.Addr, maximumResolvedIPs+1)
			for index := range values {
				values[index] = netip.AddrFrom4([4]byte{198, 51, 100, byte(index + 1)})
			}
			return values, nil
		},
	}
	for name, lookup := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewEndpointResolverWithLookup(lookup).resolve(context.Background(), profile)
			if !errors.Is(err, ErrEndpointUnresolved) {
				t.Fatalf("Resolve error = %v", err)
			}
			assertAppCode(t, err, "VPN_ENDPOINT_UNRESOLVED")
			if strings.Contains(err.Error(), "vpn.proton.test") || !strings.Contains(apperrorMessage(t, err), "Generate and import") {
				t.Fatal("endpoint error was not redacted and actionable")
			}
		})
	}
}

func TestEndpointResolverCancellationAndTimeout(t *testing.T) {
	profile := mustParseProfile(t, validProfile(false, "vpn.proton.test:51820"))
	defer profile.Destroy()
	blocking := lookupFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewEndpointResolverWithLookup(blocking).resolve(canceled, profile); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Resolve error = %v", err)
	}
	resolver := &EndpointResolver{lookup: blocking, timeout: 10 * time.Millisecond}
	started := time.Now()
	if _, err := resolver.resolve(context.Background(), profile); !errors.Is(err, ErrEndpointUnresolved) {
		t.Fatalf("timed out Resolve error = %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("resolver timeout was not bounded")
	}
}

func apperrorMessage(t *testing.T, err error) string {
	t.Helper()
	// apperror.Error exposes stable fields rather than an external cause.
	var typed *apperror.Error
	if !errors.As(err, &typed) {
		t.Fatal("expected typed application error")
	}
	return typed.Remediation
}
