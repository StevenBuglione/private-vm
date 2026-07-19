package guestvpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
)

type staticHandshake struct {
	ok  bool
	err error
}

func (probe staticHandshake) Recent(context.Context) (bool, error) { return probe.ok, probe.err }

type staticDNSLeak struct {
	tunnel  bool
	blocked bool
	err     error
}

func (probe staticDNSLeak) TunnelAndBypass(context.Context, string) (bool, bool, error) {
	return probe.tunnel, probe.blocked, probe.err
}

type recordingConnectivity struct {
	mu      sync.Mutex
	results map[string]bool
	errors  map[string]error
	calls   []string
}

func (probe *recordingConnectivity) Reachable(_ context.Context, name string, target netip.AddrPort) (bool, error) {
	key := name + "/4"
	if target.Addr().Is6() {
		key = name + "/6"
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	probe.calls = append(probe.calls, key)
	return probe.results[key], probe.errors[key]
}

type staticTorrentBinding struct {
	bound bool
	err   error
	calls int
}

func (probe *staticTorrentBinding) Bound(context.Context) (bool, error) {
	probe.calls++
	return probe.bound, probe.err
}

func controlledTargets() ProbeTargets {
	return ProbeTargets{
		DNSName: "probe.private-vm.example",
		IPv4:    netip.MustParseAddrPort("1.1.1.1:443"),
		IPv6:    netip.MustParseAddrPort("[2606:4700:4700::1111]:443"),
	}
}

func successfulConnectivity() *recordingConnectivity {
	return &recordingConnectivity{
		results: map[string]bool{
			TunnelInterface + "/4": true, UnderlayInterface + "/4": false,
			TunnelInterface + "/6": true, UnderlayInterface + "/6": false,
		},
		errors: make(map[string]error),
	}
}

func TestControlledVerifierProvesAllDownloaderGatesInOrder(t *testing.T) {
	connectivity := successfulConnectivity()
	torrent := &staticTorrentBinding{bound: true}
	verifier, err := NewControlledVerifier(
		staticHandshake{ok: true}, staticDNSLeak{tunnel: true, blocked: true}, connectivity, torrent, controlledTargets(),
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := verifier.Verify(context.Background(), RolePolicy{
		Role: session.RoleDownloader, RequireTorrentBinding: true, RequireIPv6Tunnel: true,
	})
	if err != nil || !proof.complete(true, true) || torrent.calls != 1 {
		t.Fatalf("proof = %#v, torrent calls=%d, err=%v", proof, torrent.calls, err)
	}
	connectivity.mu.Lock()
	calls := append([]string(nil), connectivity.calls...)
	connectivity.mu.Unlock()
	if got := fmt.Sprint(calls); got != "[proton0/4 eth0/4 proton0/6 eth0/6]" {
		t.Fatalf("probe order = %s", got)
	}
}

func TestControlledVerifierFailsClosedForEveryNegativeProof(t *testing.T) {
	tests := []struct {
		name      string
		handshake bool
		dns       bool
		dnsBlock  bool
		mutate    func(*recordingConnectivity, *staticTorrentBinding)
	}{
		{name: "handshake"},
		{name: "tunnel DNS", handshake: true},
		{name: "DNS bypass", handshake: true, dns: true},
		{name: "IPv4 tunnel", handshake: true, dns: true, dnsBlock: true, mutate: func(connectivity *recordingConnectivity, _ *staticTorrentBinding) {
			connectivity.results[TunnelInterface+"/4"] = false
		}},
		{name: "IPv4 bypass", handshake: true, dns: true, dnsBlock: true, mutate: func(connectivity *recordingConnectivity, _ *staticTorrentBinding) {
			connectivity.results[UnderlayInterface+"/4"] = true
		}},
		{name: "IPv6 tunnel", handshake: true, dns: true, dnsBlock: true, mutate: func(connectivity *recordingConnectivity, _ *staticTorrentBinding) {
			connectivity.results[TunnelInterface+"/6"] = false
		}},
		{name: "IPv6 bypass", handshake: true, dns: true, dnsBlock: true, mutate: func(connectivity *recordingConnectivity, _ *staticTorrentBinding) {
			connectivity.results[UnderlayInterface+"/6"] = true
		}},
		{name: "torrent binding", handshake: true, dns: true, dnsBlock: true, mutate: func(_ *recordingConnectivity, torrent *staticTorrentBinding) { torrent.bound = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connectivity := successfulConnectivity()
			torrent := &staticTorrentBinding{bound: true}
			if test.mutate != nil {
				test.mutate(connectivity, torrent)
			}
			verifier, err := NewControlledVerifier(
				staticHandshake{ok: test.handshake}, staticDNSLeak{tunnel: test.dns, blocked: test.dnsBlock}, connectivity, torrent, controlledTargets(),
			)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := verifier.Verify(context.Background(), RolePolicy{Role: session.RoleDownloader, RequireTorrentBinding: true, RequireIPv6Tunnel: true})
			if err != nil || proof.complete(true, true) {
				t.Fatalf("negative proof passed: %#v, %v", proof, err)
			}
		})
	}
}

func TestControlledVerifierIPv4ProfileStillProvesIPv6Bypass(t *testing.T) {
	connectivity := successfulConnectivity()
	verifier, err := NewControlledVerifier(
		staticHandshake{ok: true}, staticDNSLeak{tunnel: true, blocked: true}, connectivity, &staticTorrentBinding{bound: true}, controlledTargets(),
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := verifier.Verify(context.Background(), RolePolicy{Role: session.RoleWorkstation})
	if err != nil || proof.IPv6ThroughTunnel || !proof.IPv6BypassBlocked || !proof.complete(false, false) {
		t.Fatalf("IPv4-only proof = %#v, %v", proof, err)
	}
	connectivity.mu.Lock()
	calls := fmt.Sprint(connectivity.calls)
	connectivity.mu.Unlock()
	if strings.Contains(calls, TunnelInterface+"/6") || !strings.Contains(calls, UnderlayInterface+"/6") {
		t.Fatalf("IPv4-only IPv6 probes = %s", calls)
	}
}

func TestControlledVerifierErrorsAndTargetsAreRedacted(t *testing.T) {
	targets := controlledTargets()
	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X"} {
		if got := fmt.Sprintf(verb, targets); got != redactedProbeTargets {
			t.Fatalf("target formatting %s = %q", verb, got)
		}
	}
	if _, err := json.Marshal(targets); !errors.Is(err, secret.ErrSerialization) {
		t.Fatalf("target JSON error = %v", err)
	}
	verifier, err := NewControlledVerifier(
		staticHandshake{err: errors.New("probe.private-vm.example 1.1.1.1")},
		staticDNSLeak{}, successfulConnectivity(), &staticTorrentBinding{}, targets,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(context.Background(), RolePolicy{Role: session.RoleWorkstation})
	if err == nil || strings.Contains(err.Error(), "probe.private-vm.example") || strings.Contains(err.Error(), "1.1.1.1") {
		t.Fatalf("unsafe probe error = %v", err)
	}

	blocking := &recordingConnectivity{results: map[string]bool{}, errors: map[string]error{TunnelInterface + "/4": context.DeadlineExceeded}}
	verifier, _ = NewControlledVerifier(staticHandshake{ok: true}, staticDNSLeak{tunnel: true, blocked: true}, blocking, &staticTorrentBinding{}, targets)
	verifier.timeout = 10 * time.Millisecond
	if _, err := verifier.Verify(context.Background(), RolePolicy{Role: session.RoleWorkstation}); err == nil {
		t.Fatal("probe failure unexpectedly passed")
	}
}
