package guestvpn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/vpn"
)

type fakeBackend struct {
	mu         sync.Mutex
	operations []string
	fail       map[string]int
	block      string
	config     []byte
}

func newFakeBackend() *fakeBackend { return &fakeBackend{fail: make(map[string]int)} }

func (backend *fakeBackend) step(ctx context.Context, operation string) error {
	backend.mu.Lock()
	backend.operations = append(backend.operations, operation)
	if backend.fail[operation] > 0 {
		backend.fail[operation]--
		backend.mu.Unlock()
		return errors.New("synthetic sensitive backend detail 1.1.1.1")
	}
	block := backend.block == operation
	backend.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	return ctx.Err()
}

func (backend *fakeBackend) ArmKillSwitch(ctx context.Context, setup vpn.GuestSetup) error {
	if err := backend.step(ctx, "arm"); err != nil {
		return err
	}
	return setup.Endpoint(ctx, func(netip.Addr, uint16) error { return nil })
}

func (backend *fakeBackend) ConfigureTunnel(ctx context.Context, underlay Underlay, setup vpn.GuestSetup) error {
	if err := backend.step(ctx, "configure"); err != nil {
		return err
	}
	if err := underlay.validate(); err != nil {
		return err
	}
	return setup.WithWireGuardConfig(ctx, func(_ context.Context, reader io.Reader) error {
		value, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		backend.mu.Lock()
		backend.config = append(backend.config[:0], value...)
		backend.mu.Unlock()
		clear(value)
		return nil
	})
}

func (backend *fakeBackend) RemoveTunnel(ctx context.Context) error {
	return backend.step(ctx, "remove_tunnel")
}

func (backend *fakeBackend) RemoveKillSwitch(ctx context.Context) error {
	return backend.step(ctx, "remove_kill_switch")
}

func (backend *fakeBackend) operationSnapshot() []string {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return append([]string(nil), backend.operations...)
}

type fakeVerifier struct {
	mu     sync.Mutex
	proofs []Proof
	errors []error
	calls  int
	block  bool
}

func (verifier *fakeVerifier) Verify(ctx context.Context, _ RolePolicy) (Proof, error) {
	verifier.mu.Lock()
	index := verifier.calls
	verifier.calls++
	block := verifier.block
	var proof Proof
	var err error
	if index < len(verifier.proofs) {
		proof = verifier.proofs[index]
	}
	if index < len(verifier.errors) {
		err = verifier.errors[index]
	}
	verifier.mu.Unlock()
	if block {
		<-ctx.Done()
		return Proof{}, ctx.Err()
	}
	return proof, err
}

type fakeResponder struct {
	called chan Status
	err    error
}

func (responder *fakeResponder) OnVPNLoss(_ context.Context, status Status) error {
	responder.called <- status
	return responder.err
}

func completeProof() Proof {
	return Proof{
		Handshake: true, DNSThroughTunnel: true, IPv4ThroughTunnel: true, IPv6ThroughTunnel: true,
		IPv4BypassBlocked: true, IPv6BypassBlocked: true, TorrentBound: true,
	}
}

func validUnderlay() Underlay {
	return Underlay{
		IPv4Address: netip.MustParsePrefix("10.240.0.2/30"), IPv4Gateway: netip.MustParseAddr("10.240.0.1"),
		IPv6Address: netip.MustParsePrefix("fd70:766d::2/126"), IPv6Gateway: netip.MustParseAddr("fd70:766d::1"),
	}
}

func testProfile(t *testing.T, ipv6 bool) vpn.Profile {
	t.Helper()
	encoded := func(value byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)) }
	address, dns, allowed := "10.2.0.2/32", "10.2.0.1", "0.0.0.0/0"
	if ipv6 {
		address += ", fd00::2/128"
		dns += ", fd00::1"
		allowed += ", ::/0"
	}
	value := "[Interface]\nPrivateKey = " + encoded(0x11) + "\nAddress = " + address + "\nDNS = " + dns +
		"\n\n[Peer]\nPublicKey = " + encoded(0x22) + "\nAllowedIPs = " + allowed + "\nEndpoint = 1.1.1.1:51820\n"
	profile, err := vpn.Parse(strings.NewReader(value))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(profile.Destroy)
	return profile
}

func newDownloaderController(t *testing.T, backend *fakeBackend, verifier *fakeVerifier) *Controller {
	t.Helper()
	t.Cleanup(func() {
		backend.mu.Lock()
		clear(backend.config)
		backend.config = nil
		backend.mu.Unlock()
	})
	controller, err := NewController(backend, verifier, RolePolicy{Role: session.RoleDownloader, RequireTorrentBinding: true}, validUnderlay())
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func TestConfigureArmsKillSwitchBeforeTunnelAndVerifiesEveryGate(t *testing.T) {
	backend := newFakeBackend()
	controller := newDownloaderController(t, backend, &fakeVerifier{proofs: []Proof{completeProof()}})
	status, err := controller.Configure(context.Background(), testProfile(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if got := backend.operationSnapshot(); fmt.Sprint(got) != "[arm configure]" {
		t.Fatalf("unsafe configuration order: %v", got)
	}
	if status.State != StateVerified || !status.KillSwitchArmed || !status.Configured || status.Code != "GUEST_VPN_VERIFIED" {
		t.Fatalf("unexpected verified status: %#v", status)
	}
	backend.mu.Lock()
	config := append([]byte(nil), backend.config...)
	backend.mu.Unlock()
	defer clear(config)
	if !bytes.Contains(config, []byte("PrivateKey = ")) || bytes.Contains(config, []byte("Address =")) || bytes.Contains(config, []byte("DNS =")) {
		t.Fatal("backend did not receive the minimal WireGuard-only stream")
	}

	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"1.1.1.1", "10.2.0.2", encodedKeyForTest(0x11)} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("status disclosed %q: %s", forbidden, encoded)
		}
	}
}

func TestConfigureFailureMatrixRetainsFailClosedState(t *testing.T) {
	tests := []struct {
		name        string
		operation   string
		wantState   State
		wantArmed   bool
		wantCleanup bool
	}{
		{name: "kill switch", operation: "arm", wantState: StateUnconfigured},
		{name: "tunnel", operation: "configure", wantState: StateKillSwitchArmed, wantArmed: true, wantCleanup: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newFakeBackend()
			backend.fail[test.operation] = 1
			controller := newDownloaderController(t, backend, &fakeVerifier{proofs: []Proof{completeProof()}})
			status, err := controller.Configure(context.Background(), testProfile(t, true))
			if err == nil || status.State != test.wantState || status.KillSwitchArmed != test.wantArmed || status.Configured {
				t.Fatalf("failure status = %#v, %v", status, err)
			}
			if strings.Contains(err.Error(), "1.1.1.1") {
				t.Fatalf("backend detail escaped normalized error: %v", err)
			}
			gotCleanup := strings.Contains(fmt.Sprint(backend.operationSnapshot()), "remove_tunnel")
			if gotCleanup != test.wantCleanup {
				t.Fatalf("cleanup called = %v, operations = %v", gotCleanup, backend.operationSnapshot())
			}
		})
	}
}

func TestIncompleteVerificationBlocksNetworkApplications(t *testing.T) {
	proof := completeProof()
	proof.TorrentBound = false
	controller := newDownloaderController(t, newFakeBackend(), &fakeVerifier{proofs: []Proof{proof}})
	status, err := controller.Configure(context.Background(), testProfile(t, true))
	if !errors.Is(err, ErrVerificationFailed) || status.State != StateDegraded || !status.KillSwitchArmed || !status.Configured {
		t.Fatalf("incomplete verification = %#v, %v", status, err)
	}
}

func TestMonitorTunnelLossTriggersRoleResponseAndLeavesKillSwitch(t *testing.T) {
	bad := completeProof()
	bad.Handshake = false
	verifier := &fakeVerifier{proofs: []Proof{completeProof(), bad}}
	controller := newDownloaderController(t, newFakeBackend(), verifier)
	if _, err := controller.Configure(context.Background(), testProfile(t, true)); err != nil {
		t.Fatal(err)
	}
	responder := &fakeResponder{called: make(chan Status, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := controller.Monitor(ctx, time.Millisecond, responder)
	if !errors.Is(err, ErrTunnelLost) {
		t.Fatalf("monitor error = %v", err)
	}
	select {
	case status := <-responder.called:
		if status.State != StateDegraded || !status.KillSwitchArmed || status.Handshake {
			t.Fatalf("loss response status = %#v", status)
		}
	default:
		t.Fatal("role-specific loss response was not called")
	}
}

func TestCancellationTimeoutAndMonitorCancellationAreBounded(t *testing.T) {
	backend := newFakeBackend()
	backend.block = "arm"
	controller := newDownloaderController(t, backend, &fakeVerifier{proofs: []Proof{completeProof()}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := controller.Configure(ctx, testProfile(t, true)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("configuration timeout = %v", err)
	}

	controller = newDownloaderController(t, newFakeBackend(), &fakeVerifier{proofs: []Proof{completeProof()}})
	if _, err := controller.Configure(context.Background(), testProfile(t, false)); err != nil {
		t.Fatal(err)
	}
	monitorCtx, stopMonitor := context.WithCancel(context.Background())
	stopMonitor()
	if err := controller.Monitor(monitorCtx, time.Millisecond, &fakeResponder{called: make(chan Status, 1)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("monitor cancellation = %v", err)
	}
}

func TestStopRetriesWithoutRemovingKillSwitchEarly(t *testing.T) {
	backend := newFakeBackend()
	controller := newDownloaderController(t, backend, &fakeVerifier{proofs: []Proof{completeProof()}})
	if _, err := controller.Configure(context.Background(), testProfile(t, true)); err != nil {
		t.Fatal(err)
	}
	backend.fail["remove_tunnel"] = 1
	if err := controller.Stop(context.Background()); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("first stop error = %v", err)
	}
	if got := backend.operationSnapshot(); strings.Contains(fmt.Sprint(got), "remove_kill_switch") {
		t.Fatalf("kill switch was removed before tunnel cleanup: %v", got)
	}
	if status := controller.Status(); !status.KillSwitchArmed || !status.Configured {
		t.Fatalf("partial cleanup status = %#v", status)
	}
	if err := controller.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := controller.Stop(context.Background()); err != nil {
		t.Fatalf("idempotent stop = %v", err)
	}
	status := controller.Status()
	if status.State != StateStopped || status.KillSwitchArmed || status.Configured {
		t.Fatalf("stopped status = %#v", status)
	}
}

func TestRoleAndUnderlayContractsFailClosedAndRedact(t *testing.T) {
	backend, verifier := newFakeBackend(), &fakeVerifier{}
	for _, policy := range []RolePolicy{
		{Role: session.RoleExporter},
		{Role: session.RoleScanner},
		{Role: session.RoleDownloader},
		{Role: session.RoleScanner, ScannerUpdate: true, RequireTorrentBinding: true},
	} {
		if _, err := NewController(backend, verifier, policy, validUnderlay()); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("unsafe role policy passed: %#v, %v", policy, err)
		}
	}
	if _, err := NewController(backend, verifier, RolePolicy{Role: session.RoleWorkstation}, Underlay{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid underlay passed: %v", err)
	}
	underlay := validUnderlay()
	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X"} {
		if got := fmt.Sprintf(verb, underlay); got != redactedUnderlay {
			t.Fatalf("underlay formatting %s = %q", verb, got)
		}
	}
	if _, err := json.Marshal(underlay); !errors.Is(err, secret.ErrSerialization) {
		t.Fatalf("underlay JSON error = %v", err)
	}
}

func encodedKeyForTest(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}
