package guest

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/netip"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/vpn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type rpcVPNBackend struct {
	armed      bool
	configured bool
}

func (backend *rpcVPNBackend) ArmKillSwitch(ctx context.Context, setup vpn.GuestSetup) error {
	backend.armed = true
	return setup.Endpoint(ctx, func(netip.Addr, uint16) error { return nil })
}

func (backend *rpcVPNBackend) ConfigureTunnel(ctx context.Context, _ guestvpn.Underlay, setup vpn.GuestSetup) error {
	if !backend.armed {
		return context.Canceled
	}
	backend.configured = true
	return setup.WithWireGuardConfig(ctx, func(_ context.Context, reader io.Reader) error {
		_, err := io.Copy(io.Discard, reader)
		return err
	})
}

func (backend *rpcVPNBackend) RemoveTunnel(context.Context) error {
	backend.configured = false
	return nil
}

func (backend *rpcVPNBackend) RemoveKillSwitch(context.Context) error {
	backend.armed = false
	return nil
}

type rpcVPNVerifier struct{}

func (rpcVPNVerifier) Verify(context.Context, guestvpn.RolePolicy) (guestvpn.Proof, error) {
	return guestvpn.Proof{
		Handshake: true, DNSThroughTunnel: true, IPv4ThroughTunnel: true, IPv6ThroughTunnel: true,
		IPv4BypassBlocked: true, IPv6BypassBlocked: true, TorrentBound: true,
	}, nil
}

func downloaderVPNHandler(t *testing.T) *DownloaderVPNServer {
	t.Helper()
	controller, err := guestvpn.NewController(
		&rpcVPNBackend{}, rpcVPNVerifier{},
		guestvpn.RolePolicy{Role: session.RoleDownloader, RequireTorrentBinding: true},
		guestvpn.Underlay{
			IPv4Address: netip.MustParsePrefix("10.240.0.2/30"), IPv4Gateway: netip.MustParseAddr("10.240.0.1"),
			IPv6Address: netip.MustParsePrefix("fd70:766d::2/126"), IPv6Gateway: netip.MustParseAddr("fd70:766d::1"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewDownloaderVPNServer(controller)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func downloaderProfile() []byte {
	encoded := func(value byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)) }
	return []byte("[Interface]\nPrivateKey = " + encoded(0x11) +
		"\nAddress = 10.2.0.2/32, fd00::2/128\nDNS = 10.2.0.1, fd00::1\n\n[Peer]\nPublicKey = " + encoded(0x22) +
		"\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 1.1.1.1:51820\n")
}

func TestDownloaderVPNRPCConsumesAndClearsProfileBytes(t *testing.T) {
	handler := downloaderVPNHandler(t)
	raw := downloaderProfile()
	request := &privatevmv1.ConfigureWireGuardRequest{Context: helloRequest(session.RoleDownloader, APIMajor, APIMinor).GetContext(), Profile: raw}
	response, err := handler.ConfigureWireGuard(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if request.Profile != nil || !allZeroGuestBytes(raw) {
		t.Fatal("RPC profile buffer remained reachable or uncleared")
	}
	if !response.GetConfigured() || !response.GetHandshake() || !response.GetDnsThroughTunnel() ||
		!response.GetIpv4BypassBlocked() || !response.GetIpv6BypassBlocked() || len(response.GetDiagnostics()) != 1 {
		t.Fatalf("unexpected safe VPN response: %#v", response)
	}
	verified, err := handler.VerifyVPN(context.Background(), &privatevmv1.VerifyVPNRequest{Context: helloRequest(session.RoleDownloader, APIMajor, APIMinor).GetContext()})
	if err != nil || !verified.GetHandshake() {
		t.Fatalf("VerifyVPN = %#v, %v", verified, err)
	}
}

func TestDownloaderVPNRPCClearsRejectedProfile(t *testing.T) {
	handler := downloaderVPNHandler(t)
	raw := downloaderProfile()
	request := &privatevmv1.ConfigureWireGuardRequest{Context: helloRequest(session.RoleWorkstation, APIMajor, APIMinor).GetContext(), Profile: raw}
	_, err := handler.ConfigureWireGuard(context.Background(), request)
	if status.Code(err) != codes.FailedPrecondition || request.Profile != nil || !allZeroGuestBytes(raw) {
		t.Fatalf("rejected RPC = %v; profile reachable=%v cleared=%v", err, request.Profile != nil, allZeroGuestBytes(raw))
	}
}

func allZeroGuestBytes(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}
