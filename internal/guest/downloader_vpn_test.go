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
		Handshake: true, DNSThroughTunnel: true, DNSBypassBlocked: true, IPv4ThroughTunnel: true, IPv6ThroughTunnel: true,
		IPv4BypassBlocked: true, IPv6BypassBlocked: true, TorrentBound: true,
	}, nil
}

func downloaderVPNHandler(t *testing.T) *DownloaderVPNServer {
	t.Helper()
	return &DownloaderVPNServer{controllerFactory: func(underlay guestvpn.Underlay, _ guestvpn.ProbeTargets) (*guestvpn.Controller, error) {
		return guestvpn.NewController(
			&rpcVPNBackend{}, rpcVPNVerifier{},
			guestvpn.RolePolicy{Role: session.RoleDownloader, RequireTorrentBinding: true}, underlay,
		)
	}}
}

func downloaderNetworkFields(t *testing.T) (*privatevmv1.GuestUnderlay, *privatevmv1.VPNProbeTargets) {
	t.Helper()
	underlay, err := guestvpn.NewUnderlay(
		netip.MustParsePrefix("10.240.0.2/30"), netip.MustParseAddr("10.240.0.1"),
		netip.MustParsePrefix("fd70:766d::2/126"), netip.MustParseAddr("fd70:766d::1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := guestvpn.NewProbeTargets("probe.example.com", netip.MustParseAddrPort("1.1.1.1:443"), netip.MustParseAddrPort("[2606:4700:4700::1111]:443"))
	if err != nil {
		t.Fatal(err)
	}
	return EncodeDownloaderNetworkRequest(underlay, targets)
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
	underlay, targets := downloaderNetworkFields(t)
	request := &privatevmv1.ConfigureWireGuardRequest{Context: helloRequest(session.RoleDownloader, APIMajor, APIMinor).GetContext(), Profile: raw, Underlay: underlay, ProbeTargets: targets}
	response, err := handler.ConfigureWireGuard(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if request.Profile != nil || request.Underlay != nil || request.ProbeTargets != nil || !allZeroGuestBytes(raw) {
		t.Fatal("RPC network material remained reachable or uncleared")
	}
	if !response.GetConfigured() || !response.GetHandshake() || !response.GetDnsThroughTunnel() ||
		!response.GetDnsBypassBlocked() || !response.GetIpv4ThroughTunnel() || !response.GetIpv6ThroughTunnel() ||
		!response.GetIpv4BypassBlocked() || !response.GetIpv6BypassBlocked() || !response.GetTorrentBound() || len(response.GetDiagnostics()) != 1 {
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
	underlay, targets := downloaderNetworkFields(t)
	request := &privatevmv1.ConfigureWireGuardRequest{Context: helloRequest(session.RoleWorkstation, APIMajor, APIMinor).GetContext(), Profile: raw, Underlay: underlay, ProbeTargets: targets}
	_, err := handler.ConfigureWireGuard(context.Background(), request)
	if status.Code(err) != codes.FailedPrecondition || request.Profile != nil || request.Underlay != nil || request.ProbeTargets != nil || !allZeroGuestBytes(raw) {
		t.Fatalf("rejected RPC = %v; profile reachable=%v cleared=%v", err, request.Profile != nil, allZeroGuestBytes(raw))
	}
}

func TestDownloaderVPNRPCRejectsMalformedTypedUnderlayBeforeComposition(t *testing.T) {
	handler := downloaderVPNHandler(t)
	raw := downloaderProfile()
	_, targets := downloaderNetworkFields(t)
	request := &privatevmv1.ConfigureWireGuardRequest{
		Context: helloRequest(session.RoleDownloader, APIMajor, APIMinor).GetContext(), Profile: raw,
		Underlay: &privatevmv1.GuestUnderlay{Ipv4Address: []byte{10, 0, 0, 2}, Ipv4PrefixLength: 24}, ProbeTargets: targets,
	}
	_, err := handler.ConfigureWireGuard(t.Context(), request)
	if status.Code(err) != codes.InvalidArgument || handler.controller != nil || request.Underlay != nil || request.ProbeTargets != nil || !allZeroGuestBytes(raw) {
		t.Fatalf("malformed underlay result err=%v controller=%v request=%+v", err, handler.controller != nil, request)
	}
}

func TestWorkstationVPNRPCUsesWorkstationRoleWithoutDownloaderService(t *testing.T) {
	factory := func(underlay guestvpn.Underlay, _ guestvpn.ProbeTargets) (*guestvpn.Controller, error) {
		return guestvpn.NewController(
			&rpcVPNBackend{}, rpcVPNVerifier{}, guestvpn.RolePolicy{Role: session.RoleWorkstation}, underlay,
		)
	}
	handler, err := NewWorkstationVPNServer(workstationServer{}, factory)
	if err != nil {
		t.Fatal(err)
	}
	raw := downloaderProfile()
	underlay, targets := downloaderNetworkFields(t)
	request := &privatevmv1.ConfigureWireGuardRequest{
		Context: helloRequest(session.RoleWorkstation, APIMajor, APIMinor).GetContext(),
		Profile: raw, Underlay: underlay, ProbeTargets: targets,
	}
	configured, err := handler.ConfigureWireGuard(t.Context(), request)
	if err != nil || !configured.GetHandshake() || !configured.GetConfigured() {
		t.Fatalf("workstation ConfigureWireGuard = %#v, %v", configured, err)
	}
	verified, err := handler.VerifyVPN(t.Context(), &privatevmv1.VerifyVPNRequest{
		Context: helloRequest(session.RoleWorkstation, APIMajor, APIMinor).GetContext(),
	})
	if err != nil || !verified.GetHandshake() {
		t.Fatalf("workstation VerifyVPN = %#v, %v", verified, err)
	}

	wrong := downloaderProfile()
	underlay, targets = downloaderNetworkFields(t)
	_, err = handler.ConfigureWireGuard(t.Context(), &privatevmv1.ConfigureWireGuardRequest{
		Context: helloRequest(session.RoleDownloader, APIMajor, APIMinor).GetContext(),
		Profile: wrong, Underlay: underlay, ProbeTargets: targets,
	})
	if status.Code(err) != codes.FailedPrecondition || !allZeroGuestBytes(wrong) {
		t.Fatalf("workstation accepted downloader role: %v", err)
	}
	if err := handler.Close(t.Context()); err != nil {
		t.Fatal(err)
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
