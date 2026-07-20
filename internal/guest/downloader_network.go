package guest

import (
	"net/netip"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"google.golang.org/grpc/codes"
)

func protoGuestUnderlay(value guestvpn.Underlay) *privatevmv1.GuestUnderlay {
	return &privatevmv1.GuestUnderlay{
		Ipv4Address: append([]byte(nil), value.IPv4Address.Addr().AsSlice()...), Ipv4PrefixLength: uint32(value.IPv4Address.Bits()),
		Ipv4Gateway: append([]byte(nil), value.IPv4Gateway.AsSlice()...),
		Ipv6Address: append([]byte(nil), value.IPv6Address.Addr().AsSlice()...), Ipv6PrefixLength: uint32(value.IPv6Address.Bits()),
		Ipv6Gateway: append([]byte(nil), value.IPv6Gateway.AsSlice()...),
	}
}

func guestUnderlayFromProto(value *privatevmv1.GuestUnderlay) (guestvpn.Underlay, error) {
	if value == nil || value.GetIpv4PrefixLength() > 32 || value.GetIpv6PrefixLength() > 128 {
		return guestvpn.Underlay{}, guestNetworkRequestError()
	}
	ipv4, ok4 := netip.AddrFromSlice(value.GetIpv4Address())
	ipv4Gateway, ok4Gateway := netip.AddrFromSlice(value.GetIpv4Gateway())
	ipv6, ok6 := netip.AddrFromSlice(value.GetIpv6Address())
	ipv6Gateway, ok6Gateway := netip.AddrFromSlice(value.GetIpv6Gateway())
	if !ok4 || !ok4Gateway || !ok6 || !ok6Gateway || !ipv4.Is4() || !ipv4Gateway.Is4() || !ipv6.Is6() || ipv6.Is4In6() || !ipv6Gateway.Is6() || ipv6Gateway.Is4In6() {
		return guestvpn.Underlay{}, guestNetworkRequestError()
	}
	result, err := guestvpn.NewUnderlay(
		netip.PrefixFrom(ipv4, int(value.GetIpv4PrefixLength())), ipv4Gateway,
		netip.PrefixFrom(ipv6, int(value.GetIpv6PrefixLength())), ipv6Gateway,
	)
	if err != nil {
		return guestvpn.Underlay{}, guestNetworkRequestError()
	}
	return result, nil
}

func protoVPNProbeTargets(value guestvpn.ProbeTargets) *privatevmv1.VPNProbeTargets {
	return &privatevmv1.VPNProbeTargets{
		DnsName:     value.DNSName,
		Ipv4Address: append([]byte(nil), value.IPv4.Addr().AsSlice()...), Ipv4Port: uint32(value.IPv4.Port()),
		Ipv6Address: append([]byte(nil), value.IPv6.Addr().AsSlice()...), Ipv6Port: uint32(value.IPv6.Port()),
	}
}

func vpnProbeTargetsFromProto(value *privatevmv1.VPNProbeTargets) (guestvpn.ProbeTargets, error) {
	if value == nil || value.GetIpv4Port() == 0 || value.GetIpv4Port() > 65535 || value.GetIpv6Port() == 0 || value.GetIpv6Port() > 65535 {
		return guestvpn.ProbeTargets{}, guestNetworkRequestError()
	}
	ipv4, ok4 := netip.AddrFromSlice(value.GetIpv4Address())
	ipv6, ok6 := netip.AddrFromSlice(value.GetIpv6Address())
	if !ok4 || !ok6 || !ipv4.Is4() || !ipv6.Is6() || ipv6.Is4In6() {
		return guestvpn.ProbeTargets{}, guestNetworkRequestError()
	}
	result, err := guestvpn.NewProbeTargets(value.GetDnsName(), netip.AddrPortFrom(ipv4, uint16(value.GetIpv4Port())), netip.AddrPortFrom(ipv6, uint16(value.GetIpv6Port())))
	if err != nil {
		return guestvpn.ProbeTargets{}, guestNetworkRequestError()
	}
	return result, nil
}

func guestNetworkRequestError() error {
	return guestRPCError(codes.InvalidArgument, "GUEST_VPN_REQUEST_INVALID", "The typed guest network request is invalid.", "Destroy the guest and retry through the private-vm daemon network owner.", false)
}

func clearDownloaderNetworkRequest(request *privatevmv1.ConfigureWireGuardRequest) {
	if request == nil {
		return
	}
	if underlay := request.GetUnderlay(); underlay != nil {
		clear(underlay.Ipv4Address)
		clear(underlay.Ipv4Gateway)
		clear(underlay.Ipv6Address)
		clear(underlay.Ipv6Gateway)
	}
	if targets := request.GetProbeTargets(); targets != nil {
		clear(targets.Ipv4Address)
		clear(targets.Ipv6Address)
		targets.DnsName = ""
	}
	request.Underlay = nil
	request.ProbeTargets = nil
}

// EncodeDownloaderNetworkRequest is the sole host-side encoder for the
// private underlay and controlled probe fixtures. Callers still supply the
// profile separately as protected bytes.
func EncodeDownloaderNetworkRequest(underlay guestvpn.Underlay, targets guestvpn.ProbeTargets) (*privatevmv1.GuestUnderlay, *privatevmv1.VPNProbeTargets) {
	return protoGuestUnderlay(underlay), protoVPNProbeTargets(targets)
}
