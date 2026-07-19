package guestvpn

import (
	"bytes"
	"context"
	"net/netip"
	"strconv"

	"github.com/StevenBuglione/private-vm/internal/vpn"
)

func killSwitchRules(ctx context.Context, setup vpn.GuestSetup) ([]byte, error) {
	var destination bytes.Buffer
	writeLine(&destination, "table inet private_vm_guest {")
	writeLine(&destination, " chain input {")
	writeLine(&destination, "  type filter hook input priority filter; policy drop;")
	writeLine(&destination, "  iifname \"lo\" accept")
	writeLine(&destination, "  ct state { established, related } accept")
	writeLine(&destination, "  iifname \"", TunnelInterface, "\" accept")
	writeLine(&destination, "  iifname \"", UnderlayInterface, "\" meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept")
	writeLine(&destination, " }")
	writeLine(&destination, " chain forward { type filter hook forward priority filter; policy drop; }")
	writeLine(&destination, " chain output {")
	writeLine(&destination, "  type filter hook output priority filter; policy drop;")
	writeLine(&destination, "  oifname \"lo\" accept")
	writeLine(&destination, "  oifname \"", TunnelInterface, "\" accept")
	writeLine(&destination, "  oifname \"", UnderlayInterface, "\" meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept")
	endpointCount := 0
	err := setup.Endpoint(ctx, func(address netip.Addr, port uint16) error {
		endpointCount++
		if endpointCount > 1 || !address.IsValid() || address.Is4In6() || port == 0 {
			return invalidRequest()
		}
		family := "ip"
		if address.Is6() {
			family = "ip6"
		}
		write(&destination, "  oifname \"", UnderlayInterface, "\" ", family, " daddr ")
		_, _ = destination.Write(address.AppendTo(nil))
		writeLine(&destination, " udp dport ", strconv.FormatUint(uint64(port), 10), " accept")
		return nil
	})
	if err != nil || endpointCount != 1 {
		clear(destination.Bytes())
		return nil, invalidRequest()
	}
	writeLine(&destination, " }")
	writeLine(&destination, "}")
	if destination.Len() > guestCommandInputLimit {
		clear(destination.Bytes())
		return nil, invalidRequest()
	}
	return destination.Bytes(), nil
}

func underlayCommands(ctx context.Context, underlay Underlay, setup vpn.GuestSetup) ([]byte, error) {
	var destination bytes.Buffer
	writeLine(&destination, "address flush dev ", UnderlayInterface, " scope global")
	write(&destination, "address add ")
	_, _ = destination.Write(underlay.IPv4Address.AppendTo(nil))
	writeLine(&destination, " dev ", UnderlayInterface)
	write(&destination, "address add ")
	_, _ = destination.Write(underlay.IPv6Address.AppendTo(nil))
	writeLine(&destination, " dev ", UnderlayInterface)
	writeLine(&destination, "link set ", UnderlayInterface, " up")
	endpointCount := 0
	err := setup.Endpoint(ctx, func(address netip.Addr, _ uint16) error {
		endpointCount++
		if endpointCount > 1 || !address.IsValid() || address.Is4In6() {
			return invalidRequest()
		}
		write(&destination, "route replace ")
		_, _ = destination.Write(netip.PrefixFrom(address, address.BitLen()).AppendTo(nil))
		write(&destination, " via ")
		if address.Is4() {
			_, _ = destination.Write(underlay.IPv4Gateway.AppendTo(nil))
		} else {
			_, _ = destination.Write(underlay.IPv6Gateway.AppendTo(nil))
		}
		writeLine(&destination, " dev ", UnderlayInterface)
		return nil
	})
	if err != nil || endpointCount != 1 || destination.Len() > guestCommandInputLimit {
		clear(destination.Bytes())
		return nil, invalidRequest()
	}
	return destination.Bytes(), nil
}

func tunnelCommands(ctx context.Context, setup vpn.GuestSetup) ([]byte, error) {
	var destination bytes.Buffer
	addressCount := 0
	err := setup.InterfaceAddresses(ctx, func(address netip.Prefix) error {
		addressCount++
		if addressCount > 8 || !address.IsValid() {
			return invalidRequest()
		}
		write(&destination, "address add ")
		_, _ = destination.Write(address.AppendTo(nil))
		writeLine(&destination, " dev ", TunnelInterface)
		return nil
	})
	if err != nil || addressCount == 0 {
		clear(destination.Bytes())
		return nil, invalidRequest()
	}
	writeLine(&destination, "link set ", TunnelInterface, " up")
	writeLine(&destination, "route replace default dev ", TunnelInterface)
	writeLine(&destination, "-6 route replace default dev ", TunnelInterface)
	if destination.Len() > guestCommandInputLimit {
		clear(destination.Bytes())
		return nil, invalidRequest()
	}
	return destination.Bytes(), nil
}

func write(destination *bytes.Buffer, values ...string) {
	for _, value := range values {
		_, _ = destination.WriteString(value)
	}
}

func writeLine(destination *bytes.Buffer, values ...string) {
	write(destination, values...)
	_ = destination.WriteByte('\n')
}
