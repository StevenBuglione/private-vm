package guestvpn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	resolvedProtocolDNS = uint64(1 << 0)
	resolvedNoSearch    = uint64(1 << 8)
	maximumDNSAnswers   = 16
)

type resolvedAnswer struct {
	Interface int32
	Family    int32
	Address   []byte
}

// ResolvedDNSLeakProbe forces the same controlled hostname over proton0 and
// then eth0 through resolve1. Tunnel success plus clear-interface failure is a
// DNS-routing proof; answers and canonical names are destroyed and never
// returned.
type ResolvedDNSLeakProbe struct {
	connect   resolvedConnector
	linkIndex linkIndexResolver
	timeout   time.Duration
}

func NewResolvedDNSLeakProbe() *ResolvedDNSLeakProbe {
	return &ResolvedDNSLeakProbe{
		connect: connectResolvedSystemBus,
		linkIndex: func(name string) (int32, error) {
			link, err := net.InterfaceByName(name)
			if err != nil || link.Index <= 0 {
				return 0, errors.New("DNS probe link unavailable")
			}
			return int32(link.Index), nil
		},
		timeout: resolvedTimeout,
	}
}

func newResolvedDNSLeakProbe(connect resolvedConnector, linkIndex linkIndexResolver) *ResolvedDNSLeakProbe {
	return &ResolvedDNSLeakProbe{connect: connect, linkIndex: linkIndex, timeout: resolvedTimeout}
}

func (probe *ResolvedDNSLeakProbe) TunnelAndBypass(ctx context.Context, hostname string) (bool, bool, error) {
	if ctx == nil || probe == nil || isNilLike(probe.connect) || isNilLike(probe.linkIndex) ||
		len(hostname) == 0 || len(hostname) > 253 || !probeDomainPattern.MatchString(strings.TrimSuffix(strings.ToLower(hostname), ".")) {
		return false, false, invalidRequest()
	}
	operationCtx, cancel := boundedContext(ctx, probe.effectiveTimeout())
	defer cancel()
	if err := operationCtx.Err(); err != nil {
		return false, false, err
	}
	tunnelIndex, err := probe.linkIndex(TunnelInterface)
	if err != nil || tunnelIndex <= 0 {
		return false, false, errors.New("DNS probe tunnel unavailable")
	}
	underlayIndex, err := probe.linkIndex(UnderlayInterface)
	if err != nil || underlayIndex <= 0 || underlayIndex == tunnelIndex {
		return false, false, errors.New("DNS probe underlay unavailable")
	}
	connection, err := probe.connect(operationCtx)
	if err != nil {
		return false, false, normalizeResolvedError(operationCtx)
	}
	defer connection.Close()
	tunnelOK, err := resolveOnLink(operationCtx, connection, tunnelIndex, hostname)
	if err != nil || !tunnelOK {
		return false, false, normalizeResolvedProbeError(operationCtx, err)
	}
	underlayOK, underlayErr := resolveOnLink(operationCtx, connection, underlayIndex, hostname)
	if operationCtx.Err() != nil {
		return true, false, operationCtx.Err()
	}
	if underlayErr != nil {
		return true, true, nil
	}
	return true, !underlayOK, nil
}

func (probe *ResolvedDNSLeakProbe) effectiveTimeout() time.Duration {
	if probe.timeout <= 0 || probe.timeout > resolvedTimeout {
		return resolvedTimeout
	}
	return probe.timeout
}

func resolveOnLink(ctx context.Context, connection resolvedConnection, index int32, hostname string) (bool, error) {
	var answers []resolvedAnswer
	var canonical string
	var flags uint64
	defer func() {
		for position := range answers {
			clear(answers[position].Address)
		}
		clear(answers)
		canonical = ""
		flags = 0
	}()
	err := connection.CallStore(
		ctx, resolvedManager+".ResolveHostname",
		[]any{index, hostname, int32(unix.AF_UNSPEC), resolvedProtocolDNS | resolvedNoSearch},
		&answers, &canonical, &flags,
	)
	if err != nil {
		return false, err
	}
	if len(answers) == 0 || len(answers) > maximumDNSAnswers || flags&resolvedProtocolDNS == 0 {
		return false, nil
	}
	for _, answer := range answers {
		if answer.Interface != index {
			return false, nil
		}
		var address netip.Addr
		var ok bool
		switch answer.Family {
		case unix.AF_INET:
			address, ok = netip.AddrFromSlice(answer.Address)
			ok = ok && address.Is4()
		case unix.AF_INET6:
			address, ok = netip.AddrFromSlice(answer.Address)
			ok = ok && address.Is6() && !address.Is4In6()
		default:
			return false, nil
		}
		if !ok || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return false, nil
		}
	}
	return true, nil
}

func normalizeResolvedProbeError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return errors.New("bounded resolved DNS probe failed")
	}
	return nil
}

var _ DNSLeakProbe = (*ResolvedDNSLeakProbe)(nil)
