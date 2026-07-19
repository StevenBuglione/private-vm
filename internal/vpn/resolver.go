package vpn

import (
	"context"
	"net"
	"net/netip"
	"time"
)

const (
	endpointResolveTimeout = 10 * time.Second
	maximumResolvedIPs     = 16
)

// NetIPLookup is the narrow, context-aware resolver boundary used in tests and
// by the system resolver adapter. It has no fallback to guest or pre-tunnel DNS.
type NetIPLookup interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// EndpointResolver resolves on the trusted host with a hard ten-second ceiling.
type EndpointResolver struct {
	lookup  NetIPLookup
	timeout time.Duration
}

func NewEndpointResolver() *EndpointResolver {
	return &EndpointResolver{lookup: net.DefaultResolver, timeout: endpointResolveTimeout}
}

// NewEndpointResolverWithLookup installs a narrow resolver adapter while
// retaining the production timeout. It is intended for deterministic mock
// endpoint and acceptance tests, never as a DNS-policy bypass.
func NewEndpointResolverWithLookup(lookup NetIPLookup) *EndpointResolver {
	return &EndpointResolver{lookup: lookup, timeout: endpointResolveTimeout}
}

// resolve returns a bounded, sorted, deduplicated set of public endpoint
// addresses. It is package-private so only a store can bind the result into an
// opaque generation/epoch plan. Error details never contain the hostname or
// resolver output.
func (r *EndpointResolver) resolve(ctx context.Context, profile Profile) ([]resolvedEndpoint, error) {
	if ctx == nil || r == nil || isNilLike(r.lookup) || isNilLike(profile) {
		return nil, endpointUnresolved()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	peerEndpoint, err := profile.endpointSnapshot()
	if err != nil {
		return nil, err
	}
	if peerEndpoint.literal.IsValid() {
		return []resolvedEndpoint{{address: peerEndpoint.literal, port: peerEndpoint.port}}, nil
	}
	timeout := r.timeout
	if timeout <= 0 || timeout > endpointResolveTimeout {
		timeout = endpointResolveTimeout
	}
	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addresses, lookupErr := r.lookup.LookupNetIP(resolveCtx, "ip", peerEndpoint.host)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lookupErr != nil || resolveCtx.Err() != nil || len(addresses) == 0 || len(addresses) > maximumResolvedIPs {
		return nil, endpointUnresolved()
	}
	seen := make(map[netip.Addr]struct{}, len(addresses))
	resolved := make([]resolvedEndpoint, 0, len(addresses))
	for _, address := range addresses {
		if address.Is4In6() || !publicEndpointAddress(address) {
			return nil, endpointUnresolved()
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		resolved = append(resolved, resolvedEndpoint{address: address, port: peerEndpoint.port})
	}
	if len(resolved) == 0 {
		return nil, endpointUnresolved()
	}
	sortEndpoints(resolved)
	return resolved, nil
}
