package guestvpn

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
)

const (
	maximumVerificationDuration = 30 * time.Second
	redactedProbeTargets        = "[REDACTED CONTROLLED VPN PROBE TARGETS]"
)

var probeDomainPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$`)

type HandshakeProbe interface {
	Recent(context.Context) (bool, error)
}

type DNSLeakProbe interface {
	TunnelAndBypass(context.Context, string) (tunnelOK bool, bypassBlocked bool, err error)
}

type ConnectivityProbe interface {
	Reachable(context.Context, string, netip.AddrPort) (bool, error)
}

type TorrentBindingProbe interface {
	Bound(context.Context) (bool, error)
}

// ProbeTargets is an operator-controlled fixture contract, not a general
// destination API. Formatting and serialization are disabled so probe targets
// cannot enter status, diagnostics or telemetry.
type ProbeTargets struct {
	DNSName string
	IPv4    netip.AddrPort
	IPv6    netip.AddrPort
}

// NewProbeTargets validates the operator-controlled fixtures before they can
// reach a socket. Diagnostic formatting remains redacted below.
func NewProbeTargets(dnsName string, ipv4, ipv6 netip.AddrPort) (ProbeTargets, error) {
	targets := ProbeTargets{DNSName: dnsName, IPv4: ipv4, IPv6: ipv6}
	if err := targets.validate(); err != nil {
		return ProbeTargets{}, err
	}
	return targets, nil
}

func (targets ProbeTargets) validate() error {
	domain := strings.ToLower(strings.TrimSuffix(targets.DNSName, "."))
	if len(domain) == 0 || len(domain) > 253 || !probeDomainPattern.MatchString(domain) ||
		!safeProbeTarget(targets.IPv4, true) || !safeProbeTarget(targets.IPv6, false) {
		return invalidRequest()
	}
	return nil
}

func safeProbeTarget(target netip.AddrPort, ipv4 bool) bool {
	address := target.Addr()
	if !target.IsValid() || target.Port() == 0 || address.Is4In6() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	return address.Is4() == ipv4
}

func (ProbeTargets) String() string   { return redactedProbeTargets }
func (ProbeTargets) GoString() string { return redactedProbeTargets }
func (ProbeTargets) Format(formatter fmt.State, _ rune) {
	_, _ = formatter.Write([]byte(redactedProbeTargets))
}
func (ProbeTargets) MarshalJSON() ([]byte, error)   { return nil, secret.ErrSerialization }
func (ProbeTargets) MarshalText() ([]byte, error)   { return nil, secret.ErrSerialization }
func (ProbeTargets) MarshalBinary() ([]byte, error) { return nil, secret.ErrSerialization }
func (ProbeTargets) GobEncode() ([]byte, error)     { return nil, secret.ErrSerialization }
func (ProbeTargets) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

type ControlledVerifier struct {
	handshake    HandshakeProbe
	dns          DNSLeakProbe
	connectivity ConnectivityProbe
	torrent      TorrentBindingProbe
	targets      ProbeTargets
	timeout      time.Duration
}

func NewControlledVerifier(handshake HandshakeProbe, dns DNSLeakProbe, connectivity ConnectivityProbe, torrent TorrentBindingProbe, targets ProbeTargets) (*ControlledVerifier, error) {
	if isNilLike(handshake) || isNilLike(dns) || isNilLike(connectivity) || isNilLike(torrent) || targets.validate() != nil {
		return nil, invalidRequest()
	}
	return &ControlledVerifier{
		handshake: handshake, dns: dns, connectivity: connectivity, torrent: torrent,
		targets: targets, timeout: maximumVerificationDuration,
	}, nil
}

func (verifier *ControlledVerifier) Verify(ctx context.Context, policy RolePolicy) (Proof, error) {
	if ctx == nil || verifier == nil || policy.validate() != nil || verifier.targets.validate() != nil {
		return Proof{}, invalidRequest()
	}
	operationCtx, cancel := boundedContext(ctx, verifier.effectiveTimeout())
	defer cancel()
	var proof Proof
	var err error
	if proof.Handshake, err = verifier.handshake.Recent(operationCtx); err != nil {
		return proof, probeFailed(operationCtx)
	}
	if !proof.Handshake {
		return proof, nil
	}
	if proof.DNSThroughTunnel, proof.DNSBypassBlocked, err = verifier.dns.TunnelAndBypass(operationCtx, verifier.targets.DNSName); err != nil {
		return proof, probeFailed(operationCtx)
	}
	if !proof.DNSThroughTunnel || !proof.DNSBypassBlocked {
		return proof, nil
	}
	if proof.IPv4ThroughTunnel, err = verifier.connectivity.Reachable(operationCtx, TunnelInterface, verifier.targets.IPv4); err != nil {
		return proof, probeFailed(operationCtx)
	}
	if !proof.IPv4ThroughTunnel {
		return proof, nil
	}
	underlayReachable, err := verifier.connectivity.Reachable(operationCtx, UnderlayInterface, verifier.targets.IPv4)
	if err != nil {
		return proof, probeFailed(operationCtx)
	}
	proof.IPv4BypassBlocked = !underlayReachable
	if !proof.IPv4BypassBlocked {
		return proof, nil
	}
	if policy.RequireIPv6Tunnel {
		if proof.IPv6ThroughTunnel, err = verifier.connectivity.Reachable(operationCtx, TunnelInterface, verifier.targets.IPv6); err != nil {
			return proof, probeFailed(operationCtx)
		}
		if !proof.IPv6ThroughTunnel {
			return proof, nil
		}
	}
	underlayReachable, err = verifier.connectivity.Reachable(operationCtx, UnderlayInterface, verifier.targets.IPv6)
	if err != nil {
		return proof, probeFailed(operationCtx)
	}
	proof.IPv6BypassBlocked = !underlayReachable
	if !proof.IPv6BypassBlocked {
		return proof, nil
	}
	if policy.Role == session.RoleDownloader {
		proof.TorrentBound, err = verifier.torrent.Bound(operationCtx)
		if err != nil {
			return proof, probeFailed(operationCtx)
		}
	}
	return proof, nil
}

func (verifier *ControlledVerifier) effectiveTimeout() time.Duration {
	if verifier.timeout <= 0 || verifier.timeout > maximumVerificationDuration {
		return maximumVerificationDuration
	}
	return verifier.timeout
}

func probeFailed(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("bounded controlled VPN probe failed")
}

var _ Verifier = (*ControlledVerifier)(nil)
var _ fmt.Formatter = ProbeTargets{}
var _ json.Marshaler = ProbeTargets{}
var _ xml.Marshaler = ProbeTargets{}
