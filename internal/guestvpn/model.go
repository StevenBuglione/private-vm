// Package guestvpn owns the fail-closed network state inside an online guest.
// It does not resolve endpoints and does not accept arbitrary interface names,
// routes, nftables rules, commands, or process arguments from the host.
package guestvpn

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/netip"

	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
)

const (
	UnderlayInterface = "eth0"
	TunnelInterface   = "proton0"
	redactedUnderlay  = "[REDACTED GUEST UNDERLAY]"
)

type State string

const (
	StateUnconfigured    State = "unconfigured"
	StateKillSwitchArmed State = "kill_switch_armed"
	StateConfigured      State = "configured"
	StateVerified        State = "verified"
	StateDegraded        State = "degraded"
	StateStopped         State = "stopped"
)

// RolePolicy preserves the four-role boundary. Scanner networking is valid
// only for the definitions-update boot. Exporter and scanner scan boots fail.
type RolePolicy struct {
	Role                  session.Role
	ScannerUpdate         bool
	RequireTorrentBinding bool
	RequireIPv6Tunnel     bool
}

func (policy RolePolicy) validate() error {
	switch policy.Role {
	case session.RoleWorkstation:
		return nil
	case session.RoleDownloader:
		if !policy.RequireTorrentBinding {
			return invalidRequest()
		}
		return nil
	case session.RoleScanner:
		if !policy.ScannerUpdate || policy.RequireTorrentBinding {
			return invalidRequest()
		}
		return nil
	default:
		return invalidRequest()
	}
}

// Underlay is the deterministic point-to-point address contract supplied by
// the host network owner. Its formatter and serializers are disabled because
// status and logs must not disclose session addresses.
type Underlay struct {
	IPv4Address netip.Prefix
	IPv4Gateway netip.Addr
	IPv6Address netip.Prefix
	IPv6Gateway netip.Addr
}

// NewUnderlay admits only the private point-to-point shape allocated by the
// host network owner. It keeps validation inside this package while allowing
// the authenticated RPC adapter to reconstruct the typed value.
func NewUnderlay(ipv4 netip.Prefix, ipv4Gateway netip.Addr, ipv6 netip.Prefix, ipv6Gateway netip.Addr) (Underlay, error) {
	underlay := Underlay{IPv4Address: ipv4, IPv4Gateway: ipv4Gateway, IPv6Address: ipv6, IPv6Gateway: ipv6Gateway}
	if err := underlay.validate(); err != nil {
		return Underlay{}, err
	}
	return underlay, nil
}

func (underlay Underlay) validate() error {
	if !underlay.IPv4Address.IsValid() || !underlay.IPv4Address.Addr().Is4() || underlay.IPv4Address.Bits() != 30 ||
		!underlay.IPv4Gateway.Is4() || !underlay.IPv4Address.Masked().Contains(underlay.IPv4Gateway) ||
		!underlay.IPv6Address.IsValid() || !underlay.IPv6Address.Addr().Is6() || underlay.IPv6Address.Bits() != 126 ||
		!underlay.IPv6Gateway.Is6() || !underlay.IPv6Address.Masked().Contains(underlay.IPv6Gateway) ||
		underlay.IPv4Address.Addr() == underlay.IPv4Gateway || underlay.IPv6Address.Addr() == underlay.IPv6Gateway {
		return invalidRequest()
	}
	return nil
}

func (Underlay) String() string   { return redactedUnderlay }
func (Underlay) GoString() string { return redactedUnderlay }
func (Underlay) Format(formatter fmt.State, _ rune) {
	_, _ = formatter.Write([]byte(redactedUnderlay))
}
func (Underlay) MarshalJSON() ([]byte, error)   { return nil, secret.ErrSerialization }
func (Underlay) MarshalText() ([]byte, error)   { return nil, secret.ErrSerialization }
func (Underlay) MarshalBinary() ([]byte, error) { return nil, secret.ErrSerialization }
func (Underlay) GobEncode() ([]byte, error)     { return nil, secret.ErrSerialization }
func (Underlay) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

// Proof contains only booleans. Probe targets, public IPs, DNS answers,
// interface addresses, endpoint values and command output never enter status.
type Proof struct {
	Handshake         bool
	DNSThroughTunnel  bool
	DNSBypassBlocked  bool
	IPv4ThroughTunnel bool
	IPv6ThroughTunnel bool
	IPv4BypassBlocked bool
	IPv6BypassBlocked bool
	TorrentBound      bool
}

type Status struct {
	SchemaVersion     int    `json:"schema_version"`
	State             State  `json:"state"`
	KillSwitchArmed   bool   `json:"kill_switch_armed"`
	Configured        bool   `json:"configured"`
	Handshake         bool   `json:"handshake"`
	DNSThroughTunnel  bool   `json:"dns_through_tunnel"`
	DNSBypassBlocked  bool   `json:"dns_bypass_blocked"`
	IPv4ThroughTunnel bool   `json:"ipv4_through_tunnel"`
	IPv6ThroughTunnel bool   `json:"ipv6_through_tunnel"`
	IPv4BypassBlocked bool   `json:"ipv4_bypass_blocked"`
	IPv6BypassBlocked bool   `json:"ipv6_bypass_blocked"`
	TorrentBound      bool   `json:"torrent_bound"`
	Code              string `json:"code"`
	Remediation       string `json:"remediation"`
}

var _ fmt.Formatter = Underlay{}
var _ json.Marshaler = Underlay{}
var _ xml.Marshaler = Underlay{}
