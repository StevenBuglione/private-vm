// Package vpn parses Proton WireGuard profiles and keeps them in bounded,
// explicitly destroyable volatile storage. It never persists a profile and it
// deliberately provides no string or JSON representation of secret-bearing
// values.
package vpn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

const (
	// MaximumProfileBytes is intentionally much smaller than the CLI secret
	// ceiling and includes comments and whitespace.
	MaximumProfileBytes = 64 << 10
	maximumProfileLines = 256
	maximumAddresses    = 8
	maximumDNSServers   = 8
	redactedProfile     = "[REDACTED VPN PROFILE]"
	redactedEndpoint    = "[REDACTED VPN ENDPOINT]"
	redactedConfig      = "[REDACTED VPN CONFIG READER]"
)

var allocateProfileBuffer = func() []byte { return make([]byte, MaximumProfileBytes+1) }

type section uint8

const (
	sectionNone section = iota
	sectionInterface
	sectionPeer
)

// Profile is the sealed, opaque parsed-profile contract. Its concrete state is
// package-private, so callers cannot dereference it and accidentally format
// endpoint, address, DNS or key fields.
type Profile interface {
	Inspect() (Inspection, error)
	WithGuestSetup(context.Context, func(context.Context, GuestSetup) error) error
	Destroy()
	privateVPNProfile()
	endpointSnapshot() (endpoint, error)
	withResolvedConfig(context.Context, resolvedEndpoint, func(context.Context, io.Reader) error) error
}

// GuestSetup is a callback-scoped view of the already resolved configuration
// received by a guest. It deliberately has no formatter or field access. The
// WireGuard key is available only through a bounded reader callback; endpoint,
// interface-address and DNS values are available only one item at a time.
// Retaining this view after Profile.WithGuestSetup returns is ineffective.
type GuestSetup interface {
	Endpoint(context.Context, func(netip.Addr, uint16) error) error
	InterfaceAddresses(context.Context, func(netip.Prefix) error) error
	DNSServers(context.Context, func(netip.Addr) error) error
	WithWireGuardConfig(context.Context, func(context.Context, io.Reader) error) error
	privateGuestSetup()
}

type guestSetup struct {
	state *profileState
	lease *planLease
}

// profile is a copy-safe handle to shared private state. Value and pointer
// formatting/serialization are both explicitly redacted or rejected.
type profile struct {
	state *profileState
}

type profileState struct {
	mu sync.Mutex

	privateKey *secret.Bytes
	addresses  []netip.Prefix
	dnsServers []netip.Addr
	publicKey  [32]byte
	allowedV6  bool
	endpoint   endpoint
	destroyed  bool
}

type endpoint struct {
	host    string
	literal netip.Addr
	port    uint16
}

// Inspection is the complete non-sensitive profile summary. Endpoint, keys,
// addresses, DNS values, and source paths are intentionally absent.
type Inspection struct {
	SchemaVersion         int  `json:"schema_version"`
	IPv4Enabled           bool `json:"ipv4_enabled"`
	IPv6Enabled           bool `json:"ipv6_enabled"`
	InterfaceAddressCount int  `json:"interface_address_count"`
	DNSServerCount        int  `json:"dns_server_count"`
}

// Parse reads one bounded profile and clears its private parsing buffer before
// returning. Callers own and must close or destroy the input source itself.
func Parse(reader io.Reader) (Profile, error) {
	if isNilLike(reader) {
		return nil, invalidProfile()
	}
	raw := allocateProfileBuffer()
	if len(raw) != MaximumProfileBytes+1 || cap(raw) != MaximumProfileBytes+1 {
		clear(raw)
		return nil, invalidProfile()
	}
	defer func() {
		clear(raw)
		runtime.KeepAlive(raw)
	}()
	used := 0
	emptyReads := 0
	for used < len(raw) {
		read, err := reader.Read(raw[used:])
		if read < 0 || read > len(raw)-used {
			return nil, invalidProfile()
		}
		used += read
		if err != nil {
			if err != io.EOF {
				return nil, invalidProfile()
			}
			break
		}
		if read == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return nil, invalidProfile()
			}
		} else {
			emptyReads = 0
		}
	}
	if used == 0 || used > MaximumProfileBytes {
		return nil, invalidProfile()
	}
	return parse(raw[:used])
}

// ParseSecret is the normal daemon import adapter. The source remains owned by
// the caller and should be destroyed immediately after this method returns.
func ParseSecret(source *secret.Bytes) (Profile, error) {
	if source == nil {
		return nil, invalidProfile()
	}
	var parsed Profile
	err := source.WithReader(func(reader io.Reader) error {
		var parseErr error
		parsed, parseErr = Parse(reader)
		return parseErr
	})
	if err != nil {
		if parsed != nil {
			parsed.Destroy()
		}
		return nil, invalidProfile()
	}
	return parsed, nil
}

func parse(raw []byte) (Profile, error) {
	if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return nil, invalidProfile()
	}
	fields := map[section]map[string][]byte{
		sectionInterface: {},
		sectionPeer:      {},
	}
	current := sectionNone
	seenInterface := false
	seenPeer := false
	lineCount := 0
	for len(raw) > 0 {
		lineCount++
		if lineCount > maximumProfileLines {
			return nil, invalidProfile()
		}
		line := raw
		if newline := bytes.IndexByte(raw, '\n'); newline >= 0 {
			line, raw = raw[:newline], raw[newline+1:]
		} else {
			raw = nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if hasUnsafeControl(line) {
			return nil, invalidProfile()
		}
		if line[0] == '[' {
			switch string(line) {
			case "[Interface]":
				if seenInterface || seenPeer {
					return nil, invalidProfile()
				}
				seenInterface, current = true, sectionInterface
			case "[Peer]":
				if !seenInterface || seenPeer {
					return nil, invalidProfile()
				}
				seenPeer, current = true, sectionPeer
			default:
				return nil, invalidProfile()
			}
			continue
		}
		if current == sectionNone || bytes.IndexByte(line, '=') <= 0 {
			return nil, invalidProfile()
		}
		separator := bytes.IndexByte(line, '=')
		name := string(bytes.TrimSpace(line[:separator]))
		value := bytes.TrimSpace(line[separator+1:])
		if len(value) == 0 || !allowedField(current, name) {
			return nil, invalidProfile()
		}
		if _, exists := fields[current][name]; exists {
			return nil, invalidProfile()
		}
		fields[current][name] = value
	}
	if !seenInterface || !seenPeer || !hasExactFields(fields[sectionInterface], "PrivateKey", "Address", "DNS") ||
		!hasExactFields(fields[sectionPeer], "PublicKey", "AllowedIPs", "Endpoint") {
		return nil, invalidProfile()
	}

	privateRaw, ok := decodeKey(fields[sectionInterface]["PrivateKey"])
	if !ok {
		return nil, invalidProfile()
	}
	privateKey, err := secret.New(privateRaw[:])
	clear(privateRaw[:])
	if err != nil {
		return nil, invalidProfile()
	}
	valid := false
	defer func() {
		if !valid {
			privateKey.Destroy()
		}
	}()

	addresses, hasV6Address, ok := parseAddresses(fields[sectionInterface]["Address"])
	if !ok {
		return nil, invalidProfile()
	}
	dnsServers, hasV6DNS, ok := parseDNS(fields[sectionInterface]["DNS"])
	if !ok {
		return nil, invalidProfile()
	}
	publicKey, ok := decodeKey(fields[sectionPeer]["PublicKey"])
	if !ok {
		return nil, invalidProfile()
	}
	allowedV6, ok := parseAllowedIPs(fields[sectionPeer]["AllowedIPs"])
	if !ok || (hasV6Address || hasV6DNS) && !allowedV6 {
		return nil, invalidProfile()
	}
	peerEndpoint, ok := parseEndpoint(fields[sectionPeer]["Endpoint"])
	if !ok {
		return nil, invalidProfile()
	}
	valid = true
	return profile{state: &profileState{
		privateKey: privateKey,
		addresses:  addresses,
		dnsServers: dnsServers,
		publicKey:  publicKey,
		allowedV6:  allowedV6,
		endpoint:   peerEndpoint,
	}}, nil
}

func allowedField(current section, name string) bool {
	switch current {
	case sectionInterface:
		return name == "PrivateKey" || name == "Address" || name == "DNS"
	case sectionPeer:
		return name == "PublicKey" || name == "AllowedIPs" || name == "Endpoint"
	default:
		return false
	}
}

func hasExactFields(fields map[string][]byte, names ...string) bool {
	if len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if len(fields[name]) == 0 {
			return false
		}
	}
	return true
}

func hasUnsafeControl(value []byte) bool {
	for _, character := range value {
		if character < 0x20 && character != '\t' || character == 0x7f {
			return true
		}
	}
	return false
}

func decodeKey(value []byte) ([32]byte, bool) {
	var decoded [32]byte
	if len(value) != base64.StdEncoding.EncodedLen(len(decoded)) {
		return decoded, false
	}
	written, err := base64.StdEncoding.Strict().Decode(decoded[:], value)
	if err != nil || written != len(decoded) || allZero(decoded[:]) {
		clear(decoded[:])
		return decoded, false
	}
	return decoded, true
}

func allZero(value []byte) bool {
	var combined byte
	for _, character := range value {
		combined |= character
	}
	return combined == 0
}

func splitCSV(value []byte, maximum int) ([][]byte, bool) {
	parts := bytes.Split(value, []byte{','})
	if len(parts) == 0 || len(parts) > maximum {
		return nil, false
	}
	for index := range parts {
		parts[index] = bytes.TrimSpace(parts[index])
		if len(parts[index]) == 0 {
			return nil, false
		}
	}
	return parts, true
}

func parseAddresses(value []byte) ([]netip.Prefix, bool, bool) {
	parts, ok := splitCSV(value, maximumAddresses)
	if !ok {
		return nil, false, false
	}
	addresses := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	hasV4, hasV6 := false, false
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(string(part))
		if err != nil || !safeInterfaceAddress(prefix) {
			return nil, false, false
		}
		if _, duplicate := seen[prefix]; duplicate {
			return nil, false, false
		}
		seen[prefix] = struct{}{}
		addresses = append(addresses, prefix)
		if prefix.Addr().Is4() {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}
	if !hasV4 {
		return nil, false, false
	}
	return addresses, hasV6, true
}

func safeInterfaceAddress(prefix netip.Prefix) bool {
	address := prefix.Addr()
	if !prefix.IsValid() || !safeTunnelAddress(address) {
		return false
	}
	if address.Is4() {
		return prefix.Bits() == 32
	}
	return address.Is6() && prefix.Bits() == 128
}

func parseDNS(value []byte) ([]netip.Addr, bool, bool) {
	parts, ok := splitCSV(value, maximumDNSServers)
	if !ok {
		return nil, false, false
	}
	servers := make([]netip.Addr, 0, len(parts))
	seen := make(map[netip.Addr]struct{}, len(parts))
	hasV6 := false
	for _, part := range parts {
		address, err := netip.ParseAddr(string(part))
		if err != nil || address.Is4In6() {
			return nil, false, false
		}
		if !safeDNSAddress(address) {
			return nil, false, false
		}
		if _, duplicate := seen[address]; duplicate {
			return nil, false, false
		}
		seen[address] = struct{}{}
		servers = append(servers, address)
		hasV6 = hasV6 || address.Is6()
	}
	return servers, hasV6, true
}

func safeDNSAddress(address netip.Addr) bool {
	return safeTunnelAddress(address)
}

// safeTunnelAddress is deliberately different from endpoint policy. Proton's
// in-tunnel interface and DNS addresses may be RFC1918 or ULA. Every other
// address must satisfy the reviewed public-routability policy; CGNAT,
// documentation, benchmark, link-local and other special-use ranges remain
// forbidden.
func safeTunnelAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() {
		return false
	}
	return address.IsPrivate() || publicEndpointAddress(address)
}

func parseAllowedIPs(value []byte) (bool, bool) {
	parts, ok := splitCSV(value, 2)
	if !ok {
		return false, false
	}
	first, err := netip.ParsePrefix(string(parts[0]))
	if err != nil || first != netip.MustParsePrefix("0.0.0.0/0") {
		return false, false
	}
	if len(parts) == 1 {
		return false, true
	}
	second, err := netip.ParsePrefix(string(parts[1]))
	if err != nil || second != netip.MustParsePrefix("::/0") {
		return false, false
	}
	return true, true
}

func parseEndpoint(value []byte) (endpoint, bool) {
	if len(value) > 512 {
		return endpoint{}, false
	}
	host, portText, err := net.SplitHostPort(string(value))
	if err != nil || host == "" {
		return endpoint{}, false
	}
	for _, character := range portText {
		if character < '0' || character > '9' {
			return endpoint{}, false
		}
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return endpoint{}, false
	}
	if literal, err := netip.ParseAddr(host); err == nil {
		if literal.Is4In6() {
			return endpoint{}, false
		}
		if !publicEndpointAddress(literal) {
			return endpoint{}, false
		}
		return endpoint{literal: literal, port: uint16(port)}, true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !safeEndpointHostname(host) {
		return endpoint{}, false
	}
	return endpoint{host: host + ".", port: uint16(port)}, true
}

func safeEndpointHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character < 'a' || character > 'z' {
				if character < '0' || character > '9' {
					if character != '-' {
						return false
					}
				}
			}
		}
	}
	return true
}

var forbiddenPublicEndpointPrefixes = []netip.Prefix{
	// IANA IPv4 special-purpose, non-routable, documentation, benchmark,
	// multicast and reserved ranges. Reject the complete containing range even
	// where IANA lists a narrow protocol exception: Proton endpoints must be
	// ordinary public unicast addresses.
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// IPv6 unspecified/loopback, translation/local/discard, IETF protocol,
	// documentation, 6to4, ULA, link-local, multicast and reserved examples.
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

var allocatedIPv6GlobalUnicast = netip.MustParsePrefix("2000::/3")

func publicEndpointAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() {
		return false
	}
	if address.Is6() && !allocatedIPv6GlobalUnicast.Contains(address) {
		return false
	}
	for _, prefix := range forbiddenPublicEndpointPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// Inspect returns only aggregate, non-sensitive properties.
func (p profile) Inspect() (Inspection, error) {
	if p.state == nil {
		return Inspection{}, invalidProfile()
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.destroyed {
		return Inspection{}, invalidProfile()
	}
	return Inspection{
		SchemaVersion:         1,
		IPv4Enabled:           true,
		IPv6Enabled:           p.state.allowedV6,
		InterfaceAddressCount: len(p.state.addresses),
		DNSServerCount:        len(p.state.dnsServers),
	}, nil
}

// Destroy erases the private key and clears all owned profile fields. It is
// idempotent and blocks until an active rendering callback has returned.
func (p profile) Destroy() {
	if p.state == nil {
		return
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.destroyed {
		return
	}
	p.state.privateKey.Destroy()
	p.state.privateKey = nil
	clear(p.state.publicKey[:])
	clear(p.state.addresses)
	clear(p.state.dnsServers)
	p.state.addresses = nil
	p.state.dnsServers = nil
	p.state.endpoint = endpoint{}
	p.state.destroyed = true
}

func (p profile) endpointSnapshot() (endpoint, error) {
	if p.state == nil {
		return endpoint{}, invalidProfile()
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.destroyed {
		return endpoint{}, invalidProfile()
	}
	return p.state.endpoint, nil
}

// WithGuestSetup exposes the minimum resolved values needed by the guest's
// typed network controller. The profile lock remains held for the callback so
// Destroy cannot race a configuration handoff. A lease makes a retained view
// unusable as soon as the callback returns.
func (p profile) WithGuestSetup(ctx context.Context, fn func(context.Context, GuestSetup) error) error {
	if ctx == nil || fn == nil {
		return ErrCallbackRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.state == nil {
		return invalidProfile()
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.destroyed || !p.state.endpoint.literal.IsValid() || !publicEndpointAddress(p.state.endpoint.literal) {
		return invalidProfile()
	}
	lease := newPlanLease()
	defer lease.close()
	return fn(ctx, guestSetup{state: p.state, lease: lease})
}

func (guestSetup) privateGuestSetup() {}

func (setup guestSetup) Endpoint(ctx context.Context, fn func(netip.Addr, uint16) error) error {
	if ctx == nil || fn == nil || setup.state == nil {
		return ErrCallbackRequired
	}
	return setup.lease.use(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn(setup.state.endpoint.literal, setup.state.endpoint.port)
	})
}

func (setup guestSetup) InterfaceAddresses(ctx context.Context, fn func(netip.Prefix) error) error {
	if ctx == nil || fn == nil || setup.state == nil {
		return ErrCallbackRequired
	}
	return setup.lease.use(func() error {
		for _, address := range setup.state.addresses {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := fn(address); err != nil {
				return err
			}
		}
		return nil
	})
}

func (setup guestSetup) DNSServers(ctx context.Context, fn func(netip.Addr) error) error {
	if ctx == nil || fn == nil || setup.state == nil {
		return ErrCallbackRequired
	}
	return setup.lease.use(func() error {
		for _, address := range setup.state.dnsServers {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := fn(address); err != nil {
				return err
			}
		}
		return nil
	})
}

func (setup guestSetup) WithWireGuardConfig(ctx context.Context, fn func(context.Context, io.Reader) error) error {
	if ctx == nil || fn == nil || setup.state == nil {
		return ErrCallbackRequired
	}
	return setup.lease.use(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		backing := make([]byte, MaximumProfileBytes)
		buffer := bytes.NewBuffer(backing[:0])
		defer func() {
			clear(backing)
			runtime.KeepAlive(buffer)
			runtime.KeepAlive(backing)
		}()
		_, _ = buffer.WriteString("[Interface]\nPrivateKey = ")
		if err := writePrivateKey(buffer, setup.state.privateKey); err != nil {
			return invalidProfile()
		}
		_, _ = buffer.WriteString("\n\n[Peer]\nPublicKey = ")
		writePublicKey(buffer, setup.state.publicKey)
		_, _ = buffer.WriteString("\nAllowedIPs = 0.0.0.0/0")
		if setup.state.allowedV6 {
			_, _ = buffer.WriteString(", ::/0")
		}
		_, _ = buffer.WriteString("\nEndpoint = ")
		writeEndpoint(buffer, setup.state.endpoint.literal, setup.state.endpoint.port)
		_ = buffer.WriteByte('\n')
		if buffer.Len() > MaximumProfileBytes {
			return invalidProfile()
		}
		return fn(ctx, &contextReader{ctx: ctx, reader: bytes.NewReader(buffer.Bytes())})
	})
}

func (guestSetup) String() string   { return redactedConfig }
func (guestSetup) GoString() string { return redactedConfig }
func (guestSetup) Format(formatter fmt.State, _ rune) {
	_, _ = formatter.Write([]byte(redactedConfig))
}
func (guestSetup) MarshalJSON() ([]byte, error)   { return nil, secret.ErrSerialization }
func (guestSetup) MarshalText() ([]byte, error)   { return nil, secret.ErrSerialization }
func (guestSetup) MarshalBinary() ([]byte, error) { return nil, secret.ErrSerialization }
func (guestSetup) GobEncode() ([]byte, error)     { return nil, secret.ErrSerialization }
func (guestSetup) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

func writePrivateKey(destination *bytes.Buffer, privateKey *secret.Bytes) error {
	return privateKey.WithReader(func(reader io.Reader) error {
		var raw [32]byte
		defer clear(raw[:])
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return err
		}
		var encoded [44]byte
		defer clear(encoded[:])
		base64.StdEncoding.Encode(encoded[:], raw[:])
		_, err := destination.Write(encoded[:])
		return err
	})
}

func writePublicKey(destination *bytes.Buffer, publicKey [32]byte) {
	var encoded [44]byte
	defer clear(encoded[:])
	base64.StdEncoding.Encode(encoded[:], publicKey[:])
	_, _ = destination.Write(encoded[:])
}

func writeEndpoint(destination *bytes.Buffer, address netip.Addr, port uint16) {
	if address.Is6() {
		_ = destination.WriteByte('[')
	}
	_, _ = destination.Write(address.AppendTo(nil))
	if address.Is6() {
		_ = destination.WriteByte(']')
	}
	_ = destination.WriteByte(':')
	_, _ = destination.Write(strconv.AppendUint(nil, uint64(port), 10))
}

// WithResolvedConfig constructs the guest's ephemeral WireGuard configuration
// only for the duration of fn. The key is encoded into a byte buffer, never a
// Go string; the buffer is cleared immediately after the callback. Callbacks
// are trusted, bounded adapters and must honor ctx.
func (p profile) withResolvedConfig(ctx context.Context, resolved resolvedEndpoint, fn func(context.Context, io.Reader) error) error {
	if ctx == nil || fn == nil {
		return ErrCallbackRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.state == nil || !resolved.valid() {
		return invalidProfile()
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.destroyed || p.state.endpoint.port != resolved.port {
		return invalidProfile()
	}

	backing := make([]byte, MaximumProfileBytes)
	buffer := bytes.NewBuffer(backing[:0])
	defer func() {
		clear(backing)
		runtime.KeepAlive(buffer)
		runtime.KeepAlive(backing)
	}()
	_, _ = buffer.WriteString("[Interface]\nPrivateKey = ")
	err := writePrivateKey(buffer, p.state.privateKey)
	if err != nil {
		return invalidProfile()
	}
	_, _ = buffer.WriteString("\nAddress = ")
	writePrefixes(buffer, p.state.addresses)
	_, _ = buffer.WriteString("\nDNS = ")
	writeAddresses(buffer, p.state.dnsServers)
	_, _ = buffer.WriteString("\n\n[Peer]\nPublicKey = ")
	writePublicKey(buffer, p.state.publicKey)
	_, _ = buffer.WriteString("\nAllowedIPs = 0.0.0.0/0")
	if p.state.allowedV6 {
		_, _ = buffer.WriteString(", ::/0")
	}
	_, _ = buffer.WriteString("\nEndpoint = ")
	writeEndpoint(buffer, resolved.address, resolved.port)
	_ = buffer.WriteByte('\n')
	if buffer.Len() > MaximumProfileBytes {
		return invalidProfile()
	}
	return fn(ctx, &contextReader{ctx: ctx, reader: bytes.NewReader(buffer.Bytes())})
}

func writePrefixes(destination *bytes.Buffer, values []netip.Prefix) {
	for index, value := range values {
		if index != 0 {
			_, _ = destination.WriteString(", ")
		}
		_, _ = destination.Write(value.AppendTo(nil))
	}
}

func writeAddresses(destination *bytes.Buffer, values []netip.Addr) {
	for index, value := range values {
		if index != 0 {
			_, _ = destination.WriteString(", ")
		}
		_, _ = destination.Write(value.AppendTo(nil))
	}
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (contextReader) String() string   { return redactedConfig }
func (contextReader) GoString() string { return redactedConfig }
func (contextReader) Format(formatter fmt.State, _ rune) {
	_, _ = formatter.Write([]byte(redactedConfig))
}
func (contextReader) MarshalJSON() ([]byte, error)   { return nil, secret.ErrSerialization }
func (contextReader) MarshalText() ([]byte, error)   { return nil, secret.ErrSerialization }
func (contextReader) MarshalBinary() ([]byte, error) { return nil, secret.ErrSerialization }
func (contextReader) GobEncode() ([]byte, error)     { return nil, secret.ErrSerialization }
func (contextReader) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

func (r *contextReader) Read(destination []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(destination)
}

func (profile) privateVPNProfile() {}
func (profile) String() string     { return redactedProfile }
func (profile) GoString() string   { return redactedProfile }
func (profile) Format(formatter fmt.State, _ rune) {
	_, _ = formatter.Write([]byte(redactedProfile))
}
func (profile) MarshalJSON() ([]byte, error) { return nil, secret.ErrSerialization }
func (profile) MarshalText() ([]byte, error) { return nil, secret.ErrSerialization }
func (profile) MarshalBinary() ([]byte, error) {
	return nil, secret.ErrSerialization
}
func (profile) GobEncode() ([]byte, error) { return nil, secret.ErrSerialization }
func (profile) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

type resolvedEndpoint struct {
	address netip.Addr
	port    uint16
}

func (endpoint) String() string   { return redactedEndpoint }
func (endpoint) GoString() string { return redactedEndpoint }
func (endpoint) Format(formatter fmt.State, _ rune) {
	_, _ = formatter.Write([]byte(redactedEndpoint))
}
func (endpoint) MarshalJSON() ([]byte, error)   { return nil, secret.ErrSerialization }
func (endpoint) MarshalText() ([]byte, error)   { return nil, secret.ErrSerialization }
func (endpoint) MarshalBinary() ([]byte, error) { return nil, secret.ErrSerialization }
func (endpoint) GobEncode() ([]byte, error)     { return nil, secret.ErrSerialization }
func (endpoint) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

func (resolvedEndpoint) String() string   { return redactedEndpoint }
func (resolvedEndpoint) GoString() string { return redactedEndpoint }
func (resolvedEndpoint) Format(formatter fmt.State, _ rune) {
	_, _ = formatter.Write([]byte(redactedEndpoint))
}
func (resolvedEndpoint) MarshalJSON() ([]byte, error)   { return nil, secret.ErrSerialization }
func (resolvedEndpoint) MarshalText() ([]byte, error)   { return nil, secret.ErrSerialization }
func (resolvedEndpoint) MarshalBinary() ([]byte, error) { return nil, secret.ErrSerialization }
func (resolvedEndpoint) GobEncode() ([]byte, error)     { return nil, secret.ErrSerialization }
func (resolvedEndpoint) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

func (e resolvedEndpoint) valid() bool { return publicEndpointAddress(e.address) && e.port != 0 }

func sortEndpoints(endpoints []resolvedEndpoint) {
	sort.Slice(endpoints, func(left, right int) bool {
		return endpoints[left].address.Compare(endpoints[right].address) < 0
	})
}

func isNilLike(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var (
	_ Profile        = profile{}
	_ fmt.Formatter  = profile{}
	_ json.Marshaler = profile{}
	_ xml.Marshaler  = profile{}
	_ fmt.Formatter  = endpoint{}
	_ json.Marshaler = endpoint{}
	_ xml.Marshaler  = endpoint{}
	_ fmt.Formatter  = resolvedEndpoint{}
	_ json.Marshaler = resolvedEndpoint{}
	_ xml.Marshaler  = resolvedEndpoint{}
	_ fmt.Formatter  = contextReader{}
	_ json.Marshaler = contextReader{}
	_ xml.Marshaler  = contextReader{}
)
