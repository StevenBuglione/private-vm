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
)

type section uint8

const (
	sectionNone section = iota
	sectionInterface
	sectionPeer
)

// Profile is an immutable parsed profile. Destroy invalidates all future use
// and destroys the protected private-key mapping. A Profile must not be copied.
type Profile struct {
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
func Parse(reader io.Reader) (*Profile, error) {
	if reader == nil {
		return nil, invalidProfile()
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaximumProfileBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > MaximumProfileBytes {
		clear(raw)
		return nil, invalidProfile()
	}
	defer func() {
		clear(raw)
		runtime.KeepAlive(raw)
	}()
	return parse(raw)
}

// ParseSecret is the normal daemon import adapter. The source remains owned by
// the caller and should be destroyed immediately after this method returns.
func ParseSecret(source *secret.Bytes) (*Profile, error) {
	if source == nil {
		return nil, invalidProfile()
	}
	var profile *Profile
	err := source.WithReader(func(reader io.Reader) error {
		var parseErr error
		profile, parseErr = Parse(reader)
		return parseErr
	})
	if err != nil {
		if profile != nil {
			profile.Destroy()
		}
		return nil, invalidProfile()
	}
	return profile, nil
}

func parse(raw []byte) (*Profile, error) {
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
	return &Profile{
		privateKey: privateKey,
		addresses:  addresses,
		dnsServers: dnsServers,
		publicKey:  publicKey,
		allowedV6:  allowedV6,
		endpoint:   peerEndpoint,
	}, nil
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
	if !prefix.IsValid() || address.Is4In6() || address.IsUnspecified() || address.IsLoopback() ||
		address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
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
		if err != nil {
			return nil, false, false
		}
		address = address.Unmap()
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
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsLoopback() &&
		!address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast()
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
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return endpoint{}, false
	}
	if literal, err := netip.ParseAddr(host); err == nil {
		literal = literal.Unmap()
		if !safeEndpointAddress(literal) {
			return endpoint{}, false
		}
		return endpoint{literal: literal, port: uint16(port)}, true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !safeEndpointHostname(host) {
		return endpoint{}, false
	}
	return endpoint{host: host, port: uint16(port)}, true
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

func safeEndpointAddress(address netip.Addr) bool {
	return address.IsValid() && address.IsGlobalUnicast() && !address.IsPrivate() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast()
}

// Inspect returns only aggregate, non-sensitive properties.
func (p *Profile) Inspect() (Inspection, error) {
	if p == nil {
		return Inspection{}, invalidProfile()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.destroyed {
		return Inspection{}, invalidProfile()
	}
	return Inspection{
		SchemaVersion:         1,
		IPv4Enabled:           true,
		IPv6Enabled:           p.allowedV6,
		InterfaceAddressCount: len(p.addresses),
		DNSServerCount:        len(p.dnsServers),
	}, nil
}

// Destroy erases the private key and clears all owned profile fields. It is
// idempotent and blocks until an active rendering callback has returned.
func (p *Profile) Destroy() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.destroyed {
		return
	}
	p.privateKey.Destroy()
	p.privateKey = nil
	clear(p.publicKey[:])
	p.addresses = nil
	p.dnsServers = nil
	p.endpoint = endpoint{}
	p.destroyed = true
}

func (p *Profile) endpointSnapshot() (endpoint, error) {
	if p == nil {
		return endpoint{}, invalidProfile()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.destroyed {
		return endpoint{}, invalidProfile()
	}
	return p.endpoint, nil
}

// WithResolvedConfig constructs the guest's ephemeral WireGuard configuration
// only for the duration of fn. The key is encoded into a byte buffer, never a
// Go string; the buffer is cleared immediately after the callback. Callbacks
// are trusted, bounded adapters and must honor ctx.
func (p *Profile) WithResolvedConfig(ctx context.Context, resolved ResolvedEndpoint, fn func(context.Context, io.Reader) error) error {
	if ctx == nil || fn == nil {
		return ErrCallbackRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil || !resolved.valid() {
		return invalidProfile()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.destroyed || p.endpoint.port != resolved.port {
		return invalidProfile()
	}

	buffer := bytes.NewBuffer(make([]byte, 0, 1024))
	defer func() {
		clear(buffer.Bytes())
		runtime.KeepAlive(buffer)
	}()
	_, _ = buffer.WriteString("[Interface]\nPrivateKey = ")
	err := p.privateKey.WithReader(func(reader io.Reader) error {
		var raw [32]byte
		defer clear(raw[:])
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return err
		}
		var encoded [44]byte
		defer clear(encoded[:])
		base64.StdEncoding.Encode(encoded[:], raw[:])
		_, err := buffer.Write(encoded[:])
		return err
	})
	if err != nil {
		return invalidProfile()
	}
	_, _ = buffer.WriteString("\nAddress = ")
	writePrefixes(buffer, p.addresses)
	_, _ = buffer.WriteString("\nDNS = ")
	writeAddresses(buffer, p.dnsServers)
	_, _ = buffer.WriteString("\n\n[Peer]\nPublicKey = ")
	var publicEncoded [44]byte
	base64.StdEncoding.Encode(publicEncoded[:], p.publicKey[:])
	_, _ = buffer.Write(publicEncoded[:])
	clear(publicEncoded[:])
	_, _ = buffer.WriteString("\nAllowedIPs = 0.0.0.0/0")
	if p.allowedV6 {
		_, _ = buffer.WriteString(", ::/0")
	}
	_, _ = buffer.WriteString("\nEndpoint = ")
	if resolved.address.Is6() {
		_ = buffer.WriteByte('[')
	}
	_, _ = buffer.Write(resolved.address.AppendTo(nil))
	if resolved.address.Is6() {
		_ = buffer.WriteByte(']')
	}
	_ = buffer.WriteByte(':')
	_, _ = buffer.Write(strconv.AppendUint(nil, uint64(resolved.port), 10))
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

func (r *contextReader) Read(destination []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(destination)
}

func (*Profile) String() string   { return redactedProfile }
func (*Profile) GoString() string { return redactedProfile }
func (*Profile) Format(formatter fmt.State, _ rune) {
	_, _ = formatter.Write([]byte(redactedProfile))
}
func (*Profile) MarshalJSON() ([]byte, error) { return nil, secret.ErrSerialization }
func (*Profile) MarshalText() ([]byte, error) { return nil, secret.ErrSerialization }
func (*Profile) MarshalBinary() ([]byte, error) {
	return nil, secret.ErrSerialization
}
func (*Profile) GobEncode() ([]byte, error) { return nil, secret.ErrSerialization }
func (*Profile) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

// ResolvedEndpoint is an internal network-policy input. Its fields are private,
// its formatting is redacted, and serialization is rejected so it cannot enter
// CLI records or logs accidentally.
type ResolvedEndpoint struct {
	address netip.Addr
	port    uint16
}

func (e ResolvedEndpoint) Address() netip.Addr { return e.address }
func (e ResolvedEndpoint) Port() uint16        { return e.port }
func (e ResolvedEndpoint) valid() bool         { return safeEndpointAddress(e.address) && e.port != 0 }
func (ResolvedEndpoint) String() string        { return "[REDACTED VPN ENDPOINT]" }
func (ResolvedEndpoint) GoString() string      { return "[REDACTED VPN ENDPOINT]" }
func (ResolvedEndpoint) MarshalJSON() ([]byte, error) {
	return nil, secret.ErrSerialization
}
func (ResolvedEndpoint) MarshalText() ([]byte, error) { return nil, secret.ErrSerialization }

func sortEndpoints(endpoints []ResolvedEndpoint) {
	sort.Slice(endpoints, func(left, right int) bool {
		return endpoints[left].address.Compare(endpoints[right].address) < 0
	})
}

var (
	_ fmt.Formatter  = (*Profile)(nil)
	_ json.Marshaler = (*Profile)(nil)
	_ xml.Marshaler  = (*Profile)(nil)
	_ json.Marshaler = ResolvedEndpoint{}
)
