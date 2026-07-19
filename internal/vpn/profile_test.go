package vpn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/secret"
)

func TestParseAndRenderResolvedProfile(t *testing.T) {
	profile := mustParseProfile(t, validProfile(true, "1.1.1.1:51820"))
	defer profile.Destroy()

	inspection, err := profile.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if inspection.SchemaVersion != 1 || !inspection.IPv4Enabled || !inspection.IPv6Enabled ||
		inspection.InterfaceAddressCount != 2 || inspection.DNSServerCount != 2 {
		t.Fatalf("unexpected redacted inspection: %#v", inspection)
	}

	endpoint := resolvedEndpoint{address: netip.MustParseAddr("1.1.1.1"), port: 51820}
	var rendered []byte
	err = profile.withResolvedConfig(context.Background(), endpoint, func(_ context.Context, reader io.Reader) error {
		var readErr error
		rendered, readErr = io.ReadAll(reader)
		return readErr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rendered)
	privateEncoded := encodedKey(0x11)
	if !bytes.Contains(rendered, []byte("PrivateKey = "+privateEncoded)) ||
		!bytes.Contains(rendered, []byte("Endpoint = 1.1.1.1:51820")) ||
		bytes.Contains(rendered, []byte("vpn.proton.test")) {
		t.Fatal("resolved rendering did not preserve the required fields or retained the hostname")
	}
}

func TestParseRejectsUnsafeProfiles(t *testing.T) {
	valid := validProfile(false, "vpn.proton.test:51820")
	cases := map[string]string{
		"pre-up hook":            strings.Replace(valid, "Address =", "PreUp = echo forbidden\nAddress =", 1),
		"post-up hook":           strings.Replace(valid, "Address =", "PostUp = echo forbidden\nAddress =", 1),
		"pre-down hook":          strings.Replace(valid, "Address =", "PreDown = echo forbidden\nAddress =", 1),
		"post-down hook":         strings.Replace(valid, "Address =", "PostDown = echo forbidden\nAddress =", 1),
		"duplicate field":        strings.Replace(valid, "DNS =", "DNS = 10.2.0.1\nDNS =", 1),
		"multiple peers":         valid + "\n[Peer]\nPublicKey = " + encodedKey(0x22) + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.proton.test:51820\n",
		"missing ipv4 route":     strings.Replace(valid, "0.0.0.0/0", "::/0", 1),
		"partial route":          strings.Replace(valid, "0.0.0.0/0", "0.0.0.0/1", 1),
		"extra route":            strings.Replace(valid, "0.0.0.0/0", "0.0.0.0/0, 10.0.0.0/8", 1),
		"reversed routes":        strings.Replace(valid, "0.0.0.0/0", "::/0, 0.0.0.0/0", 1),
		"ipv6 no route":          strings.Replace(validProfile(true, "vpn.proton.test:51820"), "AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 0.0.0.0/0", 1),
		"endpoint no port":       strings.Replace(valid, "vpn.proton.test:51820", "vpn.proton.test", 1),
		"private endpoint":       strings.Replace(valid, "vpn.proton.test:51820", "10.0.0.1:51820", 1),
		"persistent keepalive":   strings.Replace(valid, "Endpoint =", "PersistentKeepalive = 25\nEndpoint =", 1),
		"duplicate interface":    strings.Replace(valid, "[Peer]", "[Interface]\n[Peer]", 1),
		"duplicate address":      strings.Replace(valid, "10.2.0.2/32", "10.2.0.2/32, 10.2.0.2/32", 1),
		"duplicate dns":          strings.Replace(valid, "10.2.0.1", "10.2.0.1, 10.2.0.1", 1),
		"unsafe dns":             strings.Replace(valid, "10.2.0.1", "127.0.0.1", 1),
		"mapped unsafe dns":      strings.Replace(valid, "10.2.0.1", "::ffff:127.0.0.1", 1),
		"mapped public dns":      strings.Replace(valid, "10.2.0.1", "::ffff:1.1.1.1", 1),
		"dns hostname":           strings.Replace(valid, "10.2.0.1", "dns.proton.test", 1),
		"broad address":          strings.Replace(valid, "10.2.0.2/32", "10.2.0.2/24", 1),
		"unknown field":          strings.Replace(valid, "DNS =", "MTU = 1420\nDNS =", 1),
		"zero private key":       strings.Replace(valid, encodedKey(0x11), encodedKey(0), 1),
		"invalid public key":     strings.Replace(valid, encodedKey(0x22), "not-a-wireguard-key", 1),
		"malformed key padding":  strings.Replace(valid, encodedKey(0x11), strings.TrimSuffix(encodedKey(0x11), "="), 1),
		"zoned endpoint":         strings.Replace(valid, "vpn.proton.test:51820", "[2606:4700:4700::1111%eth0]:51820", 1),
		"documentation endpoint": strings.Replace(valid, "vpn.proton.test:51820", "192.0.2.1:51820", 1),
		"mapped public endpoint": strings.Replace(valid, "vpn.proton.test:51820", "[::ffff:1.1.1.1]:51820", 1),
		"signed endpoint port":   strings.Replace(valid, "vpn.proton.test:51820", "vpn.proton.test:+51820", 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			profile, err := Parse(strings.NewReader(input))
			if profile != nil || !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("Parse() = %#v, %v; want redacted invalid-profile error", profile, err)
			}
			assertAppCode(t, err, "VPN_PROFILE_INVALID")
			if strings.Contains(err.Error(), encodedKey(0x11)) || strings.Contains(err.Error(), "vpn.proton.test") {
				t.Fatal("parse error disclosed profile data")
			}
		})
	}
}

func TestParseRejectsBoundsAndReadFailure(t *testing.T) {
	tooLarge := bytes.Repeat([]byte{'#'}, MaximumProfileBytes+1)
	if _, err := Parse(bytes.NewReader(tooLarge)); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("oversized Parse error = %v", err)
	}
	if _, err := Parse(errorReader{}); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("failed Parse error = %v", err)
	}
	if _, err := Parse(nil); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("nil Parse error = %v", err)
	}
	var typedNil *panicReader
	if _, err := Parse(typedNil); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("typed-nil Parse error = %v", err)
	}
	tooManyLines := strings.Repeat("# synthetic\n", maximumProfileLines+1)
	if _, err := Parse(strings.NewReader(tooManyLines)); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("line-bounded Parse error = %v", err)
	}
}

func TestParseUsesAndClearsOneCompletePreallocatedBuffer(t *testing.T) {
	retained := make([]byte, MaximumProfileBytes+1)
	original := allocateProfileBuffer
	allocateProfileBuffer = func() []byte { return retained }
	t.Cleanup(func() { allocateProfileBuffer = original })
	profile, err := Parse(strings.NewReader(validProfile(false, "vpn.proton.test:51820")))
	if err != nil {
		t.Fatal(err)
	}
	profile.Destroy()
	for index, value := range retained {
		if value != 0 {
			t.Fatalf("profile parsing allocation byte %d was not cleared", index)
		}
	}
}

func TestReviewedEndpointAndTunnelDNSAddressPolicies(t *testing.T) {
	public := []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"}
	for _, value := range public {
		if !publicEndpointAddress(netip.MustParseAddr(value)) {
			t.Fatalf("public endpoint rejected: %s", value)
		}
	}
	special := []string{
		"0.0.0.1", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1",
		"172.16.0.1", "192.0.0.1", "192.0.2.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.168.1.1", "192.175.48.1",
		"198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1",
		"::", "::1", "::ffff:1.1.1.1", "64:ff9b::101:101", "64:ff9b:1::1",
		"100::1", "100:0:0:1::1", "2001::1", "2001:db8::1", "2002::1", "2620:4f:8000::1", "3fff::1", "400::1", "5f00::1",
		"fd00::1", "fe80::1", "ff02::1", "fe80::1%eth0",
	}
	for _, value := range special {
		if publicEndpointAddress(netip.MustParseAddr(value)) {
			t.Fatalf("special-use endpoint accepted: %s", value)
		}
	}
	for _, value := range []string{"10.2.0.1", "fd00::1", "1.1.1.1"} {
		if !safeDNSAddress(netip.MustParseAddr(value)) {
			t.Fatalf("permitted tunnel DNS rejected: %s", value)
		}
	}
	for _, value := range []string{"100.64.0.1", "192.0.2.1", "2001:db8::1", "fe80::1%eth0"} {
		if safeDNSAddress(netip.MustParseAddr(value)) {
			t.Fatalf("unsafe tunnel DNS accepted: %s", value)
		}
	}
}

func TestParseSecretAndProfileRedaction(t *testing.T) {
	fixture := []byte(validProfile(false, "vpn.proton.test:51820"))
	source, err := secret.New(fixture)
	clear(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Destroy()
	parsedProfile, err := ParseSecret(source)
	if err != nil {
		t.Fatal(err)
	}
	defer parsedProfile.Destroy()

	value := parsedProfile.(profile)
	for _, subject := range []any{value, &value} {
		for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X"} {
			rendered := fmt.Sprintf(verb, subject)
			if rendered != redactedProfile {
				t.Fatalf("profile formatting %s was not redacted: %q", verb, rendered)
			}
		}
		if _, err := json.Marshal(subject); !errors.Is(err, secret.ErrSerialization) {
			t.Fatalf("JSON marshal error = %v", err)
		}
	}
	if _, err := value.MarshalText(); !errors.Is(err, secret.ErrSerialization) {
		t.Fatalf("text marshal error = %v", err)
	}
	if _, err := value.MarshalBinary(); !errors.Is(err, secret.ErrSerialization) {
		t.Fatalf("binary marshal error = %v", err)
	}
	parsedProfile.Destroy()
	if _, err := parsedProfile.Inspect(); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("destroyed profile error = %v", err)
	}
	parsedProfile.Destroy()
}

func TestWithResolvedConfigCancellationAndCallbackFailure(t *testing.T) {
	profile := mustParseProfile(t, validProfile(false, "vpn.proton.test:51820"))
	defer profile.Destroy()
	endpoint := resolvedEndpoint{address: netip.MustParseAddr("1.0.0.1"), port: 51820}

	want := errors.New("synthetic callback failure")
	if err := profile.withResolvedConfig(context.Background(), endpoint, func(context.Context, io.Reader) error { return want }); !errors.Is(err, want) {
		t.Fatalf("callback error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := profile.withResolvedConfig(ctx, endpoint, func(context.Context, io.Reader) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled render error = %v", err)
	}
	active, cancelActive := context.WithCancel(context.Background())
	if err := profile.withResolvedConfig(active, endpoint, func(_ context.Context, reader io.Reader) error {
		var first [1]byte
		if _, err := reader.Read(first[:]); err != nil {
			return err
		}
		cancelActive()
		_, err := reader.Read(first[:])
		return err
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-stream cancellation error = %v", err)
	}
	if err := profile.withResolvedConfig(context.Background(), endpoint, nil); !errors.Is(err, ErrCallbackRequired) {
		t.Fatalf("nil callback error = %v", err)
	}
}

func TestGuestSetupIsResolvedMinimalAndCallbackScoped(t *testing.T) {
	profile := mustParseProfile(t, validProfile(true, "1.1.1.1:51820"))
	defer profile.Destroy()

	var retained GuestSetup
	var endpoints int
	var addresses int
	var dnsServers int
	var wireGuard []byte
	err := profile.WithGuestSetup(context.Background(), func(ctx context.Context, setup GuestSetup) error {
		retained = setup
		if err := setup.Endpoint(ctx, func(address netip.Addr, port uint16) error {
			endpoints++
			if address != netip.MustParseAddr("1.1.1.1") || port != 51820 {
				t.Fatalf("unexpected endpoint callback: %v:%d", address, port)
			}
			return nil
		}); err != nil {
			return err
		}
		if err := setup.InterfaceAddresses(ctx, func(netip.Prefix) error { addresses++; return nil }); err != nil {
			return err
		}
		if err := setup.DNSServers(ctx, func(netip.Addr) error { dnsServers++; return nil }); err != nil {
			return err
		}
		return setup.WithWireGuardConfig(ctx, func(_ context.Context, reader io.Reader) error {
			var readErr error
			wireGuard, readErr = io.ReadAll(reader)
			return readErr
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wireGuard)
	if endpoints != 1 || addresses != 2 || dnsServers != 2 {
		t.Fatalf("guest setup counts = endpoint %d, addresses %d, DNS %d", endpoints, addresses, dnsServers)
	}
	for _, required := range []string{"[Interface]", "PrivateKey = " + encodedKey(0x11), "[Peer]", "PublicKey = " + encodedKey(0x22), "AllowedIPs = 0.0.0.0/0, ::/0", "Endpoint = 1.1.1.1:51820"} {
		if !bytes.Contains(wireGuard, []byte(required)) {
			t.Fatalf("minimal WireGuard config lacks %q", required)
		}
	}
	for _, forbidden := range []string{"Address =", "DNS =", "vpn.proton.test"} {
		if bytes.Contains(wireGuard, []byte(forbidden)) {
			t.Fatalf("minimal WireGuard config contains %q", forbidden)
		}
	}
	if err := retained.Endpoint(context.Background(), func(netip.Addr, uint16) error { return nil }); !errors.Is(err, ErrProfileRotated) {
		t.Fatalf("retained guest setup remained usable: %v", err)
	}
	if got := fmt.Sprintf("%+v", retained); got != redactedConfig {
		t.Fatalf("guest setup formatting was not redacted: %q", got)
	}
	if _, err := json.Marshal(retained); !errors.Is(err, secret.ErrSerialization) {
		t.Fatalf("guest setup JSON error = %v", err)
	}
}

func TestGuestSetupRejectsUnresolvedAndCanceledProfile(t *testing.T) {
	profile := mustParseProfile(t, validProfile(false, "vpn.proton.test:51820"))
	defer profile.Destroy()
	if err := profile.WithGuestSetup(context.Background(), func(context.Context, GuestSetup) error { return nil }); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("unresolved guest profile error = %v", err)
	}

	resolved := mustParseProfile(t, validProfile(false, "1.1.1.1:51820"))
	defer resolved.Destroy()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := resolved.WithGuestSetup(ctx, func(context.Context, GuestSetup) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled guest setup error = %v", err)
	}
}

func TestEndpointAndConfigReaderFormattingAreRedacted(t *testing.T) {
	endpointValue := endpoint{host: "vpn.proton.test.", port: 51820}
	resolvedValue := resolvedEndpoint{address: netip.MustParseAddr("1.1.1.1"), port: 51820}
	for _, subject := range []any{endpointValue, &endpointValue, resolvedValue, &resolvedValue} {
		for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X"} {
			if got := fmt.Sprintf(verb, subject); got != redactedEndpoint {
				t.Fatalf("endpoint formatting %s = %q", verb, got)
			}
		}
		if _, err := json.Marshal(subject); !errors.Is(err, secret.ErrSerialization) {
			t.Fatalf("endpoint JSON error = %v", err)
		}
	}

	parsed := mustParseProfile(t, validProfile(false, "vpn.proton.test:51820"))
	defer parsed.Destroy()
	err := parsed.withResolvedConfig(context.Background(), resolvedValue, func(_ context.Context, reader io.Reader) error {
		for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X"} {
			if got := fmt.Sprintf(verb, reader); got != redactedConfig {
				t.Fatalf("config-reader formatting %s = %q", verb, got)
			}
		}
		if _, err := json.Marshal(reader); !errors.Is(err, secret.ErrSerialization) {
			t.Fatalf("config-reader JSON error = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func FuzzWireGuardProfile(f *testing.F) {
	f.Add([]byte(validProfile(false, "vpn.proton.test:51820")))
	f.Add([]byte("[Interface]\nPrivateKey = redacted\n[Peer]\n"))
	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) > MaximumProfileBytes+1 {
			value = value[:MaximumProfileBytes+1]
		}
		profile, _ := Parse(bytes.NewReader(value))
		if profile != nil {
			profile.Destroy()
		}
	})
}

func validProfile(ipv6 bool, endpoint string) string {
	address := "10.2.0.2/32"
	dns := "10.2.0.1"
	allowed := "0.0.0.0/0"
	if ipv6 {
		address += ", fd00::2/128"
		dns += ", fd00::1"
		allowed += ", ::/0"
	}
	return "# synthetic test profile\n[Interface]\nPrivateKey = " + encodedKey(0x11) +
		"\nAddress = " + address + "\nDNS = " + dns + "\n\n[Peer]\nPublicKey = " + encodedKey(0x22) +
		"\nAllowedIPs = " + allowed + "\nEndpoint = " + endpoint + "\n"
}

func encodedKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func mustParseProfile(t *testing.T, input string) Profile {
	t.Helper()
	profile, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func assertAppCode(t *testing.T, err error, code string) {
	t.Helper()
	var app *apperror.Error
	if !errors.As(err, &app) || app.Code != code {
		t.Fatalf("error = %v; want application code %s", err, code)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic read failure with sensitive detail")
}

type panicReader struct{}

func (*panicReader) Read([]byte) (int, error) {
	panic("typed-nil reader was invoked")
}
