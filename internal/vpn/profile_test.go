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
	profile := mustParseProfile(t, validProfile(true, "198.51.100.20:51820"))
	defer profile.Destroy()

	inspection, err := profile.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if inspection.SchemaVersion != 1 || !inspection.IPv4Enabled || !inspection.IPv6Enabled ||
		inspection.InterfaceAddressCount != 2 || inspection.DNSServerCount != 2 {
		t.Fatalf("unexpected redacted inspection: %#v", inspection)
	}

	endpoint := ResolvedEndpoint{address: netip.MustParseAddr("198.51.100.20"), port: 51820}
	var rendered []byte
	err = profile.WithResolvedConfig(context.Background(), endpoint, func(_ context.Context, reader io.Reader) error {
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
		!bytes.Contains(rendered, []byte("Endpoint = 198.51.100.20:51820")) ||
		bytes.Contains(rendered, []byte("vpn.proton.test")) {
		t.Fatal("resolved rendering did not preserve the required fields or retained the hostname")
	}
}

func TestParseRejectsUnsafeProfiles(t *testing.T) {
	valid := validProfile(false, "vpn.proton.test:51820")
	cases := map[string]string{
		"pre-up hook":        strings.Replace(valid, "Address =", "PreUp = echo forbidden\nAddress =", 1),
		"post-up hook":       strings.Replace(valid, "Address =", "PostUp = echo forbidden\nAddress =", 1),
		"pre-down hook":      strings.Replace(valid, "Address =", "PreDown = echo forbidden\nAddress =", 1),
		"post-down hook":     strings.Replace(valid, "Address =", "PostDown = echo forbidden\nAddress =", 1),
		"duplicate field":    strings.Replace(valid, "DNS =", "DNS = 10.2.0.1\nDNS =", 1),
		"multiple peers":     valid + "\n[Peer]\nPublicKey = " + encodedKey(0x22) + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.proton.test:51820\n",
		"missing ipv4 route": strings.Replace(valid, "0.0.0.0/0", "::/0", 1),
		"partial route":      strings.Replace(valid, "0.0.0.0/0", "0.0.0.0/1", 1),
		"extra route":        strings.Replace(valid, "0.0.0.0/0", "0.0.0.0/0, 10.0.0.0/8", 1),
		"reversed routes":    strings.Replace(valid, "0.0.0.0/0", "::/0, 0.0.0.0/0", 1),
		"ipv6 no route": strings.Replace(
			strings.Replace(valid, "Address = 10.2.0.2/32", "Address = 10.2.0.2/32, 2001:db8::2/128", 1),
			"AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0", 1),
		"endpoint no port":   strings.Replace(valid, "vpn.proton.test:51820", "vpn.proton.test", 1),
		"private endpoint":   strings.Replace(valid, "vpn.proton.test:51820", "10.0.0.1:51820", 1),
		"unsafe dns":         strings.Replace(valid, "10.2.0.1", "127.0.0.1", 1),
		"mapped unsafe dns":  strings.Replace(valid, "10.2.0.1", "::ffff:127.0.0.1", 1),
		"dns hostname":       strings.Replace(valid, "10.2.0.1", "dns.proton.test", 1),
		"broad address":      strings.Replace(valid, "10.2.0.2/32", "10.2.0.2/24", 1),
		"unknown field":      strings.Replace(valid, "DNS =", "MTU = 1420\nDNS =", 1),
		"zero private key":   strings.Replace(valid, encodedKey(0x11), encodedKey(0), 1),
		"invalid public key": strings.Replace(valid, encodedKey(0x22), "not-a-wireguard-key", 1),
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
	tooManyLines := strings.Repeat("# synthetic\n", maximumProfileLines+1)
	if _, err := Parse(strings.NewReader(tooManyLines)); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("line-bounded Parse error = %v", err)
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
	profile, err := ParseSecret(source)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Destroy()

	for _, rendered := range []string{fmt.Sprint(profile), fmt.Sprintf("%#v", profile), profile.String(), profile.GoString()} {
		if rendered != redactedProfile {
			t.Fatalf("profile formatting was not redacted: %q", rendered)
		}
	}
	if _, err := json.Marshal(profile); !errors.Is(err, secret.ErrSerialization) {
		t.Fatalf("JSON marshal error = %v", err)
	}
	profile.Destroy()
	if _, err := profile.Inspect(); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("destroyed profile error = %v", err)
	}
	profile.Destroy()
}

func TestWithResolvedConfigCancellationAndCallbackFailure(t *testing.T) {
	profile := mustParseProfile(t, validProfile(false, "vpn.proton.test:51820"))
	defer profile.Destroy()
	endpoint := ResolvedEndpoint{address: netip.MustParseAddr("198.51.100.40"), port: 51820}

	want := errors.New("synthetic callback failure")
	if err := profile.WithResolvedConfig(context.Background(), endpoint, func(context.Context, io.Reader) error { return want }); !errors.Is(err, want) {
		t.Fatalf("callback error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := profile.WithResolvedConfig(ctx, endpoint, func(context.Context, io.Reader) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled render error = %v", err)
	}
	active, cancelActive := context.WithCancel(context.Background())
	if err := profile.WithResolvedConfig(active, endpoint, func(_ context.Context, reader io.Reader) error {
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
	if err := profile.WithResolvedConfig(context.Background(), endpoint, nil); !errors.Is(err, ErrCallbackRequired) {
		t.Fatalf("nil callback error = %v", err)
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
		address += ", 2001:db8::2/128"
		dns += ", 2001:4860:4860::8888"
		allowed += ", ::/0"
	}
	return "# synthetic test profile\n[Interface]\nPrivateKey = " + encodedKey(0x11) +
		"\nAddress = " + address + "\nDNS = " + dns + "\n\n[Peer]\nPublicKey = " + encodedKey(0x22) +
		"\nAllowedIPs = " + allowed + "\nEndpoint = " + endpoint + "\n"
}

func encodedKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func mustParseProfile(t *testing.T, input string) *Profile {
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
