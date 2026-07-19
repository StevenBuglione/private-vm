package guestvpn

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type staticOutputRunner struct {
	output []byte
	err    error
	path   string
	args   []string
}

func (runner *staticOutputRunner) Run(_ context.Context, path string, args ...string) ([]byte, error) {
	runner.path = path
	runner.args = slices.Clone(args)
	return slices.Clone(runner.output), runner.err
}

func handshakeLine(timestamp int64) []byte {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	return []byte(key + "\t" + strconv.FormatInt(timestamp, 10) + "\n")
}

func TestWireGuardHandshakeProbeUsesFixedBoundedCommandAndStrictTimestamp(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	runner := &staticOutputRunner{output: handshakeLine(now.Add(-time.Minute).Unix())}
	probe, err := newWireGuardHandshakeProbe("/run/current-system/sw/bin/wg", runner, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	recent, err := probe.Recent(context.Background())
	if err != nil || !recent || runner.path != "/run/current-system/sw/bin/wg" || !slices.Equal(runner.args, []string{"show", TunnelInterface, "latest-handshakes"}) {
		t.Fatalf("handshake = %v, %v, command=%s %v", recent, err, runner.path, runner.args)
	}
	for _, output := range [][]byte{
		handshakeLine(now.Add(-10 * time.Minute).Unix()),
		handshakeLine(now.Add(time.Minute).Unix()),
		[]byte("invalid\t123\n"),
		append(handshakeLine(now.Unix()), handshakeLine(now.Unix())...),
	} {
		runner.output = output
		if recent, err := probe.Recent(context.Background()); err != nil || recent {
			t.Fatalf("unsafe handshake passed: %q, %v, %v", output, recent, err)
		}
	}
}

func TestWireGuardHandshakeProbeBoundsAndRedactsCommandFailure(t *testing.T) {
	runner := &staticOutputRunner{err: errors.New("synthetic peer key output")}
	probe, err := newWireGuardHandshakeProbe("/nix/store/test/bin/wg", runner, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Recent(context.Background()); err == nil || strings.Contains(err.Error(), "peer key") {
		t.Fatalf("unsafe handshake error = %v", err)
	}
	if _, err := NewWireGuardHandshakeProbe("wg"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("relative wg path accepted: %v", err)
	}
}

func TestBoundTCPProbeDistinguishesBindingFailureAndReachability(t *testing.T) {
	var calls []string
	probe := newBoundTCPProbe(
		func(_ context.Context, name string, target netip.AddrPort) (bool, error) {
			calls = append(calls, name+"/"+target.Addr().String())
			return name == TunnelInterface, nil
		},
		func(name string) error {
			if name != TunnelInterface && name != UnderlayInterface {
				return errors.New("unexpected")
			}
			return nil
		},
	)
	target := netip.MustParseAddrPort("1.1.1.1:443")
	if reachable, err := probe.Reachable(context.Background(), TunnelInterface, target); err != nil || !reachable {
		t.Fatalf("tunnel reachability = %v, %v", reachable, err)
	}
	if reachable, err := probe.Reachable(context.Background(), UnderlayInterface, target); err != nil || reachable {
		t.Fatalf("underlay reachability = %v, %v", reachable, err)
	}
	probe.interfaceExists = func(string) error { return errors.New("missing") }
	if _, err := probe.Reachable(context.Background(), UnderlayInterface, target); err == nil {
		t.Fatal("missing interface was classified as blocked")
	}
	probe.interfaceExists = func(string) error { return nil }
	probe.dial = func(context.Context, string, netip.AddrPort) (bool, error) { return false, errBindToDevice }
	if _, err := probe.Reachable(context.Background(), UnderlayInterface, target); err == nil {
		t.Fatal("bind failure was classified as blocked")
	}
}
