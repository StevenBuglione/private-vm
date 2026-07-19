package guestvpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/vpn"
)

type recordedCommand struct {
	path  string
	args  []string
	stdin []byte
}

type recordingRunner struct {
	mu       sync.Mutex
	commands []recordedCommand
	failAt   int
}

func (runner *recordingRunner) Run(_ context.Context, request commandRequest) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	var input []byte
	if request.stdin != nil {
		var err error
		input, err = io.ReadAll(io.LimitReader(request.stdin, guestCommandInputLimit+1))
		if err != nil {
			return err
		}
	}
	runner.commands = append(runner.commands, recordedCommand{path: request.path, args: slices.Clone(request.args), stdin: input})
	if runner.failAt > 0 && len(runner.commands) == runner.failAt {
		return errors.New("synthetic command failure with 1.1.1.1")
	}
	return nil
}

func (runner *recordingRunner) destroy() {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	for index := range runner.commands {
		clear(runner.commands[index].stdin)
		runner.commands[index].stdin = nil
	}
}

type fakeDNS struct {
	configured int
	cleared    int
	fail       bool
}

func (dns *fakeDNS) Configure(ctx context.Context, setup vpn.GuestSetup) error {
	dns.configured++
	if dns.fail {
		return errors.New("synthetic DNS failure")
	}
	count := 0
	if err := setup.DNSServers(ctx, func(netip.Addr) error { count++; return nil }); err != nil {
		return err
	}
	if count == 0 {
		return errors.New("missing DNS")
	}
	return nil
}

func (dns *fakeDNS) Clear(context.Context) error {
	dns.cleared++
	if dns.fail {
		return errors.New("synthetic DNS clear failure")
	}
	return nil
}

func testToolPaths() ToolPaths {
	return ToolPaths{IP: "/run/current-system/sw/bin/ip", NFT: "/run/current-system/sw/bin/nft", WG: "/run/current-system/sw/bin/wg"}
}

func withSetup(t *testing.T, fn func(vpn.GuestSetup) error) error {
	t.Helper()
	return testProfile(t, true).WithGuestSetup(context.Background(), func(_ context.Context, setup vpn.GuestSetup) error { return fn(setup) })
}

func TestKillSwitchPolicyAllowsOnlyTunnelEndpointAndNeighborDiscovery(t *testing.T) {
	err := withSetup(t, func(setup vpn.GuestSetup) error {
		rules, err := killSwitchRules(context.Background(), setup)
		if err != nil {
			return err
		}
		defer clear(rules)
		policy := string(rules)
		for _, required := range []string{
			"chain input", "chain output", "chain forward", "policy drop",
			"oifname \"proton0\" accept",
			"oifname \"eth0\" ip daddr 1.1.1.1 udp dport 51820 accept",
			"icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept",
		} {
			if !strings.Contains(policy, required) {
				t.Fatalf("kill switch lacks %q:\n%s", required, policy)
			}
		}
		for _, forbidden := range []string{"dport 53", " tcp ", "0.0.0.0/0", "::/0", "accept all"} {
			if strings.Contains(policy, forbidden) {
				t.Fatalf("kill switch contains unsafe rule %q", forbidden)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLinuxBackendUsesStdinAndFixedArgumentsInFailClosedOrder(t *testing.T) {
	runner, dns := &recordingRunner{}, &fakeDNS{}
	t.Cleanup(runner.destroy)
	backend, err := newLinuxBackend(testToolPaths(), dns, runner)
	if err != nil {
		t.Fatal(err)
	}
	err = withSetup(t, func(setup vpn.GuestSetup) error {
		if err := backend.ArmKillSwitch(context.Background(), setup); err != nil {
			return err
		}
		return backend.ConfigureTunnel(context.Background(), validUnderlay(), setup)
	})
	if err != nil {
		t.Fatal(err)
	}
	if dns.configured != 1 {
		t.Fatalf("DNS configure count = %d", dns.configured)
	}
	runner.mu.Lock()
	commands := append([]recordedCommand(nil), runner.commands...)
	runner.mu.Unlock()
	if len(commands) != 5 {
		t.Fatalf("command count = %d: %#v", len(commands), commands)
	}
	want := []string{"nft -f -", "ip -batch -", "ip link add proton0 type wireguard", "wg setconf proton0 /dev/stdin", "ip -batch -"}
	for index, command := range commands {
		got := filepathBase(command.path) + " " + strings.Join(command.args, " ")
		if got != want[index] {
			t.Fatalf("command %d = %q, want %q", index, got, want[index])
		}
		argv := strings.Join(command.args, " ")
		for _, private := range []string{"1.1.1.1", "10.2.0.2", "10.2.0.1", encodedKeyForTest(0x11)} {
			if strings.Contains(argv, private) {
				t.Fatalf("profile value %q escaped into argv %q", private, argv)
			}
		}
	}
	if !strings.Contains(string(commands[0].stdin), "1.1.1.1") || !strings.Contains(string(commands[3].stdin), "PrivateKey = ") {
		t.Fatal("profile data did not travel over the bounded stdin channels")
	}
	if err := backend.RemoveTunnel(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := backend.RemoveKillSwitch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := backend.RemoveTunnel(context.Background()); err != nil {
		t.Fatalf("idempotent tunnel removal = %v", err)
	}
	if err := backend.RemoveKillSwitch(context.Background()); err != nil {
		t.Fatalf("idempotent policy removal = %v", err)
	}
}

func TestLinuxBackendFailureAfterTunnelAllocationIsRetryable(t *testing.T) {
	for failAt := 1; failAt <= 5; failAt++ {
		t.Run(fmt.Sprintf("command_%d", failAt), func(t *testing.T) {
			runner, dns := &recordingRunner{failAt: failAt}, &fakeDNS{}
			t.Cleanup(runner.destroy)
			backend, err := newLinuxBackend(testToolPaths(), dns, runner)
			if err != nil {
				t.Fatal(err)
			}
			err = withSetup(t, func(setup vpn.GuestSetup) error {
				if armErr := backend.ArmKillSwitch(context.Background(), setup); armErr != nil {
					return armErr
				}
				return backend.ConfigureTunnel(context.Background(), validUnderlay(), setup)
			})
			if err == nil {
				t.Fatal("injected command failure unexpectedly passed")
			}
			if failAt == 1 {
				if backend.killArmed || backend.tunnel {
					t.Fatal("failed atomic policy was recorded as armed")
				}
				return
			}
			if !backend.killArmed {
				t.Fatal("configuration failure disarmed the kill switch")
			}
			if backend.tunnel {
				runner.failAt = 0
				if cleanupErr := backend.RemoveTunnel(context.Background()); cleanupErr != nil {
					t.Fatalf("retry cleanup = %v", cleanupErr)
				}
			}
		})
	}
}

func TestLinuxBackendToolPathsAndDNSBoundaryFailClosed(t *testing.T) {
	for _, paths := range []ToolPaths{
		{IP: "ip", NFT: testToolPaths().NFT, WG: testToolPaths().WG},
		{IP: "/nix/store/x/bin/not-ip", NFT: testToolPaths().NFT, WG: testToolPaths().WG},
		{IP: testToolPaths().IP, NFT: "nft", WG: testToolPaths().WG},
	} {
		if _, err := newLinuxBackend(paths, &fakeDNS{}, &recordingRunner{}); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("unsafe tool paths accepted: %#v, %v", paths, err)
		}
	}
	var typedNilDNS *fakeDNS
	if _, err := newLinuxBackend(testToolPaths(), typedNilDNS, &recordingRunner{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("typed nil DNS adapter accepted: %v", err)
	}
}

func filepathBase(path string) string {
	index := strings.LastIndexByte(path, '/')
	if index < 0 {
		return path
	}
	return path[index+1:]
}
