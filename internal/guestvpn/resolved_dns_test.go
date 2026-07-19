package guestvpn

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/vpn"
)

type resolvedCall struct {
	method string
	args   []any
}

type fakeResolvedConnection struct {
	mu       sync.Mutex
	calls    []resolvedCall
	failAt   int
	closed   bool
	block    bool
	retained []resolvedDNSAddress
	copyDNS  []resolvedDNSAddress
}

func (connection *fakeResolvedConnection) Call(ctx context.Context, method string, args ...any) error {
	connection.mu.Lock()
	connection.calls = append(connection.calls, resolvedCall{method: method, args: append([]any(nil), args...)})
	index := len(connection.calls)
	if method == resolvedManager+".SetLinkDNS" {
		addresses, ok := args[1].([]resolvedDNSAddress)
		if !ok {
			connection.mu.Unlock()
			return errors.New("wrong DNS signature")
		}
		connection.retained = append([]resolvedDNSAddress(nil), addresses...)
		connection.copyDNS = make([]resolvedDNSAddress, len(addresses))
		for position := range addresses {
			connection.copyDNS[position] = resolvedDNSAddress{Family: addresses[position].Family, Address: slices.Clone(addresses[position].Address)}
		}
	}
	fail := connection.failAt > 0 && index == connection.failAt
	block := connection.block
	connection.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	if fail {
		return errors.New("synthetic D-Bus error with 10.2.0.1")
	}
	return nil
}

func (connection *fakeResolvedConnection) Close() error {
	connection.mu.Lock()
	connection.closed = true
	connection.mu.Unlock()
	return nil
}

func (connection *fakeResolvedConnection) destroy() {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	for index := range connection.copyDNS {
		clear(connection.copyDNS[index].Address)
	}
}

func TestSystemdResolvedTypedCallSequenceAndBufferDestruction(t *testing.T) {
	connection := &fakeResolvedConnection{}
	t.Cleanup(connection.destroy)
	resolved := newSystemdResolvedDNS(
		func(context.Context) (resolvedConnection, error) { return connection, nil },
		func(name string) (int32, error) {
			if name != TunnelInterface {
				t.Fatalf("unexpected link lookup: %s", name)
			}
			return 42, nil
		},
	)
	err := testProfile(t, true).WithGuestSetup(context.Background(), func(ctx context.Context, setup vpn.GuestSetup) error {
		return resolved.Configure(ctx, setup)
	})
	if err != nil {
		t.Fatal(err)
	}
	connection.mu.Lock()
	calls := append([]resolvedCall(nil), connection.calls...)
	retained := append([]resolvedDNSAddress(nil), connection.retained...)
	copyDNS := append([]resolvedDNSAddress(nil), connection.copyDNS...)
	closed := connection.closed
	connection.mu.Unlock()
	want := []string{
		resolvedManager + ".SetLinkDNS",
		resolvedManager + ".SetLinkDomains",
		resolvedManager + ".SetLinkDefaultRoute",
		resolvedManager + ".SetLinkLLMNR",
		resolvedManager + ".SetLinkMulticastDNS",
	}
	if len(calls) != len(want) || !closed {
		t.Fatalf("resolved calls=%d closed=%v", len(calls), closed)
	}
	for index := range want {
		if calls[index].method != want[index] {
			t.Fatalf("call %d = %s, want %s", index, calls[index].method, want[index])
		}
	}
	if len(copyDNS) != 2 || copyDNS[0].Family == 0 || len(copyDNS[0].Address) != 4 || len(copyDNS[1].Address) != 16 {
		t.Fatalf("unexpected typed DNS values: %#v", copyDNS)
	}
	domains, ok := calls[1].args[1].([]resolvedDomain)
	if !ok || len(domains) != 1 || domains[0] != (resolvedDomain{Name: ".", RoutingOnly: true}) || calls[2].args[1] != true {
		t.Fatalf("DNS was not exclusive default-route DNS: %#v, %#v", calls[1].args, calls[2].args)
	}
	for _, address := range retained {
		for _, value := range address.Address {
			if value != 0 {
				t.Fatal("D-Bus DNS address buffer was not cleared")
			}
		}
	}
	if err := resolved.Clear(context.Background()); err != nil {
		t.Fatal(err)
	}
	connection.mu.Lock()
	last := connection.calls[len(connection.calls)-1]
	connection.mu.Unlock()
	if last.method != resolvedManager+".RevertLink" {
		t.Fatalf("clear call = %s", last.method)
	}
}

func TestSystemdResolvedFailureMatrixRevertsAndRedacts(t *testing.T) {
	for failAt := 1; failAt <= 5; failAt++ {
		t.Run(fmt.Sprintf("call_%d", failAt), func(t *testing.T) {
			connection := &fakeResolvedConnection{failAt: failAt}
			t.Cleanup(connection.destroy)
			resolved := newSystemdResolvedDNS(
				func(context.Context) (resolvedConnection, error) { return connection, nil },
				func(string) (int32, error) { return 42, nil },
			)
			err := testProfile(t, true).WithGuestSetup(context.Background(), func(ctx context.Context, setup vpn.GuestSetup) error {
				return resolved.Configure(ctx, setup)
			})
			if err == nil || strings.Contains(err.Error(), "10.2.0.1") {
				t.Fatalf("unsafe resolved error = %v", err)
			}
			connection.mu.Lock()
			last := connection.calls[len(connection.calls)-1].method
			connection.mu.Unlock()
			if last != resolvedManager+".RevertLink" {
				t.Fatalf("failure did not revert: %s", last)
			}
		})
	}
}

func TestSystemdResolvedHonorsCancellationAndRejectsMissingLink(t *testing.T) {
	connection := &fakeResolvedConnection{block: true}
	resolved := newSystemdResolvedDNS(
		func(context.Context) (resolvedConnection, error) { return connection, nil },
		func(string) (int32, error) { return 42, nil },
	)
	resolved.timeout = 10 * time.Millisecond
	err := testProfile(t, true).WithGuestSetup(context.Background(), func(ctx context.Context, setup vpn.GuestSetup) error {
		return resolved.Configure(ctx, setup)
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("resolved timeout = %v", err)
	}

	missing := newSystemdResolvedDNS(
		func(context.Context) (resolvedConnection, error) { return &fakeResolvedConnection{}, nil },
		func(string) (int32, error) { return 0, errors.New("synthetic link detail") },
	)
	err = testProfile(t, true).WithGuestSetup(context.Background(), func(ctx context.Context, setup vpn.GuestSetup) error {
		return missing.Configure(ctx, setup)
	})
	if err == nil || strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("missing-link error = %v", err)
	}
}
