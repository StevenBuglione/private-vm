package guestvpn

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

type probeResolvedConnection struct {
	mu             sync.Mutex
	tunnelIndex    int32
	underlayIndex  int32
	underlayLeaks  bool
	underlayError  error
	calls          []int32
	retainedAnswer []byte
}

func (*probeResolvedConnection) Call(context.Context, string, ...any) error { return nil }

func (connection *probeResolvedConnection) CallStore(ctx context.Context, method string, args []any, output ...any) error {
	if method != resolvedManager+".ResolveHostname" || len(args) != 4 || len(output) != 3 {
		return errors.New("unexpected resolved probe call")
	}
	index, ok := args[0].(int32)
	if !ok || args[2] != int32(unix.AF_UNSPEC) || args[3] != resolvedProtocolDNS|resolvedNoSearch {
		return errors.New("invalid resolved probe signature")
	}
	connection.mu.Lock()
	connection.calls = append(connection.calls, index)
	connection.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if index == connection.underlayIndex && !connection.underlayLeaks {
		if connection.underlayError != nil {
			return connection.underlayError
		}
		return errors.New("clear-interface DNS blocked")
	}
	answers := output[0].(*[]resolvedAnswer)
	canonical := output[1].(*string)
	flags := output[2].(*uint64)
	address := netip.MustParseAddr("1.1.1.1").AsSlice()
	connection.mu.Lock()
	connection.retainedAnswer = address
	connection.mu.Unlock()
	*answers = []resolvedAnswer{{Interface: index, Family: unix.AF_INET, Address: address}}
	*canonical = "probe.private-vm.example"
	*flags = resolvedProtocolDNS
	return nil
}

func (*probeResolvedConnection) Close() error { return nil }

func TestResolvedDNSLeakProbeRequiresTunnelSuccessAndUnderlayFailure(t *testing.T) {
	connection := &probeResolvedConnection{tunnelIndex: 42, underlayIndex: 7}
	probe := newResolvedDNSLeakProbe(
		func(context.Context) (resolvedConnection, error) { return connection, nil },
		func(name string) (int32, error) {
			switch name {
			case TunnelInterface:
				return 42, nil
			case UnderlayInterface:
				return 7, nil
			default:
				return 0, errors.New("unexpected link")
			}
		},
	)
	tunnel, blocked, err := probe.TunnelAndBypass(context.Background(), "probe.private-vm.example")
	if err != nil || !tunnel || !blocked {
		t.Fatalf("DNS proof = %v, %v, %v", tunnel, blocked, err)
	}
	connection.mu.Lock()
	calls := append([]int32(nil), connection.calls...)
	retained := connection.retainedAnswer
	connection.mu.Unlock()
	if len(calls) != 2 || calls[0] != 42 || calls[1] != 7 {
		t.Fatalf("DNS link sequence = %v", calls)
	}
	for _, value := range retained {
		if value != 0 {
			t.Fatal("resolved answer buffer was not cleared")
		}
	}
}

func TestResolvedDNSLeakProbeDetectsUnderlayAnswer(t *testing.T) {
	connection := &probeResolvedConnection{tunnelIndex: 42, underlayIndex: 7, underlayLeaks: true}
	probe := newResolvedDNSLeakProbe(
		func(context.Context) (resolvedConnection, error) { return connection, nil },
		func(name string) (int32, error) {
			if name == TunnelInterface {
				return 42, nil
			}
			return 7, nil
		},
	)
	tunnel, blocked, err := probe.TunnelAndBypass(context.Background(), "probe.private-vm.example")
	if err != nil || !tunnel || blocked {
		t.Fatalf("DNS leak proof = %v, %v, %v", tunnel, blocked, err)
	}
}

func TestResolvedDNSLeakProbeRejectsUnsafeInputsAndContext(t *testing.T) {
	probe := newResolvedDNSLeakProbe(
		func(context.Context) (resolvedConnection, error) { return &probeResolvedConnection{}, nil },
		func(string) (int32, error) { return 1, nil },
	)
	if _, _, err := probe.TunnelAndBypass(context.Background(), "localhost"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unsafe hostname accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := probe.TunnelAndBypass(ctx, "probe.private-vm.example"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled DNS proof = %v", err)
	}
}
