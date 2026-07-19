package guestvpn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/StevenBuglione/private-vm/internal/vpn"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	resolvedBusSocket = "/run/dbus/system_bus_socket"
	resolvedService   = "org.freedesktop.resolve1"
	resolvedPath      = dbus.ObjectPath("/org/freedesktop/resolve1")
	resolvedManager   = "org.freedesktop.resolve1.Manager"
	resolvedTimeout   = 10 * time.Second
)

type resolvedDNSAddress struct {
	Family  int32
	Address []byte
}

type resolvedDomain struct {
	Name        string
	RoutingOnly bool
}

type resolvedConnection interface {
	Call(context.Context, string, ...any) error
	Close() error
}

type resolvedConnector func(context.Context) (resolvedConnection, error)
type linkIndexResolver func(string) (int32, error)

// SystemdResolvedDNS configures tunnel-only DNS through resolve1's typed D-Bus
// API. It writes no file and places no address in argv, environment, log or
// returned error. Each operation has a private bounded bus connection.
type SystemdResolvedDNS struct {
	connect   resolvedConnector
	linkIndex linkIndexResolver
	timeout   time.Duration
}

func NewSystemdResolvedDNS() *SystemdResolvedDNS {
	return &SystemdResolvedDNS{
		connect: connectResolvedSystemBus,
		linkIndex: func(name string) (int32, error) {
			link, err := net.InterfaceByName(name)
			if err != nil || link.Index <= 0 {
				return 0, errors.New("resolved tunnel link unavailable")
			}
			return int32(link.Index), nil
		},
		timeout: resolvedTimeout,
	}
}

func newSystemdResolvedDNS(connect resolvedConnector, linkIndex linkIndexResolver) *SystemdResolvedDNS {
	return &SystemdResolvedDNS{connect: connect, linkIndex: linkIndex, timeout: resolvedTimeout}
}

func (resolved *SystemdResolvedDNS) Configure(ctx context.Context, setup vpn.GuestSetup) error {
	if ctx == nil || resolved == nil || isNilLike(resolved.connect) || isNilLike(resolved.linkIndex) || setup == nil {
		return invalidRequest()
	}
	operationCtx, cancel := boundedContext(ctx, resolved.effectiveTimeout())
	defer cancel()
	index, err := resolved.linkIndex(TunnelInterface)
	if err != nil || index <= 0 {
		return errors.New("systemd-resolved tunnel link unavailable")
	}
	addresses := make([]resolvedDNSAddress, 0, 8)
	defer func() { destroyResolvedAddresses(addresses) }()
	if err := setup.DNSServers(operationCtx, func(address netip.Addr) error {
		if len(addresses) >= 8 || !address.IsValid() || address.Is4In6() {
			return invalidRequest()
		}
		family := int32(unix.AF_INET6)
		if address.Is4() {
			family = unix.AF_INET
		}
		addresses = append(addresses, resolvedDNSAddress{Family: family, Address: append([]byte(nil), address.AsSlice()...)})
		return nil
	}); err != nil || len(addresses) == 0 {
		return errors.New("systemd-resolved DNS configuration invalid")
	}
	connection, err := resolved.connect(operationCtx)
	if err != nil {
		return normalizeResolvedError(operationCtx)
	}
	defer connection.Close()
	calls := []struct {
		method string
		args   []any
	}{
		{resolvedManager + ".SetLinkDNS", []any{index, addresses}},
		{resolvedManager + ".SetLinkDomains", []any{index, []resolvedDomain{{Name: ".", RoutingOnly: true}}}},
		{resolvedManager + ".SetLinkDefaultRoute", []any{index, true}},
		{resolvedManager + ".SetLinkLLMNR", []any{index, "no"}},
		{resolvedManager + ".SetLinkMulticastDNS", []any{index, "no"}},
	}
	for _, call := range calls {
		if err := connection.Call(operationCtx, call.method, call.args...); err != nil {
			_ = connection.Call(operationCtx, resolvedManager+".RevertLink", index)
			return normalizeResolvedError(operationCtx)
		}
	}
	return nil
}

func (resolved *SystemdResolvedDNS) Clear(ctx context.Context) error {
	if ctx == nil || resolved == nil || isNilLike(resolved.connect) || isNilLike(resolved.linkIndex) {
		return invalidRequest()
	}
	operationCtx, cancel := boundedContext(ctx, resolved.effectiveTimeout())
	defer cancel()
	index, err := resolved.linkIndex(TunnelInterface)
	if err != nil || index <= 0 {
		return errors.New("systemd-resolved tunnel link unavailable")
	}
	connection, err := resolved.connect(operationCtx)
	if err != nil {
		return normalizeResolvedError(operationCtx)
	}
	defer connection.Close()
	if err := connection.Call(operationCtx, resolvedManager+".RevertLink", index); err != nil {
		return normalizeResolvedError(operationCtx)
	}
	return nil
}

func (resolved *SystemdResolvedDNS) effectiveTimeout() time.Duration {
	if resolved.timeout <= 0 || resolved.timeout > resolvedTimeout {
		return resolvedTimeout
	}
	return resolved.timeout
}

func destroyResolvedAddresses(addresses []resolvedDNSAddress) {
	for index := range addresses {
		clear(addresses[index].Address)
		addresses[index].Address = nil
		addresses[index].Family = 0
	}
	clear(addresses)
}

func normalizeResolvedError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("bounded systemd-resolved operation failed")
}

type godbusResolvedConnection struct {
	connection *dbus.Conn
	object     dbus.BusObject
}

func (connection *godbusResolvedConnection) Call(ctx context.Context, method string, args ...any) error {
	if connection == nil || connection.object == nil {
		return errors.New("systemd-resolved bus unavailable")
	}
	if call := connection.object.CallWithContext(ctx, method, 0, args...); call.Err != nil {
		return errors.New("systemd-resolved call failed")
	}
	return nil
}

func (connection *godbusResolvedConnection) Close() error {
	if connection == nil || connection.connection == nil {
		return nil
	}
	return connection.connection.Close()
}

func connectResolvedSystemBus(ctx context.Context) (resolvedConnection, error) {
	if ctx == nil {
		return nil, errors.New("system bus context required")
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", resolvedBusSocket)
	if err != nil {
		return nil, normalizeResolvedError(ctx)
	}
	unixConnection, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, errors.New("system bus transport invalid")
	}
	deadline := time.Now().Add(resolvedTimeout)
	if current, ok := ctx.Deadline(); ok && current.Before(deadline) {
		deadline = current
	}
	if err := unixConnection.SetDeadline(deadline); err != nil {
		_ = unixConnection.Close()
		return nil, errors.New("system bus deadline failed")
	}
	connection, err := dbus.DialUnix(unixConnection)
	if err != nil {
		_ = unixConnection.Close()
		return nil, errors.New("system bus connection failed")
	}
	if err := connection.Auth(nil); err != nil {
		_ = connection.Close()
		return nil, errors.New("system bus authentication failed")
	}
	if err := connection.Hello(); err != nil {
		_ = connection.Close()
		return nil, errors.New("system bus hello failed")
	}
	if err := unixConnection.SetDeadline(time.Time{}); err != nil {
		_ = connection.Close()
		return nil, errors.New("system bus deadline reset failed")
	}
	return &godbusResolvedConnection{
		connection: connection,
		object:     connection.Object(resolvedService, resolvedPath),
	}, nil
}

var _ DNSConfigurator = (*SystemdResolvedDNS)(nil)
