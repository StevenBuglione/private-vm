package guestvpn

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maximumProbeOutput   = 64 << 10
	maximumHandshakeAge  = 3 * time.Minute
	maximumFutureSkew    = 30 * time.Second
	maximumConnectProbe  = 5 * time.Second
	wireGuardPublicBytes = 32
)

type probeOutputRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type osProbeOutputRunner struct{}

func (osProbeOutputRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	if ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid probe command")
	}
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"LANG=C.UTF-8"}
	var output boundedProbeBuffer
	output.limit = maximumProbeOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		clear(output.Bytes())
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("bounded probe command failed")
	}
	if output.exceeded {
		clear(output.Bytes())
		return nil, errors.New("bounded probe output exceeded")
	}
	return output.Bytes(), nil
}

type boundedProbeBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *boundedProbeBuffer) Write(value []byte) (int, error) {
	if buffer.Len()+len(value) > buffer.limit {
		remaining := buffer.limit - buffer.Len()
		if remaining > 0 {
			_, _ = buffer.Buffer.Write(value[:remaining])
		}
		buffer.exceeded = true
		return len(value), nil
	}
	return buffer.Buffer.Write(value)
}

// WireGuardHandshakeProbe reads only the fixed proton0 latest-handshakes
// report. Peer keys and timestamps are parsed in a bounded buffer and cleared;
// neither value is returned.
type WireGuardHandshakeProbe struct {
	path   string
	runner probeOutputRunner
	now    func() time.Time
	maxAge time.Duration
}

func NewWireGuardHandshakeProbe(path string) (*WireGuardHandshakeProbe, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "wg" {
		return nil, invalidRequest()
	}
	return &WireGuardHandshakeProbe{path: path, runner: osProbeOutputRunner{}, now: time.Now, maxAge: maximumHandshakeAge}, nil
}

func newWireGuardHandshakeProbe(path string, runner probeOutputRunner, now func() time.Time) (*WireGuardHandshakeProbe, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "wg" || isNilLike(runner) || now == nil {
		return nil, invalidRequest()
	}
	return &WireGuardHandshakeProbe{path: path, runner: runner, now: now, maxAge: maximumHandshakeAge}, nil
}

func (probe *WireGuardHandshakeProbe) Recent(ctx context.Context) (bool, error) {
	if ctx == nil || probe == nil || isNilLike(probe.runner) || probe.now == nil {
		return false, invalidRequest()
	}
	output, err := probe.runner.Run(ctx, probe.path, "show", TunnelInterface, "latest-handshakes")
	if err != nil {
		return false, probeFailed(ctx)
	}
	defer clear(output)
	line := bytes.TrimSpace(output)
	if len(line) == 0 || bytes.Count(line, []byte{'\n'}) != 0 {
		return false, nil
	}
	fields := bytes.Fields(line)
	if len(fields) != 2 {
		return false, nil
	}
	decoded := make([]byte, wireGuardPublicBytes)
	defer clear(decoded)
	written, decodeErr := base64.StdEncoding.Strict().Decode(decoded, fields[0])
	if decodeErr != nil || written != wireGuardPublicBytes || allZeroBytes(decoded) {
		return false, nil
	}
	timestamp, parseErr := strconv.ParseInt(string(fields[1]), 10, 64)
	if parseErr != nil || timestamp <= 0 {
		return false, nil
	}
	now := probe.now()
	handshake := time.Unix(timestamp, 0)
	maxAge := probe.maxAge
	if maxAge <= 0 || maxAge > maximumHandshakeAge {
		maxAge = maximumHandshakeAge
	}
	return !handshake.After(now.Add(maximumFutureSkew)) && !handshake.Before(now.Add(-maxAge)), nil
}

func allZeroBytes(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}

type boundDial func(context.Context, string, netip.AddrPort) (bool, error)
type interfaceLookup func(string) error

// BoundTCPProbe makes short controlled connections while pinning the socket to
// an exact fixed interface. A bind failure is distinct from an unreachable
// target and fails verification instead of being misclassified as a block.
type BoundTCPProbe struct {
	dial            boundDial
	interfaceExists interfaceLookup
	timeout         time.Duration
}

func NewBoundTCPProbe() *BoundTCPProbe {
	return &BoundTCPProbe{
		dial: dialBoundTCP,
		interfaceExists: func(name string) error {
			_, err := net.InterfaceByName(name)
			return err
		},
		timeout: maximumConnectProbe,
	}
}

func newBoundTCPProbe(dial boundDial, lookup interfaceLookup) *BoundTCPProbe {
	return &BoundTCPProbe{dial: dial, interfaceExists: lookup, timeout: maximumConnectProbe}
}

func (probe *BoundTCPProbe) Reachable(ctx context.Context, interfaceName string, target netip.AddrPort) (bool, error) {
	if ctx == nil || probe == nil || isNilLike(probe.dial) || isNilLike(probe.interfaceExists) ||
		(interfaceName != TunnelInterface && interfaceName != UnderlayInterface) || !target.IsValid() {
		return false, invalidRequest()
	}
	if err := probe.interfaceExists(interfaceName); err != nil {
		return false, errors.New("controlled probe interface unavailable")
	}
	probeCtx, cancel := boundedContext(ctx, probe.effectiveTimeout())
	defer cancel()
	reachable, err := probe.dial(probeCtx, interfaceName, target)
	if err != nil {
		if probeCtx.Err() != nil {
			return false, probeCtx.Err()
		}
		return false, errors.New("controlled bound connect failed")
	}
	return reachable, nil
}

func (probe *BoundTCPProbe) effectiveTimeout() time.Duration {
	if probe.timeout <= 0 || probe.timeout > maximumConnectProbe {
		return maximumConnectProbe
	}
	return probe.timeout
}

var errBindToDevice = errors.New("bind socket to device failed")

func dialBoundTCP(ctx context.Context, interfaceName string, target netip.AddrPort) (bool, error) {
	network := "tcp6"
	if target.Addr().Is4() {
		network = "tcp4"
	}
	dialer := net.Dialer{
		Control: func(_, _ string, raw syscall.RawConn) error {
			var controlErr error
			if err := raw.Control(func(descriptor uintptr) {
				if err := unix.SetsockoptString(int(descriptor), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, interfaceName); err != nil {
					controlErr = errBindToDevice
				}
			}); err != nil {
				return errBindToDevice
			}
			return controlErr
		},
	}
	connection, err := dialer.DialContext(ctx, network, target.String())
	if err != nil {
		if errors.Is(err, errBindToDevice) {
			return false, errBindToDevice
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	_ = connection.Close()
	return true, nil
}

var _ HandshakeProbe = (*WireGuardHandshakeProbe)(nil)
var _ ConnectivityProbe = (*BoundTCPProbe)(nil)
