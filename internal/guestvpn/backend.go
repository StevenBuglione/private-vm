package guestvpn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/StevenBuglione/private-vm/internal/vpn"
)

const guestCommandInputLimit = 64 << 10

// ToolPaths contains package-selected executables. No caller-provided command,
// argument, interface name, route, or nftables fragment crosses this boundary.
type ToolPaths struct {
	IP  string
	NFT string
	WG  string
}

func (paths ToolPaths) validate() error {
	for _, tool := range []struct{ path, base string }{{paths.IP, "ip"}, {paths.NFT, "nft"}, {paths.WG, "wg"}} {
		if !filepath.IsAbs(tool.path) || filepath.Clean(tool.path) != tool.path || filepath.Base(tool.path) != tool.base {
			return invalidRequest()
		}
	}
	return nil
}

// DNSConfigurator is the narrow systemd-resolved D-Bus boundary. The
// implementation receives only an opaque setup callback and must configure
// proton0 as the exclusive default DNS route without files or argv values.
type DNSConfigurator interface {
	Configure(context.Context, vpn.GuestSetup) error
	Clear(context.Context) error
}

type commandRequest struct {
	path  string
	args  []string
	stdin io.Reader
}

type commandRunner interface {
	Run(context.Context, commandRequest) error
}

type osCommandRunner struct{}

func (osCommandRunner) Run(ctx context.Context, request commandRequest) error {
	if ctx == nil || !filepath.IsAbs(request.path) || filepath.Clean(request.path) != request.path {
		return errors.New("invalid guest network command")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, request.path, request.args...)
	command.Env = []string{"LANG=C.UTF-8"}
	command.Stdin = request.stdin
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return errors.New("bounded guest network command failed")
	}
	return nil
}

// LinuxBackend applies the reviewed guest network mutations. It never invokes
// a shell. All profile-derived values travel over stdin or the injected D-Bus
// DNS adapter, never argv or the environment.
type LinuxBackend struct {
	mu        sync.Mutex
	paths     ToolPaths
	runner    commandRunner
	dns       DNSConfigurator
	killArmed bool
	tunnel    bool
}

func NewLinuxBackend(paths ToolPaths, dns DNSConfigurator) (*LinuxBackend, error) {
	if err := paths.validate(); err != nil || isNilLike(dns) {
		return nil, invalidRequest()
	}
	return &LinuxBackend{paths: paths, runner: osCommandRunner{}, dns: dns}, nil
}

func newLinuxBackend(paths ToolPaths, dns DNSConfigurator, runner commandRunner) (*LinuxBackend, error) {
	if err := paths.validate(); err != nil || isNilLike(dns) || isNilLike(runner) {
		return nil, invalidRequest()
	}
	return &LinuxBackend{paths: paths, runner: runner, dns: dns}, nil
}

func (backend *LinuxBackend) ArmKillSwitch(ctx context.Context, setup vpn.GuestSetup) error {
	if ctx == nil || backend == nil || setup == nil {
		return invalidRequest()
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.killArmed || backend.tunnel {
		return invalidRequest()
	}
	rules, err := killSwitchRules(ctx, setup)
	if err != nil {
		return err
	}
	defer clear(rules)
	if err := backend.runner.Run(ctx, commandRequest{path: backend.paths.NFT, args: []string{"-f", "-"}, stdin: bytes.NewReader(rules)}); err != nil {
		return err
	}
	backend.killArmed = true
	return nil
}

func (backend *LinuxBackend) ConfigureTunnel(ctx context.Context, underlay Underlay, setup vpn.GuestSetup) error {
	if ctx == nil || backend == nil || setup == nil || underlay.validate() != nil {
		return invalidRequest()
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if !backend.killArmed || backend.tunnel {
		return invalidRequest()
	}
	underlayBatch, err := underlayCommands(ctx, underlay, setup)
	if err != nil {
		return err
	}
	if err := backend.runBytes(ctx, backend.paths.IP, []string{"-batch", "-"}, underlayBatch); err != nil {
		return err
	}
	// Mark the fixed guest interface as possibly allocated before mutation so a
	// false-negative command result still forces cleanup to revisit it.
	backend.tunnel = true
	if err := backend.runner.Run(ctx, commandRequest{path: backend.paths.IP, args: []string{"link", "add", TunnelInterface, "type", "wireguard"}}); err != nil {
		return err
	}
	if err := setup.WithWireGuardConfig(ctx, func(callbackCtx context.Context, reader io.Reader) error {
		return backend.runner.Run(callbackCtx, commandRequest{path: backend.paths.WG, args: []string{"setconf", TunnelInterface, "/dev/stdin"}, stdin: reader})
	}); err != nil {
		return err
	}
	tunnelBatch, err := tunnelCommands(ctx, setup)
	if err != nil {
		return err
	}
	if err := backend.runBytes(ctx, backend.paths.IP, []string{"-batch", "-"}, tunnelBatch); err != nil {
		return err
	}
	if err := backend.dns.Configure(ctx, setup); err != nil {
		return err
	}
	return nil
}

func (backend *LinuxBackend) RemoveTunnel(ctx context.Context) error {
	if ctx == nil || backend == nil {
		return invalidRequest()
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if !backend.tunnel {
		return nil
	}
	if err := backend.dns.Clear(ctx); err != nil {
		return err
	}
	if err := backend.runner.Run(ctx, commandRequest{path: backend.paths.IP, args: []string{"link", "delete", TunnelInterface}}); err != nil {
		return err
	}
	backend.tunnel = false
	return nil
}

func (backend *LinuxBackend) RemoveKillSwitch(ctx context.Context) error {
	if ctx == nil || backend == nil {
		return invalidRequest()
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.tunnel {
		return cleanupIncomplete()
	}
	if !backend.killArmed {
		return nil
	}
	if err := backend.runner.Run(ctx, commandRequest{path: backend.paths.NFT, args: []string{"delete", "table", "inet", "private_vm_guest"}}); err != nil {
		return err
	}
	backend.killArmed = false
	return nil
}

func (backend *LinuxBackend) runBytes(ctx context.Context, path string, args []string, value []byte) error {
	defer clear(value)
	if len(value) == 0 || len(value) > guestCommandInputLimit {
		return invalidRequest()
	}
	return backend.runner.Run(ctx, commandRequest{path: path, args: args, stdin: bytes.NewReader(value)})
}

var _ Backend = (*LinuxBackend)(nil)
