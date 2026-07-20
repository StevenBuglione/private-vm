package network

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

const networkCommandOutputLimit = 64 << 10

// ToolPaths selects package-controlled networking tools. Each path is checked
// for the exact expected basename before any command can run.
type ToolPaths struct {
	IP     string
	NFT    string
	Sysctl string
	Tun    string
}

func (paths ToolPaths) validate() error {
	for _, tool := range []struct{ path, base string }{{paths.IP, "ip"}, {paths.NFT, "nft"}, {paths.Sysctl, "sysctl"}} {
		if !filepath.IsAbs(tool.path) || filepath.Clean(tool.path) != tool.path || filepath.Base(tool.path) != tool.base {
			return ErrBackendUnavailable
		}
	}
	if !filepath.IsAbs(paths.Tun) || filepath.Clean(paths.Tun) != paths.Tun || paths.Tun != "/dev/net/tun" {
		return ErrBackendUnavailable
	}
	return nil
}

type backend interface {
	Available(context.Context, topologySpec) (bool, error)
	CreateNamespace(context.Context, topologySpec) error
	CreateVeth(context.Context, topologySpec) error
	ConfigureHost(context.Context, topologySpec) error
	ConfigureNamespace(context.Context, topologySpec) error
	CreateTAP(context.Context, topologySpec) (*os.File, error)
	ConfigureTAP(context.Context, topologySpec) error
	ApplyNamespacePolicy(context.Context, topologySpec, endpointPolicy) error
	ApplyHostPolicy(context.Context, topologySpec, endpointPolicy) error
	AuditPolicy(context.Context, topologySpec) (PolicyAudit, error)
	DisableEgress(context.Context, topologySpec) error
	DeleteHostPolicy(context.Context, topologySpec) error
	DeleteNamespacePolicy(context.Context, topologySpec) error
	DeleteTAP(context.Context, topologySpec) error
	DeleteVeth(context.Context, topologySpec) error
	DeleteNamespace(context.Context, topologySpec) error
	AuditAbsent(context.Context, topologySpec) (bool, error)
}

type command struct {
	path  string
	args  []string
	stdin []byte
}

type commandResult struct {
	stdout   []byte
	exitCode int
}

type commandRunner interface {
	Run(context.Context, command) (commandResult, error)
}

type osCommandRunner struct{}

func (osCommandRunner) Run(ctx context.Context, request command) (commandResult, error) {
	if ctx == nil || !filepath.IsAbs(request.path) || filepath.Clean(request.path) != request.path {
		return commandResult{}, ErrBackendUnavailable
	}
	if err := ctx.Err(); err != nil {
		return commandResult{}, err
	}
	process := exec.CommandContext(ctx, request.path, request.args...)
	process.Env = []string{"LANG=C.UTF-8"}
	if request.stdin != nil {
		process.Stdin = bytes.NewReader(request.stdin)
	}
	var stdout limitedBuffer
	stdout.limit = networkCommandOutputLimit
	defer func() { clear(stdout.Bytes()) }()
	process.Stdout = &stdout
	process.Stderr = io.Discard
	err := process.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return commandResult{}, ctxErr
	}
	if stdout.exceeded {
		return commandResult{}, ErrCommandOutputBound
	}
	result := commandResult{stdout: append([]byte(nil), stdout.Bytes()...)}
	if err == nil {
		return result, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		result.exitCode = exit.ExitCode()
		return result, nil
	}
	return commandResult{}, ErrBackendUnavailable
}

type limitedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
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
