package network

import (
	"context"
	"errors"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

var (
	ErrInvalidRequest     = errors.New("invalid network topology request")
	ErrTopologyExists     = errors.New("network topology already exists")
	ErrCollisionExhausted = errors.New("network allocation collision limit reached")
	ErrTopologyFailed     = errors.New("network topology creation failed")
	ErrPolicyFailed       = errors.New("host endpoint policy installation failed")
	ErrTopologyNotReady   = errors.New("network topology is not ready")
	ErrCleanupIncomplete  = errors.New("network cleanup is incomplete")
	ErrBackendUnavailable = errors.New("network backend is unavailable")
	ErrCommandFailed      = errors.New("bounded network command failed")
	ErrCommandOutputBound = errors.New("bounded network command output exceeded its limit")
)

func invalidRequest() error {
	return apperror.Wrap(
		"NETWORK_REQUEST_INVALID", exitcode.Network,
		"The requested private network contract is invalid.",
		"Create networking only for an active internal session and a current resolved VPN plan.",
		ErrInvalidRequest,
	)
}

func topologyExists() error {
	return apperror.Wrap(
		"NETWORK_TOPOLOGY_EXISTS", exitcode.Network,
		"A private network already belongs to this session.",
		"Reuse the existing session network or complete its cleanup before retrying.",
		ErrTopologyExists,
	)
}

func collisionExhausted() error {
	return apperror.Wrap(
		"NETWORK_COLLISION_EXHAUSTED", exitcode.Network,
		"No collision-free bounded network allocation is available.",
		"Clean verified orphaned private-vm network resources and retry.",
		ErrCollisionExhausted,
	)
}

func topologyFailed(cause error) error {
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	return apperror.Wrap(
		"NETWORK_TOPOLOGY_FAILED", exitcode.Network,
		"The isolated session network could not be created safely.",
		"Run private-vm doctor --strict, clean verified orphaned resources, and retry.",
		ErrTopologyFailed,
	)
}

func policyFailed(cause error) error {
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	return apperror.Wrap(
		"HOST_EGRESS_POLICY_FAILED", exitcode.Network,
		"The exact Proton endpoint allowlist could not be installed atomically.",
		"Do not start QEMU; clean the session network, verify nftables support, and retry with a current VPN plan.",
		ErrPolicyFailed,
	)
}

func topologyNotReady() error {
	return apperror.Wrap(
		"NETWORK_TOPOLOGY_NOT_READY", exitcode.Network,
		"The isolated session network is not ready for guest launch.",
		"Complete successful topology and endpoint-policy creation before starting QEMU.",
		ErrTopologyNotReady,
	)
}

func cleanupIncomplete() error {
	return apperror.Wrap(
		"NETWORK_CLEANUP_INCOMPLETE", exitcode.Cleanup,
		"One or more owned network resources could not be removed or audited absent.",
		"Keep the session in cleanup state, inspect redacted diagnostics, and retry verified cleanup.",
		ErrCleanupIncomplete,
	)
}
