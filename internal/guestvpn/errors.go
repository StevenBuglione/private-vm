package guestvpn

import (
	"context"
	"errors"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

var (
	ErrInvalidRequest      = errors.New("invalid guest VPN request")
	ErrKillSwitchFailed    = errors.New("guest VPN kill switch failed")
	ErrConfigurationFailed = errors.New("guest VPN configuration failed")
	ErrVerificationFailed  = errors.New("guest VPN verification failed")
	ErrTunnelLost          = errors.New("guest VPN tunnel lost")
	ErrCleanupIncomplete   = errors.New("guest VPN cleanup incomplete")
)

func invalidRequest() error {
	return apperror.Wrap(
		"GUEST_VPN_REQUEST_INVALID", exitcode.Network,
		"The guest VPN request is not valid for this role.",
		"Use the typed network workflow for a workstation, downloader, or scanner update boot.",
		ErrInvalidRequest,
	)
}

func killSwitchFailed(cause error) error {
	if isContextError(cause) {
		return cause
	}
	return apperror.Wrap(
		"GUEST_KILL_SWITCH_FAILED", exitcode.Network,
		"The guest kill switch could not be armed.",
		"Do not start guest applications; stop the guest and clean the session network.",
		ErrKillSwitchFailed,
	)
}

func configurationFailed(cause error) error {
	if isContextError(cause) {
		return cause
	}
	return apperror.Wrap(
		"GUEST_VPN_CONFIGURATION_FAILED", exitcode.Network,
		"The guest WireGuard tunnel could not be configured.",
		"Keep the kill switch armed, stop the guest, and retry with a current Proton profile.",
		ErrConfigurationFailed,
	)
}

func verificationFailed(cause error) error {
	if isContextError(cause) {
		return cause
	}
	return apperror.Wrap(
		"GUEST_VPN_VERIFICATION_FAILED", exitcode.Network,
		"The guest VPN did not pass every required tunnel and bypass check.",
		"Keep the kill switch armed and do not start network applications; inspect redacted diagnostics and retry.",
		ErrVerificationFailed,
	)
}

func tunnelLost() error {
	return apperror.Wrap(
		"GUEST_VPN_TUNNEL_LOST", exitcode.Network,
		"The verified guest VPN tunnel is no longer healthy.",
		"Keep the kill switch armed, pause network work, and reconnect or stop the session.",
		ErrTunnelLost,
	)
}

func cleanupIncomplete() error {
	return apperror.Wrap(
		"GUEST_VPN_CLEANUP_INCOMPLETE", exitcode.Cleanup,
		"The guest VPN resources were not completely removed.",
		"Keep the session in cleanup state and retry verified teardown before reuse.",
		ErrCleanupIncomplete,
	)
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
