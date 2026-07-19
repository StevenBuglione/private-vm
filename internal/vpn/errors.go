package vpn

import (
	"errors"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

var (
	// These sentinels classify failures without retaining rejected profile data,
	// resolver output, or wrapped operating-system errors.
	ErrInvalidProfile     = errors.New("invalid Proton WireGuard profile")
	ErrEndpointUnresolved = errors.New("proton endpoint unresolved")
	ErrProfileNotFound    = errors.New("volatile VPN profile not imported")
	ErrProfileNotReady    = errors.New("volatile VPN profile endpoint check required")
	ErrProfileRotated     = errors.New("volatile VPN profile generation changed")
	ErrProfileLimit       = errors.New("volatile VPN profile limit reached")
	ErrStoreClosed        = errors.New("volatile VPN profile store is closed")
	ErrCallbackRequired   = errors.New("bounded VPN profile callback is required")
)

func invalidProfile() error {
	return apperror.Wrap(
		"VPN_PROFILE_INVALID",
		exitcode.Network,
		"The Proton WireGuard profile is invalid.",
		"Generate a new Proton WireGuard profile containing one peer, default routes, literal DNS addresses, and no hooks.",
		ErrInvalidProfile,
	)
}

func endpointUnresolved() error {
	return apperror.Wrap(
		"VPN_ENDPOINT_UNRESOLVED",
		exitcode.Network,
		"The Proton endpoint could not be resolved safely.",
		"Generate and import a current Proton WireGuard profile, then retry the bounded endpoint check.",
		ErrEndpointUnresolved,
	)
}

func profileNotFound() error {
	return apperror.Wrap(
		"VPN_PROFILE_NOT_IMPORTED",
		exitcode.Network,
		"No volatile Proton WireGuard profile is available.",
		"Import a current Proton WireGuard profile before starting a networked role.",
		ErrProfileNotFound,
	)
}

func profileNotReady() error {
	return apperror.Wrap(
		"VPN_ENDPOINT_CHECK_REQUIRED",
		exitcode.Network,
		"The Proton endpoint has not been verified for this profile generation.",
		"Run the bounded trusted-host endpoint check before delivering the profile to a guest.",
		ErrProfileNotReady,
	)
}

func profileRotated() error {
	return apperror.Wrap(
		"VPN_PROFILE_ROTATED",
		exitcode.Network,
		"The volatile Proton profile generation changed before delivery.",
		"Resolve the current profile generation and rebuild the endpoint policy before retrying.",
		ErrProfileRotated,
	)
}

func profileLimit() error {
	return apperror.Wrap(
		"VPN_PROFILE_LIMIT",
		exitcode.Network,
		"The volatile Proton profile limit was reached.",
		"Remove an unused imported profile before importing another name.",
		ErrProfileLimit,
	)
}

func storeClosed() error {
	return apperror.Wrap(
		"VPN_PROFILE_STORE_CLOSED",
		exitcode.Network,
		"The volatile Proton profile store is unavailable.",
		"Restart the daemon and import the Proton WireGuard profile again.",
		ErrStoreClosed,
	)
}
