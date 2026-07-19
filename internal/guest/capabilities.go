package guest

import (
	"errors"
	"slices"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
)

const (
	APIMajor    uint32 = 1
	APIMinor    uint32 = 0
	DefaultPort uint32 = 4050
)

// CompiledRole is set only by the role-specific Nix guestd derivation. An
// empty value deliberately makes a generic/host build refuse to start guestd.
var (
	CompiledRole = ""
	ImageDigest  = "unverified"
)

var commonCapabilities = []string{
	"guest-events",
	"guest-shutdown",
	"guest-status",
}

var roleCapabilities = map[session.Role][]string{
	session.RoleWorkstation: {"desktop", "network-warning", "vpn-verification", "wireguard-config", "workspace-export", "workspace-import"},
	session.RoleDownloader:  {"quarantine-seal", "torrent-download", "torrent-metadata", "vpn-verification", "wireguard-config"},
	session.RoleScanner:     {"approved-export", "definitions-update", "inventory", "offline-verification", "reconstruct", "scan", "scan-report", "vpn-verification", "wireguard-config"},
	session.RoleExporter:    {"usb-finalize", "usb-inspect", "usb-prepare", "usb-verify", "usb-write"},
}

func CompiledSessionRole() (session.Role, error) {
	role := session.Role(CompiledRole)
	if err := session.ValidateRole(role); err != nil {
		return "", errors.New("guestd has no valid compile-time role")
	}
	return role, nil
}

func Capabilities(role session.Role) ([]string, error) {
	if err := session.ValidateRole(role); err != nil {
		return nil, err
	}
	capabilities := append([]string(nil), commonCapabilities...)
	capabilities = append(capabilities, roleCapabilities[role]...)
	slices.Sort(capabilities)
	return capabilities, nil
}

func ProtoRole(role session.Role) (privatevmv1.GuestRole, error) {
	switch role {
	case session.RoleWorkstation:
		return privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION, nil
	case session.RoleDownloader:
		return privatevmv1.GuestRole_GUEST_ROLE_DOWNLOADER, nil
	case session.RoleScanner:
		return privatevmv1.GuestRole_GUEST_ROLE_SCANNER, nil
	case session.RoleExporter:
		return privatevmv1.GuestRole_GUEST_ROLE_EXPORTER, nil
	default:
		return privatevmv1.GuestRole_GUEST_ROLE_UNSPECIFIED, errors.New("unsupported guest role")
	}
}

func SessionRole(role privatevmv1.GuestRole) (session.Role, error) {
	switch role {
	case privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION:
		return session.RoleWorkstation, nil
	case privatevmv1.GuestRole_GUEST_ROLE_DOWNLOADER:
		return session.RoleDownloader, nil
	case privatevmv1.GuestRole_GUEST_ROLE_SCANNER:
		return session.RoleScanner, nil
	case privatevmv1.GuestRole_GUEST_ROLE_EXPORTER:
		return session.RoleExporter, nil
	default:
		return "", errors.New("unsupported guest role")
	}
}
