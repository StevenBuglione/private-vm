package guest

import (
	"bytes"
	"context"
	"errors"
	"sync"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/torrent"
	"github.com/StevenBuglione/private-vm/internal/vpn"
	"google.golang.org/grpc/codes"
)

// DownloaderVPNServer wires only the downloader VPN methods into the
// downloader role service. Torrent methods remain separately composed; the
// generated unimplemented server fails them closed until their owner exists.
type DownloaderVPNServer struct {
	privatevmv1.UnimplementedDownloaderGuestServiceServer
	mu                sync.Mutex
	controller        *guestvpn.Controller
	controllerFactory DownloaderControllerFactory
	torrentController *torrent.Controller
}

// DownloaderControllerFactory binds the controller to the exact private
// underlay and controlled probe fixtures received over authenticated VSOCK.
// It has no logging or serialization surface.
type DownloaderControllerFactory func(guestvpn.Underlay, guestvpn.ProbeTargets) (*guestvpn.Controller, error)

// NewDownloaderServer composes the exact downloader VPN and torrent services.
// The controller is created at most once, after the typed host network values
// have passed the authenticated request boundary.
func NewDownloaderServer(factory DownloaderControllerFactory, torrentController *torrent.Controller) (*DownloaderVPNServer, error) {
	if factory == nil || torrentController == nil {
		return nil, errors.New("downloader VPN factory and torrent controller are required")
	}
	return &DownloaderVPNServer{controllerFactory: factory, torrentController: torrentController}, nil
}

func (server *DownloaderVPNServer) ConfigureWireGuard(ctx context.Context, request *privatevmv1.ConfigureWireGuardRequest) (*privatevmv1.VPNStatus, error) {
	if request == nil {
		return nil, guestRPCError(codes.InvalidArgument, "GUEST_VPN_REQUEST_INVALID", "A complete guest VPN request is required.", "Retry through the private-vm daemon.", false)
	}
	raw := request.GetProfile()
	request.Profile = nil
	defer clear(raw)
	defer clearDownloaderNetworkRequest(request)
	if server == nil {
		return nil, guestRPCError(codes.InvalidArgument, "GUEST_VPN_REQUEST_INVALID", "A complete guest VPN request is required.", "Retry through the private-vm daemon.", false)
	}
	if err := ValidateGuestContext(request.GetContext(), session.RoleDownloader); err != nil {
		return nil, err
	}
	underlay, err := guestUnderlayFromProto(request.GetUnderlay())
	if err != nil {
		return nil, err
	}
	targets, err := vpnProbeTargetsFromProto(request.GetProbeTargets())
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > vpn.MaximumProfileBytes {
		return nil, guestRPCError(codes.InvalidArgument, "VPN_PROFILE_INVALID", "The Proton WireGuard profile is invalid.", "Generate and import a current strict Proton WireGuard profile.", false)
	}
	profile, err := vpn.Parse(bytes.NewReader(raw))
	if err != nil {
		return nil, vpnRPCError(err)
	}
	defer profile.Destroy()
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.controller != nil || server.controllerFactory == nil {
		return nil, guestRPCError(codes.FailedPrecondition, "GUEST_VPN_ALREADY_CONFIGURED", "The downloader network owner is already configured.", "Destroy the downloader before supplying a different network plan.", false)
	}
	controller, err := server.controllerFactory(underlay, targets)
	if err != nil || controller == nil {
		return nil, guestRPCError(codes.FailedPrecondition, "GUEST_VPN_COMPOSITION_FAILED", "The downloader network adapters are unavailable.", "Destroy the guest and install the verified downloader image.", false)
	}
	server.controller = controller
	status, err := controller.Configure(ctx, profile)
	if err != nil {
		return nil, vpnRPCError(err)
	}
	return protoVPNStatus(status), nil
}

func (server *DownloaderVPNServer) VerifyVPN(ctx context.Context, request *privatevmv1.VerifyVPNRequest) (*privatevmv1.VPNStatus, error) {
	if server == nil || request == nil {
		return nil, guestRPCError(codes.InvalidArgument, "GUEST_VPN_REQUEST_INVALID", "A complete guest VPN request is required.", "Retry through the private-vm daemon.", false)
	}
	if err := ValidateGuestContext(request.GetContext(), session.RoleDownloader); err != nil {
		return nil, err
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.controller == nil {
		return nil, guestRPCError(codes.FailedPrecondition, "GUEST_VPN_UNCONFIGURED", "The downloader VPN has not been configured.", "Configure the authenticated downloader before verification.", false)
	}
	status, err := server.controller.Verify(ctx)
	if err != nil {
		return nil, vpnRPCError(err)
	}
	return protoVPNStatus(status), nil
}

func protoVPNStatus(status guestvpn.Status) *privatevmv1.VPNStatus {
	severity := privatevmv1.Diagnostic_SEVERITY_BLOCKING
	if status.State == guestvpn.StateVerified {
		severity = privatevmv1.Diagnostic_SEVERITY_INFO
	}
	return &privatevmv1.VPNStatus{
		Configured:        status.Configured,
		Handshake:         status.Handshake,
		DnsThroughTunnel:  status.DNSThroughTunnel,
		Ipv4BypassBlocked: status.IPv4BypassBlocked,
		Ipv6BypassBlocked: status.IPv6BypassBlocked,
		DnsBypassBlocked:  status.DNSBypassBlocked,
		Ipv4ThroughTunnel: status.IPv4ThroughTunnel,
		Ipv6ThroughTunnel: status.IPv6ThroughTunnel,
		TorrentBound:      status.TorrentBound,
		Diagnostics: []*privatevmv1.Diagnostic{{
			Code: status.Code, Severity: severity, Summary: "Guest VPN state is " + string(status.State) + ".",
			Remediation: status.Remediation, Overridable: false,
		}},
	}
}

func vpnRPCError(err error) error {
	if errors.Is(err, context.Canceled) {
		return guestRPCError(codes.Canceled, "GUEST_VPN_CANCELLED", "The guest VPN operation was cancelled.", "Retry after resolving the cancellation source.", true)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return guestRPCError(codes.DeadlineExceeded, "GUEST_VPN_TIMEOUT", "The guest VPN operation exceeded its bounded deadline.", "Verify the guest network and retry.", true)
	}
	application := apperror.From(err)
	grpcCode := codes.FailedPrecondition
	if errors.Is(err, guestvpn.ErrInvalidRequest) || errors.Is(err, vpn.ErrInvalidProfile) {
		grpcCode = codes.InvalidArgument
	}
	return guestRPCError(grpcCode, application.Code, application.Message, application.Remediation, false)
}

var _ privatevmv1.DownloaderGuestServiceServer = (*DownloaderVPNServer)(nil)
