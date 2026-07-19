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

// DownloaderVPNServer wires the separately owned VPN and torrent controllers
// into only the downloader role service.
type DownloaderVPNServer struct {
	privatevmv1.UnimplementedDownloaderGuestServiceServer
	mu                sync.Mutex
	expectedRole      session.Role
	controller        *guestvpn.Controller
	controllerFactory DownloaderControllerFactory
	torrentController *torrent.Controller
}

// DownloaderControllerFactory binds the controller to the exact private
// underlay and controlled probe fixtures received over authenticated VSOCK.
// It has no logging or serialization surface.
type DownloaderControllerFactory func(guestvpn.Underlay, guestvpn.ProbeTargets) (*guestvpn.Controller, error)

// WorkstationVPNServer decorates the workstation owner with the same bounded
// network lifecycle while preserving a workstation-only gRPC registration.
type WorkstationVPNServer struct {
	privatevmv1.WorkstationGuestServiceServer
	network *DownloaderVPNServer
}

// NewWorkstationVPNServer adds the role-safe network methods without exposing
// downloader torrent methods in the workstation image.
func NewWorkstationVPNServer(workspace privatevmv1.WorkstationGuestServiceServer, factory DownloaderControllerFactory) (*WorkstationVPNServer, error) {
	if workspace == nil || factory == nil {
		return nil, errors.New("workstation owner and VPN factory are required")
	}
	return &WorkstationVPNServer{
		WorkstationGuestServiceServer: workspace,
		network:                       &DownloaderVPNServer{expectedRole: session.RoleWorkstation, controllerFactory: factory},
	}, nil
}

// NewDownloaderServer composes the exact downloader VPN and torrent services.
// The controller is created at most once, after the typed host network values
// have passed the authenticated request boundary.
func NewDownloaderServer(factory DownloaderControllerFactory, torrentController *torrent.Controller) (*DownloaderVPNServer, error) {
	if factory == nil || torrentController == nil {
		return nil, errors.New("downloader VPN factory and torrent controller are required")
	}
	return &DownloaderVPNServer{expectedRole: session.RoleDownloader, controllerFactory: factory, torrentController: torrentController}, nil
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
	if err := ValidateGuestContext(request.GetContext(), server.role()); err != nil {
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
		return nil, guestRPCError(codes.FailedPrecondition, "GUEST_VPN_ALREADY_CONFIGURED", "The guest network owner is already configured.", "Destroy the guest before supplying a different network plan.", false)
	}
	controller, err := server.controllerFactory(underlay, targets)
	if err != nil || controller == nil {
		return nil, guestRPCError(codes.FailedPrecondition, "GUEST_VPN_COMPOSITION_FAILED", "The guest network adapters are unavailable.", "Destroy the guest and install the verified role image.", false)
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
	if err := ValidateGuestContext(request.GetContext(), server.role()); err != nil {
		return nil, err
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.controller == nil {
		return nil, guestRPCError(codes.FailedPrecondition, "GUEST_VPN_UNCONFIGURED", "The guest VPN has not been configured.", "Configure the authenticated guest before verification.", false)
	}
	status, err := server.controller.Verify(ctx)
	if err != nil {
		return nil, vpnRPCError(err)
	}
	return protoVPNStatus(status), nil
}

func (server *DownloaderVPNServer) role() session.Role {
	if server != nil && server.expectedRole == session.RoleWorkstation {
		return session.RoleWorkstation
	}
	return session.RoleDownloader
}

// StopVPN is used only by the guestd process cleanup owner. It preserves the
// application -> tunnel -> kill-switch dependency order inside the controller.
func (server *DownloaderVPNServer) StopVPN(ctx context.Context) error {
	if server == nil || ctx == nil {
		return errors.New("downloader VPN cleanup is invalid")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.controller == nil {
		return nil
	}
	return server.controller.Stop(ctx)
}

func (server *WorkstationVPNServer) ConfigureWireGuard(ctx context.Context, request *privatevmv1.ConfigureWireGuardRequest) (*privatevmv1.VPNStatus, error) {
	if server == nil || server.network == nil {
		return nil, guestRPCError(codes.FailedPrecondition, "GUEST_VPN_COMPOSITION_FAILED", "The guest network adapters are unavailable.", "Destroy the guest and install the verified role image.", false)
	}
	return server.network.ConfigureWireGuard(ctx, request)
}

func (server *WorkstationVPNServer) VerifyVPN(ctx context.Context, request *privatevmv1.VerifyVPNRequest) (*privatevmv1.VPNStatus, error) {
	if server == nil || server.network == nil {
		return nil, guestRPCError(codes.FailedPrecondition, "GUEST_VPN_COMPOSITION_FAILED", "The guest network adapters are unavailable.", "Destroy the guest and install the verified role image.", false)
	}
	return server.network.VerifyVPN(ctx, request)
}

func (server *WorkstationVPNServer) StopVPN(ctx context.Context) error {
	if server == nil || server.network == nil {
		return nil
	}
	return server.network.StopVPN(ctx)
}

// Close lets guestd keep one bounded role cleanup owner.
func (server *WorkstationVPNServer) Close(ctx context.Context) error {
	return server.StopVPN(ctx)
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
var _ privatevmv1.WorkstationGuestServiceServer = (*WorkstationVPNServer)(nil)
