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

// ScannerVPNServer decorates only the scanner role service. The two VPN RPCs
// are used exclusively by the definitions-update boot; the offline boot has no
// QEMU NIC and therefore cannot successfully configure this controller.
type ScannerVPNServer struct {
	privatevmv1.ScannerGuestServiceServer
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

func NewScannerVPNServer(scanner privatevmv1.ScannerGuestServiceServer, factory DownloaderControllerFactory) (*ScannerVPNServer, error) {
	if scanner == nil || factory == nil {
		return nil, errors.New("scanner owner and VPN factory are required")
	}
	return &ScannerVPNServer{
		ScannerGuestServiceServer: scanner,
		network:                   &DownloaderVPNServer{expectedRole: session.RoleScanner, controllerFactory: factory},
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
	if server != nil {
		switch server.expectedRole {
		case session.RoleWorkstation, session.RoleDownloader, session.RoleScanner:
			return server.expectedRole
		}
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

func (server *ScannerVPNServer) ConfigureWireGuard(ctx context.Context, request *privatevmv1.ConfigureWireGuardRequest) (*privatevmv1.VPNStatus, error) {
	if server == nil || server.network == nil {
		return nil, guestRPCError(codes.FailedPrecondition, "GUEST_VPN_COMPOSITION_FAILED", "The guest network adapters are unavailable.", "Destroy the guest and install the verified scanner image.", false)
	}
	return server.network.ConfigureWireGuard(ctx, request)
}

func (server *ScannerVPNServer) VerifyVPN(ctx context.Context, request *privatevmv1.VerifyVPNRequest) (*privatevmv1.VPNStatus, error) {
	if server == nil || server.network == nil {
		return nil, guestRPCError(codes.FailedPrecondition, "GUEST_VPN_COMPOSITION_FAILED", "The guest network adapters are unavailable.", "Destroy the guest and install the verified scanner image.", false)
	}
	return server.network.VerifyVPN(ctx, request)
}

func (server *ScannerVPNServer) UpdateDefinitions(ctx context.Context, request *privatevmv1.ScannerRequest) (*privatevmv1.DefinitionsStatus, error) {
	if server == nil || server.network == nil || server.ScannerGuestServiceServer == nil || request == nil {
		return nil, guestRPCError(codes.FailedPrecondition, "GUEST_VPN_UNVERIFIED", "Scanner definitions cannot update before the guest VPN is verified.", "Configure and verify Proton through the authenticated host workflow before updating definitions.", false)
	}
	verified, err := server.network.VerifyVPN(ctx, &privatevmv1.VerifyVPNRequest{Context: request.GetContext()})
	if err != nil || verified == nil || !verified.GetConfigured() || !verified.GetHandshake() ||
		!verified.GetDnsThroughTunnel() || !verified.GetDnsBypassBlocked() || !verified.GetIpv4ThroughTunnel() ||
		!verified.GetIpv6ThroughTunnel() || !verified.GetIpv4BypassBlocked() || !verified.GetIpv6BypassBlocked() {
		return nil, guestRPCError(codes.FailedPrecondition, "GUEST_VPN_UNVERIFIED", "Scanner definitions cannot update before the guest VPN is verified.", "Configure and verify Proton through the authenticated host workflow before updating definitions.", false)
	}
	// The unforgeable in-process marker is consumed by the production boot
	// probe. It is scoped to this one serialized call and is set only after the
	// controller has repeated the complete verified-state proof above.
	return server.ScannerGuestServiceServer.UpdateDefinitions(scannerVPNVerifiedContext(ctx), request)
}

// Close tears down the scanner's VPN before closing parser/output resources.
// The embedded scanner owner remains the sole service-phase serializer.
func (server *ScannerVPNServer) Close(ctx context.Context) error {
	if server == nil {
		return nil
	}
	networkErr := server.network.StopVPN(ctx)
	var scannerErr error
	if closer, ok := server.ScannerGuestServiceServer.(interface{ Close(context.Context) error }); ok {
		scannerErr = closer.Close(ctx)
	}
	return errors.Join(networkErr, scannerErr)
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
var _ privatevmv1.ScannerGuestServiceServer = (*ScannerVPNServer)(nil)
