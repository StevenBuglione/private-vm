package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/torrent"
	"google.golang.org/grpc"
)

const (
	maximumGuestVPNProfileBytes = 64 << 10
	maximumTorrentEvents        = 4096
)

type VSOCKGuestConnector struct {
	Expected     guest.HandshakeExpectation
	ProbeTargets guestvpn.ProbeTargets
}

func (connector VSOCKGuestConnector) Connect(ctx context.Context, cid uint32, role session.Role, capability Capability) (GuestConnection, error) {
	token, ok := capability.(*guest.Token)
	if !ok || token == nil || connector.Expected.Role != role || connector.Expected.SessionID == "" {
		return nil, ErrNetworkedStart
	}
	connection, err := guest.Dial(guest.ClientConfig{CID: cid, Port: guest.DefaultPort, Token: token})
	if err != nil {
		return nil, err
	}
	return &vsockGuestConnection{
		connection: connection, role: role, expected: connector.Expected,
		common:           privatevmv1.NewGuestCommonServiceClient(connection),
		workstation:      privatevmv1.NewWorkstationGuestServiceClient(connection),
		downloader:       privatevmv1.NewDownloaderGuestServiceClient(connection),
		scanner:          privatevmv1.NewScannerGuestServiceClient(connection),
		probeTargets:     connector.ProbeTargets,
		workspaceExports: make(map[string][32]byte),
	}, nil
}

type vsockGuestConnection struct {
	mu sync.Mutex

	connection       *grpc.ClientConn
	role             session.Role
	expected         guest.HandshakeExpectation
	common           privatevmv1.GuestCommonServiceClient
	workstation      privatevmv1.WorkstationGuestServiceClient
	downloader       privatevmv1.DownloaderGuestServiceClient
	scanner          privatevmv1.ScannerGuestServiceClient
	probeTargets     guestvpn.ProbeTargets
	workspaceExports map[string][32]byte
	closed           bool
}

func (connection *vsockGuestConnection) Handshake(ctx context.Context) error {
	expected := connection.expected
	requestID, err := newGuestRequestID()
	if err != nil {
		return err
	}
	expected.RequestID = requestID
	_, err = guest.Handshake(ctx, connection.common, expected)
	return err
}

func (connection *vsockGuestConnection) ConfigureVPN(ctx context.Context, underlay guestvpn.Underlay, profile io.Reader) (guestvpn.Status, error) {
	if connection.role != session.RoleWorkstation && connection.role != session.RoleDownloader && connection.role != session.RoleScanner {
		return guestvpn.Status{}, ErrNetworkedStart
	}
	data, err := io.ReadAll(io.LimitReader(profile, maximumGuestVPNProfileBytes+1))
	if err != nil || len(data) == 0 || len(data) > maximumGuestVPNProfileBytes {
		clear(data)
		return guestvpn.Status{}, ErrNetworkedStart
	}
	defer clear(data)
	request, err := connection.guestContext()
	if err != nil {
		return guestvpn.Status{}, err
	}
	protoUnderlay, protoTargets := guest.EncodeDownloaderNetworkRequest(underlay, connection.probeTargets)
	configure := &privatevmv1.ConfigureWireGuardRequest{Context: request, Profile: data, Underlay: protoUnderlay, ProbeTargets: protoTargets}
	defer func() {
		clear(protoUnderlay.Ipv4Address)
		clear(protoUnderlay.Ipv4Gateway)
		clear(protoUnderlay.Ipv6Address)
		clear(protoUnderlay.Ipv6Gateway)
		clear(protoTargets.Ipv4Address)
		clear(protoTargets.Ipv6Address)
		protoTargets.DnsName = ""
	}()
	var response *privatevmv1.VPNStatus
	switch connection.role {
	case session.RoleWorkstation:
		response, err = connection.workstation.ConfigureWireGuard(ctx, configure)
	case session.RoleDownloader:
		response, err = connection.downloader.ConfigureWireGuard(ctx, configure)
	case session.RoleScanner:
		response, err = connection.scanner.ConfigureWireGuard(ctx, configure)
	default:
		err = ErrNetworkedStart
	}
	clear(configure.Profile)
	configure.Profile = nil
	return vpnStatus(response, connection.role), err
}

func (connection *vsockGuestConnection) VerifyVPN(ctx context.Context) (guestvpn.Status, error) {
	request, err := connection.guestContext()
	if err != nil {
		return guestvpn.Status{}, err
	}
	var response *privatevmv1.VPNStatus
	switch connection.role {
	case session.RoleWorkstation:
		response, err = connection.workstation.VerifyVPN(ctx, &privatevmv1.VerifyVPNRequest{Context: request})
	case session.RoleDownloader:
		response, err = connection.downloader.VerifyVPN(ctx, &privatevmv1.VerifyVPNRequest{Context: request})
	case session.RoleScanner:
		response, err = connection.scanner.VerifyVPN(ctx, &privatevmv1.VerifyVPNRequest{Context: request})
	default:
		err = ErrNetworkedStart
	}
	return vpnStatus(response, connection.role), err
}

func (connection *vsockGuestConnection) MonitorVPN(ctx context.Context, interval time.Duration, responder guestvpn.LossResponder) error {
	if interval <= 0 || interval > 5*time.Minute || responder == nil {
		return ErrNetworkedStart
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			probeCtx, cancel := context.WithTimeout(ctx, minDuration(interval, 5*time.Second))
			status, err := connection.VerifyVPN(probeCtx)
			cancel()
			if err == nil && verifiedStatus(status, connection.role) {
				continue
			}
			degraded := status
			degraded.State = guestvpn.StateDegraded
			degraded.Code = "GUEST_VPN_TUNNEL_LOST"
			if responseErr := connection.respondToVPNLoss(ctx); responseErr != nil {
				return responseErr
			}
			if err := responder.OnVPNLoss(ctx, degraded); err != nil {
				return err
			}
			return guestvpn.ErrTunnelLost
		}
	}
}

func (connection *vsockGuestConnection) respondToVPNLoss(ctx context.Context) error {
	request, err := connection.guestContext()
	if err != nil {
		return err
	}
	switch connection.role {
	case session.RoleWorkstation:
		_, err = connection.workstation.ShowNetworkWarning(ctx, &privatevmv1.NetworkWarningRequest{Context: request, WarningCode: "VPN_DEGRADED"})
	case session.RoleDownloader:
		_, err = connection.downloader.PauseDownload(ctx, &privatevmv1.TorrentRequest{Context: request})
	case session.RoleScanner:
		_, err = connection.common.Shutdown(ctx, &privatevmv1.ShutdownRequest{Context: request, Poweroff: true})
	default:
		err = ErrNetworkedStart
	}
	return err
}

func (connection *vsockGuestConnection) ScannerClient() (privatevmv1.ScannerGuestServiceClient, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.role != session.RoleScanner || connection.closed || connection.scanner == nil {
		return nil, ErrNetworkedStart
	}
	return connection.scanner, nil
}

func (connection *vsockGuestConnection) WorkspaceDirty(ctx context.Context) (bool, error) {
	state, err := connection.WorkspaceState(ctx)
	if err != nil {
		return false, err
	}
	return state != "CLEAN" && state != "READY", nil
}

func (connection *vsockGuestConnection) WorkspaceState(ctx context.Context) (string, error) {
	if connection.role != session.RoleWorkstation {
		return "", ErrNetworkedStart
	}
	request, err := connection.guestContext()
	if err != nil {
		return "", err
	}
	response, err := connection.workstation.GetWorkspaceState(ctx, &privatevmv1.WorkspaceStateRequest{Context: request})
	if err != nil {
		return "", err
	}
	switch response.GetState() {
	case "CLEAN", "READY", "UNEXPORTED", "CHANGED":
		return response.GetState(), nil
	default:
		return "", ErrNetworkedNotVerified
	}
}

func (connection *vsockGuestConnection) Shutdown(ctx context.Context) error {
	request, err := connection.guestContext()
	if err != nil {
		return err
	}
	_, err = connection.common.Shutdown(ctx, &privatevmv1.ShutdownRequest{Context: request, Poweroff: true})
	return err
}

func (connection *vsockGuestConnection) Close() error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.closed {
		return nil
	}
	connection.closed = true
	clear(connection.workspaceExports)
	connection.workspaceExports = nil
	return connection.connection.Close()
}

func (connection *vsockGuestConnection) Add(ctx context.Context, kind torrent.InputKind, source io.Reader) (*privatevmv1.TorrentMetadata, error) {
	if connection.role != session.RoleDownloader || source == nil {
		return nil, torrent.ErrInvalidRequest
	}
	stream, err := connection.downloader.AddTorrent(ctx)
	if err != nil {
		return nil, err
	}
	maximum := torrent.MaximumMetainfoBytes
	if kind == torrent.InputMagnet {
		maximum = torrent.MaximumMagnetBytes
	} else if kind != torrent.InputMetainfo {
		return nil, torrent.ErrInvalidInput
	}
	request, err := connection.guestContext()
	if err != nil {
		return nil, err
	}
	if err := sendTorrentInput(stream, request, kind, source, maximum); err != nil {
		return nil, err
	}
	return stream.CloseAndRecv()
}

func (connection *vsockGuestConnection) Metadata(ctx context.Context) (*privatevmv1.TorrentMetadata, error) {
	request, err := connection.torrentContext()
	if err != nil {
		return nil, err
	}
	return connection.downloader.GetTorrentMetadata(ctx, request)
}

func (connection *vsockGuestConnection) Select(ctx context.Context, indexes []uint32, evidence torrent.CapacityEvidence) (*privatevmv1.TorrentMetadata, error) {
	request, err := connection.guestContext()
	if err != nil {
		return nil, err
	}
	receipt, err := torrentCapacityReceipt(evidence)
	if err != nil {
		return nil, err
	}
	return connection.downloader.SelectTorrentFiles(ctx, &privatevmv1.SelectTorrentFilesRequest{
		Context: request, Indexes: append([]uint32(nil), indexes...), Capacity: receipt,
	})
}

func torrentCapacityReceipt(evidence torrent.CapacityEvidence) (*privatevmv1.TorrentCapacityReceipt, error) {
	var destination privatevmv1.TorrentDestination
	switch evidence.Destination {
	case torrent.DestinationWorkstation:
		destination = privatevmv1.TorrentDestination_TORRENT_DESTINATION_WORKSTATION
	case torrent.DestinationUSB:
		destination = privatevmv1.TorrentDestination_TORRENT_DESTINATION_USB
	default:
		return nil, torrent.ErrCapacityEvidence
	}
	if evidence.ScanAvailableBytes == 0 || evidence.ReconstructionAvailable == 0 || evidence.DestinationAvailable == 0 ||
		evidence.RootOverlayBudgetBytes == 0 || evidence.ReconstructionBytes == 0 || evidence.MaximumOutputBytes == 0 || evidence.MaximumSelectedBytes == 0 {
		return nil, torrent.ErrCapacityEvidence
	}
	return &privatevmv1.TorrentCapacityReceipt{
		SchemaVersion: 1, Destination: destination,
		ScanAvailableBytes:           evidence.ScanAvailableBytes,
		ReconstructionAvailableBytes: evidence.ReconstructionAvailable,
		DestinationAvailableBytes:    evidence.DestinationAvailable,
		RootOverlayBudgetBytes:       evidence.RootOverlayBudgetBytes,
		ArchiveExpansionBytes:        evidence.ArchiveExpansionBytes,
		ReconstructionBytes:          evidence.ReconstructionBytes,
		MaximumOutputBytes:           evidence.MaximumOutputBytes,
		MaximumSelectedBytes:         evidence.MaximumSelectedBytes,
	}, nil
}

func (connection *vsockGuestConnection) Start(ctx context.Context, emit func(*privatevmv1.TorrentEvent) error) error {
	if emit == nil {
		return torrent.ErrInvalidRequest
	}
	request, err := connection.torrentContext()
	if err != nil {
		return err
	}
	stream, err := connection.downloader.StartDownload(ctx, request)
	if err != nil {
		return err
	}
	for count := 0; count < maximumTorrentEvents; count++ {
		event, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := emit(event); err != nil {
			return err
		}
	}
	return torrent.ErrDownloadFailed
}

func (connection *vsockGuestConnection) Pause(ctx context.Context) (*privatevmv1.TorrentStatus, error) {
	request, err := connection.torrentContext()
	if err != nil {
		return nil, err
	}
	return connection.downloader.PauseDownload(ctx, request)
}

func (connection *vsockGuestConnection) Status(ctx context.Context) (*privatevmv1.TorrentStatus, error) {
	request, err := connection.torrentContext()
	if err != nil {
		return nil, err
	}
	return connection.downloader.GetDownloadStatus(ctx, request)
}

func (connection *vsockGuestConnection) Seal(ctx context.Context) (*privatevmv1.TorrentStatus, error) {
	request, err := connection.torrentContext()
	if err != nil {
		return nil, err
	}
	if _, err := connection.downloader.SealQuarantine(ctx, request); err != nil {
		return nil, err
	}
	return &privatevmv1.TorrentStatus{State: "QUARANTINE_SEALED", Diagnostics: []*privatevmv1.Diagnostic{{
		Code: "QUARANTINE_SEALED", Severity: privatevmv1.Diagnostic_SEVERITY_INFO,
		Summary: "The downloader sealed the quarantine.", Remediation: "Continue only after downloader teardown is audited.",
	}}}, nil
}

func (connection *vsockGuestConnection) torrentContext() (*privatevmv1.TorrentRequest, error) {
	if connection.role != session.RoleDownloader {
		return nil, torrent.ErrInvalidRequest
	}
	request, err := connection.guestContext()
	if err != nil {
		return nil, err
	}
	return &privatevmv1.TorrentRequest{Context: request}, nil
}

func (connection *vsockGuestConnection) guestContext() (*privatevmv1.GuestContext, error) {
	requestID, err := newGuestRequestID()
	if err != nil {
		return nil, err
	}
	role, err := guest.ProtoRole(connection.role)
	if err != nil {
		return nil, err
	}
	return &privatevmv1.GuestContext{Context: &privatevmv1.RequestContext{
		ApiVersion: &privatevmv1.ApiVersion{Major: guest.APIMajor, Minor: guest.APIMinor},
		RequestId:  requestID, SessionId: connection.expected.SessionID,
	}, ExpectedRole: role}, nil
}

type torrentInputSender interface {
	Send(*privatevmv1.TorrentInputFrame) error
}

func sendTorrentInput(stream torrentInputSender, request *privatevmv1.GuestContext, kind torrent.InputKind, source io.Reader, maximum int) error {
	if stream == nil || request == nil || source == nil || maximum <= 0 ||
		(kind != torrent.InputMagnet && kind != torrent.InputMetainfo) {
		return torrent.ErrInvalidInput
	}
	current := make([]byte, 16<<10)
	next := make([]byte, 16<<10)
	defer clear(current)
	defer clear(next)
	currentCount, currentErr := io.ReadFull(source, current)
	if currentErr != nil && !errors.Is(currentErr, io.EOF) && !errors.Is(currentErr, io.ErrUnexpectedEOF) {
		return currentErr
	}
	if currentCount == 0 {
		return torrent.ErrInvalidInput
	}
	if currentCount > maximum {
		return torrent.ErrInputTooLarge
	}
	total := currentCount
	first := true
	for {
		nextCount, nextErr := io.ReadFull(source, next)
		if nextErr != nil && !errors.Is(nextErr, io.EOF) && !errors.Is(nextErr, io.ErrUnexpectedEOF) {
			return nextErr
		}
		if nextCount > maximum-total {
			return torrent.ErrInputTooLarge
		}
		total += nextCount
		final := (errors.Is(nextErr, io.EOF) || errors.Is(nextErr, io.ErrUnexpectedEOF)) && nextCount == 0
		frame := &privatevmv1.TorrentInputFrame{Final: final}
		if first {
			frame.Context = request
			first = false
		}
		chunk := append([]byte(nil), current[:currentCount]...)
		if kind == torrent.InputMagnet {
			frame.Frame = &privatevmv1.TorrentInputFrame_MagnetChunk{MagnetChunk: chunk}
		} else {
			frame.Frame = &privatevmv1.TorrentInputFrame_TorrentChunk{TorrentChunk: chunk}
		}
		if err := stream.Send(frame); err != nil {
			clear(chunk)
			return err
		}
		clear(chunk)
		clear(current[:currentCount])
		if final {
			return nil
		}
		if nextCount == 0 || (nextErr != nil && !errors.Is(nextErr, io.ErrUnexpectedEOF)) {
			return torrent.ErrInvalidInput
		}
		current, next = next, current
		currentCount = nextCount
	}
}

func vpnStatus(response *privatevmv1.VPNStatus, role session.Role) guestvpn.Status {
	if response == nil {
		return guestvpn.Status{}
	}
	result := guestvpn.Status{
		SchemaVersion: 1, KillSwitchArmed: response.GetConfigured(), Configured: response.GetConfigured(),
		Handshake: response.GetHandshake(), DNSThroughTunnel: response.GetDnsThroughTunnel(), DNSBypassBlocked: response.GetDnsBypassBlocked(),
		IPv4ThroughTunnel: response.GetIpv4ThroughTunnel(), IPv6ThroughTunnel: response.GetIpv6ThroughTunnel(),
		IPv4BypassBlocked: response.GetIpv4BypassBlocked(), IPv6BypassBlocked: response.GetIpv6BypassBlocked(), TorrentBound: response.GetTorrentBound(),
	}
	if result.Configured && result.Handshake && result.DNSThroughTunnel && result.DNSBypassBlocked && result.IPv4ThroughTunnel &&
		result.IPv4BypassBlocked && result.IPv6BypassBlocked && (role != session.RoleDownloader || result.TorrentBound) {
		result.State = guestvpn.StateVerified
		result.Code = "GUEST_VPN_VERIFIED"
	} else if result.Configured {
		result.State = guestvpn.StateConfigured
		result.Code = "GUEST_VPN_NOT_VERIFIED"
	}
	return result
}

func newGuestRequestID() (string, error) {
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "host-" + hex.EncodeToString(value[:]), nil
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

type inertHostLossResponder struct{}

func (inertHostLossResponder) OnVPNLoss(context.Context, guestvpn.Status) error { return nil }

var _ GuestConnector = VSOCKGuestConnector{}
var _ GuestConnection = (*vsockGuestConnection)(nil)
var _ TorrentRelay = (*vsockGuestConnection)(nil)
