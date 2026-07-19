package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/torrent"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type recordingWorkstationVPNClient struct {
	privatevmv1.WorkstationGuestServiceClient
	request *privatevmv1.ConfigureWireGuardRequest
	verify  int
}

func (client *recordingWorkstationVPNClient) ConfigureWireGuard(_ context.Context, request *privatevmv1.ConfigureWireGuardRequest, _ ...grpc.CallOption) (*privatevmv1.VPNStatus, error) {
	client.request = proto.Clone(request).(*privatevmv1.ConfigureWireGuardRequest)
	return verifiedVPNStatus(false), nil
}

func (client *recordingWorkstationVPNClient) VerifyVPN(context.Context, *privatevmv1.VerifyVPNRequest, ...grpc.CallOption) (*privatevmv1.VPNStatus, error) {
	client.verify++
	return verifiedVPNStatus(false), nil
}

type recordingDownloaderVPNClient struct {
	privatevmv1.DownloaderGuestServiceClient
	request *privatevmv1.ConfigureWireGuardRequest
	verify  int
}

func (client *recordingDownloaderVPNClient) ConfigureWireGuard(_ context.Context, request *privatevmv1.ConfigureWireGuardRequest, _ ...grpc.CallOption) (*privatevmv1.VPNStatus, error) {
	client.request = proto.Clone(request).(*privatevmv1.ConfigureWireGuardRequest)
	return verifiedVPNStatus(true), nil
}

func (client *recordingDownloaderVPNClient) VerifyVPN(context.Context, *privatevmv1.VerifyVPNRequest, ...grpc.CallOption) (*privatevmv1.VPNStatus, error) {
	client.verify++
	return verifiedVPNStatus(true), nil
}

func verifiedVPNStatus(torrentBound bool) *privatevmv1.VPNStatus {
	return &privatevmv1.VPNStatus{
		Configured: true, Handshake: true, DnsThroughTunnel: true, DnsBypassBlocked: true,
		Ipv4ThroughTunnel: true, Ipv4BypassBlocked: true, Ipv6ThroughTunnel: true,
		Ipv6BypassBlocked: true, TorrentBound: torrentBound,
	}
}

type recordingTorrentSender struct {
	frames []*privatevmv1.TorrentInputFrame
	err    error
}

func (sender *recordingTorrentSender) Send(frame *privatevmv1.TorrentInputFrame) error {
	if sender.err != nil {
		return sender.err
	}
	sender.frames = append(sender.frames, proto.Clone(frame).(*privatevmv1.TorrentInputFrame))
	return nil
}

func TestSendTorrentInputFramesBoundedInputAndContextOnce(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, (16<<10)+37)
	request := &privatevmv1.GuestContext{Context: &privatevmv1.RequestContext{SessionId: hostRoleSessionID}}
	sender := &recordingTorrentSender{}
	if err := sendTorrentInput(sender, request, torrent.InputMetainfo, bytes.NewReader(payload), len(payload)); err != nil {
		t.Fatal(err)
	}
	if len(sender.frames) != 2 || sender.frames[0].GetContext() == nil || sender.frames[1].GetContext() != nil ||
		sender.frames[0].GetFinal() || !sender.frames[1].GetFinal() {
		t.Fatalf("unexpected frame envelope: %+v", sender.frames)
	}
	combined := append(append([]byte(nil), sender.frames[0].GetTorrentChunk()...), sender.frames[1].GetTorrentChunk()...)
	if !bytes.Equal(combined, payload) {
		t.Fatal("framed payload changed")
	}
}

func TestSendTorrentInputRejectsEmptyOversizeAndSendFailure(t *testing.T) {
	request := &privatevmv1.GuestContext{}
	if err := sendTorrentInput(&recordingTorrentSender{}, request, torrent.InputMagnet, bytes.NewReader(nil), 32); !errors.Is(err, torrent.ErrInvalidInput) {
		t.Fatalf("empty input error = %v", err)
	}
	if err := sendTorrentInput(&recordingTorrentSender{}, request, torrent.InputMagnet, bytes.NewReader(bytes.Repeat([]byte{'x'}, 33)), 32); !errors.Is(err, torrent.ErrInputTooLarge) {
		t.Fatalf("oversize error = %v", err)
	}
	want := errors.New("send failed")
	if err := sendTorrentInput(&recordingTorrentSender{err: want}, request, torrent.InputMagnet, bytes.NewReader([]byte("magnet:?xt=fixture")), 64); !errors.Is(err, want) {
		t.Fatalf("send error = %v", err)
	}
}

func TestVSOCKGuestConnectionRoutesTypedVPNRequestByRole(t *testing.T) {
	underlay, err := guestvpn.NewUnderlay(
		netip.MustParsePrefix("10.240.0.2/30"), netip.MustParseAddr("10.240.0.1"),
		netip.MustParsePrefix("fd70:766d::2/126"), netip.MustParseAddr("fd70:766d::1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := guestvpn.NewProbeTargets(
		"one.one.one.one", netip.MustParseAddrPort("1.1.1.1:853"),
		netip.MustParseAddrPort("[2606:4700:4700::1111]:853"),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []session.Role{session.RoleWorkstation, session.RoleDownloader} {
		workstation := &recordingWorkstationVPNClient{}
		downloader := &recordingDownloaderVPNClient{}
		connection := &vsockGuestConnection{
			role: role, expected: guestHandshakeExpectation(), probeTargets: targets,
			workstation: workstation, downloader: downloader,
		}
		status, err := connection.ConfigureVPN(t.Context(), underlay, bytes.NewReader([]byte("profile-fixture")))
		if err != nil || status.State != guestvpn.StateVerified {
			t.Fatalf("role %s configure = (%+v, %v)", role, status, err)
		}
		if _, err := connection.VerifyVPN(t.Context()); err != nil {
			t.Fatalf("role %s verify = %v", role, err)
		}
		request := workstation.request
		if role == session.RoleDownloader {
			request = downloader.request
			if workstation.request != nil || workstation.verify != 0 || downloader.verify != 1 {
				t.Fatalf("downloader used wrong generated service")
			}
		} else if downloader.request != nil || downloader.verify != 0 || workstation.verify != 1 {
			t.Fatalf("workstation used wrong generated service")
		}
		if request == nil || request.GetContext().GetExpectedRole().String() == "GUEST_ROLE_UNSPECIFIED" ||
			!bytes.Equal(request.GetUnderlay().GetIpv4Address(), netip.MustParseAddr("10.240.0.2").AsSlice()) ||
			request.GetProbeTargets().GetDnsName() != "one.one.one.one" || request.GetProbeTargets().GetIpv4Port() != 853 || request.GetProbeTargets().GetIpv6Port() != 853 {
			t.Fatalf("role %s received incomplete typed request: %+v", role, request)
		}
	}
}

func guestHandshakeExpectation() guest.HandshakeExpectation {
	return guest.HandshakeExpectation{SessionID: hostRoleSessionID}
}

func TestRuntimeSocketDirectoriesCleanupIsIdempotent(t *testing.T) {
	runtimeRoot := t.TempDir()
	parent := filepath.Join(runtimeRoot, hostRoleSessionID)
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	directories, err := createRuntimeSocketDirectories(runtimeRoot, hostRoleSessionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := directories.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := directories.Cleanup(); err != nil {
		t.Fatalf("repeated cleanup = %v", err)
	}
	if err := directories.Audit(); err != nil {
		t.Fatal(err)
	}
}
