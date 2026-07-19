package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc"
)

const responderSessionID = "pvm-11111111111111111111111111111111"

func responderContext(t *testing.T, role session.Role) *privatevmv1.GuestContext {
	t.Helper()
	protoRole, err := guest.ProtoRole(role)
	if err != nil {
		t.Fatal(err)
	}
	return &privatevmv1.GuestContext{
		Context: &privatevmv1.RequestContext{
			ApiVersion: &privatevmv1.ApiVersion{Major: guest.APIMajor, Minor: guest.APIMinor},
			RequestId:  "request-123", SessionId: responderSessionID,
		},
		ExpectedRole: protoRole,
	}
}

func degradedVPNStatus() guestvpn.Status {
	return guestvpn.Status{SchemaVersion: 1, State: guestvpn.StateDegraded, KillSwitchArmed: true, Configured: true}
}

type warningClientFunc func(context.Context, *privatevmv1.NetworkWarningRequest) (*privatevmv1.Empty, error)

func (function warningClientFunc) ShowNetworkWarning(ctx context.Context, request *privatevmv1.NetworkWarningRequest, _ ...grpc.CallOption) (*privatevmv1.Empty, error) {
	return function(ctx, request)
}

type pauseClientFunc func(context.Context, *privatevmv1.TorrentRequest) (*privatevmv1.TorrentStatus, error)

func (function pauseClientFunc) PauseDownload(ctx context.Context, request *privatevmv1.TorrentRequest, _ ...grpc.CallOption) (*privatevmv1.TorrentStatus, error) {
	return function(ctx, request)
}

func TestWorkstationLossResponderSendsOnlyTypedBlockingWarning(t *testing.T) {
	requestContext := responderContext(t, session.RoleWorkstation)
	called := false
	responder, err := NewWorkstationWarningResponder(warningClientFunc(func(_ context.Context, request *privatevmv1.NetworkWarningRequest) (*privatevmv1.Empty, error) {
		called = true
		if request.GetWarningCode() != VPNWarningCode || request.GetContext().GetExpectedRole() != privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION ||
			request.GetContext().GetContext().GetSessionId() != responderSessionID {
			t.Fatalf("unexpected warning request: %#v", request)
		}
		return &privatevmv1.Empty{}, nil
	}), requestContext)
	if err != nil {
		t.Fatal(err)
	}
	requestContext.Context.SessionId = "mutated"
	if err := responder.OnVPNLoss(context.Background(), degradedVPNStatus()); err != nil || !called {
		t.Fatalf("warning response = called %v, %v", called, err)
	}
}

func TestDownloaderLossResponderRequiresConfirmedPausedState(t *testing.T) {
	called := false
	responder, err := NewDownloaderPauseResponder(pauseClientFunc(func(_ context.Context, request *privatevmv1.TorrentRequest) (*privatevmv1.TorrentStatus, error) {
		called = true
		if request.GetContext().GetExpectedRole() != privatevmv1.GuestRole_GUEST_ROLE_DOWNLOADER {
			t.Fatal("wrong role in pause request")
		}
		return &privatevmv1.TorrentStatus{State: TorrentPausedVPNLoss}, nil
	}), responderContext(t, session.RoleDownloader))
	if err != nil {
		t.Fatal(err)
	}
	if err := responder.OnVPNLoss(context.Background(), degradedVPNStatus()); err != nil || !called {
		t.Fatalf("pause response = called %v, %v", called, err)
	}

	responder.client = pauseClientFunc(func(context.Context, *privatevmv1.TorrentRequest) (*privatevmv1.TorrentStatus, error) {
		return &privatevmv1.TorrentStatus{State: "downloading"}, nil
	})
	if err := responder.OnVPNLoss(context.Background(), degradedVPNStatus()); err == nil {
		t.Fatal("unconfirmed pause passed")
	}
}

func TestVPNLossRespondersRejectUnsafeStateRoleAndTimeout(t *testing.T) {
	if _, err := NewWorkstationWarningResponder(warningClientFunc(nil), responderContext(t, session.RoleDownloader)); err == nil {
		t.Fatal("wrong-role warning responder passed")
	}
	responder, err := NewWorkstationWarningResponder(warningClientFunc(func(ctx context.Context, _ *privatevmv1.NetworkWarningRequest) (*privatevmv1.Empty, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}), responderContext(t, session.RoleWorkstation))
	if err != nil {
		t.Fatal(err)
	}
	responder.timeout = 10 * time.Millisecond
	if err := responder.OnVPNLoss(context.Background(), degradedVPNStatus()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("warning timeout = %v", err)
	}
	unsafe := degradedVPNStatus()
	unsafe.KillSwitchArmed = false
	if err := responder.OnVPNLoss(context.Background(), unsafe); err == nil {
		t.Fatal("loss response without kill switch passed")
	}
}
