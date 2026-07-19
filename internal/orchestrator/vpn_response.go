// Package orchestrator composes typed host-owned lifecycle dependencies. It
// never accepts generic commands, QEMU arguments, mounts, devices or network
// rules from an RPC caller.
package orchestrator

import (
	"context"
	"errors"
	"reflect"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const (
	vpnLossResponseTimeout = 5 * time.Second
	VPNWarningCode         = "VPN_DEGRADED"
	TorrentPausedVPNLoss   = "paused_vpn_loss"
)

type workstationWarningClient interface {
	ShowNetworkWarning(context.Context, *privatevmv1.NetworkWarningRequest, ...grpc.CallOption) (*privatevmv1.Empty, error)
}

type downloaderPauseClient interface {
	PauseDownload(context.Context, *privatevmv1.TorrentRequest, ...grpc.CallOption) (*privatevmv1.TorrentStatus, error)
}

type WorkstationWarningResponder struct {
	client  workstationWarningClient
	context *privatevmv1.GuestContext
	timeout time.Duration
}

func NewWorkstationWarningResponder(client workstationWarningClient, requestContext *privatevmv1.GuestContext) (*WorkstationWarningResponder, error) {
	if isNilLike(client) || guest.ValidateGuestContext(requestContext, session.RoleWorkstation) != nil {
		return nil, errors.New("workstation VPN-loss responder is invalid")
	}
	return &WorkstationWarningResponder{client: client, context: cloneGuestContext(requestContext), timeout: vpnLossResponseTimeout}, nil
}

func (responder *WorkstationWarningResponder) OnVPNLoss(ctx context.Context, status guestvpn.Status) error {
	if ctx == nil || responder == nil || isNilLike(responder.client) || !safeLossStatus(status) {
		return errors.New("workstation VPN-loss response rejected")
	}
	responseCtx, cancel := boundedContext(ctx, responder.effectiveTimeout())
	defer cancel()
	response, err := responder.client.ShowNetworkWarning(responseCtx, &privatevmv1.NetworkWarningRequest{
		Context: cloneGuestContext(responder.context), WarningCode: VPNWarningCode,
	})
	if err != nil || response == nil {
		if responseCtx.Err() != nil {
			return responseCtx.Err()
		}
		return errors.New("workstation VPN-loss warning failed")
	}
	return nil
}

func (responder *WorkstationWarningResponder) effectiveTimeout() time.Duration {
	if responder.timeout <= 0 || responder.timeout > vpnLossResponseTimeout {
		return vpnLossResponseTimeout
	}
	return responder.timeout
}

type DownloaderPauseResponder struct {
	client  downloaderPauseClient
	context *privatevmv1.GuestContext
	timeout time.Duration
}

func NewDownloaderPauseResponder(client downloaderPauseClient, requestContext *privatevmv1.GuestContext) (*DownloaderPauseResponder, error) {
	if isNilLike(client) || guest.ValidateGuestContext(requestContext, session.RoleDownloader) != nil {
		return nil, errors.New("downloader VPN-loss responder is invalid")
	}
	return &DownloaderPauseResponder{client: client, context: cloneGuestContext(requestContext), timeout: vpnLossResponseTimeout}, nil
}

func (responder *DownloaderPauseResponder) OnVPNLoss(ctx context.Context, status guestvpn.Status) error {
	if ctx == nil || responder == nil || isNilLike(responder.client) || !safeLossStatus(status) {
		return errors.New("downloader VPN-loss response rejected")
	}
	responseCtx, cancel := boundedContext(ctx, responder.effectiveTimeout())
	defer cancel()
	response, err := responder.client.PauseDownload(responseCtx, &privatevmv1.TorrentRequest{Context: cloneGuestContext(responder.context)})
	if err != nil || response == nil || response.GetState() != TorrentPausedVPNLoss {
		if responseCtx.Err() != nil {
			return responseCtx.Err()
		}
		return errors.New("downloader VPN-loss pause failed")
	}
	return nil
}

func (responder *DownloaderPauseResponder) effectiveTimeout() time.Duration {
	if responder.timeout <= 0 || responder.timeout > vpnLossResponseTimeout {
		return vpnLossResponseTimeout
	}
	return responder.timeout
}

func safeLossStatus(status guestvpn.Status) bool {
	return status.SchemaVersion == 1 && status.State == guestvpn.StateDegraded && status.KillSwitchArmed && status.Configured
}

func cloneGuestContext(value *privatevmv1.GuestContext) *privatevmv1.GuestContext {
	if value == nil {
		return nil
	}
	return proto.Clone(value).(*privatevmv1.GuestContext)
}

func boundedContext(ctx context.Context, maximum time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(maximum)
	if current, ok := ctx.Deadline(); ok && current.Before(deadline) {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, deadline)
}

func isNilLike(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ guestvpn.LossResponder = (*WorkstationWarningResponder)(nil)
var _ guestvpn.LossResponder = (*DownloaderPauseResponder)(nil)
