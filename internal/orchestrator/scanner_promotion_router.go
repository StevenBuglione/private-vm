package orchestrator

import (
	"context"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
)

// ScannerPromotionRouter keeps workstation and USB promotion as separate,
// closed semantic relays while allowing the production scanner runtime to
// expose both frozen v1 destinations.
type ScannerPromotionRouter struct {
	workstation ScannerPromotionRelay
	usb         ScannerPromotionRelay
}

func NewScannerPromotionRouter(workstation, usb ScannerPromotionRelay) (*ScannerPromotionRouter, error) {
	if nilLikeHost(workstation) || nilLikeHost(usb) {
		return nil, ErrScannerPromotionPending
	}
	return &ScannerPromotionRouter{workstation: workstation, usb: usb}, nil
}

func (router *ScannerPromotionRouter) Promote(ctx context.Context, scanner session.Snapshot, report scan.ScanReport, destination string, target session.Snapshot, client privatevmv1.ScannerGuestServiceClient) error {
	if router == nil {
		return ErrScannerPromotionPending
	}
	switch destination {
	case "workstation":
		return router.workstation.Promote(ctx, scanner, report, destination, target, client)
	case "usb":
		return router.usb.Promote(ctx, scanner, report, destination, target, client)
	default:
		return ErrScannerPromotionPending
	}
}

func (router *ScannerPromotionRouter) ForgetScanner(sessionID string) {
	if router == nil {
		return
	}
	if cleanup, ok := router.workstation.(scannerPromotionCleanup); ok {
		cleanup.ForgetScanner(sessionID)
	}
	if cleanup, ok := router.usb.(scannerPromotionCleanup); ok {
		cleanup.ForgetScanner(sessionID)
	}
}
