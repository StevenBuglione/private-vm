package main

import (
	"context"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/daemon"
	"github.com/StevenBuglione/private-vm/internal/orchestrator"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
)

// scannerRuntimeDaemonAdapter keeps the daemon API semantic while the concrete
// image/storage/QEMU owner remains in the host orchestrator package.
type scannerRuntimeDaemonAdapter struct {
	runtime *orchestrator.ProductionScannerRuntime
}

func (adapter scannerRuntimeDaemonAdapter) Preflight(ctx context.Context, source, scanner session.Snapshot) error {
	return adapter.runtime.Preflight(ctx, source, scanner)
}

func (adapter scannerRuntimeDaemonAdapter) VerifyImage(ctx context.Context, scanner session.Snapshot) error {
	return adapter.runtime.VerifyImage(ctx, scanner)
}

func (adapter scannerRuntimeDaemonAdapter) StorageAllocation(source, scanner session.Snapshot) session.AllocateFunc {
	return adapter.runtime.StorageAllocation(source, scanner)
}

func (adapter scannerRuntimeDaemonAdapter) UpdateRuntimeAllocation(scanner session.Snapshot) session.AllocateFunc {
	return adapter.runtime.UpdateRuntimeAllocation(scanner)
}

func (adapter scannerRuntimeDaemonAdapter) UpdateClient(ctx context.Context, scanner session.Snapshot) (privatevmv1.ScannerGuestServiceClient, error) {
	return adapter.runtime.UpdateClient(ctx, scanner)
}

func (adapter scannerRuntimeDaemonAdapter) StopUpdate(ctx context.Context, scanner session.Snapshot) error {
	return adapter.runtime.StopUpdate(ctx, scanner)
}

func (adapter scannerRuntimeDaemonAdapter) OfflineRuntimeAllocation(scanner session.Snapshot) session.AllocateFunc {
	return adapter.runtime.OfflineRuntimeAllocation(scanner)
}

func (adapter scannerRuntimeDaemonAdapter) OfflineClient(ctx context.Context, scanner session.Snapshot) (privatevmv1.ScannerGuestServiceClient, error) {
	return adapter.runtime.OfflineClient(ctx, scanner)
}

func (adapter scannerRuntimeDaemonAdapter) VerifyReport(ctx context.Context, scanner session.Snapshot, envelope scan.AuthenticatedReport) (scan.ScanReport, error) {
	return adapter.runtime.VerifyReport(ctx, scanner, envelope)
}

func (adapter scannerRuntimeDaemonAdapter) Promote(ctx context.Context, scanner session.Snapshot, evidence daemon.ScannerReportEvidence, destination daemon.ScannerDestination, target session.Snapshot) error {
	return adapter.runtime.Promote(ctx, scanner, evidence.Report, string(destination), target)
}

func (adapter scannerRuntimeDaemonAdapter) StopOffline(ctx context.Context, scanner session.Snapshot) error {
	return adapter.runtime.StopOffline(ctx, scanner)
}

var _ daemon.ScannerGuestRuntime = scannerRuntimeDaemonAdapter{}
