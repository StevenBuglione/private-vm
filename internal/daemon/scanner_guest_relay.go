package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"sync"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
)

const maximumScannerRelayEvents = 1_000_004

// ScannerGuestRuntime owns concrete verified-image, storage, QEMU, QMP, VSOCK
// and token resources. Clients returned here must have completed the Hello
// identity handshake and must attach the per-boot capability through gRPC
// metadata; an implementation may not return an unauthenticated/TCP client.
// VerifyReport uses the volatile session report key and rejects a changed,
// noncanonical or incomplete envelope. Promote owns the bounded scanner-to-
// destination relay and its end-to-end hash proof.
type ScannerGuestRuntime interface {
	Preflight(context.Context, session.Snapshot, session.Snapshot) error
	VerifyImage(context.Context, session.Snapshot) error
	StorageAllocation(session.Snapshot, session.Snapshot) session.AllocateFunc
	UpdateRuntimeAllocation(session.Snapshot) session.AllocateFunc
	UpdateClient(context.Context, session.Snapshot) (privatevmv1.ScannerGuestServiceClient, error)
	StopUpdate(context.Context, session.Snapshot) error
	OfflineRuntimeAllocation(session.Snapshot) session.AllocateFunc
	OfflineClient(context.Context, session.Snapshot) (privatevmv1.ScannerGuestServiceClient, error)
	VerifyReport(context.Context, session.Snapshot, scan.AuthenticatedReport) (scan.ScanReport, error)
	Promote(context.Context, session.Snapshot, ScannerReportEvidence, ScannerDestination) error
	StopOffline(context.Context, session.Snapshot) error
}

// GuestScannerRelay is the production semantic adapter from the host daemon to
// the role-restricted ScannerGuestService. It retains authenticated report
// evidence only in memory so a rejected scanner may be powered off before the
// user inspects and explicitly cleans the result.
type GuestScannerRelay struct {
	runtime ScannerGuestRuntime
	mu      sync.RWMutex
	reports map[string]ScannerReportEvidence
}

func NewGuestScannerRelay(runtime ScannerGuestRuntime) (*GuestScannerRelay, error) {
	if runtime == nil {
		return nil, errors.New("scanner guest runtime is required")
	}
	return &GuestScannerRelay{runtime: runtime, reports: make(map[string]ScannerReportEvidence)}, nil
}

func (relay *GuestScannerRelay) Preflight(ctx context.Context, source, scanner session.Snapshot) error {
	return relay.runtime.Preflight(ctx, source, scanner)
}

func (relay *GuestScannerRelay) VerifyImage(ctx context.Context, scanner session.Snapshot) error {
	return relay.runtime.VerifyImage(ctx, scanner)
}

func (relay *GuestScannerRelay) StorageAllocation(source, scanner session.Snapshot) session.AllocateFunc {
	allocate := relay.runtime.StorageAllocation(source, scanner)
	if allocate == nil {
		return nil
	}
	return func(ctx context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		cleanup, audit, err := allocate(ctx)
		if cleanup == nil || audit == nil {
			return cleanup, audit, err
		}
		wrappedCleanup := func(cleanupContext context.Context) error {
			if cleanupErr := cleanup(cleanupContext); cleanupErr != nil {
				return cleanupErr
			}
			relay.mu.Lock()
			delete(relay.reports, scanner.ID)
			relay.mu.Unlock()
			return nil
		}
		return wrappedCleanup, audit, err
	}
}

func (relay *GuestScannerRelay) UpdateRuntimeAllocation(scanner session.Snapshot) session.AllocateFunc {
	return relay.runtime.UpdateRuntimeAllocation(scanner)
}

func (relay *GuestScannerRelay) UpdateDefinitions(ctx context.Context, scanner session.Snapshot) (*privatevmv1.DefinitionsStatus, error) {
	client, err := relay.runtime.UpdateClient(ctx, scanner)
	if err != nil {
		return nil, err
	}
	request, err := scannerGuestRequest(scanner.ID, "")
	if err != nil {
		return nil, err
	}
	return client.UpdateDefinitions(ctx, request)
}

func (relay *GuestScannerRelay) StopUpdate(ctx context.Context, scanner session.Snapshot) error {
	return relay.runtime.StopUpdate(ctx, scanner)
}

func (relay *GuestScannerRelay) OfflineRuntimeAllocation(scanner session.Snapshot) session.AllocateFunc {
	return relay.runtime.OfflineRuntimeAllocation(scanner)
}

func (relay *GuestScannerRelay) VerifyOffline(ctx context.Context, scanner session.Snapshot) (*privatevmv1.OfflineStatus, error) {
	client, err := relay.runtime.OfflineClient(ctx, scanner)
	if err != nil {
		return nil, err
	}
	request, err := scannerGuestRequest(scanner.ID, "")
	if err != nil {
		return nil, err
	}
	return client.VerifyOfflineMode(ctx, request)
}

func (relay *GuestScannerRelay) Inventory(ctx context.Context, scanner session.Snapshot, policyName string, send func(*privatevmv1.ScanEvent) error) error {
	client, request, err := relay.offlineRequest(ctx, scanner, policyName)
	if err != nil {
		return err
	}
	stream, err := client.Inventory(ctx, request)
	if err != nil {
		return err
	}
	return relayScannerStream(stream, send)
}

func (relay *GuestScannerRelay) Scan(ctx context.Context, scanner session.Snapshot, policyName string, send func(*privatevmv1.ScanEvent) error) error {
	client, request, err := relay.offlineRequest(ctx, scanner, policyName)
	if err != nil {
		return err
	}
	stream, err := client.Scan(ctx, request)
	if err != nil {
		return err
	}
	return relayScannerStream(stream, send)
}

func (relay *GuestScannerRelay) Reconstruct(ctx context.Context, scanner session.Snapshot, policyName string, send func(*privatevmv1.ScanEvent) error) error {
	client, request, err := relay.offlineRequest(ctx, scanner, policyName)
	if err != nil {
		return err
	}
	stream, err := client.Reconstruct(ctx, request)
	if err != nil {
		return err
	}
	return relayScannerStream(stream, send)
}

func (relay *GuestScannerRelay) Report(ctx context.Context, scanner session.Snapshot, policyName string) (ScannerReportEvidence, error) {
	relay.mu.RLock()
	cached, exists := relay.reports[scanner.ID]
	relay.mu.RUnlock()
	if exists {
		return cloneScannerEvidence(cached), nil
	}
	client, request, err := relay.offlineRequest(ctx, scanner, policyName)
	if err != nil {
		return ScannerReportEvidence{}, err
	}
	envelope, err := client.GetScanReport(ctx, request)
	if err != nil {
		return ScannerReportEvidence{}, err
	}
	if envelope == nil || len(envelope.GetCanonicalJson()) == 0 || len(envelope.GetCanonicalJson()) > scan.MaximumScanReportBytes || len(envelope.GetAuthenticationTag()) != scan.ScanReportMACBytes || !envelope.GetComplete() {
		return ScannerReportEvidence{}, errors.New("scanner report envelope is incomplete")
	}
	report, err := relay.runtime.VerifyReport(ctx, scanner, scan.AuthenticatedReport{
		CanonicalJSON: slices.Clone(envelope.GetCanonicalJson()), AuthenticationTag: slices.Clone(envelope.GetAuthenticationTag()), Complete: envelope.GetComplete(),
	})
	if err != nil {
		return ScannerReportEvidence{}, err
	}
	evidence := ScannerReportEvidence{Report: report}
	if err := validateScannerEvidence(scanner, evidence); err != nil {
		return ScannerReportEvidence{}, err
	}
	relay.mu.Lock()
	if existing, present := relay.reports[scanner.ID]; present {
		evidence = existing
	} else {
		relay.reports[scanner.ID] = cloneScannerEvidence(evidence)
	}
	relay.mu.Unlock()
	return cloneScannerEvidence(evidence), nil
}

func (relay *GuestScannerRelay) Promote(ctx context.Context, scanner session.Snapshot, evidence ScannerReportEvidence, destination ScannerDestination) error {
	if err := validateScannerEvidence(scanner, evidence); err != nil || evidence.Report.Result != "approved" {
		return errors.New("scanner report does not authorize promotion")
	}
	if destination != ScannerDestinationWorkstation && destination != ScannerDestinationUSB {
		return errors.New("scanner promotion destination is invalid")
	}
	return relay.runtime.Promote(ctx, scanner, cloneScannerEvidence(evidence), destination)
}

func (relay *GuestScannerRelay) StopOffline(ctx context.Context, scanner session.Snapshot) error {
	return relay.runtime.StopOffline(ctx, scanner)
}

func (relay *GuestScannerRelay) offlineRequest(ctx context.Context, scanner session.Snapshot, policyName string) (privatevmv1.ScannerGuestServiceClient, *privatevmv1.ScannerRequest, error) {
	client, err := relay.runtime.OfflineClient(ctx, scanner)
	if err != nil {
		return nil, nil, err
	}
	request, err := scannerGuestRequest(scanner.ID, policyName)
	if err != nil {
		return nil, nil, err
	}
	return client, request, nil
}

type scannerEventReceiver interface {
	Recv() (*privatevmv1.ScanEvent, error)
}

func relayScannerStream(stream scannerEventReceiver, send func(*privatevmv1.ScanEvent) error) error {
	if stream == nil || send == nil {
		return errors.New("scanner relay stream is unavailable")
	}
	complete := false
	for count := 0; count < maximumScannerRelayEvents; count++ {
		event, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			if !complete {
				return errors.New("scanner relay ended without complete evidence")
			}
			return nil
		}
		if err != nil {
			return err
		}
		if event == nil || complete {
			return errors.New("scanner relay event sequence is invalid")
		}
		if err := send(event); err != nil {
			return err
		}
		complete = event.GetComplete()
	}
	return errors.New("scanner relay event limit reached")
}

func scannerGuestRequest(sessionID, policyName string) (*privatevmv1.ScannerRequest, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, errors.New("scanner guest request identity is unavailable")
	}
	return &privatevmv1.ScannerRequest{
		Context: &privatevmv1.GuestContext{
			Context: &privatevmv1.RequestContext{
				ApiVersion: &privatevmv1.ApiVersion{Major: 1, Minor: 0},
				RequestId:  "scan-host-" + hex.EncodeToString(raw[:]), SessionId: sessionID,
			},
			ExpectedRole: privatevmv1.GuestRole_GUEST_ROLE_SCANNER,
		},
		PolicyName: policyName,
	}, nil
}

func cloneScannerEvidence(value ScannerReportEvidence) ScannerReportEvidence {
	report := value.Report
	report.Isolation.MountOptions = slices.Clone(report.Isolation.MountOptions)
	report.Inputs = slices.Clone(report.Inputs)
	report.Archives = slices.Clone(report.Archives)
	report.Findings = slices.Clone(report.Findings)
	report.SanitizedOutputs = slices.Clone(report.SanitizedOutputs)
	report.Tools = slices.Clone(report.Tools)
	return ScannerReportEvidence{Report: report}
}

var _ ScannerOrchestrator = (*GuestScannerRelay)(nil)
