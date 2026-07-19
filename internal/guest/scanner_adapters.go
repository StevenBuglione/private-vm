package guest

import (
	"context"
	"io"

	"github.com/StevenBuglione/private-vm/internal/policy"
	"github.com/StevenBuglione/private-vm/internal/scan"
)

// NewFailClosedScannerService installs the implemented RPC state machine while
// the image-specific evidence, receipt and external-tool adapters are absent.
// It is used by the generic source composition root; official scanner images
// must replace these adapters with their pinned system composition. Starting
// the service is safe, and every scanner operation returns a typed blocking
// error rather than pretending an unverified check succeeded.
func NewFailClosedScannerService(identity Identity, reportKey *Token) (*ScannerService, error) {
	unavailable := unavailableScannerAdapters{}
	return NewScannerService(ScannerServiceConfig{
		Identity: identity, Definitions: unavailable, Isolation: unavailable,
		Inventory: unavailable, Malware: unavailable, Reconstruction: unavailable,
		Policies:       unavailable,
		Tools:          []scan.ToolEvidence{{Name: "private-vm-guestd", Version: identity.GuestdVersion}},
		CleanupTimeout: defaultScannerCleanupTimeout,
	}, reportKey)
}

type unavailableScannerAdapters struct{}

func (unavailableScannerAdapters) Update(context.Context) (scan.UpdateReceipt, error) {
	return scan.UpdateReceipt{}, scannerAdapterUnavailable("definition update")
}

func (unavailableScannerAdapters) Status(context.Context) (scan.UpdateReceipt, error) {
	return scan.UpdateReceipt{}, scannerAdapterUnavailable("definition receipt")
}

func (unavailableScannerAdapters) Verify(context.Context, scan.UpdateReceipt) (scan.BootEvidence, error) {
	return scan.BootEvidence{}, scannerAdapterUnavailable("offline isolation")
}

func (unavailableScannerAdapters) Inventory(context.Context, policy.Policy) (scan.Inventory, error) {
	return scan.Inventory{}, scannerAdapterUnavailable("inventory")
}

func (unavailableScannerAdapters) Scan(context.Context, scan.Inventory, policy.Policy) (scan.ScanSummary, error) {
	return scan.ScanSummary{}, scannerAdapterUnavailable("malware scanner")
}

func (unavailableScannerAdapters) Reconstruct(context.Context, scan.Inventory, scan.ScanSummary, policy.Policy) (ScannerReconstruction, error) {
	return ScannerReconstruction{}, scannerAdapterUnavailable("reconstruction")
}

func (unavailableScannerAdapters) OpenApproved(context.Context, string) (io.ReadCloser, error) {
	return nil, scannerAdapterUnavailable("approved output")
}

func (unavailableScannerAdapters) Cleanup(context.Context) error { return nil }

func (unavailableScannerAdapters) Resolve(string) (policy.Policy, error) {
	return policy.Policy{}, scannerAdapterUnavailable("policy")
}

// ScannerBootProbe collects guest-local state. Implementations must use fixed,
// image-owned paths and must not accept evidence supplied by the host request.
type ScannerBootProbe interface {
	Evidence(context.Context) (scan.BootEvidence, error)
}

// ScannerReceiptStore persists only non-secret definition evidence in the
// retained scanner overlay. Its implementation is responsible for bounded,
// strict decoding and identity-safe atomic replacement.
type ScannerReceiptStore interface {
	Save(context.Context, scan.UpdateReceipt) error
	Load(context.Context) (scan.UpdateReceipt, error)
}

// ScannerOfflineBootStager makes the immutable scanner-offline Nix
// specialisation the next boot target. It exposes no path, boot entry, command
// or argument supplied by an RPC caller.
type ScannerOfflineBootStager interface {
	Stage(context.Context) error
}

// CoreScannerDefinitions binds the source scanner definition manager to an
// independently probed boot and an overlay-backed receipt store.
type CoreScannerDefinitions struct {
	Manager scan.DefinitionManager
	Probe   ScannerBootProbe
	Store   ScannerReceiptStore
	Stager  ScannerOfflineBootStager
}

func (adapter CoreScannerDefinitions) Update(ctx context.Context) (scan.UpdateReceipt, error) {
	if adapter.Probe == nil || adapter.Store == nil || adapter.Stager == nil {
		return scan.UpdateReceipt{}, scannerAdapterUnavailable("definition update")
	}
	boot, err := adapter.Probe.Evidence(ctx)
	if err != nil {
		return scan.UpdateReceipt{}, scannerAdapterError("SCANNER_EVIDENCE_UNAVAILABLE", "Scanner boot evidence could not be collected.", "Destroy the scanner and retry with the verified scanner image.", err)
	}
	receipt, err := adapter.Manager.Update(ctx, boot)
	if err != nil {
		return scan.UpdateReceipt{}, err
	}
	if err := adapter.Store.Save(ctx, receipt); err != nil {
		return scan.UpdateReceipt{}, scannerAdapterError("SCANNER_RECEIPT_WRITE_FAILED", "Definition evidence could not be committed to the retained overlay.", "Destroy the scanner and repeat the online update boot.", err)
	}
	if err := adapter.Stager.Stage(ctx); err != nil {
		return scan.UpdateReceipt{}, err
	}
	return receipt, nil
}

func (adapter CoreScannerDefinitions) Status(ctx context.Context) (scan.UpdateReceipt, error) {
	if adapter.Store == nil {
		return scan.UpdateReceipt{}, scannerAdapterUnavailable("definition receipt")
	}
	receipt, err := adapter.Store.Load(ctx)
	if err != nil {
		return scan.UpdateReceipt{}, scannerAdapterError("SCANNER_RECEIPT_UNAVAILABLE", "Definition evidence is unavailable from the retained overlay.", "Repeat the online update boot before scanning.", err)
	}
	if err := adapter.Manager.ValidateCurrent(receipt.Definitions); err != nil {
		return scan.UpdateReceipt{}, err
	}
	return receipt, nil
}

// CoreScannerIsolation applies the core same-overlay/no-network/read-only
// decision to boot evidence collected inside the offline guest.
type CoreScannerIsolation struct {
	Manager scan.DefinitionManager
	Probe   ScannerBootProbe
}

func (adapter CoreScannerIsolation) Verify(ctx context.Context, receipt scan.UpdateReceipt) (scan.BootEvidence, error) {
	if adapter.Probe == nil {
		return scan.BootEvidence{}, scannerAdapterUnavailable("offline isolation")
	}
	boot, err := adapter.Probe.Evidence(ctx)
	if err != nil {
		return scan.BootEvidence{}, scannerAdapterError("SCANNER_EVIDENCE_UNAVAILABLE", "Offline scanner evidence could not be collected.", "Destroy the scanner and retry with the verified offline image launch.", err)
	}
	if err := scan.VerifyOfflineBoot(boot, receipt, adapter.Manager); err != nil {
		return scan.BootEvidence{}, err
	}
	return boot, nil
}

type CoreScannerInventory struct {
	RootPath   string
	Classifier scan.MIMEClassifier
}

func (adapter CoreScannerInventory) Inventory(ctx context.Context, selected policy.Policy) (scan.Inventory, error) {
	if err := selected.Validate(); err != nil {
		return scan.Inventory{}, scannerAdapterError("SCANNER_POLICY_INVALID", "The scanner policy is invalid.", "Use an installed, validated scanner policy.", err)
	}
	limits := selected.Limits()
	return scan.BuildInventory(ctx, adapter.RootPath, scan.InventoryLimits{
		MaxFiles: limits.MaxFiles(), MaxInputBytes: limits.MaxInputBytes(),
		MaxPathBytes: scan.MaximumInventoryPathBytes, MaxPrefixBytes: scan.DefaultInventoryPrefixBytes,
	}, adapter.Classifier)
}

type ScannerContentScanner interface {
	Scan(context.Context, io.Reader, uint64) (scan.ClamResult, error)
}

type CoreScannerMalware struct {
	RootPath string
	Scanner  ScannerContentScanner
}

func (adapter CoreScannerMalware) Scan(ctx context.Context, inventory scan.Inventory, selected policy.Policy) (scan.ScanSummary, error) {
	if err := selected.Validate(); err != nil {
		return scan.ScanSummary{}, scannerAdapterError("SCANNER_POLICY_INVALID", "The scanner policy is invalid.", "Use an installed, validated scanner policy.", err)
	}
	if adapter.Scanner == nil {
		return scan.ScanSummary{}, scannerAdapterUnavailable("malware scanner")
	}
	return scan.ScanInventory(ctx, inventory, func(ctx context.Context, entry scan.InventoryEntry) (io.ReadCloser, error) {
		return scan.OpenInventoryEntry(ctx, adapter.RootPath, entry)
	}, adapter.Scanner)
}

func scannerAdapterUnavailable(component string) error {
	return &scan.Error{
		Code: "SCANNER_TOOLCHAIN_UNAVAILABLE", Message: "A required scanner adapter is unavailable.",
		Remediation: "Install the verified scanner image with its bounded " + component + " adapter.",
	}
}

func scannerAdapterError(code, message, remediation string, _ error) error {
	// The wrapped tool or operating-system error is deliberately discarded at
	// this boundary because it can contain hostile names or raw tool output.
	return &scan.Error{Code: code, Message: message, Remediation: remediation}
}
