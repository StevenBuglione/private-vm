package scan

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
)

const (
	DefaultMaximumDefinitionAge = 24 * time.Hour
	maximumIdentityLength       = 256
)

type BootPhase string

const (
	PhaseUpdate  BootPhase = "update"
	PhaseOffline BootPhase = "offline-scan"
)

// DefinitionEvidence contains only non-secret release identity. Complete is
// set by the updater after it has observed successful completion rather than
// merely the presence of database files.
type DefinitionEvidence struct {
	EngineVersion   string
	DatabaseVersion string
	UpdatedAt       time.Time
	Official        bool
	Compatible      bool
	Complete        bool
}

type InterfaceEvidence struct {
	Name     string
	Loopback bool
}

type QuarantineEvidence struct {
	Attached     bool
	ReadOnly     bool
	MountOptions []string
}

// BootEvidence is collected inside the guest. OverlayIdentity is an opaque,
// non-user-supplied identity for the retained scanner root overlay.
type BootEvidence struct {
	Phase           BootPhase
	OverlayIdentity string
	VPNVerified     bool
	Interfaces      []InterfaceEvidence
	Quarantine      QuarantineEvidence
}

type DefinitionUpdater interface {
	Update(context.Context) (DefinitionEvidence, error)
}

type DefinitionManager struct {
	Updater    DefinitionUpdater
	Now        func() time.Time
	MaximumAge time.Duration
}

type UpdateReceipt struct {
	OverlayIdentity string
	Definitions     DefinitionEvidence
}

func (m DefinitionManager) Update(ctx context.Context, boot BootEvidence) (UpdateReceipt, error) {
	if err := validateUpdateBoot(boot); err != nil {
		return UpdateReceipt{}, err
	}
	if m.Updater == nil {
		return UpdateReceipt{}, scanError("SCANNER_UPDATE_FAILED", "The scanner definition updater is unavailable.", "Destroy the scanner and reinstall the verified scanner image.", nil)
	}
	if err := ctx.Err(); err != nil {
		return UpdateReceipt{}, contextScanError(err)
	}
	evidence, err := m.Updater.Update(ctx)
	if err != nil {
		return UpdateReceipt{}, scanError("SCANNER_UPDATE_FAILED", "Scanner definitions could not be updated completely.", "Retry the online update boot before attaching quarantine.", err)
	}
	if err := m.ValidateCurrent(evidence); err != nil {
		return UpdateReceipt{}, err
	}
	return UpdateReceipt{OverlayIdentity: boot.OverlayIdentity, Definitions: evidence}, nil
}

func (m DefinitionManager) ValidateCurrent(evidence DefinitionEvidence) error {
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now().UTC()
	}
	maximumAge := m.MaximumAge
	if maximumAge == 0 {
		maximumAge = DefaultMaximumDefinitionAge
	}
	if maximumAge < time.Minute || maximumAge > 30*24*time.Hour {
		return scanError("SCANNER_POLICY_INVALID", "The scanner definition-age policy is invalid.", "Use a definition age between one minute and thirty days.", nil)
	}
	if !validIdentity(evidence.EngineVersion) || !validIdentity(evidence.DatabaseVersion) ||
		!evidence.Complete || !evidence.Official || !evidence.Compatible || evidence.UpdatedAt.IsZero() {
		return scanError("SCANNER_DEFINITIONS_INVALID", "Scanner definition evidence is incomplete or incompatible.", "Complete an official freshclam update with the verified scanner engine.", nil)
	}
	updated := evidence.UpdatedAt.UTC()
	if updated.After(now.Add(5*time.Minute)) || now.Sub(updated) > maximumAge {
		return scanError("SCANNER_DEFINITIONS_STALE", "Scanner definitions are outside the permitted age.", "Run a new online scanner update boot before scanning.", nil)
	}
	return nil
}

func VerifyOfflineBoot(boot BootEvidence, receipt UpdateReceipt, manager DefinitionManager) error {
	if boot.Phase != PhaseOffline {
		return scanError("SCANNER_PHASE_INVALID", "The scanner is not in its offline scan phase.", "Stop the update guest and boot the same overlay using the offline scanner launch specification.", nil)
	}
	if !validIdentity(boot.OverlayIdentity) || boot.OverlayIdentity != receipt.OverlayIdentity {
		return scanError("SCANNER_OVERLAY_MISMATCH", "The offline scanner does not use the updated scanner overlay.", "Destroy the scanner and repeat update and offline boot with one session-owned overlay.", nil)
	}
	for _, iface := range boot.Interfaces {
		if !iface.Loopback {
			return scanError("SCANNER_NETWORK_PRESENT", "A non-loopback network interface is present during scanning.", "Destroy the scanner and boot the scan role with no NIC device.", nil)
		}
	}
	if !boot.Quarantine.Attached || !boot.Quarantine.ReadOnly {
		return scanError("QUARANTINE_NOT_READ_ONLY", "The quarantine device is absent or writable.", "Destroy the scanner and attach exactly one quarantine disk read-only.", nil)
	}
	wantOptions := []string{"nodev", "noexec", "nosuid", "ro"}
	options := slices.Clone(boot.Quarantine.MountOptions)
	slices.Sort(options)
	options = slices.Compact(options)
	if !slices.Equal(options, wantOptions) {
		return scanError("QUARANTINE_MOUNT_UNSAFE", "The quarantine mount options are not the exact read-only policy.", "Remount quarantine with only ro,nodev,nosuid,noexec before scanning.", nil)
	}
	return manager.ValidateCurrent(receipt.Definitions)
}

func validateUpdateBoot(boot BootEvidence) error {
	if boot.Phase != PhaseUpdate {
		return scanError("SCANNER_PHASE_INVALID", "The scanner is not in its definition-update phase.", "Boot the scanner update role before requesting fresh definitions.", nil)
	}
	if !validIdentity(boot.OverlayIdentity) {
		return scanError("SCANNER_OVERLAY_INVALID", "The scanner overlay identity is unavailable.", "Recreate the session-owned scanner overlay and retry.", nil)
	}
	if boot.Quarantine.Attached {
		return scanError("SCANNER_UPDATE_QUARANTINE_PRESENT", "Quarantine is attached during the online update phase.", "Destroy the scanner and repeat the update boot without quarantine.", nil)
	}
	if !boot.VPNVerified {
		return scanError("VPN_HANDSHAKE_FAILED", "The scanner update tunnel is not verified.", "Verify Proton routing and leak tests before updating definitions.", nil)
	}
	hasNetwork := false
	for _, iface := range boot.Interfaces {
		if !iface.Loopback {
			hasNetwork = true
			break
		}
	}
	if !hasNetwork {
		return scanError("SCANNER_UPDATE_NETWORK_ABSENT", "The scanner update phase has no network interface.", "Boot the online update role with the endpoint-restricted Proton network.", nil)
	}
	return nil
}

func validIdentity(value string) bool {
	return value != "" && len(value) <= maximumIdentityLength && !strings.ContainsAny(value, "\x00\r\n")
}

func contextScanError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return scanError("SCAN_TIMEOUT", "The scanner operation exceeded its deadline.", "Destroy the scanner or retry with the documented bounded policy timeout.", err)
	}
	return scanError("SCAN_CANCELLED", "The scanner operation was cancelled.", "Retry the scanner workflow from its last verified phase.", err)
}
