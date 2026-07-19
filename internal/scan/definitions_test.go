package scan

import (
	"context"
	"errors"
	"testing"
	"time"
)

type definitionUpdaterFunc func(context.Context) (DefinitionEvidence, error)

func (f definitionUpdaterFunc) Update(ctx context.Context) (DefinitionEvidence, error) { return f(ctx) }

func TestDefinitionUpdateAndOfflineBoot(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	manager := DefinitionManager{
		Now: func() time.Time { return now }, MaximumAge: 24 * time.Hour,
		Updater: definitionUpdaterFunc(func(context.Context) (DefinitionEvidence, error) {
			return DefinitionEvidence{
				EngineVersion: "1.5.1", DatabaseVersion: "daily-28100",
				UpdatedAt: now.Add(-time.Hour), Official: true, Compatible: true, Complete: true,
			}, nil
		}),
	}
	receipt, err := manager.Update(t.Context(), BootEvidence{
		Phase: PhaseUpdate, OverlayIdentity: "overlay-0123456789abcdef",
		VPNVerified: true, Interfaces: []InterfaceEvidence{{Name: "eth0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyOfflineBoot(BootEvidence{
		Phase: PhaseOffline, OverlayIdentity: receipt.OverlayIdentity,
		Interfaces: []InterfaceEvidence{{Name: "lo", Loopback: true}},
		Quarantine: QuarantineEvidence{Attached: true, ReadOnly: true, MountOptions: []string{"ro", "noexec", "nodev", "nosuid"}},
	}, receipt, manager)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDefinitionUpdateFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	valid := DefinitionEvidence{EngineVersion: "1.5.1", DatabaseVersion: "daily", UpdatedAt: now, Official: true, Compatible: true, Complete: true}
	manager := DefinitionManager{Now: func() time.Time { return now }, Updater: definitionUpdaterFunc(func(context.Context) (DefinitionEvidence, error) { return valid, nil })}
	base := BootEvidence{Phase: PhaseUpdate, OverlayIdentity: "overlay", VPNVerified: true, Interfaces: []InterfaceEvidence{{Name: "eth0"}}}

	tests := []struct {
		name string
		boot BootEvidence
		code string
	}{
		{"quarantine", func() BootEvidence { b := base; b.Quarantine.Attached = true; return b }(), "SCANNER_UPDATE_QUARANTINE_PRESENT"},
		{"vpn", func() BootEvidence { b := base; b.VPNVerified = false; return b }(), "VPN_HANDSHAKE_FAILED"},
		{"network", func() BootEvidence {
			b := base
			b.Interfaces = []InterfaceEvidence{{Name: "lo", Loopback: true}}
			return b
		}(), "SCANNER_UPDATE_NETWORK_ABSENT"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := manager.Update(t.Context(), test.boot)
			if ErrorCode(err) != test.code {
				t.Fatalf("code = %s, error = %v", ErrorCode(err), err)
			}
		})
	}

	stale := valid
	stale.UpdatedAt = now.Add(-25 * time.Hour)
	if ErrorCode(manager.ValidateCurrent(stale)) != "SCANNER_DEFINITIONS_STALE" {
		t.Fatal("stale definitions were accepted")
	}

	receipt := UpdateReceipt{OverlayIdentity: "overlay", Definitions: valid}
	offline := BootEvidence{Phase: PhaseOffline, OverlayIdentity: "overlay", Interfaces: []InterfaceEvidence{{Name: "lo", Loopback: true}}, Quarantine: QuarantineEvidence{Attached: true, ReadOnly: true, MountOptions: []string{"ro", "nodev", "nosuid", "noexec"}}}
	for name, mutate := range map[string]func(*BootEvidence){
		"network":  func(b *BootEvidence) { b.Interfaces = append(b.Interfaces, InterfaceEvidence{Name: "eth0"}) },
		"writable": func(b *BootEvidence) { b.Quarantine.ReadOnly = false },
		"mount":    func(b *BootEvidence) { b.Quarantine.MountOptions = []string{"ro"} },
		"overlay":  func(b *BootEvidence) { b.OverlayIdentity = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := offline
			mutate(&changed)
			if err := VerifyOfflineBoot(changed, receipt, manager); err == nil {
				t.Fatal("unsafe offline boot was accepted")
			}
		})
	}
}

func TestDefinitionUpdateCancellationAndFailure(t *testing.T) {
	boot := BootEvidence{Phase: PhaseUpdate, OverlayIdentity: "overlay", VPNVerified: true, Interfaces: []InterfaceEvidence{{Name: "eth0"}}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	manager := DefinitionManager{Updater: definitionUpdaterFunc(func(context.Context) (DefinitionEvidence, error) { return DefinitionEvidence{}, nil })}
	if ErrorCode(func() error { _, err := manager.Update(ctx, boot); return err }()) != "SCAN_CANCELLED" {
		t.Fatal("cancelled update did not return stable cancellation")
	}
	manager.Updater = definitionUpdaterFunc(func(context.Context) (DefinitionEvidence, error) {
		return DefinitionEvidence{}, errors.New("sensitive path")
	})
	_, err := manager.Update(t.Context(), boot)
	if ErrorCode(err) != "SCANNER_UPDATE_FAILED" || err.Error() == "sensitive path" {
		t.Fatalf("unexpected update error: %v", err)
	}
}
