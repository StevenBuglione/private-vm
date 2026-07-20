package main

import (
	"context"
	"errors"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/config"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/storage"
	"github.com/StevenBuglione/private-vm/internal/torrent"
)

type versionRunner struct {
	output []byte
	err    error
}

func TestProductionTorrentCapacityUsesIndependentRoleContracts(t *testing.T) {
	source := productionTorrentCapacitySource()
	contract := guest.DefaultProductionScannerCapacity()
	if contract.ScratchBytes != guest.DefaultProductionScannerConfig().SandboxMaxBytes ||
		source.ScannerReadOnlyBytes != contract.ReadOnlyScanBytes || source.ScannerScratchBytes != contract.ScratchBytes ||
		source.WorkstationDestinationBytes != 32<<30 || source.ArchiveExpansionBytes != contract.ArchiveExpansionBytes ||
		source.ReconstructionBytes != contract.ReconstructionWorkBytes || source.MaximumOutputBytes != contract.MaximumOutputBytes ||
		source.MaximumSelectedBytes != contract.MaximumInputBytes {
		t.Fatalf("production capacity source = %+v", source)
	}
	if contract.ReconstructionWorkBytes != 2*contract.MaximumOutputBytes ||
		contract.ArchiveExpansionBytes+contract.ReconstructionWorkBytes+(64<<20) > contract.ScratchBytes ||
		contract.ReadOnlyScanBytes != contract.MaximumInputBytes+(64<<20) {
		t.Fatalf("incoherent scanner capacity contract = %+v", contract)
	}
	if source.USBDestinationBytes != 0 {
		t.Fatal("USB capacity was invented before an enrolled destination exists")
	}

	snapshot := session.Snapshot{ID: "pvm-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Role: session.RoleDownloader}
	launch := session.LaunchPlan{Role: session.RoleDownloader, RootBytes: 32 << 30, ScratchBytes: 64 << 30}
	evidence, err := source.Evidence(t.Context(), snapshot, launch, torrent.DestinationWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	metadata := torrent.Metadata{PayloadPaused: true, Files: []torrent.File{{Index: 0, DisplayPath: "small.pdf", SizeBytes: 8 << 20}}}
	_, plan, err := torrent.PlanSelection(metadata, []uint32{0}, evidence, 1<<30, true)
	if err != nil || plan.ReconstructionNeed > contract.ScratchBytes {
		t.Fatalf("small production selection plan = %+v, %v", plan, err)
	}
	for name, fail := range map[string]func(*torrent.CapacityEvidence) uint64{
		"quarantine": func(*torrent.CapacityEvidence) uint64 { return plan.QuarantineRequired - 1 },
		"scan": func(value *torrent.CapacityEvidence) uint64 {
			value.ScanAvailableBytes = plan.ScanRequired - 1
			return 1 << 30
		},
		"reconstruction": func(value *torrent.CapacityEvidence) uint64 {
			value.ReconstructionAvailable = plan.ReconstructionNeed - 1
			return 1 << 30
		},
		"destination": func(value *torrent.CapacityEvidence) uint64 {
			value.DestinationAvailable = plan.DestinationRequired - 1
			return 1 << 30
		},
	} {
		t.Run(name, func(t *testing.T) {
			insufficient := evidence
			quarantine := fail(&insufficient)
			if _, _, err := torrent.PlanSelection(metadata, []uint32{0}, insufficient, quarantine, true); !errors.Is(err, torrent.ErrCapacity) {
				t.Fatalf("stage overflow error = %v", err)
			}
		})
	}
	oversized := metadata
	oversized.Files = []torrent.File{{Index: 0, DisplayPath: "large.pdf", SizeBytes: contract.MaximumInputBytes + 1}}
	if _, _, err := torrent.PlanSelection(oversized, []uint32{0}, evidence, 1<<30, true); !errors.Is(err, torrent.ErrCapacity) {
		t.Fatalf("oversized production selection error = %v", err)
	}
	archive := metadata
	archive.Files = []torrent.File{{Index: 0, DisplayPath: "small.zip", SizeBytes: 8 << 20, HazardCodes: []string{"TYPE_ARCHIVE"}}}
	if _, archivePlan, err := torrent.PlanSelection(archive, []uint32{0}, evidence, 1<<30, true); err != nil || archivePlan.ReconstructionNeed > contract.ScratchBytes {
		t.Fatalf("archive production selection plan = %+v, %v", archivePlan, err)
	}
}

func TestProductionProbeTargetsComeFromValidatedConfiguration(t *testing.T) {
	targets, err := productionProbeTargets(config.Defaults().VPN())
	if err != nil || targets.DNSName != config.DefaultProbeDNSName || targets.IPv4.String() != config.DefaultProbeIPv4 || targets.IPv6.String() != config.DefaultProbeIPv6 {
		t.Fatalf("targets = (%v, %v)", targets, err)
	}
	if _, err := productionProbeTargets((config.Config{}).VPN()); err == nil {
		t.Fatal("missing production probe targets were accepted")
	}
}

func (runner versionRunner) Run(context.Context, storage.Command) (storage.Result, error) {
	return storage.Result{Stdout: append([]byte(nil), runner.output...)}, runner.err
}

func TestProbeQEMUVersionAcceptsOnlyBoundedSemanticVersion(t *testing.T) {
	got, err := probeQEMUVersion(t.Context(), versionRunner{output: []byte("QEMU emulator version 10.2.4\n")}, "/trusted/qemu")
	if err != nil || got != "10.2.4" {
		t.Fatalf("version = %q, %v", got, err)
	}
	for _, runner := range []versionRunner{
		{output: []byte("unrecognized\n")},
		{err: errors.New("failed")},
	} {
		if _, err := probeQEMUVersion(t.Context(), runner, "/trusted/qemu"); err == nil {
			t.Fatal("unsafe version response was accepted")
		}
	}
}
