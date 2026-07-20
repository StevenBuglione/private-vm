package main

import (
	"context"
	"errors"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/config"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/storage"
)

type versionRunner struct {
	output []byte
	err    error
}

func TestProductionTorrentCapacityUsesIndependentRoleContracts(t *testing.T) {
	source := productionTorrentCapacitySource()
	if source.ScannerScratchBytes != guest.DefaultProductionScannerConfig().SandboxMaxBytes ||
		source.WorkstationDestinationBytes != 32<<30 || source.ArchiveExpansionBytes != 4<<30 ||
		source.ReconstructionBytes != 1<<30 || source.MaximumSelectedBytes != 500<<30 {
		t.Fatalf("production capacity source = %+v", source)
	}
	if source.USBDestinationBytes != 0 {
		t.Fatal("USB capacity was invented before an enrolled destination exists")
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
