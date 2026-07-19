package main

import (
	"context"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/transfer"
)

type guestdExporterAdapter struct{}

func (guestdExporterAdapter) Inspect(context.Context, guest.ExporterDeviceExpectation) (guest.ExporterDeviceEvidence, error) {
	return guest.ExporterDeviceEvidence{}, nil
}
func (guestdExporterAdapter) Prepare(context.Context, *secret.Bytes) (guest.ExporterPrepareEvidence, error) {
	return guest.ExporterPrepareEvidence{}, nil
}
func (guestdExporterAdapter) BeginWrite(context.Context, transfer.Header, string) (guest.ExporterWriter, error) {
	return nil, nil
}
func (guestdExporterAdapter) Reread(context.Context, string) ([sha256.Size]byte, error) {
	return [sha256.Size]byte{}, nil
}
func (guestdExporterAdapter) Finalize(context.Context) (guest.ExporterFinalizeEvidence, error) {
	return guest.ExporterFinalizeEvidence{}, nil
}
func (guestdExporterAdapter) Cleanup(context.Context) error { return nil }

func TestCurrentVersionReportsCompiledRoleAndCapabilities(t *testing.T) {
	previous := guest.CompiledRole
	guest.CompiledRole = string(session.RoleScanner)
	t.Cleanup(func() { guest.CompiledRole = previous })

	record := currentVersion()
	want, err := guest.Capabilities(session.RoleScanner)
	if err != nil {
		t.Fatal(err)
	}
	if record.GuestRole != string(session.RoleScanner) || !slices.Equal(record.Capabilities, want) {
		t.Fatalf("currentVersion() role=%q capabilities=%v", record.GuestRole, record.Capabilities)
	}
	if record.APIMajor != guest.APIMajor || record.APIMinor != guest.APIMinor {
		t.Fatalf("currentVersion() API=%d.%d", record.APIMajor, record.APIMinor)
	}
}

func TestComposeGuestServerConfigWiresOnlyScannerCompiledRole(t *testing.T) {
	token, err := guest.TokenFromBytes(make([]byte, guest.TokenSize))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(token.Destroy)
	identity := guest.Identity{
		Role: session.RoleScanner, ImageDigest: "sha256:" + strings.Repeat("a", 64),
		SourceCommit: strings.Repeat("b", 40), BootNonce: append([]byte{1}, make([]byte, guest.BootNonceSize-1)...),
		OSRelease: "26.05", GuestdVersion: "test",
	}
	config, scannerService, err := composeGuestServerConfig(identity, token)
	if err != nil {
		t.Fatal(err)
	}
	if scannerService == nil || any(config.Scanner) != any(scannerService) || config.Workstation != nil || config.Downloader != nil || config.Exporter != nil {
		t.Fatalf("scanner composition = %#v", config)
	}
	if err := scannerService.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	identity.Role = session.RoleDownloader
	config, scannerService, err = composeGuestServerConfig(identity, token)
	if err != nil {
		t.Fatal(err)
	}
	if scannerService != nil || config.Scanner != nil {
		t.Fatal("non-scanner composition registered scanner service")
	}
}

func TestCurrentVersionGenericBuildFailsClosed(t *testing.T) {
	previous := guest.CompiledRole
	guest.CompiledRole = ""
	t.Cleanup(func() { guest.CompiledRole = previous })

	record := currentVersion()
	if record.GuestRole != "uncompiled" || len(record.Capabilities) != 0 {
		t.Fatalf("generic currentVersion() = %#v", record)
	}
}

func TestComposeExporterUsesOnlyFixedPathAdapter(t *testing.T) {
	previous := newFixedExporterAdapter
	newFixedExporterAdapter = func() (guest.ExporterAdapter, error) { return guestdExporterAdapter{}, nil }
	t.Cleanup(func() { newFixedExporterAdapter = previous })
	token, err := guest.TokenFromBytes(make([]byte, guest.TokenSize))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(token.Destroy)
	identity := guest.Identity{
		Role: session.RoleExporter, ImageDigest: "sha256:" + strings.Repeat("a", 64),
		SourceCommit: strings.Repeat("b", 40), BootNonce: append([]byte{1}, make([]byte, guest.BootNonceSize-1)...),
		OSRelease: "26.05", GuestdVersion: "test",
	}
	config, service, err := composeGuestServerConfig(identity, token)
	if err != nil || service == nil || any(config.Exporter) != any(service) || config.Workstation != nil || config.Downloader != nil || config.Scanner != nil {
		t.Fatalf("exporter composition = config=%#v service=%v err=%v", config, service, err)
	}
	if err := service.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}
