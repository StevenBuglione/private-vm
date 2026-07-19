package main

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/session"
)

func TestGuestCompositionMessageExposesOnlyFixedStage(t *testing.T) {
	if got := guestCompositionMessage(errors.Join(errors.New("private detail"), compositionError("downloader quarantine"))); got != "the fixed downloader quarantine component could not be composed" {
		t.Fatalf("composition message = %q", got)
	}
	if got := guestCompositionMessage(errors.New("private detail")); got != "the role-specific guest service could not be composed" {
		t.Fatalf("fallback composition message = %q", got)
	}
}

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
	if scannerService == nil || config.Scanner == nil || config.Workstation != nil || config.Downloader != nil || config.Exporter != nil {
		t.Fatalf("scanner composition = %#v", config)
	}
	if err := scannerService.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	identity.Role = session.RoleExporter
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
