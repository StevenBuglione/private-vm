package main

import (
	"slices"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/session"
)

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

func TestCurrentVersionGenericBuildFailsClosed(t *testing.T) {
	previous := guest.CompiledRole
	guest.CompiledRole = ""
	t.Cleanup(func() { guest.CompiledRole = previous })

	record := currentVersion()
	if record.GuestRole != "uncompiled" || len(record.Capabilities) != 0 {
		t.Fatalf("generic currentVersion() = %#v", record)
	}
}
