package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeExampleShape(t *testing.T) {
	cfg, err := Decode(strings.NewReader(`
schema_version = 1
strict = true
[image_source]
registry = "ghcr.io"
repository = "StevenBuglione/private-vm"
channel = "stable"
require_attestation = true
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ImageSource.Repository != OfficialRepository || !cfg.Strict {
		t.Fatalf("unexpected configuration: %#v", cfg)
	}
}

func TestLoadDaemonUsesOnlyExplicitFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.toml")
	if err := os.WriteFile(path, []byte("schema_version = 1\nstrict = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadDaemon(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Strict {
		t.Fatal("explicit daemon configuration was not applied")
	}
}

func TestDecodeRejectsUnknownAndSecrets(t *testing.T) {
	for _, input := range []string{
		"schema_version=1\nunknown=true\n",
		"schema_version=1\nprivate_key=\"not-even-a-real-key\"\n",
	} {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatalf("expected rejection for %q", input)
		}
	}
}

func TestDefaultsValidate(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsUnpublishedDesktopBundle(t *testing.T) {
	cfg := Defaults()
	cfg.Desktop.Bundle = "research"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected unpublished workstation bundle to be rejected")
	}
}
