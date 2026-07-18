package config

import (
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
