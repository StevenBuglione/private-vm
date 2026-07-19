package policy

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyExamplesLoadAndMatchFixedSemantics(t *testing.T) {
	for _, name := range []string{"safe", "quarantine"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "examples", "policy."+name+".toml")
			loaded, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.SchemaVersion() != 1 || loaded.Name() != name || string(loaded.Mode()) != name {
				t.Fatalf("unexpected policy identity: %#v", loaded)
			}
			if !loaded.Rules().RejectOnMalware() || !loaded.Rules().RejectOnScanError() ||
				!loaded.Rules().RejectOnSkippedFile() || !loaded.Rules().RejectEncrypted() {
				t.Fatal("mandatory fail-closed rule was disabled")
			}
			if name == "safe" && (!loaded.Rules().SanitizeDocuments() || !loaded.Rules().ReencodeMedia() || !loaded.Rules().StripMetadata()) {
				t.Fatal("safe reconstruction rule was disabled")
			}
			if name == "quarantine" && (loaded.Rules().BlockExecutables() || loaded.Rules().SanitizeDocuments()) {
				t.Fatal("quarantine semantics do not match the fixed v1 policy")
			}
			encoded, err := json.Marshal(loaded)
			if err != nil || !strings.Contains(string(encoded), `"schema_version":1`) {
				t.Fatalf("effective policy JSON is invalid: %s, %v", encoded, err)
			}
		})
	}
}

func TestPolicyRejectsUnknownSecretAndWeakening(t *testing.T) {
	safe := readExample(t, "policy.safe.toml")
	tests := []struct {
		name  string
		input string
		code  string
	}{
		{name: "unknown", input: safe + "\nunknown=true\n", code: "POLICY_PARSE"},
		{name: "secret", input: safe + "\nprivate_key=\"SENSITIVE-MARKER\"\n", code: "POLICY_SECRET_FIELD"},
		{name: "API key", input: safe + "\napi_key=\"SENSITIVE-MARKER\"\n", code: "POLICY_SECRET_FIELD"},
		{name: "malware weakening", input: strings.Replace(safe, "reject_on_malware = true", "reject_on_malware = false", 1), code: "POLICY_WEAKENING"},
		{name: "safe executable weakening", input: strings.Replace(safe, "block_executables = true", "block_executables = false", 1), code: "POLICY_WEAKENING"},
		{name: "raw mode", input: strings.Replace(safe, `mode = "safe"`, `mode = "raw"`, 1), code: "POLICY_INVALID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(test.input))
			if Code(err) != test.code {
				t.Fatalf("got %v, want %s", err, test.code)
			}
			if strings.Contains(err.Error(), "SENSITIVE-MARKER") || strings.Contains(err.Error(), "private_key") {
				t.Fatalf("policy error disclosed rejected input: %v", err)
			}
		})
	}
}

func TestPolicyRequiresEveryDocumentedField(t *testing.T) {
	quarantine := readExample(t, "policy.quarantine.toml")
	for _, line := range []string{
		"name = \"quarantine\"\n", "max_archive_depth = 3\n", "block_executables = false\n",
	} {
		_, err := Decode(strings.NewReader(strings.Replace(quarantine, line, "", 1)))
		if Code(err) != "POLICY_PARSE" {
			t.Fatalf("missing %q returned %v", strings.TrimSpace(line), err)
		}
	}
}

func TestPolicyLimitsFailClosed(t *testing.T) {
	safe := readExample(t, "policy.safe.toml")
	for _, replacement := range []struct{ old, new string }{
		{"max_files = 100000", "max_files = 0"},
		{"max_archive_depth = 3", "max_archive_depth = 11"},
		{"max_expansion_ratio = 100.0", "max_expansion_ratio = 1001.0"},
		{"scan_timeout_seconds = 14400", "scan_timeout_seconds = 29"},
	} {
		_, err := Decode(strings.NewReader(strings.Replace(safe, replacement.old, replacement.new, 1)))
		if Code(err) != "POLICY_LIMIT" {
			t.Fatalf("got %v for %s", err, replacement.new)
		}
	}
}

func TestPolicyMigrationRegistryIsCopiedAndBounded(t *testing.T) {
	registry := map[int]Migration{0: func(document map[string]any) (map[string]any, error) {
		document["schema_version"] = int64(1)
		return document, nil
	}}
	loader, err := NewLoader(registry)
	if err != nil {
		t.Fatal(err)
	}
	delete(registry, 0)
	legacy := strings.Replace(readExample(t, "policy.safe.toml"), "schema_version = 1", "schema_version = 0", 1)
	if _, err := loader.Decode(strings.NewReader(legacy)); err != nil {
		t.Fatal(err)
	}
	_, err = Decode(io.LimitReader(strings.NewReader(strings.Repeat("x", maximumPolicySize+2)), maximumPolicySize+2))
	if Code(err) != "POLICY_TOO_LARGE" {
		t.Fatalf("got %v, want bounded rejection", err)
	}
}

func TestPolicyMigrationOutputIsBounded(t *testing.T) {
	loader, err := NewLoader(map[int]Migration{0: func(document map[string]any) (map[string]any, error) {
		document["schema_version"] = int64(1)
		document["padding"] = strings.Repeat("x", maximumPolicySize)
		return document, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = loader.Decode(strings.NewReader("schema_version=0\n"))
	if Code(err) != "POLICY_TOO_LARGE" {
		t.Fatalf("got %v, want bounded migration rejection", err)
	}
}

func TestPolicyMigrationAndReaderErrorsAreRedacted(t *testing.T) {
	loader, err := NewLoader(map[int]Migration{0: func(map[string]any) (map[string]any, error) {
		return nil, errors.New("SENSITIVE-MARKER")
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = loader.Decode(strings.NewReader("schema_version=0\n"))
	if Code(err) != "POLICY_MIGRATION" || strings.Contains(err.Error(), "SENSITIVE-MARKER") {
		t.Fatalf("migration error was not redacted: %v", err)
	}
	_, err = Decode(policyReaderError{})
	if Code(err) != "POLICY_READ" || strings.Contains(err.Error(), "SENSITIVE-MARKER") {
		t.Fatalf("reader error was not redacted: %v", err)
	}
}

func TestPolicyMigrationRejectsSecretOutput(t *testing.T) {
	loader, err := NewLoader(map[int]Migration{0: func(document map[string]any) (map[string]any, error) {
		document["schema_version"] = int64(1)
		document["wireguard_key"] = "SENSITIVE-MARKER"
		return document, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = loader.Decode(strings.NewReader("schema_version=0\n"))
	if Code(err) != "POLICY_SECRET_FIELD" || strings.Contains(err.Error(), "SENSITIVE-MARKER") {
		t.Fatalf("secret migration output returned %v", err)
	}
}

func readExample(t *testing.T, name string) string {
	t.Helper()
	value, err := os.ReadFile(filepath.Join("..", "..", "examples", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

type policyReaderError struct{}

func (policyReaderError) Read([]byte) (int, error) {
	return 0, errors.New("SENSITIVE-MARKER")
}
