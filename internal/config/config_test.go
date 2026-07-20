package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsAreValidAndImmutableValues(t *testing.T) {
	configuration := Defaults()
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	if configuration.SchemaVersion() != 1 || !configuration.Strict() {
		t.Fatalf("unexpected defaults: %#v", configuration)
	}
	if configuration.Desktop().MemoryBytes() != 4<<30 || configuration.Desktop().VCPUs() != 2 {
		t.Fatalf("unsafe workstation defaults: memory=%d vcpus=%d", configuration.Desktop().MemoryBytes(), configuration.Desktop().VCPUs())
	}
	runtimeCopy := configuration.Runtime()
	if runtimeCopy.Directory() != DefaultRuntimePath || configuration.Runtime().Directory() != DefaultRuntimePath {
		t.Fatal("runtime getter did not return the immutable value")
	}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"schema_version":1`, `"runtime"`, `"desktop"`, `"logging"`} {
		if !bytes.Contains(encoded, []byte(required)) {
			t.Fatalf("effective JSON lacks %s: %s", required, encoded)
		}
	}
}

func TestDecodeExampleFile(t *testing.T) {
	file, err := os.Open(filepath.Join("..", "..", "examples", "config.example.toml"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	configuration, err := Decode(file)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.ImageSource().Repository() != OfficialRepository ||
		configuration.Desktop().Bundle() != "development" ||
		configuration.Runtime().Directory() != DefaultRuntimePath {
		t.Fatalf("unexpected example configuration: %#v", configuration)
	}
}

func TestLoaderAppliesDefaultsSystemUserAndCLIOverrides(t *testing.T) {
	directory := t.TempDir()
	systemPath := filepath.Join(directory, "system.toml")
	userPath := filepath.Join(directory, "user.toml")
	writeConfig(t, systemPath, `
schema_version = 1
strict = false
[image_source]
channel = "edge"
[desktop]
bundle = "basic"
audio = true
`)
	writeConfig(t, userPath, `
schema_version = 1
strict = true
[desktop]
bundle = "office"
`)
	strict := false
	bundle := "development"
	audio := false
	configuration, err := defaultLoader().Load(LoadOptions{
		System: FileLayer{Path: systemPath, Required: true},
		User:   FileLayer{Path: userPath, Required: true},
		Overrides: Overrides{
			Strict:  &strict,
			Desktop: DesktopOverrides{Bundle: &bundle, Audio: &audio},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Strict() || configuration.Desktop().Bundle() != "development" || configuration.Desktop().Audio() {
		t.Fatalf("CLI overrides were not highest precedence: %#v", configuration)
	}
	if configuration.ImageSource().Channel() != "edge" {
		t.Fatal("system layer was not retained")
	}
}

func TestSelectedUserPathReplacesDefaultUserLayer(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	defaultPath := filepath.Join(configHome, "private-vm", "config.toml")
	if err := os.MkdirAll(filepath.Dir(defaultPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, defaultPath, "schema_version=1\n[desktop]\nbundle=\"office\"\n")
	selectedPath := filepath.Join(t.TempDir(), "selected.toml")
	writeConfig(t, selectedPath, "schema_version=1\n[desktop]\nbundle=\"basic\"\n")

	fromDefault, err := LoadWithOverrides("", Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	fromSelected, err := LoadWithOverrides(selectedPath, Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if fromDefault.Desktop().Bundle() != "office" || fromSelected.Desktop().Bundle() != "basic" {
		t.Fatalf("default=%q selected=%q", fromDefault.Desktop().Bundle(), fromSelected.Desktop().Bundle())
	}
}

func TestOptionalAndRequiredLayers(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.toml")
	if _, err := defaultLoader().Load(LoadOptions{System: FileLayer{Path: missing}}); err != nil {
		t.Fatalf("optional missing layer failed: %v", err)
	}
	_, err := defaultLoader().Load(LoadOptions{System: FileLayer{Path: missing, Required: true}})
	assertConfigCode(t, err, "CONFIG_READ")
	if strings.Contains(err.Error(), missing) {
		t.Fatalf("read error exposed the selected path: %v", err)
	}
}

func TestDaemonLayerDoesNotLoadAUserFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.toml")
	writeConfig(t, path, "schema_version = 1\nstrict = false\n")
	configuration, err := defaultLoader().Load(LoadOptions{
		System: FileLayer{Path: path, Required: true, Trust: TrustAny},
	})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Strict() {
		t.Fatal("system daemon configuration was not applied")
	}
}

func TestDecodeRejectsUnknownAndSecretFieldsWithoutDisclosure(t *testing.T) {
	tests := []struct {
		name  string
		input string
		code  string
	}{
		{name: "unknown", input: "schema_version=1\nunknown=true\n", code: "CONFIG_PARSE"},
		{name: "private key", input: "schema_version=1\nprivate_key=\"SENSITIVE-MARKER\"\n", code: "CONFIG_SECRET_FIELD"},
		{name: "API key", input: "schema_version=1\napi_key=\"SENSITIVE-MARKER\"\n", code: "CONFIG_SECRET_FIELD"},
		{name: "nested array token", input: "schema_version=1\nitems=[{api_token=\"SENSITIVE-MARKER\"}]\n", code: "CONFIG_SECRET_FIELD"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(test.input))
			assertConfigCode(t, err, test.code)
			for _, forbidden := range []string{"SENSITIVE-MARKER", "private_key", "api_key", "api_token"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("error disclosed rejected input: %v", err)
				}
			}
		})
	}
}

func TestDecodeRejectsMissingInvalidAndFutureSchemaVersions(t *testing.T) {
	tests := []string{
		"strict=true\n",
		"schema_version=\"1\"\n",
		"schema_version=2\n",
	}
	for _, input := range tests {
		_, err := Decode(strings.NewReader(input))
		assertConfigCode(t, err, "CONFIG_SCHEMA_VERSION")
	}
}

func TestMigrationHookAdvancesExactlyOneVersion(t *testing.T) {
	registry := map[int]Migration{
		0: func(document map[string]any) (map[string]any, error) {
			document["schema_version"] = int64(1)
			document["strict"] = false
			return document, nil
		},
	}
	loader, err := NewLoader(registry)
	if err != nil {
		t.Fatal(err)
	}
	delete(registry, 0)
	configuration, err := loader.Decode(strings.NewReader("schema_version=0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Strict() {
		t.Fatal("registered migration was not applied from the copied registry")
	}
}

func TestMigrationFailuresAreRedactedAndFailClosed(t *testing.T) {
	tests := []struct {
		name      string
		migration Migration
		code      string
	}{
		{name: "error", migration: func(map[string]any) (map[string]any, error) {
			return nil, errors.New("SENSITIVE-MARKER")
		}, code: "CONFIG_MIGRATION"},
		{name: "skips version", migration: func(document map[string]any) (map[string]any, error) {
			document["schema_version"] = int64(2)
			return document, nil
		}, code: "CONFIG_MIGRATION"},
		{name: "introduces secret", migration: func(document map[string]any) (map[string]any, error) {
			document["schema_version"] = int64(1)
			document["password"] = "SENSITIVE-MARKER"
			return document, nil
		}, code: "CONFIG_SECRET_FIELD"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loader, err := NewLoader(map[int]Migration{0: test.migration})
			if err != nil {
				t.Fatal(err)
			}
			_, err = loader.Decode(strings.NewReader("schema_version=0\n"))
			assertConfigCode(t, err, test.code)
			if strings.Contains(err.Error(), "SENSITIVE-MARKER") {
				t.Fatalf("migration error disclosed a cause: %v", err)
			}
		})
	}
}

func TestMigrationOutputIsBounded(t *testing.T) {
	loader, err := NewLoader(map[int]Migration{0: func(document map[string]any) (map[string]any, error) {
		document["schema_version"] = int64(1)
		document["padding"] = strings.Repeat("x", maximumConfigBytes)
		return document, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = loader.Decode(strings.NewReader("schema_version=0\n"))
	assertConfigCode(t, err, "CONFIG_TOO_LARGE")
}

func TestDecodeIsBoundedAndRedactsReaderErrors(t *testing.T) {
	_, err := Decode(io.LimitReader(strings.NewReader(strings.Repeat("x", maximumConfigBytes+2)), maximumConfigBytes+2))
	assertConfigCode(t, err, "CONFIG_TOO_LARGE")
	_, err = Decode(readerError{err: errors.New("SENSITIVE-MARKER")})
	assertConfigCode(t, err, "CONFIG_READ")
	if strings.Contains(err.Error(), "SENSITIVE-MARKER") {
		t.Fatalf("reader cause was disclosed: %v", err)
	}
}

func TestValidationRejectsSecurityWeakeningOverrides(t *testing.T) {
	falseValue := false
	trueValue := true
	badRuntime := "/var/lib/private-vm/runtime"
	telemetry := true
	tests := []Overrides{
		{ImageSource: ImageSourceOverrides{RequireAttestation: &falseValue}},
		{Runtime: RuntimeOverrides{Directory: &badRuntime}},
		{VPN: VPNOverrides{DisableIPv6IfNotTunneled: &falseValue}},
		{USB: USBOverrides{RequireUSBGuard: &falseValue}},
		{Logging: LoggingOverrides{Telemetry: &telemetry}},
		{Strict: &trueValue, Desktop: DesktopOverrides{VCPUs: pointer(uint32(65))}},
	}
	for index, overrides := range tests {
		_, err := defaultLoader().Load(LoadOptions{Overrides: overrides})
		if errorCode(err) != "CONFIG_INVALID" {
			t.Fatalf("case %d returned %v", index, err)
		}
	}
}

func TestUserPathRequiresCleanAbsoluteBase(t *testing.T) {
	for _, base := range []string{"relative/config", "/", "/tmp/control\npath"} {
		t.Setenv("XDG_CONFIG_HOME", base)
		_, err := UserPath()
		assertConfigCode(t, err, "CONFIG_PATH")
	}
}

func TestValidationRejectsUnsafeAndOverlappingHostPaths(t *testing.T) {
	for _, overrides := range []Overrides{
		{Runtime: RuntimeOverrides{ImageCache: pointer("/")}},
		{Runtime: RuntimeOverrides{ScratchDirectory: pointer("/run/private-vm")}},
		{Runtime: RuntimeOverrides{ImageCache: pointer("/var/lib/private-vm"), ScratchDirectory: pointer("/var/lib/private-vm/scratch")}},
		{Runtime: RuntimeOverrides{ImageCache: pointer("/var/lib/private-vm/control\npath")}},
	} {
		_, err := defaultLoader().Load(LoadOptions{Overrides: overrides})
		assertConfigCode(t, err, "CONFIG_INVALID")
	}
}

func TestValidationRejectsMalformedRegistryIdentity(t *testing.T) {
	for _, registry := range []string{"GHCR.io", "ghcr .io", "ghcr..io", "-ghcr.io", "ghcr.io:65536", "https://ghcr.io", strings.Repeat("a", 256)} {
		_, err := defaultLoader().Load(LoadOptions{Overrides: Overrides{
			ImageSource: ImageSourceOverrides{Registry: &registry},
		}})
		assertConfigCode(t, err, "CONFIG_INVALID")
	}
	badRepository := "../image"
	_, err := defaultLoader().Load(LoadOptions{Overrides: Overrides{
		ImageSource: ImageSourceOverrides{Repository: &badRepository},
	}})
	assertConfigCode(t, err, "CONFIG_INVALID")
}

func TestValidationRejectsUnsafeVPNProbeTargets(t *testing.T) {
	tests := []VPNOverrides{
		{ProbeDNSName: pointer("localhost")},
		{ProbeIPv4: pointer("127.0.0.1:853")},
		{ProbeIPv4: pointer("10.0.0.1:853")},
		{ProbeIPv4: pointer("[2606:4700:4700::1111]:853")},
		{ProbeIPv6: pointer("1.1.1.1:853")},
		{ProbeIPv6: pointer("[fe80::1]:853")},
		{ProbeIPv6: pointer("[2606:4700:4700::1111]:0")},
	}
	for index, vpnOverrides := range tests {
		_, err := defaultLoader().Load(LoadOptions{Overrides: Overrides{VPN: vpnOverrides}})
		if errorCode(err) != "CONFIG_INVALID" {
			t.Fatalf("case %d returned %v", index, err)
		}
	}
}

func writeConfig(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertConfigCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || errorCode(err) != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}

func pointer[T any](value T) *T { return &value }

type readerError struct{ err error }

func (reader readerError) Read([]byte) (int, error) { return 0, reader.err }
