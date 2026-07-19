package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const maximumConfigBytes = 1 << 20

var errConfigFileTooLarge = errors.New("configuration file exceeds bound")

// Migration upgrades one parsed, non-secret TOML document by exactly one
// schema version. It must set schema_version to from+1. The loader copies the
// migration registry at construction and revalidates every output.
type Migration func(document map[string]any) (map[string]any, error)

type Loader struct {
	migrations map[int]Migration
}

type FileTrust uint8

const (
	TrustAny FileTrust = iota
	TrustSystem
	TrustUser
)

type FileLayer struct {
	Path     string
	Required bool
	Trust    FileTrust
}

// LoadOptions applies System, User, then Overrides in ascending precedence.
// An empty file-layer path disables that layer, which is useful for hermetic
// tests and daemon-only loading.
type LoadOptions struct {
	System    FileLayer
	User      FileLayer
	Overrides Overrides
}

func NewLoader(migrations map[int]Migration) (Loader, error) {
	copyOfMigrations := make(map[int]Migration, len(migrations))
	for version, migration := range migrations {
		if version < 0 || version >= SchemaVersion || migration == nil {
			return Loader{}, &Error{
				Code: "CONFIG_MIGRATION", Message: "The migration registry is invalid.",
				Remediation: "Register one non-nil migration for each supported older schema version.",
			}
		}
		copyOfMigrations[version] = migration
	}
	return Loader{migrations: copyOfMigrations}, nil
}

func defaultLoader() Loader {
	loader, err := NewLoader(nil)
	if err != nil {
		panic(err)
	}
	return loader
}

// Load reads the optional system file and either the default optional user file
// or a selected required user file. The selected path replaces, rather than
// supplements, the default user layer.
func Load(selectedUserPath string) (Config, error) {
	return LoadWithOverrides(selectedUserPath, Overrides{})
}

func LoadWithOverrides(selectedUserPath string, overrides Overrides) (Config, error) {
	var userPath string
	userRequired := selectedUserPath != ""
	if selectedUserPath != "" {
		userPath = selectedUserPath
	} else {
		var err error
		userPath, err = UserPath()
		if err != nil {
			return Config{}, err
		}
	}
	return defaultLoader().Load(LoadOptions{
		System:    FileLayer{Path: DefaultSystemPath, Trust: TrustSystem},
		User:      FileLayer{Path: userPath, Required: userRequired, Trust: TrustUser},
		Overrides: overrides,
	})
}

// LoadDaemon loads exactly one required system configuration and never a root
// user layer or command-line override.
func LoadDaemon(path string) (Config, error) {
	if path == "" {
		path = DefaultSystemPath
	}
	return defaultLoader().Load(LoadOptions{System: FileLayer{Path: path, Required: true, Trust: TrustSystem}})
}

func (loader Loader) Load(options LoadOptions) (Config, error) {
	value := Defaults().wire()
	for _, layer := range []FileLayer{options.System, options.User} {
		if layer.Path == "" {
			continue
		}
		data, err := readConfigFile(layer.Path, layer.Trust)
		if errors.Is(err, os.ErrNotExist) && !layer.Required {
			continue
		}
		if errors.Is(err, errConfigFileTooLarge) {
			return Config{}, &Error{
				Code: "CONFIG_TOO_LARGE", Message: "A configuration layer exceeds 1 MiB.",
				Remediation: "Remove unrelated data and keep only documented non-secret fields.",
			}
		}
		if err != nil {
			return Config{}, &Error{
				Code: "CONFIG_READ", Message: "A configuration layer could not be read.",
				Remediation: "Verify that the selected configuration exists, is a regular file, and is readable.",
			}
		}
		value, err = loader.decodeLayer(data, value)
		if err != nil {
			return Config{}, err
		}
	}
	applyOverrides(&value, options.Overrides)
	result := configFromWire(value)
	if err := result.Validate(); err != nil {
		return Config{}, err
	}
	return result, nil
}

func Decode(reader io.Reader) (Config, error) { return defaultLoader().Decode(reader) }

func (loader Loader) Decode(reader io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximumConfigBytes+1))
	if err != nil {
		return Config{}, &Error{
			Code: "CONFIG_READ", Message: "The configuration input could not be read.",
			Remediation: "Provide a readable TOML document no larger than 1 MiB.",
		}
	}
	value, err := loader.decodeLayer(data, Defaults().wire())
	if err != nil {
		return Config{}, err
	}
	result := configFromWire(value)
	if err := result.Validate(); err != nil {
		return Config{}, err
	}
	return result, nil
}

func (loader Loader) decodeLayer(data []byte, base wireConfig) (wireConfig, error) {
	if len(data) > maximumConfigBytes {
		return wireConfig{}, &Error{
			Code: "CONFIG_TOO_LARGE", Message: "The configuration exceeds 1 MiB.",
			Remediation: "Remove unrelated data and keep secrets outside configuration files.",
		}
	}
	var document map[string]any
	if err := toml.Unmarshal(data, &document); err != nil {
		return wireConfig{}, parseError()
	}
	if err := rejectSecretKeys(document); err != nil {
		return wireConfig{}, err
	}
	version, err := documentVersion(document)
	if err != nil {
		return wireConfig{}, err
	}
	for version < SchemaVersion {
		migration, ok := loader.migrations[version]
		if !ok {
			return wireConfig{}, &Error{
				Code: "CONFIG_MIGRATION", Message: "No migration is registered for this configuration version.",
				Remediation: "Use schema_version = 1 or run the documented migration tool.",
			}
		}
		next, migrationErr := migration(document)
		if migrationErr != nil || next == nil {
			return wireConfig{}, &Error{
				Code: "CONFIG_MIGRATION", Message: "The configuration migration failed.",
				Remediation: "Restore the original file and run the documented migration tool.",
			}
		}
		document = next
		if err := rejectSecretKeys(document); err != nil {
			return wireConfig{}, err
		}
		nextVersion, versionErr := documentVersion(document)
		if versionErr != nil || nextVersion != version+1 {
			return wireConfig{}, &Error{
				Code: "CONFIG_MIGRATION", Message: "A migration produced an invalid schema version.",
				Remediation: "Use a migration that advances exactly one schema version.",
			}
		}
		version = nextVersion
	}
	if version != SchemaVersion {
		return wireConfig{}, &Error{
			Code: "CONFIG_SCHEMA_VERSION", Message: "The configuration schema version is unsupported.",
			Remediation: "Use schema_version = 1 with this private-vm release.",
		}
	}
	migrated, err := toml.Marshal(document)
	if err != nil {
		return wireConfig{}, parseError()
	}
	if len(migrated) > maximumConfigBytes {
		return wireConfig{}, &Error{
			Code: "CONFIG_TOO_LARGE", Message: "The migrated configuration exceeds 1 MiB.",
			Remediation: "Use a bounded migration that emits only documented configuration fields.",
		}
	}
	decoder := toml.NewDecoder(bytes.NewReader(migrated))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&base); err != nil {
		return wireConfig{}, parseError()
	}
	return base, nil
}

func documentVersion(document map[string]any) (int, error) {
	raw, ok := document["schema_version"]
	if !ok {
		return 0, &Error{
			Code: "CONFIG_SCHEMA_VERSION", Message: "The configuration schema version is missing.",
			Remediation: "Add schema_version = 1 at the document root.",
		}
	}
	version, ok := raw.(int64)
	if !ok || version < 0 || version > int64(^uint(0)>>1) {
		return 0, &Error{
			Code: "CONFIG_SCHEMA_VERSION", Message: "The configuration schema version is invalid.",
			Remediation: "Set schema_version to the integer 1.",
		}
	}
	return int(version), nil
}

func rejectSecretKeys(value any) error {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			if secretFieldName(key) {
				return &Error{
					Code: "CONFIG_SECRET_FIELD", Message: "A secret-bearing field is forbidden in configuration.",
					Remediation: "Remove credentials, magnets, tokens, passwords, and private keys; supply them through the documented input channel.",
				}
			}
			if err := rejectSecretKeys(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range current {
			if err := rejectSecretKeys(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func secretFieldName(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, forbidden := range []string{"private_key", "password", "passphrase", "secret", "token", "magnet", "credential"} {
		if strings.Contains(normalized, forbidden) {
			return true
		}
	}
	return normalized == "key" || strings.HasPrefix(normalized, "key_") || strings.HasSuffix(normalized, "_key")
}

func readConfigFile(path string, trust FileTrust) ([]byte, error) {
	file, err := openConfigFile(path, trust)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 {
		_ = file.Close()
		return nil, errors.New("invalid configuration file")
	}
	if info.Size() > maximumConfigBytes {
		_ = file.Close()
		return nil, errConfigFileTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumConfigBytes+1))
	closeErr := file.Close()
	if len(data) > maximumConfigBytes {
		return nil, errConfigFileTooLarge
	}
	if err != nil || closeErr != nil {
		return nil, errors.New("invalid configuration file")
	}
	return data, nil
}

func UserPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		directory, err := os.UserConfigDir()
		if err != nil {
			return "", &Error{
				Code: "CONFIG_PATH", Message: "The user configuration directory could not be resolved.",
				Remediation: "Set XDG_CONFIG_HOME to a clean absolute path.",
			}
		}
		base = directory
	}
	if !safeHostPath(base) {
		return "", &Error{
			Code: "CONFIG_PATH", Message: "The user configuration directory is invalid.",
			Remediation: "Set XDG_CONFIG_HOME to a clean absolute path.",
		}
	}
	return filepath.Join(base, "private-vm", "config.toml"), nil
}

func parseError() error {
	return &Error{
		Code: "CONFIG_PARSE", Message: "The configuration is not valid schema-versioned TOML.",
		Remediation: "Remove unknown fields and compare the file with examples/config.example.toml.",
	}
}
