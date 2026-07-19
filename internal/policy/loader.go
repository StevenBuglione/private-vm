package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const (
	SchemaVersion     = 1
	maximumPolicySize = 1 << 20
	maximumInputBytes = uint64(1 << 40)
	maximumSingleFile = uint64(4 << 30)
	maximumFiles      = uint64(1_000_000)
	maximumExpanded   = uint64(4 << 30)
	maximumRatio      = 1000.0
	maximumTimeout    = uint64(300)
)

var policyNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

type Mode string

const (
	ModeSafe       Mode = "safe"
	ModeQuarantine Mode = "quarantine"
)

// Policy is an immutable, fully validated content-policy snapshot.
type Policy struct {
	schemaVersion int
	name          string
	mode          Mode
	limits        Limits
	rules         Rules
}

type Limits struct {
	maxInputBytes      uint64
	maxSingleFileBytes uint64
	maxFiles           uint64
	maxArchiveDepth    uint32
	maxExpansionRatio  float64
	maxExpandedBytes   uint64
	scanTimeoutSeconds uint64
}

func (p Policy) SchemaVersion() int { return p.schemaVersion }
func (p Policy) Name() string       { return p.name }
func (p Policy) Mode() Mode         { return p.mode }
func (p Policy) Limits() Limits     { return p.limits }
func (p Policy) Rules() Rules       { return p.rules }

func (l Limits) MaxInputBytes() uint64      { return l.maxInputBytes }
func (l Limits) MaxSingleFileBytes() uint64 { return l.maxSingleFileBytes }
func (l Limits) MaxFiles() uint64           { return l.maxFiles }
func (l Limits) MaxArchiveDepth() uint32    { return l.maxArchiveDepth }
func (l Limits) MaxExpansionRatio() float64 { return l.maxExpansionRatio }
func (l Limits) MaxExpandedBytes() uint64   { return l.maxExpandedBytes }
func (l Limits) ScanTimeoutSeconds() uint64 { return l.scanTimeoutSeconds }

type wirePolicy struct {
	SchemaVersion int        `toml:"schema_version" json:"schema_version"`
	Name          string     `toml:"name" json:"name"`
	Mode          Mode       `toml:"mode" json:"mode"`
	Limits        wireLimits `toml:"limits" json:"limits"`
	Rules         wireRules  `toml:"rules" json:"rules"`
}

type wireLimits struct {
	MaxInputBytes      uint64  `toml:"max_input_bytes" json:"max_input_bytes"`
	MaxSingleFileBytes uint64  `toml:"max_single_file_bytes" json:"max_single_file_bytes"`
	MaxFiles           uint64  `toml:"max_files" json:"max_files"`
	MaxArchiveDepth    uint32  `toml:"max_archive_depth" json:"max_archive_depth"`
	MaxExpansionRatio  float64 `toml:"max_expansion_ratio" json:"max_expansion_ratio"`
	MaxExpandedBytes   uint64  `toml:"max_expanded_bytes" json:"max_expanded_bytes"`
	ScanTimeoutSeconds uint64  `toml:"scan_timeout_seconds" json:"scan_timeout_seconds"`
}

type wireRules struct {
	RejectOnMalware     bool `toml:"reject_on_malware" json:"reject_on_malware"`
	RejectOnScanError   bool `toml:"reject_on_scan_error" json:"reject_on_scan_error"`
	RejectOnSkippedFile bool `toml:"reject_on_skipped_file" json:"reject_on_skipped_file"`
	RejectEncrypted     bool `toml:"reject_encrypted_archives" json:"reject_encrypted_archives"`
	BlockExecutables    bool `toml:"block_executables" json:"block_executables"`
	BlockScripts        bool `toml:"block_scripts" json:"block_scripts"`
	BlockDiskImages     bool `toml:"block_disk_images" json:"block_disk_images"`
	SanitizeDocuments   bool `toml:"sanitize_documents" json:"sanitize_documents"`
	ReencodeMedia       bool `toml:"reencode_media" json:"reencode_media"`
	StripMetadata       bool `toml:"strip_metadata" json:"strip_metadata"`
}

func policyFromWire(value wirePolicy) Policy {
	return Policy{
		schemaVersion: value.SchemaVersion,
		name:          value.Name,
		mode:          value.Mode,
		limits: Limits{
			maxInputBytes:      value.Limits.MaxInputBytes,
			maxSingleFileBytes: value.Limits.MaxSingleFileBytes,
			maxFiles:           value.Limits.MaxFiles,
			maxArchiveDepth:    value.Limits.MaxArchiveDepth,
			maxExpansionRatio:  value.Limits.MaxExpansionRatio,
			maxExpandedBytes:   value.Limits.MaxExpandedBytes,
			scanTimeoutSeconds: value.Limits.ScanTimeoutSeconds,
		},
		rules: Rules{
			validated:           true,
			rejectOnMalware:     value.Rules.RejectOnMalware,
			rejectOnScanError:   value.Rules.RejectOnScanError,
			rejectOnSkippedFile: value.Rules.RejectOnSkippedFile,
			rejectEncrypted:     value.Rules.RejectEncrypted,
			blockExecutables:    value.Rules.BlockExecutables,
			blockScripts:        value.Rules.BlockScripts,
			blockDiskImages:     value.Rules.BlockDiskImages,
			sanitizeDocuments:   value.Rules.SanitizeDocuments,
			reencodeMedia:       value.Rules.ReencodeMedia,
			stripMetadata:       value.Rules.StripMetadata,
		},
	}
}

func (p Policy) wire() wirePolicy {
	return wirePolicy{
		SchemaVersion: p.schemaVersion, Name: p.name, Mode: p.mode,
		Limits: wireLimits{
			MaxInputBytes:      p.limits.maxInputBytes,
			MaxSingleFileBytes: p.limits.maxSingleFileBytes,
			MaxFiles:           p.limits.maxFiles,
			MaxArchiveDepth:    p.limits.maxArchiveDepth,
			MaxExpansionRatio:  p.limits.maxExpansionRatio,
			MaxExpandedBytes:   p.limits.maxExpandedBytes,
			ScanTimeoutSeconds: p.limits.scanTimeoutSeconds,
		},
		Rules: wireRules{
			RejectOnMalware:     p.rules.rejectOnMalware,
			RejectOnScanError:   p.rules.rejectOnScanError,
			RejectOnSkippedFile: p.rules.rejectOnSkippedFile,
			RejectEncrypted:     p.rules.rejectEncrypted,
			BlockExecutables:    p.rules.blockExecutables,
			BlockScripts:        p.rules.blockScripts,
			BlockDiskImages:     p.rules.blockDiskImages,
			SanitizeDocuments:   p.rules.sanitizeDocuments,
			ReencodeMedia:       p.rules.reencodeMedia,
			StripMetadata:       p.rules.stripMetadata,
		},
	}
}

func (p Policy) MarshalJSON() ([]byte, error) { return json.Marshal(p.wire()) }

func (p Policy) Validate() error {
	if p.schemaVersion != SchemaVersion {
		return policyError("POLICY_SCHEMA_VERSION", "The policy schema version is unsupported.", "Use schema_version = 1.")
	}
	if !policyNamePattern.MatchString(p.name) || string(p.mode) != p.name {
		return policyError("POLICY_INVALID", "The policy identity is invalid.", "Use the built-in safe or quarantine policy identity.")
	}
	if p.mode != ModeSafe && p.mode != ModeQuarantine {
		return policyError("POLICY_INVALID", "The policy mode is unsupported.", "Use safe or quarantine; raw mode does not exist in v1.")
	}
	limits := p.limits
	if limits.maxInputBytes == 0 || limits.maxInputBytes > maximumInputBytes ||
		limits.maxSingleFileBytes == 0 || limits.maxSingleFileBytes > maximumSingleFile ||
		limits.maxSingleFileBytes > limits.maxInputBytes ||
		limits.maxFiles == 0 || limits.maxFiles > maximumFiles ||
		limits.maxArchiveDepth > 10 ||
		math.IsNaN(limits.maxExpansionRatio) || math.IsInf(limits.maxExpansionRatio, 0) ||
		limits.maxExpansionRatio < 1 || limits.maxExpansionRatio > maximumRatio ||
		limits.maxExpandedBytes == 0 || limits.maxExpandedBytes > maximumExpanded ||
		limits.scanTimeoutSeconds < 30 || limits.scanTimeoutSeconds > maximumTimeout {
		return policyError("POLICY_LIMIT", "A policy limit is outside supported bounds.", "Use the documented finite file, archive, expansion, and timeout limits.")
	}
	rules := p.rules
	if !rules.rejectOnMalware || !rules.rejectOnScanError || !rules.rejectOnSkippedFile || !rules.rejectEncrypted {
		return policyError("POLICY_WEAKENING", "Mandatory fail-closed scan rules were disabled.", "Enable malware, scan-error, skipped-file, and encrypted-content rejection.")
	}
	if p.mode == ModeSafe && (!rules.blockExecutables || !rules.blockScripts || !rules.blockDiskImages ||
		!rules.sanitizeDocuments || !rules.reencodeMedia || !rules.stripMetadata) {
		return policyError("POLICY_WEAKENING", "The safe policy disabled a mandatory reconstruction rule.", "Restore every rule from examples/policy.safe.toml.")
	}
	if p.mode == ModeQuarantine && (rules.blockExecutables || rules.blockScripts || rules.blockDiskImages ||
		rules.sanitizeDocuments || rules.reencodeMedia || rules.stripMetadata) {
		return policyError("POLICY_INVALID", "The quarantine policy does not match its fixed v1 semantics.", "Restore every rule from examples/policy.quarantine.toml.")
	}
	return nil
}

type Migration func(document map[string]any) (map[string]any, error)

type Loader struct{ migrations map[int]Migration }

func NewLoader(migrations map[int]Migration) (Loader, error) {
	copyOfMigrations := make(map[int]Migration, len(migrations))
	for version, migration := range migrations {
		if version < 0 || version >= SchemaVersion || migration == nil {
			return Loader{}, policyError("POLICY_MIGRATION", "The policy migration registry is invalid.", "Register non-nil one-version migrations only.")
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

func Load(path string) (Policy, error) {
	file, err := openPolicyFile(path)
	if err != nil {
		return Policy{}, policyError("POLICY_READ", "The policy file could not be opened.", "Select an installed, readable policy file.")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 {
		_ = file.Close()
		return Policy{}, policyError("POLICY_READ", "The policy file is invalid.", "Select a regular policy file no larger than 1 MiB.")
	}
	if info.Size() > maximumPolicySize {
		_ = file.Close()
		return Policy{}, policyError("POLICY_TOO_LARGE", "The policy exceeds 1 MiB.", "Reduce the policy to the documented bounded fields.")
	}
	result, decodeErr := defaultLoader().Decode(file)
	closeErr := file.Close()
	if closeErr != nil {
		return Policy{}, policyError("POLICY_READ", "The policy file could not be closed safely.", "Resolve the local filesystem error and retry.")
	}
	return result, decodeErr
}

func Decode(reader io.Reader) (Policy, error) { return defaultLoader().Decode(reader) }

func (loader Loader) Decode(reader io.Reader) (Policy, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximumPolicySize+1))
	if err != nil {
		return Policy{}, policyError("POLICY_READ", "The policy input could not be read.", "Provide a readable policy no larger than 1 MiB.")
	}
	if len(data) > maximumPolicySize {
		return Policy{}, policyError("POLICY_TOO_LARGE", "The policy exceeds 1 MiB.", "Reduce the policy to the documented bounded fields.")
	}
	var document map[string]any
	if err := toml.Unmarshal(data, &document); err != nil {
		return Policy{}, policyParseError()
	}
	if containsSecretField(document) {
		return Policy{}, policyError("POLICY_SECRET_FIELD", "A secret-bearing field is forbidden in policy.", "Remove all credentials, tokens, magnets, and private keys.")
	}
	version, err := policyDocumentVersion(document)
	if err != nil {
		return Policy{}, err
	}
	for version < SchemaVersion {
		migration, ok := loader.migrations[version]
		if !ok {
			return Policy{}, policyError("POLICY_MIGRATION", "No migration is registered for this policy version.", "Use schema_version = 1 or the documented migration tool.")
		}
		next, migrationErr := migration(document)
		if migrationErr != nil || next == nil {
			return Policy{}, policyError("POLICY_MIGRATION", "The policy migration failed.", "Restore the original policy and run the documented migration tool.")
		}
		if containsSecretField(next) {
			return Policy{}, policyError("POLICY_SECRET_FIELD", "A migration produced a secret-bearing policy field.", "Remove all credentials, tokens, magnets, and private keys from the migration output.")
		}
		document = next
		nextVersion, versionErr := policyDocumentVersion(document)
		if versionErr != nil || nextVersion != version+1 {
			return Policy{}, policyError("POLICY_MIGRATION", "A migration produced an invalid policy schema version.", "Advance exactly one schema version per migration.")
		}
		version = nextVersion
	}
	if version != SchemaVersion {
		return Policy{}, policyError("POLICY_SCHEMA_VERSION", "The policy schema version is unsupported.", "Use schema_version = 1.")
	}
	migrated, err := toml.Marshal(document)
	if err != nil {
		return Policy{}, policyParseError()
	}
	if len(migrated) > maximumPolicySize {
		return Policy{}, policyError("POLICY_TOO_LARGE", "The migrated policy exceeds 1 MiB.", "Use a bounded migration that emits only documented policy fields.")
	}
	if !completePolicyDocument(document) {
		return Policy{}, policyParseError()
	}
	var wire wirePolicy
	decoder := toml.NewDecoder(bytes.NewReader(migrated))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Policy{}, policyParseError()
	}
	result := policyFromWire(wire)
	if err := result.Validate(); err != nil {
		return Policy{}, err
	}
	return result, nil
}

func policyDocumentVersion(document map[string]any) (int, error) {
	raw, ok := document["schema_version"]
	version, integer := raw.(int64)
	if !ok || !integer || version < 0 || version > int64(^uint(0)>>1) {
		return 0, policyError("POLICY_SCHEMA_VERSION", "The policy schema version is missing or invalid.", "Set schema_version to the integer 1.")
	}
	return int(version), nil
}

func containsSecretField(value any) bool {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			if secretPolicyFieldName(key) {
				return true
			}
			if containsSecretField(child) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if containsSecretField(child) {
				return true
			}
		}
	}
	return false
}

func secretPolicyFieldName(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, forbidden := range []string{"private_key", "password", "passphrase", "secret", "token", "magnet", "credential"} {
		if strings.Contains(normalized, forbidden) {
			return true
		}
	}
	return normalized == "key" || strings.HasPrefix(normalized, "key_") || strings.HasSuffix(normalized, "_key")
}

func completePolicyDocument(document map[string]any) bool {
	for _, field := range []string{"schema_version", "name", "mode", "limits", "rules"} {
		if _, ok := document[field]; !ok {
			return false
		}
	}
	limits, ok := document["limits"].(map[string]any)
	if !ok {
		return false
	}
	for _, field := range []string{"max_input_bytes", "max_single_file_bytes", "max_files", "max_archive_depth", "max_expansion_ratio", "max_expanded_bytes", "scan_timeout_seconds"} {
		if _, ok := limits[field]; !ok {
			return false
		}
	}
	rules, ok := document["rules"].(map[string]any)
	if !ok {
		return false
	}
	for _, field := range []string{
		"reject_on_malware", "reject_on_scan_error", "reject_on_skipped_file", "reject_encrypted_archives",
		"block_executables", "block_scripts", "block_disk_images", "sanitize_documents", "reencode_media", "strip_metadata",
	} {
		if _, ok := rules[field]; !ok {
			return false
		}
	}
	return true
}

type Error struct {
	Code, Message, Remediation string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s Remediation: %s", e.Code, e.Message, e.Remediation)
}

func Code(err error) string {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return ""
}

func policyError(code, message, remediation string) error {
	return &Error{Code: code, Message: message, Remediation: remediation}
}

func policyParseError() error {
	return policyError("POLICY_PARSE", "The policy is not valid schema-versioned TOML.", "Remove unknown fields and compare it with the installed policy examples.")
}
