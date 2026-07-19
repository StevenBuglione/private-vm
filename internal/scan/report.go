package scan

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

const (
	ScanReportSchemaVersion = 1
	MaximumScanReportBytes  = 4 << 20
	ScanReportMACBytes      = sha256.Size
)

var (
	reportSessionIDPattern = regexp.MustCompile(`^pvm-[a-f0-9]{32}$`)
	reportDigestPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	reportImagePattern     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	reportCommitPattern    = regexp.MustCompile(`^[a-f0-9]{40}$`)
	reportOutputIDPattern  = regexp.MustCompile(`^scan-out-[a-f0-9]{32}$`)
)

type ScanReport struct {
	SchemaVersion    int                     `json:"schema_version"`
	SessionID        string                  `json:"session_id"`
	Policy           string                  `json:"policy"`
	StartedAt        time.Time               `json:"started_at"`
	CompletedAt      time.Time               `json:"completed_at"`
	DurationMillis   uint64                  `json:"duration_millis"`
	Scanner          ReportScannerIdentity   `json:"scanner"`
	Definitions      ReportDefinitions       `json:"definitions"`
	Isolation        ReportIsolation         `json:"isolation"`
	Phases           ReportPhases            `json:"phases"`
	Inputs           []ReportInput           `json:"inputs"`
	Archives         []ReportArchive         `json:"archives"`
	Findings         []Finding               `json:"findings"`
	SanitizedOutputs []ReportSanitizedOutput `json:"sanitized_outputs"`
	Tools            []ToolEvidence          `json:"tools"`
	Result           string                  `json:"result"`
	Complete         bool                    `json:"complete"`
}

type ReportScannerIdentity struct {
	ImageDigest   string `json:"image_digest"`
	SourceCommit  string `json:"source_commit"`
	GuestdVersion string `json:"guestd_version"`
}

type ReportDefinitions struct {
	EngineVersion   string    `json:"engine_version"`
	DatabaseVersion string    `json:"database_version"`
	UpdatedAt       time.Time `json:"updated_at"`
	Official        bool      `json:"official"`
	Compatible      bool      `json:"compatible"`
}

type ReportIsolation struct {
	NoNetwork          bool     `json:"no_network"`
	QuarantineReadOnly bool     `json:"quarantine_read_only"`
	MountOptions       []string `json:"mount_options"`
}

type ReportPhases struct {
	DefinitionsVerified       bool `json:"definitions_verified"`
	OfflineVerified           bool `json:"offline_verified"`
	InventoryComplete         bool `json:"inventory_complete"`
	MalwareScanComplete       bool `json:"malware_scan_complete"`
	ArchiveInspectionComplete bool `json:"archive_inspection_complete"`
	ReconstructionComplete    bool `json:"reconstruction_complete"`
	OutputRescanComplete      bool `json:"output_rescan_complete"`
}

type ReportInput struct {
	LogicalName        string `json:"logical_name"`
	SizeBytes          uint64 `json:"size_bytes"`
	SHA256             string `json:"sha256"`
	DetectedMIME       string `json:"detected_mime"`
	ExtensionMIME      string `json:"extension_mime,omitempty"`
	ExtensionAgreement bool   `json:"extension_agreement"`
	ClamAVVerdict      string `json:"clamav_verdict"`
}

type ReportArchive struct {
	SourceSHA256  string        `json:"source_sha256"`
	Format        ArchiveFormat `json:"format"`
	Depth         uint32        `json:"depth"`
	EntryCount    uint64        `json:"entry_count"`
	ExpandedBytes uint64        `json:"expanded_bytes"`
	Complete      bool          `json:"complete"`
}

type ReportSanitizedOutput struct {
	OutputID       string `json:"output_id"`
	LogicalName    string `json:"logical_name"`
	SourceSHA256   string `json:"source_sha256"`
	SizeBytes      uint64 `json:"size_bytes"`
	SHA256         string `json:"sha256"`
	DetectedMIME   string `json:"detected_mime"`
	Transformation string `json:"transformation"`
	RescanVerdict  string `json:"rescan_verdict"`
}

type AuthenticatedReport struct {
	CanonicalJSON     []byte
	AuthenticationTag []byte
	Complete          bool
}

func (report ScanReport) CanonicalJSON() ([]byte, error) {
	if err := report.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > MaximumScanReportBytes {
		return nil, scanError("REPORT_TOO_LARGE", "The scan report exceeds its canonical size bound.", "Reduce the selected file count and repeat scanning.", err)
	}
	return encoded, nil
}

func (report ScanReport) Validate() error {
	if report.SchemaVersion != ScanReportSchemaVersion || !reportSessionIDPattern.MatchString(report.SessionID) ||
		(report.Policy != "safe" && report.Policy != "quarantine") {
		return reportInvalid("The scan report identity or schema is invalid.")
	}
	if report.StartedAt.IsZero() || report.CompletedAt.IsZero() || !report.CompletedAt.After(report.StartedAt) ||
		report.CompletedAt.Sub(report.StartedAt) > 24*time.Hour || uint64(report.CompletedAt.Sub(report.StartedAt)/time.Millisecond) != report.DurationMillis {
		return reportInvalid("The scan report timing evidence is incomplete or inconsistent.")
	}
	if !reportImagePattern.MatchString(report.Scanner.ImageDigest) || !reportCommitPattern.MatchString(report.Scanner.SourceCommit) || !validIdentity(report.Scanner.GuestdVersion) {
		return reportInvalid("The scanner image identity is incomplete.")
	}
	if !validIdentity(report.Definitions.EngineVersion) || !validIdentity(report.Definitions.DatabaseVersion) || report.Definitions.UpdatedAt.IsZero() ||
		!report.Definitions.Official || !report.Definitions.Compatible || report.Definitions.UpdatedAt.After(report.CompletedAt.Add(5*time.Minute)) {
		return reportInvalid("The scanner definition identity is incomplete.")
	}
	if !report.Isolation.NoNetwork || !report.Isolation.QuarantineReadOnly || !slices.Equal(report.Isolation.MountOptions, []string{"nodev", "noexec", "nosuid", "ro"}) {
		return reportInvalid("The offline scanner isolation evidence is incomplete.")
	}
	if len(report.Inputs) == 0 || len(report.Inputs) > 1_000_000 || !strictlySortedInputs(report.Inputs) {
		return reportInvalid("The scan input inventory is empty, oversized or not canonical.")
	}
	inputHashes := make(map[string]struct{}, len(report.Inputs))
	for _, input := range report.Inputs {
		if !validLogicalName(input.LogicalName) || input.SizeBytes == 0 || !reportDigestPattern.MatchString(input.SHA256) ||
			!validMIME(input.DetectedMIME) || (input.ExtensionMIME != "" && !validMIME(input.ExtensionMIME)) || !validIdentity(input.ClamAVVerdict) {
			return reportInvalid("A scan input record is incomplete.")
		}
		inputHashes[input.SHA256] = struct{}{}
	}
	if len(report.Archives) > 1_000_000 || !strictlySortedArchives(report.Archives) {
		return reportInvalid("Archive report records are oversized or not canonical.")
	}
	for _, archive := range report.Archives {
		if !reportDigestPattern.MatchString(archive.SourceSHA256) || (archive.Format != ArchiveZIP && archive.Format != ArchiveTAR) ||
			archive.Depth > 10 || archive.EntryCount == 0 || archive.ExpandedBytes == 0 || !archive.Complete {
			return reportInvalid("An archive report record is incomplete.")
		}
	}
	if len(report.Findings) > 1_000_000 || !strictlySortedFindings(report.Findings) {
		return reportInvalid("Scan findings are oversized or not canonical.")
	}
	blocking := false
	for _, finding := range report.Findings {
		if !finding.valid() || (finding.RelativePath != "" && !validLogicalName(finding.RelativePath)) {
			return reportInvalid("A scan finding is incomplete.")
		}
		blocking = blocking || finding.Severity == SeverityBlocking
	}
	if len(report.SanitizedOutputs) > 1_000_000 || !strictlySortedOutputs(report.SanitizedOutputs) {
		return reportInvalid("Sanitized outputs are oversized or not canonical.")
	}
	for _, output := range report.SanitizedOutputs {
		if !reportOutputIDPattern.MatchString(output.OutputID) || !validLogicalName(output.LogicalName) ||
			!reportDigestPattern.MatchString(output.SourceSHA256) || output.SizeBytes == 0 || !reportDigestPattern.MatchString(output.SHA256) ||
			!validMIME(output.DetectedMIME) || !validIdentity(output.Transformation) || output.RescanVerdict != "CLAMAV_CLEAN" {
			return reportInvalid("A sanitized output record is incomplete or was not rescanned.")
		}
	}
	if len(report.Tools) == 0 || len(report.Tools) > 256 || !strictlySortedTools(report.Tools) {
		return reportInvalid("Scanner tool identity is empty, oversized or not canonical.")
	}
	for _, tool := range report.Tools {
		if !tool.valid() {
			return reportInvalid("A scanner tool identity is incomplete.")
		}
	}
	allPhases := report.Phases.DefinitionsVerified && report.Phases.OfflineVerified && report.Phases.InventoryComplete &&
		report.Phases.MalwareScanComplete && report.Phases.ArchiveInspectionComplete && report.Phases.ReconstructionComplete && report.Phases.OutputRescanComplete
	switch report.Result {
	case "approved":
		if !report.Complete || report.Policy != "safe" || !allPhases || blocking || len(report.SanitizedOutputs) == 0 ||
			report.CompletedAt.Sub(report.Definitions.UpdatedAt) > DefaultMaximumDefinitionAge {
			return scanError("REPORT_INCOMPLETE", "The scan report cannot authorize promotion.", "Repeat every scanner phase with current definitions and no blocking findings.", nil)
		}
	case "rejected":
		if !report.Complete || !allPhases || !blocking || len(report.SanitizedOutputs) != 0 {
			return reportInvalid("A rejected report lacks a complete blocking decision or contains promotable output.")
		}
	case "error":
		if report.Complete || len(report.SanitizedOutputs) != 0 {
			return reportInvalid("An error report cannot be complete or contain promotable output.")
		}
	default:
		return reportInvalid("The scan report result is invalid.")
	}
	return nil
}

func SignReport(report ScanReport, key *secret.Bytes) (AuthenticatedReport, error) {
	canonical, err := report.CanonicalJSON()
	if err != nil {
		return AuthenticatedReport{}, err
	}
	tag, err := reportMAC(key, canonical)
	if err != nil {
		return AuthenticatedReport{}, err
	}
	return AuthenticatedReport{CanonicalJSON: canonical, AuthenticationTag: tag, Complete: report.Complete}, nil
}

func VerifyReport(envelope AuthenticatedReport, key *secret.Bytes) (ScanReport, error) {
	if len(envelope.CanonicalJSON) == 0 || len(envelope.CanonicalJSON) > MaximumScanReportBytes || len(envelope.AuthenticationTag) != ScanReportMACBytes {
		return ScanReport{}, scanError("REPORT_AUTHENTICATION_FAILED", "The scan report envelope is invalid.", "Destroy the scanner and repeat the complete scan workflow.", nil)
	}
	expected, err := reportMAC(key, envelope.CanonicalJSON)
	if err != nil {
		return ScanReport{}, err
	}
	matched := hmac.Equal(expected, envelope.AuthenticationTag)
	clear(expected)
	if !matched {
		return ScanReport{}, scanError("REPORT_AUTHENTICATION_FAILED", "The scan report authentication tag does not match.", "Destroy the scanner and repeat the complete scan workflow.", nil)
	}
	report, err := decodeCanonicalReport(envelope.CanonicalJSON)
	if err != nil {
		return ScanReport{}, err
	}
	if report.Complete != envelope.Complete {
		return ScanReport{}, scanError("REPORT_AUTHENTICATION_FAILED", "The scan report completeness flag is inconsistent.", "Destroy the scanner and repeat the complete scan workflow.", nil)
	}
	return report, nil
}

func VerifyApproval(envelope AuthenticatedReport, key *secret.Bytes) (ScanReport, error) {
	report, err := VerifyReport(envelope, key)
	if err != nil {
		return ScanReport{}, err
	}
	if !report.Complete || report.Result != "approved" {
		return ScanReport{}, scanError("REPORT_INCOMPLETE", "The scan report does not authorize promotion.", "Complete every scanner phase with an approved result before transfer.", nil)
	}
	return report, nil
}

func decodeCanonicalReport(encoded []byte) (ScanReport, error) {
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(encoded), MaximumScanReportBytes+1))
	decoder.DisallowUnknownFields()
	var report ScanReport
	if err := decoder.Decode(&report); err != nil {
		return ScanReport{}, reportInvalid("The authenticated scan report JSON is invalid.")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ScanReport{}, reportInvalid("The authenticated scan report has trailing content.")
	}
	if err := report.Validate(); err != nil {
		return ScanReport{}, err
	}
	canonical, err := json.Marshal(report)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ScanReport{}, reportInvalid("The authenticated scan report is not canonical JSON.")
	}
	return report, nil
}

func reportMAC(key *secret.Bytes, message []byte) ([]byte, error) {
	if key == nil {
		return nil, scanError("REPORT_KEY_UNAVAILABLE", "The volatile report authentication key is unavailable.", "Destroy the scanner and start a fresh authenticated session.", nil)
	}
	var tag []byte
	err := key.WithReader(func(reader io.Reader) error {
		keyBytes, err := io.ReadAll(io.LimitReader(reader, ScanReportMACBytes+1))
		if err != nil || len(keyBytes) != ScanReportMACBytes {
			clear(keyBytes)
			return errors.New("invalid report authentication key")
		}
		mac := hmac.New(sha256.New, keyBytes)
		clear(keyBytes)
		_, _ = mac.Write(message)
		tag = mac.Sum(nil)
		return nil
	})
	if err != nil {
		clear(tag)
		return nil, scanError("REPORT_KEY_UNAVAILABLE", "The volatile report authentication key is unavailable.", "Destroy the scanner and start a fresh authenticated session.", err)
	}
	return tag, nil
}

func reportInvalid(message string) error {
	return scanError("REPORT_INCOMPLETE", message, "Repeat the complete offline scan and generate a new authenticated report.", nil)
}

func validLogicalName(value string) bool {
	return value != "" && len(value) <= MaximumInventoryPathBytes && !strings.ContainsAny(value, "\x00\\") &&
		!strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "." && value != ".."
}

func strictlySortedInputs(values []ReportInput) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1].LogicalName >= values[index].LogicalName {
			return false
		}
	}
	return true
}

func strictlySortedArchives(values []ReportArchive) bool {
	for index := 1; index < len(values); index++ {
		left, right := values[index-1], values[index]
		if left.SourceSHA256 > right.SourceSHA256 || (left.SourceSHA256 == right.SourceSHA256 && left.Depth >= right.Depth) {
			return false
		}
	}
	return true
}

func strictlySortedFindings(values []Finding) bool {
	for index := 1; index < len(values); index++ {
		left := values[index-1].RelativePath + "\x00" + values[index-1].Code + "\x00" + values[index-1].Identifier
		right := values[index].RelativePath + "\x00" + values[index].Code + "\x00" + values[index].Identifier
		if left >= right {
			return false
		}
	}
	return true
}

func strictlySortedOutputs(values []ReportSanitizedOutput) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1].OutputID >= values[index].OutputID {
			return false
		}
	}
	return true
}

func strictlySortedTools(values []ToolEvidence) bool {
	for index := 1; index < len(values); index++ {
		left := values[index-1].Name + "\x00" + values[index-1].Version
		right := values[index].Name + "\x00" + values[index].Version
		if left >= right {
			return false
		}
	}
	return true
}

func reportDigest(value []byte) string { return hex.EncodeToString(value) }
