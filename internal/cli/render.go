// Package cli contains presentation-only command-line helpers.
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

const (
	// OutputSchemaVersion is the version of every CLI machine-output envelope.
	OutputSchemaVersion = 1
	// DefaultMaxOutputBytes bounds one rendered record, including its newline.
	DefaultMaxOutputBytes = 1 << 20
)

var (
	usbDeviceIDOutputPattern    = regexp.MustCompile(`^usbdev-[0-9a-f]{16}$`)
	usbEnrollmentOutputPattern  = regexp.MustCompile(`^usb-[0-9a-f]{16}$`)
	usbHexIDOutputPattern       = regexp.MustCompile(`^[0-9a-f]{4}$`)
	usbPortOutputPattern        = regexp.MustCompile(`^[0-9]+-[0-9]+(?:\.[0-9]+)*$`)
	usbInterfaceOutputPattern   = regexp.MustCompile(`^08:[0-9a-f]{2}:[0-9a-f]{2}$`)
	usbHashOutputPattern        = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{16,256}$`)
	usbFingerprintOutputPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	usbBlockPathOutputPattern   = regexp.MustCompile(`^/dev/[A-Za-z0-9._-]+$`)
	usbClaimOutputPattern       = regexp.MustCompile(`^usbclaim-[0-9a-f]{32}$`)
)

// Code is a stable, machine-readable result or event code.
type Code string

const (
	CodeVersion         Code = "VERSION_REPORTED"
	CodeDoctorReport    Code = "DOCTOR_REPORT"
	CodeAcknowledged    Code = "ACKNOWLEDGED"
	CodeVPNProfile      Code = "VPN_PROFILE_STATUS"
	CodeSessionStatus   Code = "SESSION_STATUS"
	CodeWorkspaceStatus Code = "WORKSPACE_STATUS"
	CodeTorrentStatus   Code = "TORRENT_STATUS"
	CodeScannerStatus   Code = "SCANNER_STATUS"
	CodeUSBDevices      Code = "USB_DEVICE_STATUS"
	CodeUSBEnrollment   Code = "USB_ENROLLMENT_STATUS"
	CodeUSBPrepared     Code = "USB_PREPARED"
	CodeUSBExported     Code = "USB_EXPORT_VERIFIED"
	CodeInternalError   Code = "INTERNAL_ERROR"
	CodeRenderFailed    Code = "OUTPUT_RENDER_FAILED"
)

// MachinePayload is deliberately sealed. Machine output must use an audited,
// typed payload rather than an arbitrary map or caller-controlled JSON value.
type MachinePayload interface {
	machinePayload()
}

// VersionPayload is the safe machine representation of build information.
type VersionPayload struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func (VersionPayload) machinePayload() {}

// DoctorDiagnostic is one redacted, read-only host diagnostic.
type DoctorDiagnostic struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Summary     string `json:"summary"`
	Remediation string `json:"remediation,omitempty"`
	Overridable bool   `json:"overridable"`
}

// DoctorPayload is the safe machine representation of a doctor report.
type DoctorPayload struct {
	Runnable    bool               `json:"runnable"`
	Diagnostics []DoctorDiagnostic `json:"diagnostics"`
}

func (DoctorPayload) machinePayload() {}

// AcknowledgementPayload is used by commands whose only safe result is a
// bounded human-readable acknowledgement.
type AcknowledgementPayload struct {
	Message string `json:"message"`
}

func (AcknowledgementPayload) machinePayload() {}

// VPNStatusPayload is the aggregate-only volatile profile status. It cannot
// represent keys, source paths, endpoints, interface addresses or DNS values.
type VPNStatusPayload struct {
	SchemaVersion uint32                `json:"schema_version"`
	Present       bool                  `json:"present"`
	Generation    uint64                `json:"generation"`
	Rotation      string                `json:"rotation"`
	Code          string                `json:"code"`
	Remediation   string                `json:"remediation"`
	Profile       *VPNInspectionPayload `json:"profile,omitempty"`
}

type VPNInspectionPayload struct {
	SchemaVersion         uint32 `json:"schema_version"`
	IPv4Enabled           bool   `json:"ipv4_enabled"`
	IPv6Enabled           bool   `json:"ipv6_enabled"`
	InterfaceAddressCount uint32 `json:"interface_address_count"`
	DNSServerCount        uint32 `json:"dns_server_count"`
}

func (VPNStatusPayload) machinePayload() {}

// SessionPayload is the redacted semantic daemon view. It intentionally omits
// image paths, socket names, network identity, filenames, hashes and raw
// diagnostics.
type SessionPayload struct {
	Sessions []SessionView `json:"sessions"`
}

type SessionView struct {
	ID            string `json:"id"`
	Role          string `json:"role"`
	Phase         string `json:"phase"`
	WorkflowState string `json:"workflow_state,omitempty"`
}

func (SessionPayload) machinePayload() {}

// WorkspaceStatusPayload is aggregate-only. It cannot represent filenames,
// paths, content hashes, socket paths or guest-internal output identities.
type WorkspaceStatusPayload struct {
	SchemaVersion   uint32 `json:"schema_version"`
	State           string `json:"state"`
	FileCount       uint32 `json:"file_count"`
	ExportedCount   uint32 `json:"exported_count"`
	UnexportedCount uint32 `json:"unexported_count"`
	ChangedCount    uint32 `json:"changed_count"`
}

func (WorkspaceStatusPayload) machinePayload() {}

// TorrentStatusPayload deliberately carries only aggregate counters and
// stable state. Torrent names, file paths, hashes and peer identifiers never
// cross the CLI machine-output boundary.
type TorrentStatusPayload struct {
	SchemaVersion  uint32 `json:"schema_version"`
	State          string `json:"state"`
	CompletedBytes uint64 `json:"completed_bytes"`
	TotalBytes     uint64 `json:"total_bytes"`
	FileCount      uint32 `json:"file_count"`
	SelectedCount  uint32 `json:"selected_count"`
	PayloadPaused  bool   `json:"payload_paused"`
	Code           string `json:"code"`
	Remediation    string `json:"remediation"`
}

func (TorrentStatusPayload) machinePayload() {}

// ScannerStatusPayload is an aggregate-only projection of authenticated
// scanner evidence. Logical names, hashes, report JSON, malware identifiers,
// source session IDs and runtime details are intentionally unrepresentable.
type ScannerStatusPayload struct {
	SchemaVersion        uint32 `json:"schema_version"`
	SessionID            string `json:"session_id"`
	DestinationSessionID string `json:"destination_session_id,omitempty"`
	WorkflowState        string `json:"workflow_state"`
	ReportComplete       bool   `json:"report_complete"`
	Decision             string `json:"decision"`
	InputCount           uint32 `json:"input_count"`
	FindingCount         uint32 `json:"finding_count"`
	BlockingFindingCount uint32 `json:"blocking_finding_count"`
	SanitizedOutputCount uint32 `json:"sanitized_output_count"`
	SanitizedOutputBytes uint64 `json:"sanitized_output_bytes"`
	Code                 string `json:"code"`
	Remediation          string `json:"remediation"`
}

func (ScannerStatusPayload) machinePayload() {}

type USBDevicePayload struct {
	SchemaVersion       uint32   `json:"schema_version"`
	DeviceID            string   `json:"device_id"`
	VendorID            string   `json:"vendor_id"`
	ProductID           string   `json:"product_id"`
	Model               string   `json:"model,omitempty"`
	Serial              string   `json:"serial,omitempty"`
	USBGuardHash        string   `json:"usbguard_hash"`
	PortPath            string   `json:"port_path"`
	BlockPath           string   `json:"block_path"`
	Interfaces          []string `json:"interfaces"`
	CapacityBytes       uint64   `json:"capacity_bytes"`
	Mounted             bool     `json:"mounted"`
	ReadOnly            bool     `json:"read_only"`
	HostFilesystem      bool     `json:"host_filesystem"`
	Selectable          bool     `json:"selectable"`
	IdentityFingerprint string   `json:"identity_fingerprint"`
	Code                string   `json:"code"`
	Remediation         string   `json:"remediation"`
}

type USBDevicesPayload struct {
	Devices []USBDevicePayload `json:"devices"`
}

func (USBDevicesPayload) machinePayload() {}

type USBEnrollmentPayload struct {
	SchemaVersion       uint32   `json:"schema_version"`
	EnrollmentID        string   `json:"enrollment_id"`
	Label               string   `json:"label"`
	Filesystem          string   `json:"filesystem"`
	VendorID            string   `json:"vendor_id"`
	ProductID           string   `json:"product_id"`
	Model               string   `json:"model,omitempty"`
	Serial              string   `json:"serial,omitempty"`
	USBGuardHash        string   `json:"usbguard_hash"`
	BlockPath           string   `json:"block_path,omitempty"`
	PortPath            string   `json:"port_path"`
	PortBound           bool     `json:"port_bound"`
	Interfaces          []string `json:"interfaces"`
	CapacityBytes       uint64   `json:"capacity_bytes"`
	IdentityFingerprint string   `json:"identity_fingerprint"`
	Verified            bool     `json:"verified"`
	Code                string   `json:"code"`
	Remediation         string   `json:"remediation"`
}

func (USBEnrollmentPayload) machinePayload() {}

type USBPreparePayload struct {
	SchemaVersion       uint32 `json:"schema_version"`
	ExporterSessionID   string `json:"exporter_session_id"`
	ClaimID             string `json:"claim_id"`
	EnrollmentID        string `json:"enrollment_id"`
	Filesystem          string `json:"filesystem"`
	CapacityBytes       uint64 `json:"capacity_bytes"`
	IdentityFingerprint string `json:"identity_fingerprint"`
	State               string `json:"state"`
}

func (USBPreparePayload) machinePayload() {}

type USBExportPayload struct {
	SchemaVersion           uint32 `json:"schema_version"`
	EnrollmentID            string `json:"enrollment_id"`
	BytesWritten            uint64 `json:"bytes_written"`
	SourceRelayHashEqual    bool   `json:"source_relay_hash_equal"`
	RelayExporterHashEqual  bool   `json:"relay_exporter_hash_equal"`
	ExporterRereadHashEqual bool   `json:"exporter_reread_hash_equal"`
	FileSynced              bool   `json:"file_synced"`
	FilesystemSynced        bool   `json:"filesystem_synced"`
	AtomicRename            bool   `json:"atomic_rename"`
	USBUnmounted            bool   `json:"usb_unmounted"`
	USBDetached             bool   `json:"usb_detached"`
	ExporterStopped         bool   `json:"exporter_stopped"`
	CleanupComplete         bool   `json:"cleanup_complete"`
}

func (USBExportPayload) machinePayload() {}

// EventPayload is deliberately sealed independently from success payloads.
// Adding an event shape requires an explicit, reviewed concrete type.
type EventPayload interface {
	eventPayload()
}

// ProgressPayload contains non-sensitive progress counters.
type ProgressPayload struct {
	Current uint64 `json:"current"`
	Total   uint64 `json:"total"`
	Unit    string `json:"unit"`
}

func (ProgressPayload) eventPayload() {}

// StateChangePayload is the typed transition-event shape from the lifecycle
// contract. DisplayLabel must already be redacted by the event producer.
type StateChangePayload struct {
	State        string           `json:"state"`
	Message      string           `json:"message"`
	Timestamp    time.Time        `json:"timestamp"`
	Progress     *ProgressPayload `json:"progress,omitempty"`
	DisplayLabel string           `json:"display_label,omitempty"`
}

func (StateChangePayload) eventPayload() {}

// SuccessEnvelope is the closed, versioned success record.
type SuccessEnvelope struct {
	SchemaVersion int            `json:"schema_version"`
	OK            bool           `json:"ok"`
	Code          Code           `json:"code"`
	Data          MachinePayload `json:"data"`
}

// ErrorEnvelope is the closed, versioned error record. It intentionally has no
// cause field, so an apperror's wrapped cause cannot cross the output boundary.
type ErrorEnvelope struct {
	SchemaVersion int    `json:"schema_version"`
	OK            bool   `json:"ok"`
	Code          Code   `json:"code"`
	ExitCode      int    `json:"exit_code"`
	Message       string `json:"message"`
	Remediation   string `json:"remediation"`
	SessionID     string `json:"session_id,omitempty"`
}

// EventEnvelope is the closed, versioned event record.
type EventEnvelope struct {
	SchemaVersion int          `json:"schema_version"`
	OK            bool         `json:"ok"`
	Code          Code         `json:"code"`
	Sequence      uint64       `json:"sequence"`
	SessionID     string       `json:"session_id,omitempty"`
	Data          EventPayload `json:"data"`
}

// NewSuccessEnvelope constructs a canonical success record.
func NewSuccessEnvelope(code Code, data MachinePayload) SuccessEnvelope {
	if doctor, ok := data.(DoctorPayload); ok && doctor.Diagnostics == nil {
		doctor.Diagnostics = []DoctorDiagnostic{}
		data = doctor
	}
	return SuccessEnvelope{SchemaVersion: OutputSchemaVersion, OK: true, Code: code, Data: data}
}

// NewErrorEnvelope copies only the public, redacted apperror fields. Malformed
// errors are normalized to the internal-error contract rather than reflected.
func NewErrorEnvelope(err error) ErrorEnvelope {
	app := apperror.From(err)
	if !validCode(Code(app.Code)) ||
		!validErrorExitCode(app.ExitCode) ||
		!validRequiredString(app.Message, 512) ||
		!validRequiredString(app.Remediation, 1024) ||
		!validOptionalSessionID(app.SessionID) {
		app = apperror.New(
			string(CodeInternalError),
			exitcode.Internal,
			"An internal error occurred.",
			"Retry once; if the error persists, export a redacted diagnostic bundle.",
		)
	}
	return ErrorEnvelope{
		SchemaVersion: OutputSchemaVersion,
		OK:            false,
		Code:          Code(app.Code),
		ExitCode:      app.ExitCode,
		Message:       app.Message,
		Remediation:   app.Remediation,
		SessionID:     app.SessionID,
	}
}

// NewEventEnvelope constructs a canonical event record.
func NewEventEnvelope(code Code, sequence uint64, sessionID string, data EventPayload) EventEnvelope {
	return EventEnvelope{
		SchemaVersion: OutputSchemaVersion,
		OK:            true,
		Code:          code,
		Sequence:      sequence,
		SessionID:     sessionID,
		Data:          data,
	}
}

// Renderer writes either compact JSON records or safe human output. It buffers
// and validates the complete bounded record before issuing one Write call.
type Renderer struct {
	json     bool
	maxBytes int
}

// NewRenderer returns a renderer with the production output limit.
func NewRenderer(jsonOutput bool) Renderer {
	return Renderer{json: jsonOutput, maxBytes: DefaultMaxOutputBytes}
}

// NewBoundedRenderer returns a renderer with an explicit positive record limit.
// It is useful for callers with a stricter transport bound and for tests.
func NewBoundedRenderer(jsonOutput bool, maxBytes int) Renderer {
	return Renderer{json: jsonOutput, maxBytes: maxBytes}
}

// Success renders one success record to w.
func (r Renderer) Success(w io.Writer, code Code, data MachinePayload) error {
	envelope := NewSuccessEnvelope(code, data)
	if !validSuccess(envelope) {
		return renderFailure(errors.New("invalid success envelope"))
	}
	if r.json {
		return r.writeJSON(w, envelope)
	}
	return r.writeHuman(w, humanSuccess(code, data))
}

func validSuccess(success SuccessEnvelope) bool {
	if !validCode(success.Code) || success.Data == nil {
		return false
	}
	switch data := success.Data.(type) {
	case VersionPayload:
		return success.Code == CodeVersion &&
			validRequiredString(data.Version, 128) &&
			validRequiredString(data.Commit, 128) &&
			validRequiredString(data.Date, 64) &&
			validRequiredString(data.GoVersion, 64) &&
			validRequiredString(data.OS, 64) &&
			validRequiredString(data.Arch, 64)
	case DoctorPayload:
		if success.Code != CodeDoctorReport || data.Diagnostics == nil || len(data.Diagnostics) > 512 {
			return false
		}
		for _, diagnostic := range data.Diagnostics {
			if !validCode(Code(diagnostic.Code)) ||
				!oneOf(diagnostic.Severity, "info", "warning", "blocking") ||
				!validRequiredString(diagnostic.Summary, 512) ||
				len(diagnostic.Remediation) > 1024 || !utf8.ValidString(diagnostic.Remediation) {
				return false
			}
		}
		return true
	case AcknowledgementPayload:
		return success.Code == CodeAcknowledged && validRequiredString(data.Message, 512)
	case VPNStatusPayload:
		if success.Code != CodeVPNProfile || data.SchemaVersion != 1 ||
			!oneOf(data.Rotation, "not_imported", "resolution_required", "current", "rotation_required") ||
			!validCode(Code(data.Code)) || !validRequiredString(data.Remediation, 256) {
			return false
		}
		if !data.Present {
			return data.Generation == 0 && data.Rotation == "not_imported" && data.Code == "VPN_PROFILE_NOT_IMPORTED" && data.Profile == nil
		}
		expectedCode := map[string]string{
			"resolution_required": "VPN_ENDPOINT_CHECK_REQUIRED",
			"current":             "VPN_PROFILE_CURRENT",
			"rotation_required":   "VPN_PROFILE_ROTATION_REQUIRED",
		}[data.Rotation]
		return data.Generation > 0 && data.Profile != nil && data.Profile.SchemaVersion == 1 && data.Profile.IPv4Enabled &&
			data.Profile.InterfaceAddressCount > 0 && data.Profile.InterfaceAddressCount <= 8 &&
			data.Profile.DNSServerCount > 0 && data.Profile.DNSServerCount <= 8 &&
			expectedCode != "" && data.Code == expectedCode
	case SessionPayload:
		if success.Code != CodeSessionStatus || data.Sessions == nil || len(data.Sessions) > 64 {
			return false
		}
		for _, value := range data.Sessions {
			if value.ID == "" || !validOptionalSessionID(value.ID) ||
				!oneOf(value.Role, "workstation", "downloader", "scanner", "exporter") ||
				!oneOf(value.Phase, "CREATED", "PREFLIGHTED", "IMAGES_VERIFIED", "STORAGE_READY", "ACTIVE", "STOPPING", "ABORTING", "DESTROYING", "DESTROYED") ||
				(len(value.WorkflowState) > 64 || !utf8.ValidString(value.WorkflowState)) {
				return false
			}
		}
		return true
	case WorkspaceStatusPayload:
		return success.Code == CodeWorkspaceStatus && data.SchemaVersion == 1 &&
			oneOf(data.State, "CLEAN", "READY", "UNEXPORTED", "CHANGED") &&
			data.ExportedCount <= data.FileCount && data.UnexportedCount <= data.FileCount && data.ChangedCount <= data.FileCount
	case TorrentStatusPayload:
		return success.Code == CodeTorrentStatus && data.SchemaVersion == 1 &&
			validCode(Code(data.State)) && data.CompletedBytes <= data.TotalBytes &&
			data.SelectedCount <= data.FileCount && validCode(Code(data.Code)) &&
			validRequiredString(data.Remediation, 512)
	case ScannerStatusPayload:
		return success.Code == CodeScannerStatus && data.SchemaVersion == 1 &&
			validOptionalSessionID(data.SessionID) && data.SessionID != "" &&
			validOptionalSessionID(data.DestinationSessionID) &&
			(data.DestinationSessionID == "" || data.Decision == "approved" && data.WorkflowState == "SCAN_VM_STOPPED") &&
			validCode(Code(data.WorkflowState)) && oneOf(data.Decision, "pending", "approved", "rejected") &&
			data.BlockingFindingCount <= data.FindingCount && validCode(Code(data.Code)) &&
			validRequiredString(data.Remediation, 512)
	case USBDevicesPayload:
		if success.Code != CodeUSBDevices || data.Devices == nil || len(data.Devices) > 256 {
			return false
		}
		for _, device := range data.Devices {
			if !validUSBDevice(device) {
				return false
			}
		}
		return true
	case USBEnrollmentPayload:
		return success.Code == CodeUSBEnrollment && data.SchemaVersion == 1 && usbEnrollmentOutputPattern.MatchString(data.EnrollmentID) &&
			validRequiredString(data.Label, 32) && data.Filesystem == "luks2-ext4" && usbHexIDOutputPattern.MatchString(data.VendorID) && usbHexIDOutputPattern.MatchString(data.ProductID) &&
			data.CapacityBytes > 0 && usbFingerprintOutputPattern.MatchString(data.IdentityFingerprint) && validUSBInterfaces(data.Interfaces) && usbHashOutputPattern.MatchString(data.USBGuardHash) &&
			(data.BlockPath == "" || usbBlockPathOutputPattern.MatchString(data.BlockPath)) && usbPortOutputPattern.MatchString(data.PortPath) && validUSBText(data.Serial, 256, true) && validUSBText(data.Model, 256, true) &&
			validCode(Code(data.Code)) && validRequiredString(data.Remediation, 512)
	case USBPreparePayload:
		return success.Code == CodeUSBPrepared && data.SchemaVersion == 1 && validOptionalSessionID(data.ExporterSessionID) &&
			usbClaimOutputPattern.MatchString(data.ClaimID) && usbEnrollmentOutputPattern.MatchString(data.EnrollmentID) &&
			data.Filesystem == "luks2-ext4" && data.CapacityBytes > 0 && usbFingerprintOutputPattern.MatchString(data.IdentityFingerprint) && data.State == "DESTINATION_PREPARED"
	case USBExportPayload:
		return success.Code == CodeUSBExported && data.SchemaVersion == 1 && usbEnrollmentOutputPattern.MatchString(data.EnrollmentID) && data.BytesWritten > 0 &&
			data.SourceRelayHashEqual && data.RelayExporterHashEqual && data.ExporterRereadHashEqual && data.FileSynced && data.FilesystemSynced && data.AtomicRename &&
			data.USBUnmounted && data.USBDetached && data.ExporterStopped && data.CleanupComplete
	default:
		return false
	}
}

func validUSBDevice(device USBDevicePayload) bool {
	return device.SchemaVersion == 1 && usbDeviceIDOutputPattern.MatchString(device.DeviceID) &&
		usbHexIDOutputPattern.MatchString(device.VendorID) && usbHexIDOutputPattern.MatchString(device.ProductID) &&
		device.CapacityBytes > 0 && usbFingerprintOutputPattern.MatchString(device.IdentityFingerprint) &&
		validUSBInterfaces(device.Interfaces) && usbHashOutputPattern.MatchString(device.USBGuardHash) &&
		usbBlockPathOutputPattern.MatchString(device.BlockPath) && usbPortOutputPattern.MatchString(device.PortPath) &&
		validUSBText(device.Serial, 256, true) && validUSBText(device.Model, 256, true) &&
		validCode(Code(device.Code)) && validRequiredString(device.Remediation, 512)
}

func validUSBInterfaces(values []string) bool {
	if len(values) == 0 || len(values) > 32 {
		return false
	}
	for index, value := range values {
		if !usbInterfaceOutputPattern.MatchString(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func validUSBText(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	return len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func validRequiredString(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && utf8.ValidString(value)
}

// Error renders one application error to w without exposing its wrapped cause.
func (r Renderer) Error(w io.Writer, err error) error {
	envelope := NewErrorEnvelope(err)
	if r.json {
		return r.writeJSON(w, envelope)
	}
	return r.writeHuman(w, fmt.Sprintf(
		"%s: %s\nremediation: %s\n",
		safeLine(string(envelope.Code)),
		safeLine(envelope.Message),
		safeLine(envelope.Remediation),
	))
}

// Event renders one event record to w.
func (r Renderer) Event(w io.Writer, code Code, sequence uint64, sessionID string, data EventPayload) error {
	envelope := NewEventEnvelope(code, sequence, sessionID, data)
	if !validEvent(envelope) {
		return renderFailure(errors.New("invalid event envelope"))
	}
	if r.json {
		return r.writeJSON(w, envelope)
	}
	return r.writeHuman(w, humanEvent(envelope))
}

func (r Renderer) writeJSON(w io.Writer, value any) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return renderFailure(err)
	}
	return r.writeBounded(w, buffer.Bytes())
}

func (r Renderer) writeHuman(w io.Writer, value string) error {
	return r.writeBounded(w, []byte(value))
}

func (r Renderer) writeBounded(w io.Writer, value []byte) error {
	if w == nil {
		return renderFailure(errors.New("nil output writer"))
	}
	if r.maxBytes <= 0 || len(value) > r.maxBytes {
		return renderFailure(errors.New("output exceeds configured bound"))
	}
	n, err := w.Write(value)
	if err != nil {
		return renderFailure(err)
	}
	if n != len(value) {
		return renderFailure(io.ErrShortWrite)
	}
	return nil
}

func humanSuccess(code Code, data MachinePayload) string {
	switch value := data.(type) {
	case VersionPayload:
		return fmt.Sprintf(
			"private-vm %s\ncommit: %s\nbuilt: %s\ngo: %s\nplatform: %s/%s\n",
			safeLine(value.Version), safeLine(value.Commit), safeLine(value.Date),
			safeLine(value.GoVersion), safeLine(value.OS), safeLine(value.Arch),
		)
	case DoctorPayload:
		var buffer strings.Builder
		for _, diagnostic := range value.Diagnostics {
			fmt.Fprintf(&buffer, "[%s] %s: %s\n", safeLine(strings.ToUpper(diagnostic.Severity)), safeLine(diagnostic.Code), safeLine(diagnostic.Summary))
			if diagnostic.Remediation != "" {
				fmt.Fprintf(&buffer, "  remediation: %s\n", safeLine(diagnostic.Remediation))
			}
		}
		fmt.Fprintf(&buffer, "\nrunnable: %t\n", value.Runnable)
		return buffer.String()
	case AcknowledgementPayload:
		return fmt.Sprintf("%s: %s\n", safeLine(string(code)), safeLine(value.Message))
	case VPNStatusPayload:
		ipv4, ipv6 := false, false
		addresses, dns := uint32(0), uint32(0)
		if value.Profile != nil {
			ipv4, ipv6 = value.Profile.IPv4Enabled, value.Profile.IPv6Enabled
			addresses, dns = value.Profile.InterfaceAddressCount, value.Profile.DNSServerCount
		}
		return fmt.Sprintf(
			"%s: present=%t generation=%d rotation=%s ipv4=%t ipv6=%t addresses=%d dns=%d\nremediation: %s\n",
			safeLine(value.Code), value.Present, value.Generation, safeLine(value.Rotation),
			ipv4, ipv6, addresses, dns,
			safeLine(value.Remediation),
		)
	case SessionPayload:
		var buffer strings.Builder
		if len(value.Sessions) == 0 {
			return "no active sessions\n"
		}
		for _, current := range value.Sessions {
			workflow := ""
			if current.WorkflowState != "" {
				workflow = " workflow=" + safeLine(current.WorkflowState)
			}
			fmt.Fprintf(&buffer, "%s role=%s phase=%s%s\n", safeLine(current.ID), safeLine(current.Role), safeLine(current.Phase), workflow)
		}
		return buffer.String()
	case TorrentStatusPayload:
		return fmt.Sprintf(
			"%s state=%s progress=%d/%d files=%d selected=%d payload_paused=%t\nremediation: %s\n",
			safeLine(value.Code), safeLine(value.State), value.CompletedBytes, value.TotalBytes,
			value.FileCount, value.SelectedCount, value.PayloadPaused, safeLine(value.Remediation),
		)
	case ScannerStatusPayload:
		destination := ""
		if value.DestinationSessionID != "" {
			destination = " destination_session=" + safeLine(value.DestinationSessionID)
		}
		return fmt.Sprintf(
			"%s session=%s%s state=%s decision=%s report_complete=%t inputs=%d findings=%d blocking=%d outputs=%d output_bytes=%d\nremediation: %s\n",
			safeLine(value.Code), safeLine(value.SessionID), destination, safeLine(value.WorkflowState), safeLine(value.Decision),
			value.ReportComplete, value.InputCount, value.FindingCount, value.BlockingFindingCount,
			value.SanitizedOutputCount, value.SanitizedOutputBytes, safeLine(value.Remediation),
		)
	case USBDevicesPayload:
		if len(value.Devices) == 0 {
			return "no USB mass-storage candidates\n"
		}
		var buffer strings.Builder
		for _, device := range value.Devices {
			fmt.Fprintf(&buffer, "%s path=%s %s:%s model=%s serial=%s usbguard_hash=%s capacity=%d port=%s selectable=%t fingerprint=%s code=%s\n",
				safeLine(device.DeviceID), safeLine(device.BlockPath), safeLine(device.VendorID), safeLine(device.ProductID), safeLine(device.Model),
				safeLine(device.Serial), safeLine(device.USBGuardHash), device.CapacityBytes, safeLine(device.PortPath), device.Selectable,
				safeLine(device.IdentityFingerprint), safeLine(device.Code))
		}
		return buffer.String()
	case USBEnrollmentPayload:
		return fmt.Sprintf("%s label=%s path=%s %s:%s serial=%s usbguard_hash=%s capacity=%d port=%s port_bound=%t verified=%t fingerprint=%s code=%s\nremediation: %s\n",
			safeLine(value.EnrollmentID), safeLine(value.Label), safeLine(value.BlockPath), safeLine(value.VendorID), safeLine(value.ProductID),
			safeLine(value.Serial), safeLine(value.USBGuardHash), value.CapacityBytes, safeLine(value.PortPath), value.PortBound, value.Verified,
			safeLine(value.IdentityFingerprint), safeLine(value.Code), safeLine(value.Remediation))
	case USBPreparePayload:
		return fmt.Sprintf("exporter=%s claim=%s enrollment=%s filesystem=%s capacity=%d fingerprint=%s state=%s\n",
			safeLine(value.ExporterSessionID), safeLine(value.ClaimID), safeLine(value.EnrollmentID), safeLine(value.Filesystem), value.CapacityBytes,
			safeLine(value.IdentityFingerprint), safeLine(value.State))
	case USBExportPayload:
		return fmt.Sprintf("enrollment=%s bytes=%d source_relay_hash_equal=%t relay_exporter_hash_equal=%t exporter_reread_hash_equal=%t synced=%t filesystem_synced=%t atomic=%t unmounted=%t detached=%t stopped=%t cleanup=%t\n",
			safeLine(value.EnrollmentID), value.BytesWritten, value.SourceRelayHashEqual, value.RelayExporterHashEqual, value.ExporterRereadHashEqual,
			value.FileSynced, value.FilesystemSynced, value.AtomicRename, value.USBUnmounted, value.USBDetached, value.ExporterStopped, value.CleanupComplete)
	default:
		// MachinePayload is sealed; this protects against new payload types being
		// added without a corresponding reviewed human representation.
		return ""
	}
}

func humanEvent(event EventEnvelope) string {
	switch data := event.Data.(type) {
	case ProgressPayload:
		return fmt.Sprintf(
			"[%d] %s: %d/%d %s\n",
			event.Sequence, safeLine(string(event.Code)), data.Current, data.Total, safeLine(data.Unit),
		)
	case StateChangePayload:
		label := ""
		if data.DisplayLabel != "" {
			label = " (" + safeLine(data.DisplayLabel) + ")"
		}
		return fmt.Sprintf(
			"[%d] %s %s%s: %s\n",
			event.Sequence,
			safeLine(string(event.Code)),
			safeLine(data.State),
			label,
			safeLine(data.Message),
		)
	default:
		return ""
	}
}

func validEvent(event EventEnvelope) bool {
	if !validCode(event.Code) || event.Sequence == 0 || !validOptionalSessionID(event.SessionID) || event.Data == nil {
		return false
	}
	switch data := event.Data.(type) {
	case ProgressPayload:
		return validProgress(data)
	case StateChangePayload:
		if !validCode(Code(data.State)) || !validRequiredString(data.Message, 512) || data.Timestamp.IsZero() || len(data.DisplayLabel) > 256 || !utf8.ValidString(data.DisplayLabel) {
			return false
		}
		return data.Progress == nil || validProgress(*data.Progress)
	default:
		return false
	}
}

func validProgress(progress ProgressPayload) bool {
	return progress.Total > 0 && progress.Current <= progress.Total && validRequiredString(progress.Unit, 64)
}

func validCode(code Code) bool {
	if len(code) < 3 || len(code) > 64 || code[0] < 'A' || code[0] > 'Z' {
		return false
	}
	for index := 1; index < len(code); index++ {
		character := code[index]
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func validOptionalSessionID(sessionID string) bool {
	if sessionID == "" {
		return true
	}
	if len(sessionID) != len("pvm-")+32 || !strings.HasPrefix(sessionID, "pvm-") {
		return false
	}
	for index := len("pvm-"); index < len(sessionID); index++ {
		character := sessionID[index]
		if (character < 'a' || character > 'f') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validErrorExitCode(code int) bool {
	return code == exitcode.Usage || (code >= exitcode.Preflight && code <= exitcode.Cleanup) || code == exitcode.Internal
}

func safeLine(value string) string {
	value = strings.ToValidUTF8(value, "�")
	return strings.Map(func(character rune) rune {
		if character == '\n' || character == '\r' || character == '\t' || (!unicode.IsPrint(character) && character != utf8.RuneError) {
			return ' '
		}
		return character
	}, value)
}

func renderFailure(cause error) *apperror.Error {
	return apperror.Wrap(
		string(CodeRenderFailed),
		exitcode.Internal,
		"Unable to render command output.",
		"Retry once; if the error persists, export a redacted diagnostic bundle.",
		cause,
	)
}
