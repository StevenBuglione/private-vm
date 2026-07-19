// Package cli contains presentation-only command-line helpers.
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Code is a stable, machine-readable result or event code.
type Code string

const (
	CodeVersion       Code = "VERSION_REPORTED"
	CodeDoctorReport  Code = "DOCTOR_REPORT"
	CodeAcknowledged  Code = "ACKNOWLEDGED"
	CodeInternalError Code = "INTERNAL_ERROR"
	CodeRenderFailed  Code = "OUTPUT_RENDER_FAILED"
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
	default:
		return false
	}
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
