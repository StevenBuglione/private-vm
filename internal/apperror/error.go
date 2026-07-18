package apperror

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Error is the stable machine and human error contract. Message and
// Remediation must be safe for persistent output.
type Error struct {
	SchemaVersion int    `json:"schema_version"`
	OK            bool   `json:"ok"`
	Code          string `json:"code"`
	ExitCode      int    `json:"exit_code"`
	Message       string `json:"message"`
	Remediation   string `json:"remediation"`
	SessionID     string `json:"session_id,omitempty"`
	cause         error
}

func New(code string, exitCode int, message, remediation string) *Error {
	return &Error{SchemaVersion: 1, OK: false, Code: code, ExitCode: exitCode, Message: message, Remediation: remediation}
}

func Wrap(code string, exitCode int, message, remediation string, cause error) *Error {
	err := New(code, exitCode, message, remediation)
	err.cause = cause
	return err
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }
func (e *Error) Unwrap() error { return e.cause }

func From(err error) *Error {
	var app *Error
	if errors.As(err, &app) {
		return app
	}
	return Wrap("INTERNAL_ERROR", 70, "An internal error occurred.", "Retry once; if the error persists, export a redacted diagnostic bundle.", err)
}

func (e *Error) MarshalJSON() ([]byte, error) {
	type wire Error
	copy := wire(*e)
	copy.cause = nil
	return json.Marshal(copy)
}
