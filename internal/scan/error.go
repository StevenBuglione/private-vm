// Package scan implements the fail-closed scanner guest workflow.
package scan

import (
	"errors"
	"fmt"
)

// Error is safe to cross the guest RPC boundary. Cause is deliberately not
// rendered because operating-system and parser errors can contain input names.
type Error struct {
	Code        string
	Message     string
	Remediation string
	cause       error
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }
func (e *Error) Unwrap() error { return e.cause }

func scanError(code, message, remediation string, cause error) *Error {
	return &Error{Code: code, Message: message, Remediation: remediation, cause: cause}
}

// ErrorCode returns a stable scanner code without exposing the wrapped cause.
func ErrorCode(err error) string {
	var scanErr *Error
	if errors.As(err, &scanErr) {
		return scanErr.Code
	}
	return "SCAN_ERROR"
}
