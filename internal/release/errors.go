// Package release owns the immutable whole-release transaction. It composes
// package artifacts with the six image identities without weakening either
// package installation or image verification boundaries.
package release

import "fmt"

const (
	CodeInvalid           = "RELEASE_INVALID"
	CodeSourceUnprotected = "RELEASE_SOURCE_UNPROTECTED"
	CodeArtifactInvalid   = "RELEASE_ARTIFACT_INVALID"
	CodeProvenanceInvalid = "RELEASE_PROVENANCE_INVALID"
	CodeConflict          = "RELEASE_CONFLICT"
	CodePublishFailed     = "RELEASE_PUBLISH_FAILED"
	CodeVerifyFailed      = "RELEASE_VERIFY_FAILED"
	CodeCleanupIncomplete = "RELEASE_CLEANUP_INCOMPLETE"
	CodeCancelled         = "RELEASE_CANCELLED"
	CodeTimeout           = "RELEASE_TIMEOUT"
	CodeGatesIncomplete   = "RELEASE_GATES_INCOMPLETE"
)

// Error is the stable, redacted release error contract.
type Error struct {
	Code        string
	Message     string
	Remediation string
	cause       error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %s Remediation: %s", e.Code, e.Message, e.Remediation)
}

func (e *Error) Unwrap() error { return e.cause }

func releaseError(code, message, remediation string, cause error) error {
	return &Error{Code: code, Message: message, Remediation: remediation, cause: cause}
}
