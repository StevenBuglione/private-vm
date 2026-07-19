package image

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// ErrorCode is a stable, redacted image-pull/cache failure classification.
// CLI and daemon boundaries map trust/cache codes to exit 12 and normalize the
// cancellation/timeout codes to the canonical exit 21/15 records without
// exposing the wrapped registry or filesystem failure.
type ErrorCode string

const (
	CodeReferenceInvalid     ErrorCode = "IMAGE_REFERENCE_INVALID"
	CodeResolveFailed        ErrorCode = "IMAGE_RESOLVE_FAILED"
	CodeManifestInvalid      ErrorCode = "IMAGE_OCI_MANIFEST_INVALID"
	CodeArtifactLimit        ErrorCode = "IMAGE_ARTIFACT_LIMIT"
	CodeDigestMismatch       ErrorCode = "IMAGE_DIGEST_MISMATCH"
	CodeDownloadFailed       ErrorCode = "IMAGE_DOWNLOAD_FAILED"
	CodeExtractionFailed     ErrorCode = "IMAGE_EXTRACTION_FAILED"
	CodeCacheInvalid         ErrorCode = "IMAGE_CACHE_INVALID"
	CodeCacheConflict        ErrorCode = "IMAGE_CACHE_CONFLICT"
	CodeVerificationFailed   ErrorCode = "IMAGE_VERIFICATION_FAILED"
	CodeVerificationMissing  ErrorCode = "IMAGE_VERIFICATION_UNAVAILABLE"
	CodeManifestContract     ErrorCode = "IMAGE_MANIFEST_INVALID"
	CodeRoleMismatch         ErrorCode = "IMAGE_ROLE_MISMATCH"
	CodeBundleMismatch       ErrorCode = "IMAGE_BUNDLE_MISMATCH"
	CodeArchitectureMismatch ErrorCode = "IMAGE_ARCHITECTURE_MISMATCH"
	CodeGuestAPIMismatch     ErrorCode = "IMAGE_GUEST_API_MISMATCH"
	CodeQEMUVersionMismatch  ErrorCode = "IMAGE_QEMU_VERSION_MISMATCH"
	CodeCapabilityMismatch   ErrorCode = "IMAGE_CAPABILITY_MISMATCH"
	CodeSBOMRequired         ErrorCode = "IMAGE_SBOM_REQUIRED"
	CodeSBOMInvalid          ErrorCode = "IMAGE_SBOM_INVALID"
	CodePullCancelled        ErrorCode = "IMAGE_PULL_CANCELLED"
	CodePullTimeout          ErrorCode = "IMAGE_PULL_TIMEOUT"
)

// Error carries only stable presentation text. Cause is available to trusted
// in-process diagnostics through errors.Is/As but is never formatted.
type Error struct {
	code        ErrorCode
	message     string
	remediation string
	cause       error
}

func (e *Error) Error() string       { return fmt.Sprintf("%s: %s", e.code, e.message) }
func (e *Error) Unwrap() error       { return e.cause }
func (e *Error) Code() ErrorCode     { return e.code }
func (e *Error) Message() string     { return e.message }
func (e *Error) Remediation() string { return e.remediation }
func (e *Error) GoString() string    { return e.Error() }

// Format makes every fmt verb and flag safe. In particular, %#v must not use
// Go's structural formatter because cause intentionally retains a trusted-only
// registry/filesystem error for errors.Is/As.
func (e *Error) Format(state fmt.State, verb rune) {
	value := e.Error()
	if verb == 'q' {
		value = strconv.Quote(value)
	}
	_, _ = io.WriteString(state, value)
}

func imageError(code ErrorCode, message, remediation string, cause error) error {
	return &Error{code: code, message: message, remediation: remediation, cause: cause}
}

func contextError(ctx context.Context, fallback error) error {
	if cause := context.Cause(ctx); cause != nil {
		if errors.Is(cause, context.DeadlineExceeded) {
			return imageError(
				CodePullTimeout,
				"The image pull exceeded its bounded deadline.",
				"Retry when the registry is responsive or select an already verified cached digest.",
				cause,
			)
		}
		return imageError(
			CodePullCancelled,
			"The image pull was cancelled before installation completed.",
			"Retry the pull; incomplete cache data was removed.",
			cause,
		)
	}
	return fallback
}
