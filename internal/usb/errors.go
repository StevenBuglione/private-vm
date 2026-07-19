package usb

import "fmt"

type ErrorCode string

const (
	CodeNotEnrolled       ErrorCode = "USB_NOT_ENROLLED"
	CodeIdentityMismatch  ErrorCode = "USB_IDENTITY_MISMATCH"
	CodeAmbiguous         ErrorCode = "USB_AMBIGUOUS"
	CodeComposite         ErrorCode = "USB_COMPOSITE_INTERFACE"
	CodeHostFilesystem    ErrorCode = "USB_HOST_FILESYSTEM"
	CodeMounted           ErrorCode = "USB_MOUNTED"
	CodeTooSmall          ErrorCode = "USB_TOO_SMALL"
	CodeWriteFailed       ErrorCode = "USB_WRITE_FAILED"
	CodeHashMismatch      ErrorCode = "USB_HASH_MISMATCH"
	CodeReadOnly          ErrorCode = "USB_READ_ONLY"
	CodeConfirmation      ErrorCode = "USB_CONFIRMATION_REQUIRED"
	CodeClaimConflict     ErrorCode = "USB_ALREADY_CLAIMED"
	CodeDiscoveryFailed   ErrorCode = "USB_DISCOVERY_FAILED"
	CodeCleanupIncomplete ErrorCode = "USB_CLEANUP_INCOMPLETE"
)

// Error carries a stable code and intentionally excludes device paths, model
// strings, serials and wrapped command output from its rendered form.
type Error struct {
	Code        ErrorCode
	Message     string
	Remediation string
	cause       error
}

func newError(code ErrorCode, message, remediation string, cause error) *Error {
	return &Error{Code: code, Message: message, Remediation: remediation, cause: cause}
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }
func (e *Error) Unwrap() error { return e.cause }
