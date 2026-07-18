package daemon

import (
	"errors"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func rpcError(grpcCode codes.Code, code, message, remediation string, retryable bool) error {
	base := status.New(grpcCode, code+": "+message)
	withDetail, err := base.WithDetails(&privatevmv1.ErrorDetail{
		Code: code, SafeMessage: message, Remediation: remediation, Retryable: retryable,
	})
	if err != nil {
		return base.Err()
	}
	return withDetail.Err()
}

func sessionError(err error) error {
	switch {
	case errors.Is(err, session.ErrNotFound):
		return rpcError(codes.NotFound, "SESSION_NOT_FOUND", "The requested session does not exist.", "List sessions owned by the current user and retry with an active session ID.", false)
	case errors.Is(err, session.ErrUnauthorized):
		return rpcError(codes.PermissionDenied, "SESSION_OWNER_MISMATCH", "The requested session belongs to another user.", "Use a session created by the current user.", false)
	case errors.Is(err, session.ErrQuotaExceeded):
		return rpcError(codes.ResourceExhausted, "SESSION_QUOTA_EXCEEDED", "The per-user session limit has been reached.", "Stop or clean up an existing session before creating another.", true)
	case errors.Is(err, session.ErrInvalidTransition):
		return rpcError(codes.FailedPrecondition, "SESSION_TRANSITION_INVALID", "The requested lifecycle transition is not allowed.", "Inspect session status and request an operation valid for its current state.", false)
	default:
		return rpcError(codes.Internal, "INTERNAL_ERROR", "The daemon could not complete the request.", "Retry once; if the error persists, inspect redacted daemon diagnostics.", true)
	}
}

func unimplemented(operation string) error {
	return rpcError(codes.Unimplemented, "NOT_IMPLEMENTED", operation+" is not implemented yet.", "Do not bypass this security boundary; install a build that implements and verifies the operation.", false)
}
