package daemon

import (
	"context"
	"errors"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/usb"
	"github.com/StevenBuglione/private-vm/internal/vpn"
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

func vpnRPCError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		status.Code(err) == codes.Canceled || status.Code(err) == codes.DeadlineExceeded {
		return sessionError(err)
	}
	var application *apperror.Error
	if errors.As(err, &application) {
		grpcCode := codes.FailedPrecondition
		switch {
		case errors.Is(err, vpn.ErrInvalidProfile):
			grpcCode = codes.InvalidArgument
		case errors.Is(err, vpn.ErrProfileNotFound):
			grpcCode = codes.NotFound
		case errors.Is(err, vpn.ErrProfileLimit):
			grpcCode = codes.ResourceExhausted
		case errors.Is(err, vpn.ErrStoreClosed):
			grpcCode = codes.Unavailable
		case errors.Is(err, vpn.ErrProfileRotated):
			grpcCode = codes.Aborted
		case errors.Is(err, vpn.ErrEndpointUnresolved), errors.Is(err, vpn.ErrProfileNotReady):
			grpcCode = codes.FailedPrecondition
		default:
			return sessionError(err)
		}
		return rpcError(grpcCode, application.Code, application.Message, application.Remediation, false)
	}
	return sessionError(err)
}

func usbRPCError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		status.Code(err) == codes.Canceled || status.Code(err) == codes.DeadlineExceeded {
		return sessionError(err)
	}
	if errors.Is(err, session.ErrCleanupIncomplete) {
		return sessionError(err)
	}
	var application *usb.Error
	if !errors.As(err, &application) {
		return sessionError(err)
	}
	grpcCode := codes.FailedPrecondition
	switch application.Code {
	case usb.CodeNotEnrolled:
		grpcCode = codes.NotFound
	case usb.CodeClaimConflict:
		grpcCode = codes.Aborted
	case usb.CodeDiscoveryFailed:
		grpcCode = codes.Unavailable
	case usb.CodeConfirmation:
		grpcCode = codes.InvalidArgument
	case usb.CodeCleanupIncomplete:
		grpcCode = codes.FailedPrecondition
	}
	return rpcError(grpcCode, string(application.Code), application.Message, application.Remediation, false)
}

func sessionError(err error) error {
	switch {
	case errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled:
		return rpcError(codes.Canceled, "REQUEST_CANCELED", "The request was canceled before it completed.", "Retry the operation only if its session state permits it.", true)
	case errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded:
		return rpcError(codes.DeadlineExceeded, "REQUEST_TIMEOUT", "The request exceeded its bounded deadline.", "Inspect session status before retrying the operation.", true)
	case errors.Is(err, session.ErrNotFound):
		return rpcError(codes.NotFound, "SESSION_NOT_FOUND", "The requested session does not exist.", "List sessions owned by the current user and retry with an active session ID.", false)
	case errors.Is(err, session.ErrUnauthorized):
		return rpcError(codes.PermissionDenied, "SESSION_OWNER_MISMATCH", "The requested session belongs to another user.", "Use a session created by the current user.", false)
	case errors.Is(err, session.ErrQuotaExceeded):
		return rpcError(codes.ResourceExhausted, "SESSION_QUOTA_EXCEEDED", "The per-user session limit has been reached.", "Stop or clean up an existing session before creating another.", true)
	case errors.Is(err, session.ErrInvalidTransition):
		return rpcError(codes.FailedPrecondition, "SESSION_TRANSITION_INVALID", "The requested lifecycle transition is not allowed.", "Inspect session status and request an operation valid for its current state.", false)
	case errors.Is(err, session.ErrInvalidWorkflow):
		return rpcError(codes.FailedPrecondition, "WORKFLOW_TRANSITION_INVALID", "The requested role workflow transition is not allowed.", "Inspect the current role workflow state and request its documented successor.", false)
	case errors.Is(err, session.ErrCleanupIncomplete):
		return rpcError(codes.FailedPrecondition, "CLEANUP_INCOMPLETE", "One or more owned resources could not be proven absent.", "Keep the recovery record, inspect session status, and retry cleanup after correcting the reported host condition.", true)
	case errors.Is(err, session.ErrEventCursor):
		return rpcError(codes.InvalidArgument, "EVENT_CURSOR_INVALID", "The requested event cursor is outside this session's replay window.", "Reconnect with a sequence at or below the current session sequence.", false)
	case errors.Is(err, session.ErrSubscriberSlow):
		return rpcError(codes.ResourceExhausted, "EVENT_CONSUMER_TOO_SLOW", "The event consumer could not keep up with the bounded stream.", "Reconnect with the last confirmed sequence to replay missed events.", true)
	case errors.Is(err, session.ErrEventLimit):
		return rpcError(codes.ResourceExhausted, "EVENT_LIMIT_REACHED", "The bounded lifetime event limit was reached.", "Stop and clean up the session; do not continue without a complete event history.", false)
	case errors.Is(err, session.ErrManagerShuttingDown):
		return rpcError(codes.Unavailable, "DAEMON_SHUTTING_DOWN", "The daemon is shutting down and cannot accept a new session.", "Retry after the daemon service is running again.", true)
	default:
		return rpcError(codes.Internal, "INTERNAL_ERROR", "The daemon could not complete the request.", "Retry once; if the error persists, inspect redacted daemon diagnostics.", true)
	}
}

func authorizationDenied() error {
	return rpcError(codes.PermissionDenied, "AUTHORIZATION_DENIED", "Access to private-vmd is denied.", "Run the client as root or as a verified member of the private-vm group.", false)
}

func unimplemented(operation string) error {
	return rpcError(codes.Unimplemented, "NOT_IMPLEMENTED", operation+" is not implemented yet.", "Do not bypass this security boundary; install a build that implements and verifies the operation.", false)
}
