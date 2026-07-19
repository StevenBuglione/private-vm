package guest

import (
	"context"
	"regexp"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var (
	guestRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)
	guestSessionIDPattern = regexp.MustCompile(`^pvm-[a-f0-9]{32}$`)
)

func ContextUnaryServerInterceptor(role session.Role) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		guestContext, err := unaryGuestContext(request)
		if err != nil {
			return nil, err
		}
		if err := ValidateGuestContext(guestContext, role); err != nil {
			return nil, err
		}
		return handler(ctx, request)
	}
}

func ContextStreamServerInterceptor(role session.Role) grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(server, &contextServerStream{
			ServerStream: stream,
			role:         role,
		})
	}
}

type contextServerStream struct {
	grpc.ServerStream
	role      session.Role
	validated bool
}

func (s *contextServerStream) RecvMsg(message any) error {
	if err := s.ServerStream.RecvMsg(message); err != nil {
		return err
	}
	switch request := message.(type) {
	case *privatevmv1.TorrentInputFrame:
		if s.validated {
			return nil
		}
		if err := ValidateGuestContext(request.GetContext(), s.role); err != nil {
			return err
		}
		s.validated = true
		return nil
	case *privatevmv1.TransferFrame:
		if s.validated {
			return nil
		}
		if request.GetBegin() == nil {
			return guestRPCError(codes.InvalidArgument, "TRANSFER_BEGIN_REQUIRED", "The first transfer frame must be a begin frame.", "Retry the bounded transfer from the beginning.", false)
		}
		if err := ValidateRequestContext(request.GetBegin().GetContext()); err != nil {
			return err
		}
		s.validated = true
		return nil
	case *privatevmv1.PrepareUSBFrame:
		if s.validated {
			return nil
		}
		if request.GetBegin() == nil {
			if chunk := request.GetPassphraseChunk(); chunk != nil {
				clear(chunk.Data)
			}
			return guestRPCError(codes.InvalidArgument, "USB_PREPARE_BEGIN_REQUIRED", "USB preparation must begin with an authenticated identity expectation.", "Retry through the private-vm daemon from a fresh preparation plan.", false)
		}
		if err := ValidateGuestContext(request.GetBegin().GetContext(), s.role); err != nil {
			return err
		}
		s.validated = true
		return nil
	default:
		if s.validated {
			return nil
		}
		guestContext, err := unaryGuestContext(message)
		if err != nil {
			return err
		}
		if err := ValidateGuestContext(guestContext, s.role); err != nil {
			return err
		}
		s.validated = true
		return nil
	}
}

func unaryGuestContext(request any) (*privatevmv1.GuestContext, error) {
	switch value := request.(type) {
	case *privatevmv1.GuestHelloRequest:
		return value.GetContext(), nil
	case *privatevmv1.GuestStatusRequest:
		return value.GetContext(), nil
	case *privatevmv1.ShutdownRequest:
		return value.GetContext(), nil
	case *privatevmv1.ConfigureWireGuardRequest:
		return value.GetContext(), nil
	case *privatevmv1.VerifyVPNRequest:
		return value.GetContext(), nil
	case *privatevmv1.TorrentRequest:
		return value.GetContext(), nil
	case *privatevmv1.SelectTorrentFilesRequest:
		return value.GetContext(), nil
	case *privatevmv1.ScannerRequest:
		return value.GetContext(), nil
	case *privatevmv1.ExportApprovedFileRequest:
		return value.GetContext(), nil
	case *privatevmv1.WorkspaceStateRequest:
		return value.GetContext(), nil
	case *privatevmv1.GuestExportFileRequest:
		return value.GetContext(), nil
	case *privatevmv1.MarkExportVerifiedRequest:
		return value.GetContext(), nil
	case *privatevmv1.NetworkWarningRequest:
		return value.GetContext(), nil
	case *privatevmv1.ExporterRequest:
		return value.GetContext(), nil
	case *privatevmv1.VerifyExportRequest:
		return value.GetContext(), nil
	default:
		return nil, guestRPCError(codes.InvalidArgument, "GUEST_CONTEXT_UNSUPPORTED", "The request does not carry a supported guest context.", "Upgrade the host and guest images together.", false)
	}
}

func ValidateRequestContext(request *privatevmv1.RequestContext) error {
	if request == nil || request.GetApiVersion() == nil {
		return guestRPCError(codes.InvalidArgument, "GUEST_CONTEXT_REQUIRED", "A complete guest request context is required.", "Retry through the private-vm daemon.", false)
	}
	if request.GetApiVersion().GetMajor() != APIMajor || request.GetApiVersion().GetMinor() > APIMinor {
		return guestRPCError(codes.FailedPrecondition, "GUEST_PROTOCOL_VERSION_MISMATCH", "The requested guest protocol is not supported.", "Upgrade the host and guest images together.", false)
	}
	if !guestRequestIDPattern.MatchString(request.GetRequestId()) || !guestSessionIDPattern.MatchString(request.GetSessionId()) {
		return guestRPCError(codes.InvalidArgument, "GUEST_CONTEXT_INVALID", "The guest request or session identifier is missing or invalid.", "Retry through the private-vm daemon.", false)
	}
	return nil
}
