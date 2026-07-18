package guest

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	BootNonceSize         = 32
	DefaultMaxMessageSize = 2 << 20
	MaximumMessageSize    = 16 << 20
	MaxHeaderListSize     = 8 << 10
)

type Identity struct {
	Role          session.Role
	ImageDigest   string
	SourceCommit  string
	BootNonce     []byte
	OSRelease     string
	GuestdVersion string
}

func NewIdentity(role session.Role, imageDigest, sourceCommit, osRelease, guestdVersion string) (Identity, error) {
	nonce := make([]byte, BootNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return Identity{}, fmt.Errorf("generate boot nonce: %w", err)
	}
	identity := Identity{
		Role: role, ImageDigest: imageDigest, SourceCommit: sourceCommit,
		BootNonce: nonce, OSRelease: osRelease, GuestdVersion: guestdVersion,
	}
	if err := identity.Validate(); err != nil {
		clear(nonce)
		return Identity{}, err
	}
	return identity, nil
}

func (i Identity) Validate() error {
	if err := session.ValidateRole(i.Role); err != nil {
		return err
	}
	if len(i.BootNonce) != BootNonceSize {
		return fmt.Errorf("boot nonce must be exactly %d bytes", BootNonceSize)
	}
	for name, value := range map[string]string{
		"image digest": i.ImageDigest, "source commit": i.SourceCommit,
		"OS release": i.OSRelease, "guestd version": i.GuestdVersion,
	} {
		if value == "" || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%s is missing or invalid", name)
		}
	}
	return nil
}

type ServerConfig struct {
	Identity       Identity
	Token          *Token
	MaxMessageSize int

	Workstation privatevmv1.WorkstationGuestServiceServer
	Downloader  privatevmv1.DownloaderGuestServiceServer
	Scanner     privatevmv1.ScannerGuestServiceServer
	Exporter    privatevmv1.ExporterGuestServiceServer
}

func NewServer(config ServerConfig) (*grpc.Server, error) {
	return newServer(config, true)
}

// newServer permits transport credentials to be disabled only from same-package
// tests that replace AF_VSOCK with a bounded in-memory listener.
func newServer(config ServerConfig, enforceVSOCK bool) (*grpc.Server, error) {
	if err := config.Identity.Validate(); err != nil {
		return nil, fmt.Errorf("guest identity: %w", err)
	}
	if config.Token == nil || config.Token.value == nil {
		return nil, errors.New("guest capability is required")
	}
	if err := validateRoleHandlers(config); err != nil {
		return nil, err
	}
	config.Identity.BootNonce = slices.Clone(config.Identity.BootNonce)
	maxMessageSize := config.MaxMessageSize
	if maxMessageSize == 0 {
		maxMessageSize = DefaultMaxMessageSize
	}
	if maxMessageSize < 1<<20 || maxMessageSize > MaximumMessageSize {
		return nil, errors.New("guest gRPC message bound must be between 1 MiB and 16 MiB")
	}

	options := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			config.Token.UnaryServerInterceptor(),
			ContextUnaryServerInterceptor(config.Identity.Role),
		),
		grpc.ChainStreamInterceptor(
			config.Token.StreamServerInterceptor(),
			ContextStreamServerInterceptor(config.Identity.Role),
		),
		grpc.MaxRecvMsgSize(maxMessageSize),
		grpc.MaxSendMsgSize(maxMessageSize),
		grpc.MaxHeaderListSize(MaxHeaderListSize),
		grpc.MaxConcurrentStreams(32),
		grpc.ConnectionTimeout(10 * time.Second),
	}
	if enforceVSOCK {
		options = append(options, grpc.Creds(VSOCKTransportCredentials()))
	}
	server := grpc.NewServer(options...)
	privatevmv1.RegisterGuestCommonServiceServer(server, &CommonServer{identity: config.Identity})

	switch config.Identity.Role {
	case session.RoleWorkstation:
		handler := config.Workstation
		if handler == nil {
			handler = workstationServer{}
		}
		privatevmv1.RegisterWorkstationGuestServiceServer(server, handler)
	case session.RoleDownloader:
		handler := config.Downloader
		if handler == nil {
			handler = downloaderServer{}
		}
		privatevmv1.RegisterDownloaderGuestServiceServer(server, handler)
	case session.RoleScanner:
		handler := config.Scanner
		if handler == nil {
			handler = scannerServer{}
		}
		privatevmv1.RegisterScannerGuestServiceServer(server, handler)
	case session.RoleExporter:
		handler := config.Exporter
		if handler == nil {
			handler = exporterServer{}
		}
		privatevmv1.RegisterExporterGuestServiceServer(server, handler)
	}
	return server, nil
}

func validateRoleHandlers(config ServerConfig) error {
	present := map[session.Role]bool{
		session.RoleWorkstation: config.Workstation != nil,
		session.RoleDownloader:  config.Downloader != nil,
		session.RoleScanner:     config.Scanner != nil,
		session.RoleExporter:    config.Exporter != nil,
	}
	for role, exists := range present {
		if exists && role != config.Identity.Role {
			return errors.New("handler for a different guest role cannot be registered")
		}
	}
	return nil
}

type CommonServer struct {
	privatevmv1.UnimplementedGuestCommonServiceServer
	identity Identity
}

func (s *CommonServer) Hello(_ context.Context, request *privatevmv1.GuestHelloRequest) (*privatevmv1.GuestHelloResponse, error) {
	if err := ValidateGuestContext(request.GetContext(), s.identity.Role); err != nil {
		return nil, err
	}
	role, err := ProtoRole(s.identity.Role)
	if err != nil {
		return nil, guestRPCError(codes.Internal, "GUEST_IDENTITY_INVALID", "The guest has an invalid compiled identity.", "Destroy the session and install a verified guest image.", false)
	}
	capabilities, err := Capabilities(s.identity.Role)
	if err != nil {
		return nil, guestRPCError(codes.Internal, "GUEST_CAPABILITIES_INVALID", "The guest capability map is invalid.", "Destroy the session and install a verified guest image.", false)
	}
	return &privatevmv1.GuestHelloResponse{
		ApiVersion:    &privatevmv1.ApiVersion{Major: APIMajor, Minor: APIMinor},
		Role:          role,
		ImageDigest:   s.identity.ImageDigest,
		SourceCommit:  s.identity.SourceCommit,
		Capabilities:  capabilities,
		BootNonce:     slices.Clone(s.identity.BootNonce),
		OsRelease:     s.identity.OSRelease,
		GuestdVersion: s.identity.GuestdVersion,
	}, nil
}

func ValidateGuestContext(context *privatevmv1.GuestContext, role session.Role) error {
	if context == nil {
		return guestRPCError(codes.InvalidArgument, "GUEST_CONTEXT_REQUIRED", "A complete guest request context is required.", "Retry through the private-vm daemon.", false)
	}
	requestContext := context.GetContext()
	if err := ValidateRequestContext(requestContext); err != nil {
		return err
	}
	expectedRole, err := ProtoRole(role)
	if err != nil || context.GetExpectedRole() != expectedRole {
		return guestRPCError(codes.FailedPrecondition, "GUEST_ROLE_MISMATCH", "The running guest role does not match the requested role.", "Destroy the guest and verify the selected image manifest before retrying.", false)
	}
	return nil
}

type workstationServer struct {
	privatevmv1.UnimplementedWorkstationGuestServiceServer
}
type downloaderServer struct {
	privatevmv1.UnimplementedDownloaderGuestServiceServer
}
type scannerServer struct {
	privatevmv1.UnimplementedScannerGuestServiceServer
}
type exporterServer struct {
	privatevmv1.UnimplementedExporterGuestServiceServer
}
