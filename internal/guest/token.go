package guest

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	TokenMetadataKey = "x-private-vm-session-token"
	TokenSize        = 32
	FWCfgTokenPath   = "/sys/firmware/qemu_fw_cfg/by_name/opt/private-vm/session-capability/raw"
)

// Token owns one 256-bit boot capability. It is backed by the secret package,
// is never serializable, and must be destroyed when its guest is torn down.
// gRPC metadata necessarily creates a short-lived string copy for each call.
type Token struct {
	value *secret.Bytes
}

func NewToken() (*Token, error) {
	value := make([]byte, TokenSize)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return nil, fmt.Errorf("generate guest capability: %w", err)
	}
	token, err := TokenFromBytes(value)
	clear(value)
	runtime.KeepAlive(value)
	return token, err
}

func TokenFromBytes(value []byte) (*Token, error) {
	if len(value) != TokenSize {
		return nil, fmt.Errorf("guest capability must be exactly %d bytes", TokenSize)
	}
	stored, err := secret.New(value)
	if err != nil {
		return nil, fmt.Errorf("store guest capability: %w", err)
	}
	return &Token{value: stored}, nil
}

// ReadToken reads the raw fw_cfg item without following a symlink and rejects
// truncated or oversized values. Callers may override the path only for tests.
func ReadToken(path string) (*Token, error) {
	if path == "" {
		return nil, errors.New("fw_cfg capability path is required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open fw_cfg capability: %w", err)
	}
	file := os.NewFile(uintptr(fd), "private-vm-fw-cfg-capability")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open fw_cfg capability: invalid descriptor")
	}
	defer file.Close()

	value := make([]byte, TokenSize)
	if _, err := io.ReadFull(file, value); err != nil {
		clear(value)
		return nil, fmt.Errorf("read fw_cfg capability: %w", err)
	}
	var extra [1]byte
	n, err := file.Read(extra[:])
	if n != 0 || (err != nil && !errors.Is(err, io.EOF)) {
		clear(value)
		return nil, errors.New("fw_cfg capability has an invalid length")
	}
	token, err := TokenFromBytes(value)
	clear(value)
	runtime.KeepAlive(value)
	return token, err
}

func (t *Token) DupFile() (*os.File, error) {
	if t == nil || t.value == nil {
		return nil, errors.New("guest capability is unavailable")
	}
	return t.value.DupFile()
}

func (t *Token) Destroy() {
	if t != nil && t.value != nil {
		t.value.Destroy()
	}
}

func (t *Token) String() string   { return "[REDACTED]" }
func (t *Token) GoString() string { return "[REDACTED]" }
func (t *Token) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("[REDACTED]"))
}
func (t *Token) MarshalJSON() ([]byte, error) {
	return nil, errors.New("guest capabilities cannot be serialized")
}
func (t *Token) MarshalText() ([]byte, error) {
	return nil, errors.New("guest capabilities cannot be serialized")
}

func (t *Token) UnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx, err := t.outgoingContext(ctx)
		if err != nil {
			return err
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func (t *Token) StreamClientInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx, err := t.outgoingContext(ctx)
		if err != nil {
			return nil, err
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
}

func (t *Token) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := t.authenticate(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func (t *Token) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := t.authenticate(stream.Context()); err != nil {
			return err
		}
		return handler(srv, stream)
	}
}

func (t *Token) outgoingContext(ctx context.Context) (context.Context, error) {
	if t == nil || t.value == nil {
		return nil, errors.New("guest capability is unavailable")
	}
	var encoded string
	err := t.value.With(func(value []byte) error {
		encoded = base64.RawURLEncoding.EncodeToString(value)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("use guest capability: %w", err)
	}
	return metadata.AppendToOutgoingContext(ctx, TokenMetadataKey, encoded), nil
}

func (t *Token) authenticate(ctx context.Context) error {
	if t == nil || t.value == nil {
		return guestRPCError(codes.Unauthenticated, "GUEST_AUTHENTICATION_FAILED", "Guest authentication failed.", "Destroy the session and start a fresh verified guest.", false)
	}
	md, ok := metadata.FromIncomingContext(ctx)
	values := md.Get(TokenMetadataKey)
	if !ok || len(values) != 1 || len(values[0]) != base64.RawURLEncoding.EncodedLen(TokenSize) {
		return guestRPCError(codes.Unauthenticated, "GUEST_AUTHENTICATION_FAILED", "Guest authentication failed.", "Destroy the session and start a fresh verified guest.", false)
	}
	presented, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(presented) != TokenSize {
		clear(presented)
		return guestRPCError(codes.Unauthenticated, "GUEST_AUTHENTICATION_FAILED", "Guest authentication failed.", "Destroy the session and start a fresh verified guest.", false)
	}
	matched := false
	err = t.value.With(func(expected []byte) error {
		matched = subtle.ConstantTimeCompare(expected, presented) == 1
		return nil
	})
	clear(presented)
	runtime.KeepAlive(presented)
	if err != nil || !matched {
		return guestRPCError(codes.Unauthenticated, "GUEST_AUTHENTICATION_FAILED", "Guest authentication failed.", "Destroy the session and start a fresh verified guest.", false)
	}
	return nil
}

func guestRPCError(grpcCode codes.Code, code, message, remediation string, retryable bool) error {
	base := status.New(grpcCode, code+": "+message)
	withDetail, err := base.WithDetails(&privatevmv1.ErrorDetail{
		Code: code, SafeMessage: message, Remediation: remediation, Retryable: retryable,
	})
	if err != nil {
		return base.Err()
	}
	return withDetail.Err()
}

var _ fmt.Formatter = (*Token)(nil)
