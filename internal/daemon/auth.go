package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type identityContextKey struct{}

type Authorizer struct {
	AllowedGroup uint32
	Groups       func(PeerIdentity) ([]uint32, error)
}

func (a Authorizer) Authorize(identity PeerIdentity) error {
	if identity.UID == 0 || identity.GID == a.AllowedGroup {
		return nil
	}
	resolver := a.Groups
	if resolver == nil {
		resolver = processGroups
	}
	groups, err := resolver(identity)
	if err != nil {
		return err
	}
	for _, group := range groups {
		if group == a.AllowedGroup {
			return nil
		}
	}
	return errors.New("peer is not a member of the private-vm group")
}

func (a Authorizer) UnaryInterceptor(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	identity, err := authenticatedIdentity(ctx)
	if err != nil || a.Authorize(identity) != nil {
		return nil, status.Error(codes.PermissionDenied, "AUTHORIZATION_DENIED: access to private-vmd is denied")
	}
	ctx, cancel := boundedRPCContext(ctx, 2*time.Minute)
	defer cancel()
	return handler(context.WithValue(ctx, identityContextKey{}, identity), request)
}

func (a Authorizer) StreamInterceptor(service any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	identity, err := authenticatedIdentity(stream.Context())
	if err != nil || a.Authorize(identity) != nil {
		return status.Error(codes.PermissionDenied, "AUTHORIZATION_DENIED: access to private-vmd is denied")
	}
	ctx, cancel := boundedRPCContext(stream.Context(), 30*time.Minute)
	defer cancel()
	wrapped := &contextServerStream{ServerStream: stream, ctx: context.WithValue(ctx, identityContextKey{}, identity)}
	return handler(service, wrapped)
}

func authenticatedIdentity(ctx context.Context) (PeerIdentity, error) {
	value, ok := peer.FromContext(ctx)
	if !ok || value.AuthInfo == nil {
		return PeerIdentity{}, errors.New("unix peer credentials are absent")
	}
	auth, ok := value.AuthInfo.(PeerAuthInfo)
	if !ok {
		return PeerIdentity{}, errors.New("unexpected RPC transport credentials")
	}
	return auth.PeerIdentity, nil
}

func identityFromContext(ctx context.Context) (PeerIdentity, error) {
	identity, ok := ctx.Value(identityContextKey{}).(PeerIdentity)
	if !ok {
		return PeerIdentity{}, errors.New("authorized peer identity is absent")
	}
	return identity, nil
}

func boundedRPCContext(ctx context.Context, maximum time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(maximum)
	if current, ok := ctx.Deadline(); ok && current.Before(deadline) {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, deadline)
}

type contextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextServerStream) Context() context.Context { return s.ctx }

type Polkit interface {
	Authorize(context.Context, PeerIdentity, string) error
}

type PKCheck struct {
	Binary string
}

func (p PKCheck) Authorize(ctx context.Context, identity PeerIdentity, action string) error {
	if p.Binary == "" || p.Binary[0] != '/' {
		return errors.New("pkcheck path must be absolute")
	}
	if action != "org.private-vm.usb.prepare" {
		return errors.New("unknown Polkit action")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	process, err := polkitProcessSubject(identity)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, p.Binary,
		"--action-id", action,
		"--process", process,
		"--allow-user-interaction",
	)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("Polkit authorization denied: %w", err)
	}
	return nil
}

func polkitProcessSubject(identity PeerIdentity) (string, error) {
	data, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(identity.PID), 10) + "/stat")
	if err != nil {
		return "", fmt.Errorf("inspect Polkit process subject: %w", err)
	}
	// The second stat field is parenthesized and may contain spaces. The start
	// time is field 22, which is index 19 after the final ')'.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return "", errors.New("Polkit process subject is malformed")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return "", errors.New("Polkit process subject is incomplete")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", errors.New("Polkit process start time is invalid")
	}
	return strconv.FormatUint(uint64(identity.PID), 10) + "," + fields[19] + "," + strconv.FormatUint(uint64(identity.UID), 10), nil
}
