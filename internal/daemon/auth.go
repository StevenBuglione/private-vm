package daemon

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strconv"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

type identityContextKey struct{}

type Authorizer struct {
	AllowedGroup uint32
	Groups       func(PeerIdentity) ([]uint32, error)
}

func (a Authorizer) Authorize(identity PeerIdentity) error {
	groups, err := processGroups(identity)
	if err != nil {
		return errors.New("peer process identity could not be verified")
	}
	if a.Groups != nil {
		groups, err = a.Groups(identity)
		if err != nil {
			return errors.New("peer process group membership could not be verified")
		}
	}
	if identity.UID == 0 || identity.GID == a.AllowedGroup {
		return nil
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
		return nil, authorizationDenied()
	}
	ctx, cancel := boundedRPCContext(ctx, 2*time.Minute)
	defer cancel()
	return handler(context.WithValue(ctx, identityContextKey{}, identity), request)
}

func (a Authorizer) StreamInterceptor(service any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	identity, err := authenticatedIdentity(stream.Context())
	if err != nil || a.Authorize(identity) != nil {
		return authorizationDenied()
	}
	maximum := 30 * time.Minute
	if info.FullMethod == privatevmv1.PrivateVMDaemonService_ImportWorkspaceFile_FullMethodName ||
		info.FullMethod == privatevmv1.PrivateVMDaemonService_ImportVPNProfile_FullMethodName {
		maximum = 10 * time.Second
	} else if info.FullMethod == privatevmv1.PrivateVMDaemonService_AddTorrent_FullMethodName {
		maximum = 2 * time.Minute
	}
	ctx, cancel := boundedRPCContext(stream.Context(), maximum)
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
		return errors.New("Polkit verifier configuration is invalid")
	}
	if action != "org.private-vm.usb.prepare" {
		return errors.New("Polkit action is not permitted")
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
	command.Env = []string{}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("Polkit authorization was denied")
	}
	return nil
}

func polkitProcessSubject(identity PeerIdentity) (string, error) {
	if _, err := processGroups(identity); err != nil {
		return "", errors.New("Polkit process subject could not be verified")
	}
	return strconv.FormatUint(uint64(identity.PID), 10) + "," + strconv.FormatUint(identity.StartTimeTicks, 10) + "," + strconv.FormatUint(uint64(identity.UID), 10), nil
}
