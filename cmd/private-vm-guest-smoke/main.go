// private-vm-guest-smoke is a test-only client used by NixOS role-image gates.
// It is not included in any production package or image.
//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/mdlayher/socket"
	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	expectedRole         = ""
	expectedSourceCommit = ""
	expectedVersion      = ""
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "private-vm guest smoke failed:", err)
		os.Exit(1)
	}
	fmt.Println("private-vm authenticated guest VSOCK ready")
}

func run() error {
	role := session.Role(expectedRole)
	if err := session.ValidateRole(role); err != nil {
		return errors.New("test client has no valid compile-time role")
	}
	protoRole, err := guest.ProtoRole(role)
	if err != nil {
		return errors.New("test client role cannot be encoded")
	}
	expectedCapabilities, err := guest.Capabilities(role)
	if err != nil {
		return errors.New("test client capability map is invalid")
	}
	localCID, err := vsock.ContextID()
	if err != nil || localCID != vsock.Local {
		return errors.New("read local VSOCK context ID")
	}

	wrongBytes := bytes.Repeat([]byte{0xa5}, guest.TokenSize)
	wrongToken, err := guest.TokenFromBytes(wrongBytes)
	clear(wrongBytes)
	if err != nil {
		return errors.New("create negative-test capability")
	}
	_, wrongErr := hello(wrongToken, protoRole, localCID)
	wrongToken.Destroy()
	if status.Code(wrongErr) != codes.Unauthenticated {
		return errors.New("guestd accepted an incorrect boot capability")
	}

	token, err := guest.ReadToken(guest.FWCfgTokenPath)
	if err != nil {
		return errors.New("read synthetic fw_cfg capability")
	}
	defer token.Destroy()
	response, err := hello(token, protoRole, localCID)
	if err != nil {
		return fmt.Errorf("authenticated Hello failed: %w", err)
	}
	if response.GetApiVersion().GetMajor() != guest.APIMajor || response.GetApiVersion().GetMinor() != guest.APIMinor ||
		response.GetRole() != protoRole || !slices.Equal(response.GetCapabilities(), expectedCapabilities) ||
		len(response.GetBootNonce()) != guest.TokenSize || response.GetSourceCommit() != expectedSourceCommit ||
		response.GetOsRelease() == "" || response.GetGuestdVersion() != expectedVersion {
		return errors.New("authenticated Hello returned incomplete or mismatched identity")
	}
	return nil
}

func hello(token *guest.Token, role privatevmv1.GuestRole, localCID uint32) (*privatevmv1.GuestHelloResponse, error) {
	connection, err := localTestClient(token, localCID)
	if err != nil {
		return nil, errors.New("create local VSOCK client")
	}
	defer connection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return privatevmv1.NewGuestCommonServiceClient(connection).Hello(ctx, &privatevmv1.GuestHelloRequest{
		Context: &privatevmv1.GuestContext{
			Context: &privatevmv1.RequestContext{
				ApiVersion: &privatevmv1.ApiVersion{Major: guest.APIMajor, Minor: guest.APIMinor},
				RequestId:  "nix-vsock-smoke-0001",
				SessionId:  "pvm-00000000000000000000000000000000",
			},
			ExpectedRole: role,
		},
	})
}

// localTestClient deliberately exists only in the test-only smoke binary. The
// production host client rejects CID 1 because real guests must use allocated
// CIDs >= 3. Nix's pure build sandbox cannot expose /dev/vhost-vsock, so image
// gates use the kernel VSOCK loopback transport while exercising the same gRPC
// credentials, bounds, metadata token, interceptors, and guestd listener.
func localTestClient(token *guest.Token, localCID uint32) (*grpc.ClientConn, error) {
	if token == nil || localCID != vsock.Local {
		return nil, errors.New("invalid local VSOCK test configuration")
	}
	return grpc.NewClient(
		"passthrough:///private-vm-guest-loopback-test",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return dialLocalVSOCK(ctx, guest.DefaultPort)
		}),
		grpc.WithTransportCredentials(guest.VSOCKTransportCredentials()),
		grpc.WithMaxHeaderListSize(guest.MaxHeaderListSize),
		grpc.WithChainUnaryInterceptor(token.UnaryClientInterceptor()),
		grpc.WithChainStreamInterceptor(token.StreamClientInterceptor()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(guest.DefaultMaxMessageSize),
			grpc.MaxCallSendMsgSize(guest.DefaultMaxMessageSize),
		),
	)
}

func dialLocalVSOCK(ctx context.Context, port uint32) (net.Conn, error) {
	connection, err := socket.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0, "private-vm-vsock-loopback-test", nil)
	if err != nil {
		return nil, errors.New("create local AF_VSOCK socket")
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = connection.Close()
		}
	}()

	remote := &unix.SockaddrVM{CID: vsock.Local, Port: port}
	connected, err := connection.Connect(ctx, remote)
	if err != nil {
		return nil, errors.New("connect local AF_VSOCK socket")
	}
	if connected == nil {
		connected = remote
	}
	local, err := connection.Getsockname()
	if err != nil {
		return nil, errors.New("inspect local AF_VSOCK socket")
	}
	localVM, localOK := local.(*unix.SockaddrVM)
	remoteVM, remoteOK := connected.(*unix.SockaddrVM)
	if !localOK || !remoteOK {
		return nil, errors.New("kernel returned an unexpected AF_VSOCK address")
	}
	closeOnError = false
	return &testVSOCKConn{
		connection: connection,
		local:      &vsock.Addr{ContextID: localVM.CID, Port: localVM.Port},
		remote:     &vsock.Addr{ContextID: remoteVM.CID, Port: remoteVM.Port},
	}, nil
}

type testVSOCKConn struct {
	connection interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
		SetDeadline(time.Time) error
		SetReadDeadline(time.Time) error
		SetWriteDeadline(time.Time) error
	}
	local  *vsock.Addr
	remote *vsock.Addr
}

func (c *testVSOCKConn) Read(buffer []byte) (int, error)  { return c.connection.Read(buffer) }
func (c *testVSOCKConn) Write(buffer []byte) (int, error) { return c.connection.Write(buffer) }
func (c *testVSOCKConn) Close() error                     { return c.connection.Close() }
func (c *testVSOCKConn) LocalAddr() net.Addr              { return c.local }
func (c *testVSOCKConn) RemoteAddr() net.Addr             { return c.remote }
func (c *testVSOCKConn) SetDeadline(deadline time.Time) error {
	return c.connection.SetDeadline(deadline)
}
func (c *testVSOCKConn) SetReadDeadline(deadline time.Time) error {
	return c.connection.SetReadDeadline(deadline)
}
func (c *testVSOCKConn) SetWriteDeadline(deadline time.Time) error {
	return c.connection.SetWriteDeadline(deadline)
}
