package daemon

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/config"
	"github.com/StevenBuglione/private-vm/internal/preflight"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestSocketParentMustHaveExactTrustedIdentityAndMode(t *testing.T) {
	parent := t.TempDir()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if err := verifySocketParent(parent, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := verifySocketParent(parent, uid+1, gid); err == nil {
		t.Fatal("wrong runtime-directory owner was accepted")
	}
	if err := verifySocketParent(parent, uid, gid+1); err == nil {
		t.Fatal("wrong runtime-directory group was accepted")
	}
	if err := os.Chmod(parent, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := verifySocketParent(parent, uid, gid); err == nil {
		t.Fatal("group-writable runtime directory was accepted")
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := verifySocketParent(link, uid, gid); err == nil {
		t.Fatal("symlinked runtime directory was accepted")
	}
}

func TestServerRejectsUntrustedWritableAncestorByDefault(t *testing.T) {
	server, socket, _ := newUnstartedTestServer(t, 0)
	server.options.testOnlyAllowUntrustedAncestors = false
	if err := server.Listen(); err == nil {
		t.Fatal("server accepted a runtime path below the writable /tmp ancestor")
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected ancestor path created a socket: %v", err)
	}
}

func TestStaleSocketRemovalIsIdentityBoundAndFailsClosed(t *testing.T) {
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	makeStale := func(name string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		listener.SetUnlinkOnClose(false)
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}

	regular := filepath.Join(t.TempDir(), "control.sock")
	file, err := os.OpenFile(regular, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if err := removeStaleSocket(regular, uid, gid); err == nil {
		t.Fatal("regular file was treated as a stale socket")
	}

	stale := makeStale("control.sock")
	if err := removeStaleSocket(stale, uid, gid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale socket remains: %v", err)
	}

	ambiguous := makeStale("control.sock")
	originalDial := dialControlSocket
	dialControlSocket = func(string, string, time.Duration) (net.Conn, error) {
		return nil, syscall.ETIMEDOUT
	}
	t.Cleanup(func() { dialControlSocket = originalDial })
	if err := removeStaleSocket(ambiguous, uid, gid); err == nil {
		t.Fatal("ambiguous dial failure removed the socket")
	}
	if _, err := os.Lstat(ambiguous); err != nil {
		t.Fatalf("ambiguous socket was removed: %v", err)
	}
	dialControlSocket = originalDial

	changed := makeStale("control.sock")
	dialControlSocket = func(_, path string, _ time.Duration) (net.Conn, error) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		replacement.SetUnlinkOnClose(false)
		if err := replacement.Close(); err != nil {
			t.Fatal(err)
		}
		return nil, syscall.ECONNREFUSED
	}
	if err := removeStaleSocket(changed, uid, gid); err == nil {
		t.Fatal("socket identity swap was not detected")
	}
	if _, err := os.Lstat(changed); err != nil {
		t.Fatalf("replacement socket was removed: %v", err)
	}
	dialControlSocket = originalDial
}

func TestServerStopDoesNotRemoveReplacementSocket(t *testing.T) {
	server, socket, _ := newUnstartedTestServer(t, 0)
	if err := server.Listen(); err != nil {
		t.Fatal(err)
	}
	original := socket + ".original"
	if err := os.Rename(socket, original); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	replacement.SetUnlinkOnClose(false)
	server.Stop()
	if _, err := os.Lstat(socket); err != nil {
		t.Fatalf("server removed replacement socket: %v", err)
	}
	_ = replacement.Close()
	_ = os.Remove(socket)
	_ = os.Remove(original)
}

func TestServerBoundsHandshakeHeadersAndMessages(t *testing.T) {
	t.Run("handshake-timeout", func(t *testing.T) {
		server, socket, _ := newUnstartedTestServer(t, 25*time.Millisecond)
		serve := startTestServer(t, server)
		connection, err := net.DialTimeout("unix", socket, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 64)
		for {
			if _, err := connection.Read(buffer); err != nil {
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("connection without an HTTP/2 preface survived the handshake bound")
				}
				break
			}
		}
		stopTestServer(t, server, serve)
	})

	t.Run("headers-and-messages", func(t *testing.T) {
		server, socket, _ := newUnstartedTestServer(t, 0)
		serve := startTestServer(t, server)
		connection, client := dialTestDaemon(t, socket)
		defer connection.Close()
		defer stopTestServer(t, server, serve)
		if _, err := client.GetVersion(t.Context(), &privatevmv1.Empty{}); err != nil {
			t.Fatal(err)
		}
		const transportSentinel = "PUBLIC_TRANSPORT_SENTINEL_MUST_NOT_ESCAPE"
		headerContext := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-private-vm-test", strings.Repeat(transportSentinel, maximumRPCHeaderBytes/len(transportSentinel)+2)))
		_, headerErr := client.GetVersion(headerContext, &privatevmv1.Empty{})
		if headerErr == nil {
			t.Fatal("oversized request metadata was accepted")
		}
		assertNativeTransportError(t, headerErr, transportSentinel)
		if _, err := client.GetVersion(t.Context(), &privatevmv1.Empty{}); err != nil {
			t.Fatalf("connection did not recover after oversized metadata: %v", err)
		}
		stream, err := client.ImportWorkspaceFile(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte(transportSentinel), maximumRPCMessageBytes/len(transportSentinel)+2)
		sendErr := stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Data: payload}}})
		_, closeErr := stream.CloseAndRecv()
		if sendErr == nil && closeErr == nil {
			t.Fatal("oversized RPC message was accepted")
		}
		messageErr := sendErr
		if messageErr == nil {
			messageErr = closeErr
		}
		assertNativeTransportError(t, messageErr, transportSentinel)
		recoveryCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		started := time.Now()
		_, recoveryErr := client.GetVersion(recoveryCtx, &privatevmv1.Empty{})
		if recoveryErr != nil || time.Since(started) >= time.Second {
			t.Fatalf("client connection did not recover promptly after oversized message: %v", recoveryErr)
		}
	})
}

func TestServerFreezesValidatedServiceSnapshot(t *testing.T) {
	server, _, original := newUnstartedTestServer(t, 0)
	if server.options.Service == original {
		t.Fatal("server retained caller-owned service object")
	}
	original.Config = config.Config{}
	original.Polkit = nil
	original.Sessions = nil
	if err := server.options.Service.Config.Validate(); err != nil || server.options.Service.Polkit == nil || server.options.Service.Sessions == nil {
		t.Fatal("caller mutation altered validated server service snapshot")
	}
}

func TestAdmissionListenerRejectsExcessAndRecovers(t *testing.T) {
	base := &queuedListener{connections: make(chan net.Conn, 3), closed: make(chan struct{})}
	listener := &admissionListener{Listener: base, slots: make(chan struct{}, 1)}
	serverOne, clientOne := net.Pipe()
	base.connections <- serverOne
	acceptedOne, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	serverTwo, clientTwo := net.Pipe()
	base.connections <- serverTwo
	result := make(chan net.Conn, 1)
	go func() {
		connection, _ := listener.Accept()
		result <- connection
	}()
	_ = clientTwo.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientTwo.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection above the daemon admission bound remained open")
	}
	_ = acceptedOne.Close()
	_ = clientOne.Close()
	serverThree, clientThree := net.Pipe()
	base.connections <- serverThree
	select {
	case acceptedThree := <-result:
		if acceptedThree == nil {
			t.Fatal("admission did not recover after a connection closed")
		}
		_ = acceptedThree.Close()
	case <-time.After(time.Second):
		t.Fatal("admission did not recover after a connection closed")
	}
	_ = clientTwo.Close()
	_ = clientThree.Close()
	_ = listener.Close()
}

func TestUnauthorizedPeerIsRejectedOverUnixGRPC(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	chosen := -1
	for _, group := range groups {
		if group != os.Getegid() {
			chosen = group
			break
		}
	}
	if chosen < 0 {
		t.Skip("no supplementary group is available for the socket identity fixture")
	}
	base, err := os.MkdirTemp("/tmp", "private-vm-denial-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	runtimeDir := filepath.Join(base, "run")
	store, err := session.NewStore(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(runtimeDir, os.Geteuid(), chosen); err != nil {
		t.Skipf("cannot set supplementary test group: %v", err)
	}
	manager, err := session.NewManager(store, 4)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{Sessions: manager, Config: config.Defaults(), Polkit: allowPolkit{}}
	socket := filepath.Join(runtimeDir, "control.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socket, OwnerUID: os.Geteuid(), GroupGID: chosen, Service: service,
		Authorizer: Authorizer{AllowedGroup: uint32(chosen), Groups: func(PeerIdentity) ([]uint32, error) {
			return []uint32{uint32(os.Getegid())}, nil
		}},
		testOnlyAllowUntrustedAncestors: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := startTestServer(t, server)
	connection, client := dialTestDaemon(t, socket)
	_, err = client.GetVersion(t.Context(), &privatevmv1.Empty{})
	assertRPCError(t, err, codes.PermissionDenied, "AUTHORIZATION_DENIED")
	_ = connection.Close()
	stopTestServer(t, server, done)
}

func newUnstartedTestServer(t *testing.T, connectionTimeout time.Duration) (*Server, string, *Service) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "private-vm-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	runtimeDir := filepath.Join(base, "run")
	store, err := session.NewStore(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(store, 4)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		Sessions: manager,
		Config:   config.Defaults(),
		DoctorRun: func(context.Context, bool) preflight.Report {
			return preflight.Report{SchemaVersion: 1, Runnable: true}
		},
		Polkit: allowPolkit{},
	}
	socket := filepath.Join(runtimeDir, "control.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socket, OwnerUID: os.Geteuid(), GroupGID: os.Getegid(),
		ConnectionTimeout: connectionTimeout, Service: service,
		Authorizer:                      Authorizer{AllowedGroup: uint32(os.Getegid())},
		testOnlyAllowUntrustedAncestors: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, socket, service
}

func startTestServer(t *testing.T, server *Server) <-chan error {
	t.Helper()
	if err := server.Listen(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	return done
}

func stopTestServer(t *testing.T, server *Server, done <-chan error) {
	t.Helper()
	server.Stop()
	if err := <-done; err != nil {
		t.Fatalf("server stopped with error: %v", err)
	}
}

func dialTestDaemon(t *testing.T, socket string) (*grpc.ClientConn, privatevmv1.PrivateVMDaemonServiceClient) {
	t.Helper()
	connection, err := grpc.NewClient("passthrough:///private-vmd",
		grpc.WithTransportCredentials(NewUnixPeerCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return connection, privatevmv1.NewPrivateVMDaemonServiceClient(connection)
}

func assertNativeTransportError(t *testing.T, err error, sentinel string) {
	t.Helper()
	if err == nil {
		t.Fatal("native transport error is absent")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatal("native transport error exposed rejected bytes")
	}
	value, ok := status.FromError(err)
	if !ok {
		t.Fatalf("native transport rejection was not a gRPC status: %v", err)
	}
	for _, detail := range value.Details() {
		if _, ok := detail.(*privatevmv1.ErrorDetail); ok {
			t.Fatalf("native transport error unexpectedly carried daemon ErrorDetail: %v", err)
		}
	}
}

type queuedListener struct {
	connections chan net.Conn
	closed      chan struct{}
}

func (l *queuedListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *queuedListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *queuedListener) Addr() net.Addr { return &net.UnixAddr{Name: "queued", Net: "unix"} }
