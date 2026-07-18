package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/preflight"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthorizerUsesSupplementaryGroupAndFailsClosed(t *testing.T) {
	authorizer := Authorizer{AllowedGroup: 4242, Groups: func(identity PeerIdentity) ([]uint32, error) {
		if identity.PID == 9 {
			return nil, errors.New("process vanished")
		}
		return []uint32{1000, 4242}, nil
	}}
	if err := authorizer.Authorize(PeerIdentity{PID: 1, UID: 1000, GID: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := authorizer.Authorize(PeerIdentity{PID: 9, UID: 1000, GID: 1000}); err == nil {
		t.Fatal("authorization must fail when group evidence is unavailable")
	}
}

func TestUnixGRPCPeerIdentityLifecycleAndSocketMode(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "run")
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
		DoctorRun: func(bool) preflight.Report {
			return preflight.Report{SchemaVersion: 1, Runnable: true}
		},
		Polkit: allowPolkit{},
	}
	socket := filepath.Join(runtimeDir, "control.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socket,
		OwnerUID:   os.Geteuid(),
		GroupGID:   os.Getegid(),
		Service:    service,
		Authorizer: Authorizer{AllowedGroup: uint32(os.Getegid())},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listen(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-done; err != nil {
			t.Errorf("server stopped with error: %v", err)
		}
	})
	info, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o660 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("unexpected control socket mode: %v", info.Mode())
	}
	if err := removeStaleSocket(socket, uint32(os.Geteuid())); err == nil {
		t.Fatal("active control socket was treated as stale")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := grpc.NewClient("passthrough:///private-vmd",
		grpc.WithTransportCredentials(NewUnixPeerCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := privatevmv1.NewPrivateVMDaemonServiceClient(connection)
	requestContext := func(sessionID string) *privatevmv1.RequestContext {
		return &privatevmv1.RequestContext{ApiVersion: &privatevmv1.ApiVersion{Major: 1}, RequestId: "request-0001", SessionId: sessionID}
	}
	created, err := client.CreateSession(ctx, &privatevmv1.CreateSessionRequest{Context: requestContext(""), Role: privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION})
	if err != nil {
		t.Fatal(err)
	}
	if created.GetOwnerUid() != uint32(os.Geteuid()) || created.GetPhase() != privatevmv1.SessionPhase_SESSION_PHASE_CREATED {
		t.Fatalf("server trusted wrong owner or phase: %v", created)
	}
	listed, err := client.ListSessions(ctx, &privatevmv1.ListSessionsRequest{Context: requestContext("")})
	if err != nil || len(listed.GetSessions()) != 1 {
		t.Fatalf("list sessions: count=%d err=%v", len(listed.GetSessions()), err)
	}
	cleaned, err := client.CleanupSession(ctx, &privatevmv1.CleanupSessionRequest{Context: requestContext(created.GetId())})
	if err != nil {
		t.Fatal(err)
	}
	if cleaned.GetPhase() != privatevmv1.SessionPhase_SESSION_PHASE_DESTROYED {
		t.Fatalf("cleanup did not reach destroyed: %v", cleaned.GetPhase())
	}
}

func TestProtocolMismatchReturnsTypedStatus(t *testing.T) {
	service := &Service{}
	_, err := service.Doctor(context.Background(), &privatevmv1.DoctorRequest{Context: &privatevmv1.RequestContext{
		ApiVersion: &privatevmv1.ApiVersion{Major: 99}, RequestId: "request-0001",
	}})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unexpected status: %v", err)
	}
	value, ok := status.FromError(err)
	if !ok || len(value.Details()) != 1 {
		t.Fatalf("typed error detail missing: %v", err)
	}
	detail, ok := value.Details()[0].(*privatevmv1.ErrorDetail)
	if !ok || detail.GetCode() != "PROTOCOL_VERSION_MISMATCH" || detail.GetRemediation() == "" {
		t.Fatalf("unexpected error detail: %#v", value.Details())
	}
}

func TestPolkitSubjectIncludesPIDStartTimeAndUID(t *testing.T) {
	identity := PeerIdentity{PID: uint32(os.Getpid()), UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	subject, err := polkitProcessSubject(identity)
	if err != nil {
		t.Fatal(err)
	}
	if subject == "" {
		t.Fatal("Polkit process subject is empty")
	}
}

type allowPolkit struct{}

func (allowPolkit) Authorize(context.Context, PeerIdentity, string) error { return nil }
