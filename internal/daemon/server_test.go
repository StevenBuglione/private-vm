package daemon

import (
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
	"google.golang.org/grpc/status"
)

func TestAuthorizerUsesSupplementaryGroupAndFailsClosed(t *testing.T) {
	identity := currentProcessIdentity(t)
	authorizer := Authorizer{AllowedGroup: 4242, Groups: func(identity PeerIdentity) ([]uint32, error) {
		return []uint32{1000, 4242}, nil
	}}
	if err := authorizer.Authorize(identity); err != nil {
		t.Fatal(err)
	}
	authorizer.Groups = func(PeerIdentity) ([]uint32, error) { return nil, errors.New("process vanished") }
	if err := authorizer.Authorize(identity); err == nil {
		t.Fatal("authorization must fail when group evidence is unavailable")
	}
	reused := identity
	reused.StartTimeTicks++
	authorizer.Groups = func(PeerIdentity) ([]uint32, error) { return []uint32{4242}, nil }
	if err := authorizer.Authorize(reused); err == nil {
		t.Fatal("authorization must fail before the injected group resolver when process identity changed")
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
		Config:   config.Defaults(),
		DoctorRun: func(context.Context, bool) preflight.Report {
			return preflight.Report{SchemaVersion: 1, Runnable: true}
		},
		Polkit: allowPolkit{},
	}
	socket := filepath.Join(runtimeDir, "control.sock")
	server, err := NewServer(ServerOptions{
		SocketPath:                      socket,
		OwnerUID:                        os.Geteuid(),
		GroupGID:                        os.Getegid(),
		Service:                         service,
		Authorizer:                      Authorizer{AllowedGroup: uint32(os.Getegid())},
		testOnlyAllowUntrustedAncestors: true,
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
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		t.Fatalf("unexpected control socket identity: %#v", info.Sys())
	}
	if err := removeStaleSocket(socket, uint32(os.Geteuid()), uint32(os.Getegid())); err == nil {
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
	const privateSentinel = "PRIVATE_RPC_SENTINEL_MUST_NOT_ESCAPE"
	_, err = client.PlanSession(ctx, &privatevmv1.PlanSessionRequest{
		Context: requestContext(""), Role: privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION, ImageBundle: privateSentinel,
	})
	assertRPCError(t, err, codes.InvalidArgument, "IMAGE_BUNDLE_INVALID")
	if strings.Contains(err.Error(), privateSentinel) {
		t.Fatal("rejected RPC value escaped through the daemon error")
	}
	cleaned, err := client.CleanupSession(ctx, &privatevmv1.CleanupSessionRequest{Context: requestContext(created.GetId())})
	if err != nil {
		t.Fatal(err)
	}
	if cleaned.GetPhase() != privatevmv1.SessionPhase_SESSION_PHASE_DESTROYED {
		t.Fatalf("cleanup did not reach destroyed: %v", cleaned.GetPhase())
	}
}

func TestGetVersionReportsCurrentProtocol(t *testing.T) {
	response, err := (&Service{}).GetVersion(t.Context(), &privatevmv1.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetApiVersion().GetMajor() != protocolMajor || response.GetApiVersion().GetMinor() != protocolMinor {
		t.Fatalf("GetVersion protocol = %v, want %d.%d", response.GetApiVersion(), protocolMajor, protocolMinor)
	}
}

func TestProtocolMismatchReturnsTypedStatus(t *testing.T) {
	for _, test := range []struct {
		name    string
		version *privatevmv1.ApiVersion
	}{
		{name: "major", version: &privatevmv1.ApiVersion{Major: protocolMajor + 1}},
		{name: "future-minor", version: &privatevmv1.ApiVersion{Major: protocolMajor, Minor: protocolMinor + 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &Service{}
			_, err := service.Doctor(context.Background(), &privatevmv1.DoctorRequest{Context: &privatevmv1.RequestContext{
				ApiVersion: test.version, RequestId: "request-0001",
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
		})
	}
}

func TestPolkitSubjectIncludesPIDStartTimeAndUID(t *testing.T) {
	stat, err := readBoundedProcFile(procPIDPath(uint32(os.Getpid()), "stat"), maxProcStatBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, startTime, err := parseProcStat(stat)
	if err != nil {
		t.Fatal(err)
	}
	identity := PeerIdentity{PID: uint32(os.Getpid()), UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), StartTimeTicks: startTime}
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
