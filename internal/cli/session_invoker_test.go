package cli

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/daemon"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const cliSessionID = "pvm-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeSessionDaemon struct {
	privatevmv1.UnimplementedPrivateVMDaemonServiceServer
	mu        sync.Mutex
	runnable  bool
	startErr  error
	stopErr   error
	abortSeen int
	session   *privatevmv1.Session
}

func newFakeSessionDaemon() *fakeSessionDaemon {
	return &fakeSessionDaemon{runnable: true, session: &privatevmv1.Session{
		Id: cliSessionID, OwnerUid: 1000, Role: privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION,
		Phase: privatevmv1.SessionPhase_SESSION_PHASE_CREATED,
	}}
}

func (f *fakeSessionDaemon) PlanSession(context.Context, *privatevmv1.PlanSessionRequest) (*privatevmv1.PlanSessionResponse, error) {
	return &privatevmv1.PlanSessionResponse{Runnable: f.runnable}, nil
}

func (f *fakeSessionDaemon) CreateSession(context.Context, *privatevmv1.CreateSessionRequest) (*privatevmv1.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return proto.Clone(f.session).(*privatevmv1.Session), nil
}

func (f *fakeSessionDaemon) StartRole(context.Context, *privatevmv1.StartRoleRequest) (*privatevmv1.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return nil, f.startErr
	}
	f.session.Phase = privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE
	f.session.WorkflowState = "WORKING"
	return proto.Clone(f.session).(*privatevmv1.Session), nil
}

func (f *fakeSessionDaemon) ListSessions(context.Context, *privatevmv1.ListSessionsRequest) (*privatevmv1.ListSessionsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &privatevmv1.ListSessionsResponse{Sessions: []*privatevmv1.Session{proto.Clone(f.session).(*privatevmv1.Session)}}, nil
}

func (f *fakeSessionDaemon) GetSession(context.Context, *privatevmv1.GetSessionRequest) (*privatevmv1.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return proto.Clone(f.session).(*privatevmv1.Session), nil
}

func (f *fakeSessionDaemon) StopRole(context.Context, *privatevmv1.StopRoleRequest) (*privatevmv1.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopErr != nil {
		return nil, f.stopErr
	}
	f.session.Phase = privatevmv1.SessionPhase_SESSION_PHASE_DESTROYED
	return proto.Clone(f.session).(*privatevmv1.Session), nil
}

func (f *fakeSessionDaemon) AbortSession(context.Context, *privatevmv1.AbortSessionRequest) (*privatevmv1.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.abortSeen++
	f.session.Phase = privatevmv1.SessionPhase_SESSION_PHASE_DESTROYED
	return proto.Clone(f.session).(*privatevmv1.Session), nil
}

func (f *fakeSessionDaemon) CleanupSession(ctx context.Context, request *privatevmv1.CleanupSessionRequest) (*privatevmv1.Session, error) {
	return f.AbortSession(ctx, &privatevmv1.AbortSessionRequest{Context: request.GetContext()})
}

func TestProductionSessionInvokerPlansCreatesStartsAndRendersRedactedState(t *testing.T) {
	service := newFakeSessionDaemon()
	socket, stop := startSessionInvokerDaemon(t, service)
	defer stop()
	invoker := &ProductionInvoker{socketPath: socket, requestID: func() (string, error) { return "request-session-1234", nil }}
	result, err := invoker.Invoke(t.Context(), CommandWorkstationStart, WorkstationIntent{Bundle: "basic", Memory: "2GiB", CPUs: 2})
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := result.Data.(SessionPayload)
	if result.Code != CodeSessionStatus || !ok || len(payload.Sessions) != 1 || payload.Sessions[0].Phase != "ACTIVE" || payload.Sessions[0].WorkflowState != "WORKING" {
		t.Fatalf("start result = %+v", result)
	}
	if _, err := NewRenderer(true).renderSuccessBytes(result.Code, result.Data); err != nil {
		t.Fatalf("session result did not pass closed renderer: %v", err)
	}
}

func TestProductionSessionInvokerAbortsCreatedSessionWhenStartFails(t *testing.T) {
	service := newFakeSessionDaemon()
	service.startErr = daemonSafeError(t, codes.FailedPrecondition, "ROLE_START_FAILED")
	socket, stop := startSessionInvokerDaemon(t, service)
	defer stop()
	invoker := &ProductionInvoker{socketPath: socket, requestID: func() (string, error) { return "request-session-1234", nil }}
	_, err := invoker.Invoke(t.Context(), CommandWorkstationStart, WorkstationIntent{Bundle: "basic", Memory: "2GiB", CPUs: 2})
	application := apperror.From(err)
	if application.Code != "ROLE_START_FAILED" || application.ExitCode != exitcode.Runtime {
		t.Fatalf("start error = %+v", application)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.abortSeen != 1 {
		t.Fatalf("abort attempts = %d, want 1", service.abortSeen)
	}
}

func TestProductionSessionInvokerListsResolvesAndMapsDirtyStop(t *testing.T) {
	service := newFakeSessionDaemon()
	service.session.Phase = privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE
	socket, stop := startSessionInvokerDaemon(t, service)
	defer stop()
	invoker := &ProductionInvoker{socketPath: socket, requestID: func() (string, error) { return "request-session-1234", nil }}
	result, err := invoker.Invoke(t.Context(), "session.list", EmptyIntent{})
	if err != nil || len(result.Data.(SessionPayload).Sessions) != 1 {
		t.Fatalf("list = %+v, %v", result, err)
	}
	result, err = invoker.Invoke(t.Context(), "desktop.status", SessionIntent{})
	if err != nil || result.Data.(SessionPayload).Sessions[0].ID != cliSessionID {
		t.Fatalf("resolved status = %+v, %v", result, err)
	}
	service.stopErr = daemonSafeError(t, codes.FailedPrecondition, "WORKSPACE_DIRTY")
	_, err = invoker.Invoke(t.Context(), "desktop.stop", DesktopStopIntent{})
	application := apperror.From(err)
	if application.Code != "WORKSPACE_DIRTY" || application.ExitCode != exitcode.DirtyWorkspace {
		t.Fatalf("dirty stop error = %+v", application)
	}
}

func TestProductionSessionInvokerFailsClosedWhenRequestIDGenerationFails(t *testing.T) {
	service := newFakeSessionDaemon()
	socket, stop := startSessionInvokerDaemon(t, service)
	defer stop()
	invoker := &ProductionInvoker{socketPath: socket, requestID: func() (string, error) { return "", errors.New("entropy unavailable") }}
	_, err := invoker.Invoke(t.Context(), "session.list", EmptyIntent{})
	application := apperror.From(err)
	if application.Code != "INTERNAL_ERROR" || application.ExitCode != exitcode.Internal {
		t.Fatalf("request ID failure = %+v", application)
	}
}

func startSessionInvokerDaemon(t *testing.T, service privatevmv1.PrivateVMDaemonServiceServer) (string, func()) {
	t.Helper()
	socket := shortVPNTestSocket(t)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(daemon.NewUnixPeerCredentials()))
	privatevmv1.RegisterPrivateVMDaemonServiceServer(server, service)
	done := make(chan struct{})
	go func() {
		_ = server.Serve(listener)
		close(done)
	}()
	return socket, func() {
		server.Stop()
		_ = listener.Close()
		<-done
	}
}

func daemonSafeError(t *testing.T, codeValue codes.Code, detailCode string) error {
	t.Helper()
	base := status.New(codeValue, "safe daemon error")
	withDetail, err := base.WithDetails(&privatevmv1.ErrorDetail{
		Code: detailCode, SafeMessage: "A safe daemon message.", Remediation: "Follow the documented safe remediation.",
	})
	if err != nil {
		t.Fatal(err)
	}
	return withDetail.Err()
}

func (r Renderer) renderSuccessBytes(code Code, payload MachinePayload) ([]byte, error) {
	buffer := &testBuffer{}
	err := r.Success(buffer, code, payload)
	return buffer.value, err
}

type testBuffer struct{ value []byte }

func (b *testBuffer) Write(value []byte) (int, error) {
	if b == nil {
		return 0, errors.New("nil test buffer")
	}
	b.value = append(b.value, value...)
	return len(value), nil
}
