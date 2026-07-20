package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc/codes"
)

type fakeRoleOrchestrator struct {
	mu             sync.Mutex
	operations     []string
	failAt         string
	workspaceState string
	workspaceErr   error
	active         map[string]bool
}

func (f *fakeRoleOrchestrator) PlanAllocation(_ session.Snapshot, _ session.LaunchPlan) session.AllocateFunc {
	return f.allocation("plan")
}

func newFakeRoleOrchestrator() *fakeRoleOrchestrator {
	return &fakeRoleOrchestrator{workspaceState: "CLEAN", active: make(map[string]bool)}
}

func (f *fakeRoleOrchestrator) record(operation string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.operations = append(f.operations, operation)
	if f.failAt == operation {
		return errors.New("injected role failure")
	}
	return nil
}

func (f *fakeRoleOrchestrator) Preflight(context.Context, session.Snapshot) error {
	return f.record("preflight")
}

func (f *fakeRoleOrchestrator) VerifyImages(context.Context, session.Snapshot) error {
	return f.record("images")
}

func (f *fakeRoleOrchestrator) StorageAllocation(session.Snapshot) session.AllocateFunc {
	return f.allocation("storage")
}

func (f *fakeRoleOrchestrator) RuntimeAllocation(session.Snapshot) session.AllocateFunc {
	return f.allocation("runtime")
}

func (f *fakeRoleOrchestrator) allocation(name string) session.AllocateFunc {
	return func(context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		if err := f.record(name + ".allocate"); err != nil {
			return nil, nil, err
		}
		f.mu.Lock()
		f.active[name] = true
		f.mu.Unlock()
		return func(context.Context) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.operations = append(f.operations, name+".cleanup")
				f.active[name] = false
				return nil
			}, func(context.Context) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.operations = append(f.operations, name+".audit")
				if f.active[name] {
					return errors.New("resource remains active")
				}
				return nil
			}, nil
	}
}

func (f *fakeRoleOrchestrator) WorkspaceState(context.Context, session.Snapshot) (string, error) {
	if err := f.record("workspace.state"); err != nil {
		return "", err
	}
	return f.workspaceState, f.workspaceErr
}

func (f *fakeRoleOrchestrator) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.operations...)
}

func TestRoleServiceStartsThroughEveryOwnedGateAndStopsInReverseOrder(t *testing.T) {
	service, roles, snapshot := roleServiceFixture(t)
	ctx := roleCallerContext(t, snapshot.OwnerUID)
	started, err := service.StartRole(ctx, &privatevmv1.StartRoleRequest{Context: validRequestContext(snapshot.ID)})
	if err != nil {
		t.Fatal(err)
	}
	if started.GetPhase() != privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE || started.GetWorkflowState() != "WORKING" {
		t.Fatalf("started session = %+v", started)
	}
	wantStart := []string{"preflight", "images", "storage.allocate", "runtime.allocate"}
	if !slices.Equal(roles.log(), wantStart) {
		t.Fatalf("start operations = %v, want %v", roles.log(), wantStart)
	}
	roles.workspaceState = "READY"
	stopped, err := service.StopRole(ctx, &privatevmv1.StopRoleRequest{Context: validRequestContext(snapshot.ID)})
	if err != nil {
		t.Fatal(err)
	}
	if stopped.GetPhase() != privatevmv1.SessionPhase_SESSION_PHASE_DESTROYED {
		t.Fatalf("stopped phase = %s", stopped.GetPhase())
	}
	want := []string{
		"preflight", "images", "storage.allocate", "runtime.allocate", "workspace.state",
		"runtime.cleanup", "runtime.audit", "storage.cleanup", "storage.audit",
	}
	if !slices.Equal(roles.log(), want) {
		t.Fatalf("lifecycle operations = %v, want %v", roles.log(), want)
	}
}

func TestDownloaderStartStopsAtVerifiedVPNGateBeforeTorrentInput(t *testing.T) {
	service, _, snapshot := roleServiceFixtureForRole(t, session.RoleDownloader)
	started, err := service.StartRole(roleCallerContext(t, snapshot.OwnerUID), &privatevmv1.StartRoleRequest{Context: validRequestContext(snapshot.ID)})
	if err != nil {
		t.Fatal(err)
	}
	if started.GetPhase() != privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE || started.GetWorkflowState() != "VPN_VERIFIED" {
		t.Fatalf("downloader start = %+v", started)
	}
}

func TestRoleStartFailureMatrixAlwaysConvergesToDestroyed(t *testing.T) {
	for _, failure := range []string{"preflight", "images", "storage.allocate", "runtime.allocate"} {
		t.Run(failure, func(t *testing.T) {
			service, roles, snapshot := roleServiceFixture(t)
			roles.failAt = failure
			_, err := service.StartRole(roleCallerContext(t, snapshot.OwnerUID), &privatevmv1.StartRoleRequest{Context: validRequestContext(snapshot.ID)})
			assertRPCError(t, err, codes.FailedPrecondition, "ROLE_START_FAILED")
			current, getErr := service.Sessions.Get(snapshot.ID, snapshot.OwnerUID)
			if getErr != nil || current.Phase != session.PhaseDestroyed {
				t.Fatalf("failed start did not destroy session: snapshot=%+v err=%v log=%v", current, getErr, roles.log())
			}
			roles.mu.Lock()
			defer roles.mu.Unlock()
			for name, active := range roles.active {
				if active {
					t.Fatalf("%s remained active after %s failure", name, failure)
				}
			}
		})
	}
}

func TestProtectedStopBlocksDirtyAndUnreachableWorkspaceUntilDiscard(t *testing.T) {
	for _, fixture := range []struct {
		name  string
		state string
		err   error
		code  string
	}{
		{name: "unexported", state: "UNEXPORTED", code: "WORKSPACE_DIRTY"},
		{name: "changed", state: "CHANGED", code: "WORKSPACE_DIRTY"},
		{name: "unreachable", err: errors.New("guest unavailable"), code: "WORKSPACE_UNREACHABLE"},
		{name: "ready-require-clean", state: "READY", code: "WORKSPACE_DIRTY"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			service, roles, snapshot := roleServiceFixture(t)
			ctx := roleCallerContext(t, snapshot.OwnerUID)
			if _, err := service.StartRole(ctx, &privatevmv1.StartRoleRequest{Context: validRequestContext(snapshot.ID)}); err != nil {
				t.Fatal(err)
			}
			roles.workspaceState, roles.workspaceErr = fixture.state, fixture.err
			requireClean := fixture.name == "ready-require-clean"
			_, err := service.StopRole(ctx, &privatevmv1.StopRoleRequest{Context: validRequestContext(snapshot.ID), RequireClean: requireClean})
			assertRPCError(t, err, codes.FailedPrecondition, fixture.code)
			current, getErr := service.Sessions.Get(snapshot.ID, snapshot.OwnerUID)
			if getErr != nil || current.Phase != session.PhaseActive {
				t.Fatalf("blocked stop changed lifecycle: snapshot=%+v err=%v", current, getErr)
			}
			stopped, err := service.StopRole(ctx, &privatevmv1.StopRoleRequest{Context: validRequestContext(snapshot.ID), DiscardUnexported: true})
			if err != nil || stopped.GetPhase() != privatevmv1.SessionPhase_SESSION_PHASE_DESTROYED {
				t.Fatalf("confirmed discard stop = %+v, %v", stopped, err)
			}
		})
	}
}

func roleServiceFixture(t *testing.T) (*Service, *fakeRoleOrchestrator, session.Snapshot) {
	return roleServiceFixtureForRole(t, session.RoleWorkstation)
}

func roleServiceFixtureForRole(t *testing.T, role session.Role) (*Service, *fakeRoleOrchestrator, session.Snapshot) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	store, err := session.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(store, session.DefaultMaxSessionsPerOwner)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Create(1000, role)
	if err != nil {
		t.Fatal(err)
	}
	roles := newFakeRoleOrchestrator()
	return &Service{Sessions: manager, Roles: roles}, roles, snapshot
}

func roleCallerContext(t *testing.T, uid uint32) context.Context {
	t.Helper()
	return context.WithValue(t.Context(), identityContextKey{}, PeerIdentity{UID: uid, GID: uid, PID: uint32(os.Getpid())})
}
