package network

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/vpn"
)

const (
	testSessionID = "pvm-11111111111111111111111111111111"
	testOwner     = uint32(1000)
	testProfile   = "synthetic"
)

type lookupFunc func(context.Context, string, string) ([]netip.Addr, error)

func (lookup lookupFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return lookup(ctx, network, host)
}

func testProfilePlan(t *testing.T) (*vpn.MemoryStore, vpn.ResolutionPlan) {
	t.Helper()
	raw := syntheticProfile("vpn.proton.test:51820")
	source, err := secret.New(raw)
	clear(raw)
	if err != nil {
		t.Fatal(err)
	}
	store := vpn.NewMemoryStore()
	if _, err := store.Import(testOwner, testProfile, source); err != nil {
		source.Destroy()
		store.Close()
		t.Fatal(err)
	}
	source.Destroy()
	resolver := vpn.NewEndpointResolverWithLookup(lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")}, nil
	}))
	plan, _, err := store.Resolve(context.Background(), testOwner, testProfile, resolver)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store, plan
}

func syntheticProfile(endpoint string) []byte {
	encoded := func(value byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32)) }
	return []byte("[Interface]\nPrivateKey = " + encoded(0x11) +
		"\nAddress = 10.2.0.2/32, fd00::2/128\nDNS = 10.2.0.1, fd00::1\n\n[Peer]\nPublicKey = " + encoded(0x22) +
		"\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = " + endpoint + "\n")
}

type fakeBackend struct {
	mu sync.Mutex

	operations        []string
	fail              map[string]int
	blockOperation    string
	blockOnce         bool
	entered           chan struct{}
	release           chan struct{}
	collisions        int
	pretendDeleteVeth int

	namespace       bool
	veth            bool
	tap             bool
	namespacePolicy bool
	hostPolicy      bool
	tapRead         *os.File
	tapWrite        *os.File
	lastSpec        topologySpec
}

func newFakeBackend() *fakeBackend { return &fakeBackend{fail: make(map[string]int)} }

func (backend *fakeBackend) step(ctx context.Context, operation string) error {
	backend.mu.Lock()
	backend.operations = append(backend.operations, operation)
	if backend.fail[operation] > 0 {
		backend.fail[operation]--
		backend.mu.Unlock()
		return ErrCommandFailed
	}
	block := backend.blockOperation == operation && !backend.blockOnce
	if block {
		backend.blockOnce = true
		entered, release := backend.entered, backend.release
		backend.mu.Unlock()
		if entered != nil {
			close(entered)
		}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	backend.mu.Unlock()
	return ctx.Err()
}

func (backend *fakeBackend) Available(ctx context.Context, spec topologySpec) (bool, error) {
	if err := backend.step(ctx, "available"); err != nil {
		return false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.lastSpec = spec
	if backend.collisions > 0 {
		backend.collisions--
		return false, nil
	}
	return !backend.namespace && !backend.veth && !backend.tap && !backend.namespacePolicy && !backend.hostPolicy, nil
}

func (backend *fakeBackend) CreateNamespace(ctx context.Context, spec topologySpec) error {
	backend.mu.Lock()
	backend.namespace, backend.lastSpec = true, spec
	backend.mu.Unlock()
	return backend.step(ctx, "create_namespace")
}

func (backend *fakeBackend) CreateVeth(ctx context.Context, _ topologySpec) error {
	backend.mu.Lock()
	backend.veth = true
	backend.mu.Unlock()
	return backend.step(ctx, "create_veth")
}

func (backend *fakeBackend) ConfigureHost(ctx context.Context, _ topologySpec) error {
	return backend.step(ctx, "configure_host")
}

func (backend *fakeBackend) ConfigureNamespace(ctx context.Context, _ topologySpec) error {
	return backend.step(ctx, "configure_namespace")
}

func (backend *fakeBackend) CreateTAP(ctx context.Context, _ topologySpec) (*os.File, error) {
	read, write, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	backend.mu.Lock()
	backend.tap, backend.tapRead, backend.tapWrite = true, read, write
	backend.mu.Unlock()
	if err := backend.step(ctx, "create_tap"); err != nil {
		return nil, err
	}
	return read, nil
}

func (backend *fakeBackend) ConfigureTAP(ctx context.Context, _ topologySpec) error {
	return backend.step(ctx, "configure_tap")
}

func (backend *fakeBackend) ApplyNamespacePolicy(ctx context.Context, _ topologySpec, _ endpointPolicy) error {
	backend.mu.Lock()
	backend.namespacePolicy = true
	backend.mu.Unlock()
	return backend.step(ctx, "apply_namespace_policy")
}

func (backend *fakeBackend) ApplyHostPolicy(ctx context.Context, _ topologySpec, _ endpointPolicy) error {
	backend.mu.Lock()
	backend.hostPolicy = true
	backend.mu.Unlock()
	return backend.step(ctx, "apply_host_policy")
}

func (backend *fakeBackend) DisableEgress(ctx context.Context, _ topologySpec) error {
	return backend.step(ctx, "disable_egress")
}

func (backend *fakeBackend) DeleteHostPolicy(ctx context.Context, _ topologySpec) error {
	if err := backend.step(ctx, "delete_host_policy"); err != nil {
		return err
	}
	backend.mu.Lock()
	backend.hostPolicy = false
	backend.mu.Unlock()
	return nil
}

func (backend *fakeBackend) DeleteNamespacePolicy(ctx context.Context, _ topologySpec) error {
	if err := backend.step(ctx, "delete_namespace_policy"); err != nil {
		return err
	}
	backend.mu.Lock()
	backend.namespacePolicy = false
	backend.mu.Unlock()
	return nil
}

func (backend *fakeBackend) DeleteTAP(ctx context.Context, _ topologySpec) error {
	if err := backend.step(ctx, "delete_tap"); err != nil {
		return err
	}
	backend.mu.Lock()
	backend.tap = false
	read, write := backend.tapRead, backend.tapWrite
	backend.tapRead, backend.tapWrite = nil, nil
	backend.mu.Unlock()
	if read != nil {
		_ = read.Close()
	}
	if write != nil {
		_ = write.Close()
	}
	return nil
}

func (backend *fakeBackend) DeleteVeth(ctx context.Context, _ topologySpec) error {
	if err := backend.step(ctx, "delete_veth"); err != nil {
		return err
	}
	backend.mu.Lock()
	if backend.pretendDeleteVeth > 0 {
		backend.pretendDeleteVeth--
	} else {
		backend.veth = false
	}
	backend.mu.Unlock()
	return nil
}

func (backend *fakeBackend) DeleteNamespace(ctx context.Context, _ topologySpec) error {
	if err := backend.step(ctx, "delete_namespace"); err != nil {
		return err
	}
	backend.mu.Lock()
	backend.namespace = false
	backend.mu.Unlock()
	return nil
}

func (backend *fakeBackend) AuditAbsent(ctx context.Context, _ topologySpec) (bool, error) {
	if err := backend.step(ctx, "audit_absent"); err != nil {
		return false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return !backend.namespace && !backend.veth && !backend.tap && !backend.namespacePolicy && !backend.hostPolicy, nil
}

func (backend *fakeBackend) clean() bool {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return !backend.namespace && !backend.veth && !backend.tap && !backend.namespacePolicy && !backend.hostPolicy && backend.tapRead == nil && backend.tapWrite == nil
}

func (backend *fakeBackend) operationCount(name string) int {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	count := 0
	for _, operation := range backend.operations {
		if operation == name {
			count++
		}
	}
	return count
}

func createTestNetwork(t *testing.T, implementation *fakeBackend) (*Manager, *Handle, *vpn.MemoryStore, vpn.ResolutionPlan) {
	t.Helper()
	store, plan := testProfilePlan(t)
	manager := newManager(implementation)
	handle, err := manager.Create(context.Background(), testSessionID, testOwner, testProfile, store, plan)
	if err != nil {
		t.Fatal(err)
	}
	return manager, handle, store, plan
}

func TestCreateHandoffAndCleanupAreSealedAndComplete(t *testing.T) {
	implementation := newFakeBackend()
	manager, handle, _, _ := createTestNetwork(t, implementation)
	inspection := handle.Inspect()
	if !inspection.Ready || !inspection.TAPReady || inspection.IPv4EndpointCount != 1 || inspection.IPv6EndpointCount != 1 {
		t.Fatalf("unexpected safe inspection: %#v", inspection)
	}
	if rendered := handle.String(); rendered != redactedHandle {
		t.Fatalf("unsafe handle rendering: %q", rendered)
	}
	if _, err := handle.MarshalJSON(); !errors.Is(err, secret.ErrSerialization) {
		t.Fatalf("handle serialized: %v", err)
	}
	if err := handle.WithTAP(context.Background(), func(_ context.Context, file *os.File) error {
		_, err := file.Stat()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := handle.WithGuestAddressing(context.Background(), func(_ context.Context, addressing GuestAddressing) error {
		if !addressing.IPv4Address().IsValid() || !addressing.IPv6Address().IsValid() || !addressing.IPv4Gateway().IsValid() || !addressing.IPv6Gateway().IsValid() {
			t.Fatal("invalid static addressing")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var config []byte
	if err := handle.WithGuestVPNConfig(context.Background(), func(_ context.Context, reader io.Reader) error {
		var readErr error
		config, readErr = io.ReadAll(reader)
		return readErr
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(config, []byte("Endpoint = 1.1.1.1:51820")) {
		t.Fatal("guest config and host policy did not consume the same plan")
	}
	clear(config)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.Cleanup(canceled, testSessionID); err != nil {
		t.Fatalf("accepted cleanup was abandoned on caller cancellation: %v", err)
	}
	if !implementation.clean() || handle.Inspect().Ready {
		t.Fatal("cleanup left resources or a ready stale handle")
	}
	if err := manager.Cleanup(context.Background(), testSessionID); err != nil {
		t.Fatalf("repeated cleanup: %v", err)
	}
	for _, stale := range []func() error{
		func() error {
			return handle.WithTAP(context.Background(), func(context.Context, *os.File) error { return nil })
		},
		func() error {
			return handle.WithGuestAddressing(context.Background(), func(context.Context, GuestAddressing) error { return nil })
		},
		func() error {
			return handle.WithGuestVPNConfig(context.Background(), func(context.Context, io.Reader) error { return nil })
		},
	} {
		if err := stale(); !errors.Is(err, ErrTopologyNotReady) {
			t.Fatalf("stale handle error = %v", err)
		}
	}
}

func TestFailureAfterEveryAllocationCleansAllPartialResources(t *testing.T) {
	operations := []string{
		"create_namespace", "create_veth", "configure_host", "configure_namespace",
		"create_tap", "configure_tap", "apply_namespace_policy", "apply_host_policy",
	}
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			store, plan := testProfilePlan(t)
			implementation := newFakeBackend()
			implementation.fail[operation] = 1
			manager := newManager(implementation)
			_, err := manager.Create(context.Background(), testSessionID, testOwner, testProfile, store, plan)
			if err == nil {
				t.Fatal("injected failure succeeded")
			}
			expectedCode := "NETWORK_TOPOLOGY_FAILED"
			if operation == "apply_namespace_policy" || operation == "apply_host_policy" {
				expectedCode = "HOST_EGRESS_POLICY_FAILED"
			}
			assertNetworkCode(t, err, expectedCode)
			if !implementation.clean() {
				t.Fatal("partial allocation survived rollback")
			}
			manager.mu.Lock()
			defer manager.mu.Unlock()
			if len(manager.states) != 0 || len(manager.reservations) != 0 || len(manager.names) != 0 {
				t.Fatal("failed creation retained manager ownership")
			}
		})
	}
}

func TestCleanupRetriesEveryAttemptUntilFinalAuditPasses(t *testing.T) {
	implementation := newFakeBackend()
	implementation.pretendDeleteVeth = 1
	manager, _, _, _ := createTestNetwork(t, implementation)
	if err := manager.Cleanup(context.Background(), testSessionID); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("false-success delete passed audit: %v", err)
	} else {
		assertNetworkCode(t, err, "NETWORK_CLEANUP_INCOMPLETE")
	}
	if err := manager.Cleanup(context.Background(), testSessionID); err != nil {
		t.Fatalf("retry did not revisit attempted resources: %v", err)
	}
	if implementation.operationCount("delete_veth") != 2 || !implementation.clean() {
		t.Fatal("cleanup flag was cleared before final absence audit")
	}
}

func TestAllocationSkipsBackendAndInFlightNameCollisions(t *testing.T) {
	store, plan := testProfilePlan(t)
	implementation := newFakeBackend()
	implementation.collisions = 2
	manager := newManager(implementation)
	nameCollision := candidateFor(testSessionID, 2)
	manager.names[nameCollision.namespace] = "pvm-22222222222222222222222222222222"
	handle, err := manager.Create(context.Background(), testSessionID, testOwner, testProfile, store, plan)
	if err != nil {
		t.Fatal(err)
	}
	implementation.mu.Lock()
	allocated := implementation.lastSpec
	implementation.mu.Unlock()
	if allocated != candidateFor(testSessionID, 3) {
		t.Fatalf("allocation did not skip exact collisions: %#v", allocated)
	}
	if err := handle.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPlanRotationInvalidatesEveryHandoffWithoutWeakeningCleanup(t *testing.T) {
	implementation := newFakeBackend()
	manager, handle, store, _ := createTestNetwork(t, implementation)
	raw := syntheticProfile("1.0.0.1:51820")
	source, err := secret.New(raw)
	clear(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(testOwner, testProfile, source); err != nil {
		source.Destroy()
		t.Fatal(err)
	}
	source.Destroy()
	for _, stale := range []func() error{
		func() error {
			return handle.WithTAP(context.Background(), func(context.Context, *os.File) error { return nil })
		},
		func() error {
			return handle.WithGuestAddressing(context.Background(), func(context.Context, GuestAddressing) error { return nil })
		},
		func() error {
			return handle.WithGuestVPNConfig(context.Background(), func(context.Context, io.Reader) error { return nil })
		},
	} {
		if err := stale(); !errors.Is(err, vpn.ErrProfileRotated) {
			t.Fatalf("rotated plan handoff error = %v", err)
		}
	}
	if err := manager.Cleanup(context.Background(), testSessionID); err != nil || !implementation.clean() {
		t.Fatalf("rotation obstructed cleanup: %v", err)
	}
}

func TestProvisionAndHandoffsSerializeWithCleanup(t *testing.T) {
	t.Run("provision", func(t *testing.T) {
		store, plan := testProfilePlan(t)
		implementation := newFakeBackend()
		implementation.blockOperation = "configure_host"
		implementation.entered, implementation.release = make(chan struct{}), make(chan struct{})
		manager := newManager(implementation)
		created := make(chan *Handle, 1)
		createErr := make(chan error, 1)
		go func() {
			handle, err := manager.Create(context.Background(), testSessionID, testOwner, testProfile, store, plan)
			created <- handle
			createErr <- err
		}()
		<-implementation.entered
		cleanupDone := make(chan error, 1)
		go func() { cleanupDone <- manager.Cleanup(context.Background(), testSessionID) }()
		assertStillBlocked(t, cleanupDone)
		close(implementation.release)
		if err := <-createErr; err != nil {
			t.Fatal(err)
		}
		handle := <-created
		if err := <-cleanupDone; err != nil {
			t.Fatal(err)
		}
		if !implementation.clean() || handle.Inspect().Ready {
			t.Fatal("concurrent create/cleanup escaped lifecycle ownership")
		}
	})

	for _, handoff := range []string{"tap", "config"} {
		t.Run(handoff, func(t *testing.T) {
			implementation := newFakeBackend()
			manager, handle, _, _ := createTestNetwork(t, implementation)
			entered, release := make(chan struct{}), make(chan struct{})
			handoffDone := make(chan error, 1)
			go func() {
				if handoff == "tap" {
					handoffDone <- handle.WithTAP(context.Background(), func(context.Context, *os.File) error {
						close(entered)
						<-release
						return nil
					})
					return
				}
				handoffDone <- handle.WithGuestVPNConfig(context.Background(), func(context.Context, io.Reader) error {
					close(entered)
					<-release
					return nil
				})
			}()
			<-entered
			cleanupDone := make(chan error, 1)
			go func() { cleanupDone <- manager.Cleanup(context.Background(), testSessionID) }()
			assertStillBlocked(t, cleanupDone)
			close(release)
			if err := <-handoffDone; err != nil {
				t.Fatal(err)
			}
			if err := <-cleanupDone; err != nil {
				t.Fatal(err)
			}
			if !implementation.clean() {
				t.Fatal("cleanup completed before handoff lease released")
			}
		})
	}
}

func TestCancellationDuringProvisionRollsBackWithDetachedCleanup(t *testing.T) {
	store, plan := testProfilePlan(t)
	implementation := newFakeBackend()
	implementation.blockOperation = "configure_namespace"
	implementation.entered, implementation.release = make(chan struct{}), make(chan struct{})
	manager := newManager(implementation)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := manager.Create(ctx, testSessionID, testOwner, testProfile, store, plan)
		done <- err
	}()
	<-implementation.entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled create error = %v", err)
	}
	if !implementation.clean() {
		t.Fatal("caller cancellation abandoned rollback")
	}
}

func TestTimeoutDuringProvisionRollsBackWithDetachedCleanup(t *testing.T) {
	store, plan := testProfilePlan(t)
	implementation := newFakeBackend()
	implementation.blockOperation = "configure_namespace"
	implementation.entered, implementation.release = make(chan struct{}), make(chan struct{})
	manager := newManager(implementation)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := manager.Create(ctx, testSessionID, testOwner, testProfile, store, plan)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed-out create error = %v", err)
	}
	if !implementation.clean() {
		t.Fatal("caller timeout abandoned rollback")
	}
}

func TestHandoffHonorsCallerDeadlineAndReleasesLifecycleLease(t *testing.T) {
	implementation := newFakeBackend()
	manager, handle, _, _ := createTestNetwork(t, implementation)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := handle.WithGuestAddressing(ctx, func(callbackCtx context.Context, _ GuestAddressing) error {
		if _, bounded := callbackCtx.Deadline(); !bounded {
			t.Fatal("handoff callback had no bounded context")
		}
		<-callbackCtx.Done()
		return nil // manager must enforce the deadline even if a callback forgets.
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handoff deadline error = %v", err)
	}
	if err := manager.Cleanup(context.Background(), testSessionID); err != nil || !implementation.clean() {
		t.Fatalf("timed-out handoff retained lifecycle lease: %v", err)
	}
}

func assertStillBlocked(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("operation did not wait for lifecycle owner: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
}

func assertNetworkCode(t *testing.T, err error, code string) {
	t.Helper()
	var application *apperror.Error
	if !errors.As(err, &application) || application.Code != code {
		t.Fatalf("error = %v; want application code %s", err, code)
	}
}
