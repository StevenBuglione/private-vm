package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testSessionA = "pvm-11111111111111111111111111111111"
	testSessionB = "pvm-22222222222222222222222222222222"
	testPrint    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testBaseSeal = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type fakeBackend struct {
	mu               sync.Mutex
	candidates       []Candidate
	removed          map[string]bool
	operations       []string
	revalidateCalls  map[string]int
	failRevalidate   map[string]int
	failCleanup      map[string]int
	failAudit        map[string]int
	failSessionAudit map[string]int
	inventoryErr     error
	blockCleanup     string
}

func newFakeBackend(candidates []Candidate) *fakeBackend {
	return &fakeBackend{
		candidates: append([]Candidate(nil), candidates...), removed: make(map[string]bool),
		revalidateCalls: make(map[string]int), failRevalidate: make(map[string]int),
		failCleanup: make(map[string]int), failAudit: make(map[string]int),
		failSessionAudit: make(map[string]int),
	}
}

func candidateKey(candidate Candidate) string {
	return candidate.SessionID + ":" + string(candidate.Kind) + ":" + candidate.Locator
}

func (f *fakeBackend) Inventory(ctx context.Context) ([]Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inventoryErr != nil {
		return nil, f.inventoryErr
	}
	var candidates []Candidate
	for _, candidate := range f.candidates {
		if !f.removed[candidateKey(candidate)] {
			candidates = append(candidates, candidate)
		}
	}
	return candidates, nil
}

func (f *fakeBackend) RevalidateOwned(ctx context.Context, candidate Candidate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := candidateKey(candidate)
	f.revalidateCalls[key]++
	if f.failRevalidate[key] == f.revalidateCalls[key] {
		return errors.New("injected identity replacement containing sensitive path")
	}
	if f.removed[key] {
		return errors.New("candidate already absent")
	}
	return nil
}

func (f *fakeBackend) Cleanup(ctx context.Context, candidate Candidate) error {
	key := candidateKey(candidate)
	f.mu.Lock()
	f.operations = append(f.operations, "cleanup:"+string(candidate.Kind))
	if f.failCleanup[key] > 0 {
		f.failCleanup[key]--
		f.mu.Unlock()
		return errors.New("injected cleanup output containing sensitive path")
	}
	block := f.blockCleanup == key
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	f.mu.Lock()
	f.removed[key] = true
	f.mu.Unlock()
	return nil
}

func (f *fakeBackend) AuditAbsent(ctx context.Context, candidate Candidate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := candidateKey(candidate)
	f.operations = append(f.operations, "audit:"+string(candidate.Kind))
	if f.failAudit[key] > 0 {
		f.failAudit[key]--
		return errors.New("injected audit evidence containing identity")
	}
	if !f.removed[key] {
		return errors.New("artifact remains")
	}
	return nil
}

func (f *fakeBackend) AuditSessionAbsent(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.operations = append(f.operations, "session-audit")
	if f.failSessionAudit[id] > 0 {
		f.failSessionAudit[id]--
		return errors.New("injected undiscovered resource identity")
	}
	for _, candidate := range f.candidates {
		if candidate.SessionID == id && !f.removed[candidateKey(candidate)] {
			return errors.New("session artifact remains")
		}
	}
	return nil
}

type fakeClaim struct{ release func() }

func (c fakeClaim) Release() { c.release() }

type fakeRegistry struct {
	mu      sync.Mutex
	active  map[string]bool
	claimed map[string]bool
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{active: make(map[string]bool), claimed: make(map[string]bool)}
}

func (r *fakeRegistry) ClaimRecovery(ctx context.Context, id string) (RecoveryClaim, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active[id] || r.claimed[id] {
		return nil, ErrActiveOwner
	}
	r.claimed[id] = true
	return fakeClaim{release: func() {
		r.mu.Lock()
		delete(r.claimed, id)
		r.mu.Unlock()
	}}, nil
}

type fakeKeys struct {
	states map[string]KeyState
	err    error
}

func (k fakeKeys) State(ctx context.Context, id string) (KeyState, error) {
	if err := ctx.Err(); err != nil {
		return KeyUnknown, err
	}
	if k.err != nil {
		return KeyUnknown, k.err
	}
	state, ok := k.states[id]
	if !ok {
		return KeyUnknown, nil
	}
	return state, nil
}

type fakeBases struct {
	mu          sync.Mutex
	seal        BaseImageSeal
	snapshotErr error
	verifyErr   error
}

func (b *fakeBases) Snapshot(ctx context.Context) (BaseImageSeal, error) {
	if err := ctx.Err(); err != nil {
		return BaseImageSeal{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seal, b.snapshotErr
}
func (b *fakeBases) Verify(ctx context.Context, seal BaseImageSeal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.verifyErr != nil {
		return b.verifyErr
	}
	if seal != b.seal {
		return errors.New("base image aggregate changed")
	}
	return nil
}

func artifact(sessionID string, kind Kind, locator string) Candidate {
	return Candidate{
		SessionID: sessionID, Kind: kind, Origin: OriginKernel, Locator: locator,
		Identity: Identity{Fingerprint: testPrint, OwnerUID: 0, OwnerGID: 42},
	}
}

func testConfig() Config {
	return Config{
		DaemonUID: 0, InventoryTimeout: 100 * time.Millisecond,
		StepTimeout: 40 * time.Millisecond, SessionTimeout: 500 * time.Millisecond,
	}
}

func newTestReconciler(t *testing.T, backend *fakeBackend, registry *fakeRegistry, keys fakeKeys, bases *fakeBases) *Reconciler {
	t.Helper()
	reconciler, err := New(backend, registry, keys, bases, testConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return reconciler
}

func TestRecoveryUsesClosedDependencyOrderAndRedactedEvidence(t *testing.T) {
	candidates := make([]Candidate, 0, len(cleanupOrder))
	for index := len(cleanupOrder) - 1; index >= 0; index-- {
		candidates = append(candidates, artifact(testSessionA, cleanupOrder[index], fmt.Sprintf("owned-%02d", index)))
	}
	backend := newFakeBackend(candidates)
	reconciler := newTestReconciler(t, backend, newFakeRegistry(), fakeKeys{states: map[string]KeyState{testSessionA: KeyUnavailable}}, &fakeBases{seal: BaseImageSeal{Count: 6, Fingerprint: testBaseSeal}})

	report, err := reconciler.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Code != "RECOVERY_COMPLETED" || report.Status != StatusComplete || report.SessionsRecovered != 1 || report.KeyLossVerifiedSessions != 1 || !report.BaseImagesVerified {
		t.Fatalf("report=%+v", report)
	}
	backend.mu.Lock()
	operations := append([]string(nil), backend.operations...)
	backend.mu.Unlock()
	var want []string
	for _, kind := range cleanupOrder {
		want = append(want, "cleanup:"+string(kind), "audit:"+string(kind))
	}
	want = append(want, "session-audit")
	if strings.Join(operations, ",") != strings.Join(want, ",") {
		t.Fatalf("operation order=%v want=%v", operations, want)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{testSessionA, "owned-", testPrint, "sensitive"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("recovery report leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestRecoveryPinsWholeSessionBeforeMutation(t *testing.T) {
	first := artifact(testSessionA, KindQEMUProcess, "qemu")
	second := artifact(testSessionA, KindMapper, "mapper")
	backend := newFakeBackend([]Candidate{first, second})
	backend.failRevalidate[candidateKey(second)] = 1
	reconciler := newTestReconciler(t, backend, newFakeRegistry(), fakeKeys{states: map[string]KeyState{testSessionA: KeyUnavailable}}, &fakeBases{seal: BaseImageSeal{Count: 6, Fingerprint: testBaseSeal}})

	report, err := reconciler.Run(context.Background())
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("error=%v", err)
	}
	if len(backend.operations) != 0 {
		t.Fatalf("mutation occurred before complete pin: %v", backend.operations)
	}
	if len(report.Failures) != 1 || report.Failures[0].Code != "RECOVERY_IDENTITY_REJECTED" {
		t.Fatalf("report=%+v", report)
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("error leaked wrapped cause: %v", err)
	}
}

func TestRecoveryRevalidatesImmediatelyBeforeMutation(t *testing.T) {
	candidate := artifact(testSessionA, KindCiphertext, "/scratch/owned.luks")
	backend := newFakeBackend([]Candidate{candidate})
	backend.failRevalidate[candidateKey(candidate)] = 2
	reconciler := newTestReconciler(t, backend, newFakeRegistry(), fakeKeys{states: map[string]KeyState{testSessionA: KeyUnavailable}}, &fakeBases{seal: BaseImageSeal{Count: 6, Fingerprint: testBaseSeal}})

	report, err := reconciler.Run(context.Background())
	if !errors.Is(err, ErrIncomplete) || len(backend.operations) != 0 {
		t.Fatalf("err=%v operations=%v", err, backend.operations)
	}
	if report.Failures[0].Code != "RECOVERY_IDENTITY_CHANGED" {
		t.Fatalf("report=%+v", report)
	}
}

func TestRecoveryRejectsCurrentRegistryOwner(t *testing.T) {
	candidate := artifact(testSessionA, KindQEMUProcess, "qemu")
	backend := newFakeBackend([]Candidate{candidate})
	registry := newFakeRegistry()
	registry.active[testSessionA] = true
	reconciler := newTestReconciler(t, backend, registry, fakeKeys{states: map[string]KeyState{}}, &fakeBases{seal: BaseImageSeal{Count: 6, Fingerprint: testBaseSeal}})

	report, err := reconciler.Run(context.Background())
	if !errors.Is(err, ErrIncomplete) || len(backend.operations) != 0 {
		t.Fatalf("err=%v operations=%v", err, backend.operations)
	}
	if report.Failures[0].Code != "RECOVERY_REGISTRY_CONFLICT" || report.Failures[0].Retryable {
		t.Fatalf("report=%+v", report)
	}
}

func TestRecoveryRequiresVolatileKeyLossEvidence(t *testing.T) {
	for _, state := range []KeyState{KeyPresent, KeyUnknown} {
		t.Run(string(state), func(t *testing.T) {
			candidate := artifact(testSessionA, KindCiphertext, "/scratch/owned.luks")
			backend := newFakeBackend([]Candidate{candidate})
			reconciler := newTestReconciler(t, backend, newFakeRegistry(), fakeKeys{states: map[string]KeyState{testSessionA: state}}, &fakeBases{seal: BaseImageSeal{Count: 6, Fingerprint: testBaseSeal}})
			report, err := reconciler.Run(context.Background())
			if !errors.Is(err, ErrIncomplete) || len(backend.operations) != 0 {
				t.Fatalf("err=%v operations=%v", err, backend.operations)
			}
			if report.Failures[0].Code != "RECOVERY_KEY_STATE_UNKNOWN" {
				t.Fatalf("report=%+v", report)
			}
		})
	}
}

func TestRecoveryFailureStopsDependentsAndRetryConverges(t *testing.T) {
	qemu := artifact(testSessionA, KindQEMUProcess, "qemu")
	mapper := artifact(testSessionA, KindMapper, "mapper")
	ciphertext := artifact(testSessionA, KindCiphertext, "/scratch/owned.luks")
	backend := newFakeBackend([]Candidate{ciphertext, mapper, qemu})
	backend.failCleanup[candidateKey(mapper)] = 1
	reconciler := newTestReconciler(t, backend, newFakeRegistry(), fakeKeys{states: map[string]KeyState{testSessionA: KeyUnavailable}}, &fakeBases{seal: BaseImageSeal{Count: 6, Fingerprint: testBaseSeal}})

	first, err := reconciler.Run(context.Background())
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("first error=%v", err)
	}
	if first.ArtifactsRecovered.QEMUProcess != 1 || first.ArtifactsRecovered.Ciphertext != 0 {
		t.Fatalf("first report=%+v", first)
	}
	report, err := reconciler.Run(context.Background())
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if report.SessionsRecovered != 1 || report.ArtifactsRecovered.Mapper != 1 || report.ArtifactsRecovered.Ciphertext != 1 {
		t.Fatalf("retry report=%+v", report)
	}

	backend.mu.Lock()
	operations := strings.Join(backend.operations, ",")
	backend.mu.Unlock()
	if strings.Index(operations, "cleanup:ciphertext") < strings.LastIndex(operations, "cleanup:device_mapper") {
		t.Fatalf("dependent ciphertext ran before mapper retry: %s", operations)
	}
}

func TestRecoveryFailureMatrix(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*fakeBackend, *fakeBases)
		wantCode  string
	}{
		{name: "cleanup", configure: func(b *fakeBackend, _ *fakeBases) { b.failCleanup[candidateKey(b.candidates[0])] = 1 }, wantCode: "RECOVERY_CLEANUP_FAILED"},
		{name: "artifact audit", configure: func(b *fakeBackend, _ *fakeBases) { b.failAudit[candidateKey(b.candidates[0])] = 1 }, wantCode: "RECOVERY_ABSENCE_UNPROVEN"},
		{name: "session audit", configure: func(b *fakeBackend, _ *fakeBases) { b.failSessionAudit[testSessionA] = 1 }, wantCode: "RECOVERY_SESSION_ABSENCE_UNPROVEN"},
		{name: "base audit", configure: func(_ *fakeBackend, bases *fakeBases) { bases.verifyErr = errors.New("injected base path") }, wantCode: "RECOVERY_BASE_IMAGE_CHANGED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := artifact(testSessionA, KindQEMUProcess, "qemu")
			backend := newFakeBackend([]Candidate{candidate})
			bases := &fakeBases{seal: BaseImageSeal{Count: 6, Fingerprint: testBaseSeal}}
			test.configure(backend, bases)
			report, err := newTestReconciler(t, backend, newFakeRegistry(), fakeKeys{states: map[string]KeyState{}}, bases).Run(context.Background())
			if !errors.Is(err, ErrIncomplete) {
				t.Fatalf("error=%v", err)
			}
			if report.Failures[len(report.Failures)-1].Code != test.wantCode {
				t.Fatalf("report=%+v", report)
			}
			encoded, _ := json.Marshal(report)
			if strings.Contains(string(encoded), "injected") {
				t.Fatalf("report leaked cause: %s", encoded)
			}
		})
	}
}

func TestRecoveryCancellationAndTimeout(t *testing.T) {
	t.Run("canceled inventory", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		backend := newFakeBackend(nil)
		report, err := newTestReconciler(t, backend, newFakeRegistry(), fakeKeys{states: map[string]KeyState{}}, &fakeBases{seal: BaseImageSeal{Count: 6, Fingerprint: testBaseSeal}}).Run(ctx)
		if !errors.Is(err, ErrIncomplete) || report.Failures[0].Code != "RECOVERY_CANCELED" {
			t.Fatalf("report=%+v err=%v", report, err)
		}
	})

	t.Run("cleanup timeout", func(t *testing.T) {
		candidate := artifact(testSessionA, KindQEMUProcess, "qemu")
		backend := newFakeBackend([]Candidate{candidate})
		backend.blockCleanup = candidateKey(candidate)
		report, err := newTestReconciler(t, backend, newFakeRegistry(), fakeKeys{states: map[string]KeyState{}}, &fakeBases{seal: BaseImageSeal{Count: 6, Fingerprint: testBaseSeal}}).Run(context.Background())
		if !errors.Is(err, ErrIncomplete) || report.Failures[0].Code != "RECOVERY_TIMEOUT" {
			t.Fatalf("report=%+v err=%v", report, err)
		}
	})
}

func TestRecoveryRejectsUnsafeInventoryWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Candidate)
	}{
		{name: "session", mutate: func(c *Candidate) { c.SessionID = "../../host" }},
		{name: "kind", mutate: func(c *Candidate) { c.Kind = "base_image" }},
		{name: "origin", mutate: func(c *Candidate) { c.Origin = "user_input" }},
		{name: "locator", mutate: func(c *Candidate) { c.Locator = "unsafe\nlocator" }},
		{name: "owner", mutate: func(c *Candidate) { c.Identity.OwnerUID = 1000 }},
		{name: "fingerprint", mutate: func(c *Candidate) { c.Identity.Fingerprint = "filename-only" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := artifact(testSessionA, KindCiphertext, "/scratch/owned.luks")
			test.mutate(&candidate)
			backend := newFakeBackend([]Candidate{candidate})
			report, err := newTestReconciler(t, backend, newFakeRegistry(), fakeKeys{states: map[string]KeyState{testSessionA: KeyUnavailable}}, &fakeBases{seal: BaseImageSeal{Count: 6, Fingerprint: testBaseSeal}}).Run(context.Background())
			if !errors.Is(err, ErrIncomplete) || len(backend.operations) != 0 {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			if report.Failures[0].Code != "RECOVERY_IDENTITY_REJECTED" {
				t.Fatalf("report=%+v", report)
			}
		})
	}
}

func TestRecoveryHandlesSessionsIndependently(t *testing.T) {
	first := artifact(testSessionA, KindQEMUProcess, "qemu-a")
	second := artifact(testSessionB, KindQEMUProcess, "qemu-b")
	backend := newFakeBackend([]Candidate{second, first})
	backend.failCleanup[candidateKey(first)] = 1
	report, err := newTestReconciler(t, backend, newFakeRegistry(), fakeKeys{states: map[string]KeyState{}}, &fakeBases{seal: BaseImageSeal{Count: 6, Fingerprint: testBaseSeal}}).Run(context.Background())
	if !errors.Is(err, ErrIncomplete) || report.SessionsRecovered != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if !backend.removed[candidateKey(second)] {
		t.Fatal("independent second session did not converge")
	}
}

func TestRecoveryConstructorBounds(t *testing.T) {
	backend := newFakeBackend(nil)
	registry := newFakeRegistry()
	keys := fakeKeys{states: map[string]KeyState{}}
	bases := &fakeBases{seal: BaseImageSeal{Count: 6, Fingerprint: testBaseSeal}}
	bad := []Config{
		{},
		{InventoryTimeout: time.Second, StepTimeout: time.Second, SessionTimeout: time.Millisecond},
		{InventoryTimeout: 31 * time.Second, StepTimeout: time.Second, SessionTimeout: time.Second},
		{InventoryTimeout: time.Second, StepTimeout: time.Second, SessionTimeout: time.Second, MaxCandidates: defaultMaxCandidates + 1},
	}
	for _, config := range bad {
		if _, err := New(backend, registry, keys, bases, config); err == nil {
			t.Fatalf("accepted config=%+v", config)
		}
	}
}
