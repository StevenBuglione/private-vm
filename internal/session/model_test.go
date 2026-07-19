package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestManager(t *testing.T, quota int) (*Manager, *Store) {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(store, quota)
	if err != nil {
		t.Fatal(err)
	}
	manager.cleanupWait = 2 * time.Second
	return manager, store
}

func TestLifecycleTransitionMatrixIsExhaustive(t *testing.T) {
	phases := []Phase{
		PhaseCreated, PhasePreflighted, PhaseImagesVerified, PhaseStorageReady,
		PhaseActive, PhaseStopping, PhaseAborting, PhaseDestroying, PhaseDestroyed,
	}
	for _, from := range phases {
		for _, to := range phases {
			session, err := newOwned("pvm-00000000000000000000000000000001", 1000, RoleWorkstation, time.Unix(1, 0))
			if err != nil {
				t.Fatal(err)
			}
			session.phase = from
			_, err = session.transitionLifecycle(to, true, time.Unix(2, 0))
			want := lifecycleTransitions[from][to]
			if want && err != nil {
				t.Errorf("expected %s -> %s to succeed: %v", from, to, err)
			}
			if !want && !errors.Is(err, ErrInvalidTransition) {
				t.Errorf("expected %s -> %s to fail closed, got %v", from, to, err)
			}
		}
	}
}

func TestExternalTransitionCannotBypassCleanupOwner(t *testing.T) {
	manager, _ := newTestManager(t, DefaultMaxSessionsPerOwner)
	snapshot, err := manager.Create(1000, RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []Phase{PhasePreflighted, PhaseImagesVerified, PhaseStorageReady, PhaseActive, PhaseStopping} {
		if _, err := manager.Transition(t.Context(), snapshot.ID, 1000, phase); err != nil {
			t.Fatalf("transition to %s: %v", phase, err)
		}
	}
	if _, err := manager.Transition(t.Context(), snapshot.ID, 1000, PhaseDestroying); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("external transition entered cleanup-owned phase: %v", err)
	}
	final, err := manager.Cleanup(t.Context(), snapshot.ID, 1000)
	if err != nil || final.Phase != PhaseDestroyed {
		t.Fatalf("cleanup did not own terminal transition: snapshot=%+v err=%v", final, err)
	}
}

func TestRoleWorkflowTablesRejectSkippedAndCrossRoleStates(t *testing.T) {
	tests := []struct {
		role   Role
		states []string
	}{
		{RoleWorkstation, []string{"PLANNED", "IMAGE_READY", "STORAGE_READY", "NETWORK_READY", "VM_BOOTING", "GUEST_AUTHENTICATED", "VPN_CONFIGURED", "VPN_VERIFIED", "DISPLAY_READY", "WORKING", "CLEAN", "STOP_REQUESTED", "OUTPUT_VERIFIED", "VM_STOPPED", "SESSION_DESTROYED"}},
		{RoleDownloader, []string{"PLANNED", "SCANNER_UPDATE_PREPARED", "DOWNLOADER_BOOTING", "GUEST_AUTHENTICATED", "VPN_CONFIGURED", "VPN_VERIFIED", "METADATA_FETCHING", "METADATA_READY", "FILE_SELECTION_REQUIRED", "CAPACITY_VERIFIED", "DOWNLOADING", "DOWNLOAD_PAUSED", "DOWNLOADING", "DOWNLOAD_COMPLETE", "DOWNLOADER_STOPPED", "QUARANTINE_SEALED"}},
		{RoleScanner, []string{"UPDATE_VM_BOOTING", "DEFINITIONS_UPDATING", "DEFINITIONS_VERIFIED", "UPDATE_VM_STOPPED", "SCAN_VM_BOOTING_OFFLINE", "OFFLINE_VERIFIED", "QUARANTINE_ATTACHED_READ_ONLY", "INVENTORY_COMPLETE", "MALWARE_SCAN_COMPLETE", "RECONSTRUCTION_COMPLETE", "REPORT_COMPLETE", "POLICY_REJECTED", "SCAN_VM_STOPPED"}},
		{RoleExporter, []string{"PLANNED", "USB_IDENTIFIED", "USB_CLAIMED", "EXPORTER_BOOTING", "GUEST_AUTHENTICATED", "NO_NETWORK_VERIFIED", "USB_ATTACHED", "DESTINATION_PREPARED", "STREAMING", "STREAM_COMPLETE", "FLUSHED", "POST_WRITE_VERIFIED", "USB_UNMOUNTED", "USB_DETACHED", "EXPORTER_STOPPED"}},
	}
	for index, test := range tests {
		session, err := newOwned("pvm-0000000000000000000000000000000"+string(rune('1'+index)), 1000, test.role, time.Unix(1, 0))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.transitionWorkflow("POST_WRITE_VERIFIED", time.Unix(2, 0)); !errors.Is(err, ErrInvalidWorkflow) && test.role != RoleExporter {
			t.Fatalf("%s accepted a cross-role state", test.role)
		}
		for step, state := range test.states {
			if _, err := session.transitionWorkflow(state, time.Unix(int64(step+2), 0)); err != nil {
				t.Fatalf("%s transition to %s: %v", test.role, state, err)
			}
		}
		if _, err := session.transitionWorkflow(test.states[0], time.Unix(100, 0)); !errors.Is(err, ErrInvalidWorkflow) {
			t.Fatalf("%s accepted a workflow restart", test.role)
		}
	}
}

func TestManagerOwnershipConcurrentQuotaAndRelease(t *testing.T) {
	manager, _ := newTestManager(t, DefaultMaxSessionsPerOwner)
	const contenders = 32
	var successes atomic.Int32
	var mu sync.Mutex
	var created []Snapshot
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			snapshot, err := manager.Create(1000, RoleWorkstation)
			if err == nil {
				successes.Add(1)
				mu.Lock()
				created = append(created, snapshot)
				mu.Unlock()
				return
			}
			if !errors.Is(err, ErrQuotaExceeded) {
				t.Errorf("unexpected create error: %v", err)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != DefaultMaxSessionsPerOwner {
		t.Fatalf("quota admitted %d sessions", successes.Load())
	}
	if _, err := manager.Get(created[0].ID, 1001); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected owner rejection, got %v", err)
	}
	if _, err := manager.Cleanup(t.Context(), created[0].ID, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(1000, RoleDownloader); err != nil {
		t.Fatalf("cleanup did not release quota: %v", err)
	}
}

func TestAcquireResourceIsAtomicOnCancellation(t *testing.T) {
	manager, _ := newTestManager(t, DefaultMaxSessionsPerOwner)
	snapshot, err := manager.Create(1000, RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	operation, cancel := context.WithCancel(context.Background())
	var cleaned, audited atomic.Int32
	cleanupDone := make(chan struct{}, 1)
	auditDone := make(chan struct{}, 1)
	err = manager.AcquireResource(operation, snapshot.ID, 1000, "overlay", func(context.Context) (CleanupFunc, AuditFunc, error) {
		cancel()
		return func(context.Context) error {
				cleaned.Add(1)
				cleanupDone <- struct{}{}
				return nil
			}, func(context.Context) error {
				audited.Add(1)
				auditDone <- struct{}{}
				return nil
			}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled allocation, got %v", err)
	}
	for name, done := range map[string]<-chan struct{}{
		"cleanup": cleanupDone,
		"audit":   auditDone,
	} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("canceled allocation did not complete %s", name)
		}
	}
	if cleaned.Load() != 1 || audited.Load() != 1 {
		t.Fatalf("canceled allocation was orphaned: cleanup=%d audit=%d", cleaned.Load(), audited.Load())
	}
}

func TestPartialAllocationIsOwnedForRetryableCleanup(t *testing.T) {
	manager, _ := newTestManager(t, 4)
	snapshot, err := manager.Create(1000, RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	var cleanupCalls int
	allocated := true
	err = manager.AcquireResource(t.Context(), snapshot.ID, 1000, "partial-loop", func(context.Context) (CleanupFunc, AuditFunc, error) {
		return func(context.Context) error {
				cleanupCalls++
				allocated = false
				return nil
			}, func(context.Context) error {
				if allocated {
					return errors.New("partial resource remains")
				}
				return nil
			}, errors.New("allocation failed after ownership")
	})
	if !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("partial allocation did not return cleanup ownership error: %v", err)
	}
	if _, err := manager.Cleanup(t.Context(), snapshot.ID, 1000); err != nil {
		t.Fatal(err)
	}
	if cleanupCalls != 1 || allocated {
		t.Fatalf("partial resource cleanup calls=%d allocated=%t", cleanupCalls, allocated)
	}
}

func TestCleanupStopsAtFailureThenRetriesInReverseOrder(t *testing.T) {
	manager, _ := newTestManager(t, DefaultMaxSessionsPerOwner)
	snapshot, err := manager.Create(1000, RoleScanner)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var order []string
	register := func(name string, failFirst bool) {
		var calls atomic.Int32
		err := manager.AcquireResource(t.Context(), snapshot.ID, 1000, name, func(context.Context) (CleanupFunc, AuditFunc, error) {
			return func(context.Context) error {
				mu.Lock()
				order = append(order, name)
				mu.Unlock()
				if failFirst && calls.Add(1) == 1 {
					return errors.New("sensitive injected cause")
				}
				return nil
			}, func(context.Context) error { return nil }, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	register("parent", false)
	register("child", true)
	if _, err := manager.Cleanup(t.Context(), snapshot.ID, 1000); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("expected typed cleanup failure, got %v", err)
	}
	mu.Lock()
	first := append([]string(nil), order...)
	mu.Unlock()
	if len(first) != 1 || first[0] != "child" {
		t.Fatalf("cleanup continued after dependent failure: %v", first)
	}
	final, err := manager.Cleanup(t.Context(), snapshot.ID, 1000)
	if err != nil || final.Phase != PhaseDestroyed {
		t.Fatalf("retry failed: snapshot=%+v err=%v", final, err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"child", "child", "parent"}
	if len(order) != len(want) {
		t.Fatalf("unexpected cleanup order: %v", order)
	}
	for index := range want {
		if order[index] != want[index] {
			t.Fatalf("cleanup order=%v want=%v", order, want)
		}
	}
}

func TestCleanupAuditFailureLeavesStepRetryable(t *testing.T) {
	manager, _ := newTestManager(t, DefaultMaxSessionsPerOwner)
	snapshot, err := manager.Create(1000, RoleScanner)
	if err != nil {
		t.Fatal(err)
	}
	var cleanupCalls, auditCalls atomic.Int32
	if err := manager.AcquireResource(t.Context(), snapshot.ID, 1000, "quarantine", func(context.Context) (CleanupFunc, AuditFunc, error) {
		return func(context.Context) error {
				cleanupCalls.Add(1)
				return nil
			}, func(context.Context) error {
				if auditCalls.Add(1) == 1 {
					return errors.New("injected absence audit failure")
				}
				return nil
			}, nil
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Cleanup(t.Context(), snapshot.ID, 1000); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("expected typed audit failure, got %v", err)
	}
	final, err := manager.Cleanup(t.Context(), snapshot.ID, 1000)
	if err != nil || final.Phase != PhaseDestroyed {
		t.Fatalf("cleanup did not converge after audit retry: snapshot=%+v err=%v", final, err)
	}
	if cleanupCalls.Load() != 2 || auditCalls.Load() != 2 {
		t.Fatalf("audit failure made cleanup non-retryable: cleanup=%d audit=%d", cleanupCalls.Load(), auditCalls.Load())
	}
}

func TestConcurrentCleanupCoalescesAndExecutesOnce(t *testing.T) {
	manager, store := newTestManager(t, DefaultMaxSessionsPerOwner)
	snapshot, err := manager.Create(1000, RoleExporter)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var cleanupCalls, auditCalls atomic.Int32
	if err := manager.AcquireResource(t.Context(), snapshot.ID, 1000, "usb-claim", func(context.Context) (CleanupFunc, AuditFunc, error) {
		return func(context.Context) error {
			if cleanupCalls.Add(1) == 1 {
				close(started)
			}
			<-release
			return nil
		}, func(context.Context) error { auditCalls.Add(1); return nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	const callers = 32
	results := make(chan error, callers)
	for range callers {
		go func() {
			result, err := manager.Cleanup(context.Background(), snapshot.ID, 1000)
			if err == nil && result.Phase != PhaseDestroyed {
				err = errors.New("cleanup did not return terminal snapshot")
			}
			results <- err
		}()
	}
	<-started
	close(release)
	for range callers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if cleanupCalls.Load() != 1 || auditCalls.Load() != 1 {
		t.Fatalf("duplicate cleanup execution: cleanup=%d audit=%d", cleanupCalls.Load(), auditCalls.Load())
	}
	if _, err := os.Stat(filepath.Join(store.Root(), snapshot.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("volatile record remains: %v", err)
	}
}

func TestAcceptedCleanupSurvivesCallerCancellation(t *testing.T) {
	manager, _ := newTestManager(t, DefaultMaxSessionsPerOwner)
	snapshot, err := manager.Create(1000, RoleDownloader)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	if err := manager.AcquireResource(t.Context(), snapshot.ID, 1000, "tap", func(context.Context) (CleanupFunc, AuditFunc, error) {
		return func(context.Context) error { close(started); <-release; return nil }, func(context.Context) error { return nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := manager.Cleanup(ctx, snapshot.ID, 1000); result <- err }()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller did not observe cancellation: %v", err)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		final, err := manager.Get(snapshot.ID, 1000)
		if err == nil && final.Phase == PhaseDestroyed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon-owned cleanup did not finish: snapshot=%+v err=%v", final, err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCleanupIsAdmittedWhenCallerIsAlreadyCanceled(t *testing.T) {
	manager, _ := newTestManager(t, DefaultMaxSessionsPerOwner)
	snapshot, err := manager.Create(1000, RoleDownloader)
	if err != nil {
		t.Fatal(err)
	}
	cleaned := make(chan struct{})
	if err := manager.AcquireResource(t.Context(), snapshot.ID, 1000, "tap", func(context.Context) (CleanupFunc, AuditFunc, error) {
		return func(context.Context) error { close(cleaned); return nil }, func(context.Context) error { return nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.Cleanup(ctx, snapshot.ID, 1000); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller did not receive cancellation: %v", err)
	}
	select {
	case <-cleaned:
	case <-time.After(time.Second):
		t.Fatal("caller cancellation revoked daemon-owned cleanup admission")
	}
	deadline := time.Now().Add(time.Second)
	for {
		final, err := manager.Get(snapshot.ID, 1000)
		if err == nil && final.Phase == PhaseDestroyed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background cleanup did not finish: snapshot=%+v err=%v", final, err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestShutdownAdmitsEverySessionBeforeWaiting(t *testing.T) {
	manager, _ := newTestManager(t, DefaultMaxSessionsPerOwner)
	ids := []string{
		"pvm-00000000000000000000000000000001",
		"pvm-00000000000000000000000000000002",
	}
	var nextID atomic.Int32
	manager.newID = func() (string, error) {
		return ids[int(nextID.Add(1))-1], nil
	}
	first, err := manager.Create(1000, RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Create(1001, RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{})
	if err := manager.AcquireResource(t.Context(), first.ID, 1000, "first", func(context.Context) (CleanupFunc, AuditFunc, error) {
		return func(context.Context) error {
			close(firstStarted)
			<-releaseFirst
			return nil
		}, func(context.Context) error { return nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.AcquireResource(t.Context(), second.ID, 1001, "second", func(context.Context) (CleanupFunc, AuditFunc, error) {
		return func(context.Context) error { close(secondStarted); return nil }, func(context.Context) error { return nil }, nil
	}); err != nil {
		t.Fatal(err)
	}

	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- manager.Shutdown(context.Background()) }()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first cleanup did not start")
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for one session before admitting the next")
	}
	close(releaseFirst)
	if err := <-shutdownResult; err != nil {
		t.Fatalf("shutdown failed after all cleanups completed: %v", err)
	}
	if _, err := manager.Create(1002, RoleWorkstation); !errors.Is(err, ErrManagerShuttingDown) {
		t.Fatalf("shutdown manager admitted a new session: %v", err)
	}
}

func TestValidateSnapshotRequiresExactEventChain(t *testing.T) {
	owned, err := newOwned("pvm-00000000000000000000000000000001", 1000, RoleWorkstation, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owned.transitionLifecycle(PhasePreflighted, false, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := owned.transitionWorkflow("PLANNED", time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := owned.transitionWorkflow("IMAGE_READY", time.Unix(4, 0)); err != nil {
		t.Fatal(err)
	}
	valid := owned.Snapshot()
	if err := validateSnapshot(valid); err != nil {
		t.Fatalf("valid event chain was rejected: %v", err)
	}

	clone := func() Snapshot {
		result := valid
		result.Events = append([]Event(nil), valid.Events...)
		return result
	}
	tests := map[string]func(*Snapshot){
		"creation event": func(snapshot *Snapshot) {
			snapshot.Events[0].Time = snapshot.Events[0].Time.Add(time.Second)
		},
		"lifecycle phase skip": func(snapshot *Snapshot) {
			snapshot.Events[1].Phase = PhaseStorageReady
			snapshot.Events[1].Code = "SESSION_STORAGE_READY"
			snapshot.Events[1].Message = "Session storage is ready."
		},
		"lifecycle code mismatch": func(snapshot *Snapshot) {
			snapshot.Events[1].Code = "SESSION_ACTIVE"
			snapshot.Events[1].Message = "The session is active."
		},
		"workflow state skip": func(snapshot *Snapshot) {
			snapshot.Events[2].WorkflowState = "STORAGE_READY"
		},
		"workflow phase mismatch": func(snapshot *Snapshot) {
			snapshot.Events[2].Phase = PhaseImagesVerified
		},
		"updated time mismatch": func(snapshot *Snapshot) {
			snapshot.UpdatedAt = snapshot.UpdatedAt.Add(time.Second)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			snapshot := clone()
			mutate(&snapshot)
			if err := validateSnapshot(snapshot); err == nil {
				t.Fatal("malformed event chain was accepted")
			}
		})
	}
}

func TestEventSubscriptionReplaysFollowsAndRejectsGaps(t *testing.T) {
	manager, _ := newTestManager(t, DefaultMaxSessionsPerOwner)
	snapshot, err := manager.Create(1000, RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	subscription, err := manager.Subscribe(t.Context(), snapshot.ID, 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	replay := subscription.Replay()
	if len(replay) != 1 || replay[0].Sequence != 1 || replay[0].Code != "SESSION_CREATED" {
		t.Fatalf("unexpected replay: %+v", replay)
	}
	if _, err := manager.Transition(t.Context(), snapshot.ID, 1000, PhasePreflighted); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-subscription.Events():
		if event.Sequence != 2 || event.Code != "SESSION_PREFLIGHTED" {
			t.Fatalf("unexpected live event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("live event was not delivered")
	}
	if _, err := manager.Subscribe(t.Context(), snapshot.ID, 1000, 99); !errors.Is(err, ErrEventCursor) {
		t.Fatalf("invalid cursor did not fail closed: %v", err)
	}
}

func TestSlowSubscriberIsDisconnectedWithoutDroppingForOthers(t *testing.T) {
	manager, _ := newTestManager(t, DefaultMaxSessionsPerOwner)
	snapshot, err := manager.Create(1000, RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	subscription, err := manager.Subscribe(t.Context(), snapshot.ID, 1000, snapshot.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	item, err := manager.authorizedEntry(snapshot.ID, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(2); sequence <= maxSubscriberQueue+2; sequence++ {
		item.publish(Event{Sequence: sequence, Code: "WORKFLOW_STATE_CHANGED", Phase: PhaseCreated, Message: "Role workflow advanced.", Time: time.Now()})
	}
	select {
	case <-subscription.Done():
		if !errors.Is(subscription.Err(), ErrSubscriberSlow) {
			t.Fatalf("unexpected subscriber error: %v", subscription.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("slow subscriber remained attached")
	}
}

func TestDuplicateAndLateResourceRegistrationFailClosed(t *testing.T) {
	manager, _ := newTestManager(t, DefaultMaxSessionsPerOwner)
	snapshot, err := manager.Create(1000, RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	allocate := func(context.Context) (CleanupFunc, AuditFunc, error) {
		return func(context.Context) error { return nil }, func(context.Context) error { return nil }, nil
	}
	if err := manager.AcquireResource(t.Context(), snapshot.ID, 1000, "overlay", allocate); err != nil {
		t.Fatal(err)
	}
	if err := manager.AcquireResource(t.Context(), snapshot.ID, 1000, "overlay", allocate); !errors.Is(err, ErrDuplicateResource) {
		t.Fatalf("duplicate resource accepted: %v", err)
	}
	for _, phase := range []Phase{PhasePreflighted, PhaseImagesVerified, PhaseStorageReady, PhaseActive, PhaseStopping} {
		if _, err := manager.Transition(t.Context(), snapshot.ID, 1000, phase); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.AcquireResource(t.Context(), snapshot.ID, 1000, "late", allocate); !errors.Is(err, ErrResourceRegistrationEnd) {
		t.Fatalf("late resource accepted: %v", err)
	}
}
