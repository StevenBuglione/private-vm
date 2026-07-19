package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/recovery"
)

func TestStartupFailureMessageIsStableAndRedacted(t *testing.T) {
	if !strings.Contains(daemonStartupFailureMessage, "DAEMON_START_FAILED") || !strings.Contains(daemonStartupFailureMessage, "verify the installed configuration") {
		t.Fatalf("startup failure message lacks stable code or remediation: %q", daemonStartupFailureMessage)
	}
	for _, forbidden := range []string{"%v", "%w", "PrivateKey", "magnet:", "/home/"} {
		if strings.Contains(daemonStartupFailureMessage, forbidden) {
			t.Fatalf("startup failure message contains unsafe fragment %q", forbidden)
		}
	}
}

func TestStartupRecoveryGatesAdmissionAndAlwaysPublishesReport(t *testing.T) {
	complete := recovery.Report{SchemaVersion: 1, Code: "RECOVERY_COMPLETED", Status: recovery.StatusComplete, BaseImagesVerified: true, Failures: []recovery.Failure{}}
	writes := 0
	if err := runStartupRecovery(t.Context(), func(context.Context) (recovery.Report, error) {
		return complete, nil
	}, func(got recovery.Report) error {
		writes++
		if got.Status != recovery.StatusComplete {
			t.Fatalf("published wrong report: %+v", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("complete recovery blocked startup: %v", err)
	}
	if writes != 1 {
		t.Fatalf("report writes = %d, want 1", writes)
	}

	incomplete := complete
	incomplete.Code = "ORPHAN_CLEANUP_FAILED"
	incomplete.Status = recovery.StatusIncomplete
	incomplete.BaseImagesVerified = false
	backendFailure := errors.New("sensitive injected backend detail")
	writes = 0
	err := runStartupRecovery(t.Context(), func(context.Context) (recovery.Report, error) {
		return incomplete, backendFailure
	}, func(got recovery.Report) error {
		writes++
		if got.Status != recovery.StatusIncomplete {
			t.Fatalf("published wrong failure report: %+v", got)
		}
		return nil
	})
	if err == nil || writes != 1 || !errors.Is(err, backendFailure) {
		t.Fatalf("incomplete recovery was admitted or not reported: writes=%d err=%v", writes, err)
	}
}

func TestStartupRecoveryRefusesCancellationTimeoutAndReportFailure(t *testing.T) {
	incomplete := recovery.Report{SchemaVersion: 1, Code: "ORPHAN_CLEANUP_FAILED", Status: recovery.StatusIncomplete, Failures: []recovery.Failure{}}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		cause := cause
		t.Run(cause.Error(), func(t *testing.T) {
			err := runStartupRecovery(t.Context(), func(context.Context) (recovery.Report, error) {
				return incomplete, cause
			}, func(recovery.Report) error { return nil })
			if !errors.Is(err, cause) || !errors.Is(err, recovery.ErrIncomplete) {
				t.Fatalf("startup recovery error = %v", err)
			}
		})
	}
	reportFailure := errors.New("injected report write failure")
	err := runStartupRecovery(t.Context(), func(context.Context) (recovery.Report, error) {
		return recovery.Report{SchemaVersion: 1, Code: "RECOVERY_COMPLETED", Status: recovery.StatusComplete, BaseImagesVerified: true, Failures: []recovery.Failure{}}, nil
	}, func(recovery.Report) error { return reportFailure })
	if !errors.Is(err, reportFailure) {
		t.Fatalf("report publication failure did not block startup: %v", err)
	}
}

func TestShutdownServicesUsesFreshBudgetsAndNeverSkipsCleanup(t *testing.T) {
	serverFailure := errors.New("injected server shutdown failure")
	serveFailure := errors.New("injected serve failure")
	managerFailure := errors.New("injected manager cleanup failure")
	serverDone := make(chan error, 1)
	serverDone <- serveFailure
	var serverContext context.Context
	managerCalled := false

	err := shutdownServices(
		time.Second,
		func(ctx context.Context) error {
			serverContext = ctx
			return serverFailure
		},
		serverDone,
		func(ctx context.Context) error {
			managerCalled = true
			if ctx == serverContext {
				t.Fatal("server and manager reused one shutdown context")
			}
			if err := ctx.Err(); err != nil {
				t.Fatalf("manager received an expired cleanup context: %v", err)
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("manager cleanup context is not bounded")
			}
			return managerFailure
		},
	)
	if !managerCalled {
		t.Fatal("server failure skipped session cleanup")
	}
	for _, want := range []error{serverFailure, serveFailure, managerFailure} {
		if !errors.Is(err, want) {
			t.Fatalf("combined shutdown error does not contain %v: %v", want, err)
		}
	}
}

func TestShutdownServicesGivesManagerFullBudgetAfterServerTimeout(t *testing.T) {
	const timeout = 20 * time.Millisecond
	serverDone := make(chan error, 1)
	serverDone <- nil
	managerCalled := false
	err := shutdownServices(
		timeout,
		func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		serverDone,
		func(ctx context.Context) error {
			managerCalled = true
			remaining := time.Until(mustDeadline(t, ctx))
			if remaining < timeout/2 {
				t.Fatalf("manager did not receive a fresh cleanup budget: %s", remaining)
			}
			return nil
		},
	)
	if !managerCalled {
		t.Fatal("server timeout skipped session cleanup")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("server timeout was not preserved: %v", err)
	}
}

func mustDeadline(t *testing.T, ctx context.Context) time.Time {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("context has no deadline")
	}
	return deadline
}
