package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
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
