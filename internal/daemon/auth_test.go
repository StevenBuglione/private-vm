package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case "pkcheck-success", "pkcheck-deny", "pkcheck-timeout":
		os.Exit(runPKCheckFixture())
	default:
		os.Exit(m.Run())
	}
}

func runPKCheckFixture() int {
	if len(os.Environ()) != 0 || len(os.Args) != 6 ||
		os.Args[1] != "--action-id" || os.Args[2] != "org.private-vm.usb.prepare" ||
		os.Args[3] != "--process" || os.Args[5] != "--allow-user-interaction" {
		return 91
	}
	parts := strings.Split(os.Args[4], ",")
	if len(parts) != 3 || parts[0] != strconv.Itoa(os.Getppid()) || parts[2] != strconv.Itoa(os.Geteuid()) {
		return 92
	}
	start, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || start == 0 {
		return 93
	}
	_, _ = fmt.Fprintln(os.Stdout, "PRIVATE_FIXTURE_OUTPUT_MUST_BE_DISCARDED")
	_, _ = fmt.Fprintln(os.Stderr, "PRIVATE_FIXTURE_ERROR_MUST_BE_DISCARDED")
	switch filepath.Base(os.Args[0]) {
	case "pkcheck-deny":
		return 42
	case "pkcheck-timeout":
		time.Sleep(5 * time.Second)
	}
	return 0
}

func TestAuthorizerReturnsTypedRedactedDenial(t *testing.T) {
	identity := currentProcessIdentity(t)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: PeerAuthInfo{PeerIdentity: identity}})
	authorizer := Authorizer{
		AllowedGroup: identity.GID + 1,
		Groups:       func(PeerIdentity) ([]uint32, error) { return []uint32{identity.GID}, nil },
	}
	called := false
	_, err := authorizer.UnaryInterceptor(ctx, &privatevmv1.Empty{}, &grpc.UnaryServerInfo{}, func(context.Context, any) (any, error) {
		called = true
		return &privatevmv1.Empty{}, nil
	})
	if called {
		t.Fatal("unauthorized request reached the handler")
	}
	assertRPCError(t, err, codes.PermissionDenied, "AUTHORIZATION_DENIED")
	if strings.Contains(err.Error(), strconv.FormatUint(uint64(identity.UID), 10)) {
		t.Fatal("authorization error exposed peer identity")
	}
}

func TestAuthorizerAttachesVerifiedIdentity(t *testing.T) {
	identity := currentProcessIdentity(t)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: PeerAuthInfo{PeerIdentity: identity}})
	authorizer := Authorizer{AllowedGroup: identity.GID}
	_, err := authorizer.UnaryInterceptor(ctx, &privatevmv1.Empty{}, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ any) (any, error) {
		got, identityErr := identityFromContext(ctx)
		if identityErr != nil {
			t.Fatal(identityErr)
		}
		if got != identity {
			t.Fatalf("handler identity = %+v, want %+v", got, identity)
		}
		return &privatevmv1.Empty{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPKCheckUsesExactBoundedRedactedInvocation(t *testing.T) {
	identity := currentProcessIdentity(t)
	for _, name := range []string{"pkcheck-success", "pkcheck-deny"} {
		t.Run(name, func(t *testing.T) {
			binary := pkcheckFixture(t, name)
			err := (PKCheck{Binary: binary}).Authorize(t.Context(), identity, "org.private-vm.usb.prepare")
			if name == "pkcheck-success" && err != nil {
				t.Fatal(err)
			}
			if name == "pkcheck-deny" {
				if err == nil || err.Error() != "Polkit authorization was denied" {
					t.Fatalf("denial = %v", err)
				}
				if strings.Contains(err.Error(), "FIXTURE") {
					t.Fatal("Polkit output escaped redaction")
				}
			}
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := (PKCheck{Binary: pkcheckFixture(t, "pkcheck-timeout")}).Authorize(ctx, identity, "org.private-vm.usb.prepare")
	if err != context.DeadlineExceeded {
		t.Fatalf("timeout = %v, want context deadline", err)
	}
	if err := (PKCheck{Binary: pkcheckFixture(t, "pkcheck-success")}).Authorize(t.Context(), identity, "org.private-vm.session.manage"); err == nil {
		t.Fatal("unknown Polkit action was accepted")
	}
	if err := (PKCheck{Binary: "pkcheck"}).Authorize(t.Context(), identity, "org.private-vm.usb.prepare"); err == nil {
		t.Fatal("relative pkcheck path was accepted")
	}
}

func TestPolkitSubjectRejectsChangedIdentity(t *testing.T) {
	identity := currentProcessIdentity(t)
	identity.StartTimeTicks++
	if _, err := polkitProcessSubject(identity); err == nil {
		t.Fatal("changed process identity was accepted as a Polkit subject")
	}
}

func pkcheckFixture(t *testing.T, name string) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.Symlink(executable, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertRPCError(t *testing.T, err error, grpcCode codes.Code, stableCode string) {
	t.Helper()
	value, ok := status.FromError(err)
	if !ok || value.Code() != grpcCode {
		t.Fatalf("RPC error = %v, want %s", err, grpcCode)
	}
	for _, raw := range value.Details() {
		if detail, ok := raw.(*privatevmv1.ErrorDetail); ok {
			if detail.GetCode() != stableCode || detail.GetSafeMessage() == "" || detail.GetRemediation() == "" {
				t.Fatalf("error detail = %+v", detail)
			}
			return
		}
	}
	t.Fatalf("RPC error has no typed detail: %v", err)
}
