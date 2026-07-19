package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/daemon"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/vpn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type cliVPNLookupFunc func(context.Context, string, string) ([]netip.Addr, error)

func (fn cliVPNLookupFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return fn(ctx, network, host)
}

func TestProductionVPNInvokerPreservesStableLocalFailureContracts(t *testing.T) {
	tests := []struct {
		name        string
		inputError  error
		code        string
		exit        int
		remediation string
	}{
		{"unsafe file", ErrUnsafeInputFile, "VPN_PROFILE_SOURCE_UNSAFE", exitcode.Network, "Use a regular caller-owned file with mode 0600 and no symlinks, then retry."},
		{"oversize", ErrInputTooLarge, "VPN_PROFILE_TOO_LARGE", exitcode.Network, "Generate a standard bounded Proton WireGuard profile and retry."},
		{"canceled", context.Canceled, "OPERATION_CANCELLED", exitcode.Cancelled, "Retry the command when ready."},
		{"timeout", context.DeadlineExceeded, "OPERATION_TIMEOUT", exitcode.Runtime, "Increase --timeout within the documented limit or resolve the stalled dependency."},
		{"read failure", errors.New("raw private read failure"), "VPN_PROFILE_READ_FAILED", exitcode.Network, "Select a readable owner-only file or bounded standard input and retry."},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invoker := &ProductionInvoker{
				socketPath: filepath.Join(t.TempDir(), "control.sock"),
				readInput: func(context.Context, ValueRequest) (*secret.Bytes, error) {
					return nil, test.inputError
				},
			}
			_, err := invoker.Invoke(t.Context(), CommandVPNImport, VPNImportIntent{ProfileName: "proton-p2p", Stdin: true})
			application := apperror.From(err)
			if application.Code != test.code || application.ExitCode != test.exit || application.Remediation != test.remediation {
				t.Fatalf("application error = %+v", application)
			}
			if strings.Contains(application.Error(), "raw private") {
				t.Fatal("local error exposed raw input failure")
			}
		})
	}
}

func TestProductionVPNInvokerRNGAndRawGRPCErrorsAreRedacted(t *testing.T) {
	socket, stop := startVPNInvokerDaemon(t)
	fixture := []byte(cliVPNFixture())
	source, err := secret.New(fixture)
	if err != nil {
		t.Fatal(err)
	}
	invoker := &ProductionInvoker{
		socketPath: socket,
		readInput: func(context.Context, ValueRequest) (*secret.Bytes, error) {
			return source, nil
		},
		requestID: func() (string, error) { return "", errors.New("raw private entropy failure") },
	}
	_, err = invoker.Invoke(t.Context(), CommandVPNImport, VPNImportIntent{ProfileName: "proton-p2p", Stdin: true})
	application := apperror.From(err)
	if application.Code != "INTERNAL_ERROR" || application.ExitCode != exitcode.Internal || strings.Contains(application.Error(), "raw private") {
		t.Fatalf("RNG error = %+v", application)
	}
	if _, err := source.Equal(fixture); !errors.Is(err, secret.ErrDestroyed) {
		t.Fatalf("RNG failure did not destroy input: %v", err)
	}
	clear(fixture)
	stop()

	rawSocket, rawStop := startRawVPNInvokerDaemon(t)
	defer rawStop()
	rawInvoker := &ProductionInvoker{socketPath: rawSocket, requestID: newRequestID}
	_, err = rawInvoker.Invoke(t.Context(), CommandVPNInspect, VPNProfileIntent{ProfileName: "proton-p2p"})
	application = apperror.From(err)
	if application.Code != "DAEMON_UNAVAILABLE" || application.ExitCode != exitcode.Network || strings.Contains(application.Error(), "raw private") {
		t.Fatalf("raw gRPC error = %+v", application)
	}
}

func TestVPNDaemonDetailExitClassesAndLocalSecretFailure(t *testing.T) {
	for _, test := range []struct {
		code string
		exit int
	}{
		{"AUTHORIZATION_DENIED", exitcode.Authorization},
		{"PROTOCOL_VERSION_MISMATCH", exitcode.Runtime},
		{"INTERNAL_ERROR", exitcode.Internal},
		{"VPN_PROFILE_INVALID", exitcode.Network},
	} {
		base := status.New(codes.FailedPrecondition, "safe status")
		withDetail, err := base.WithDetails(&privatevmv1.ErrorDetail{
			Code: test.code, SafeMessage: "A safe message.", Remediation: "A safe remediation.",
		})
		if err != nil {
			t.Fatal(err)
		}
		application := apperror.From(daemonRPCError(withDetail.Err()))
		if application.Code != test.code || application.ExitCode != test.exit {
			t.Fatalf("%s mapping = %+v", test.code, application)
		}
	}
	application := apperror.From(daemonRPCError(secret.ErrDestroyed))
	if application.Code != "INTERNAL_ERROR" || application.ExitCode != exitcode.Internal {
		t.Fatalf("secret failure mapping = %+v", application)
	}
}

func TestProductionVPNInvokerUsesSemanticUnixRPCAndDestroysInput(t *testing.T) {
	socket, stop := startVPNInvokerDaemon(t)
	defer stop()
	fixture := []byte(cliVPNFixture())
	source, err := secret.New(fixture)
	if err != nil {
		t.Fatal(err)
	}
	invoker := &ProductionInvoker{
		socketPath: socket,
		stdin:      bytes.NewReader(nil),
		readInput: func(context.Context, ValueRequest) (*secret.Bytes, error) {
			return source, nil
		},
	}
	result, err := invoker.Invoke(t.Context(), CommandVPNImport, VPNImportIntent{ProfileName: "proton-p2p", Stdin: true})
	if err != nil {
		t.Fatal(err)
	}
	status, ok := result.Data.(VPNStatusPayload)
	if result.Code != CodeVPNProfile || !ok || !status.Present || status.Generation == 0 || status.Rotation != "resolution_required" {
		t.Fatalf("import result = %+v", result)
	}
	if _, err := source.Equal(fixture); !errors.Is(err, secret.ErrDestroyed) {
		t.Fatalf("successful import source was not destroyed: %v", err)
	}
	clear(fixture)

	for _, operation := range []struct {
		id       CommandID
		rotation string
		present  bool
	}{
		{CommandVPNInspect, "resolution_required", true},
		{CommandVPNTest, "current", true},
		{CommandVPNRemove, "not_imported", false},
	} {
		result, err = invoker.Invoke(t.Context(), operation.id, VPNProfileIntent{ProfileName: "proton-p2p"})
		if err != nil {
			t.Fatalf("%s: %v", operation.id, err)
		}
		status = result.Data.(VPNStatusPayload)
		if status.Rotation != operation.rotation || status.Present != operation.present {
			t.Fatalf("%s status = %+v", operation.id, status)
		}
	}
}

func TestProductionVPNInvokerSelectsSecureInputAndDestroysOnRPCFailure(t *testing.T) {
	for _, test := range []struct {
		name       string
		intent     VPNImportIntent
		wantSource InputSource
		ownerOnly  bool
		prompted   bool
	}{
		{"owner-only file", VPNImportIntent{ProfileName: "proton-p2p", FromFile: "/private/profile.conf"}, InputSourceFile, true, false},
		{"explicit stdin", VPNImportIntent{ProfileName: "proton-p2p", Stdin: true}, InputSourceStdin, false, false},
		{"interactive path prompt", VPNImportIntent{ProfileName: "proton-p2p"}, InputSourceFile, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := []byte(cliVPNFixture())
			source, err := secret.New(fixture)
			if err != nil {
				t.Fatal(err)
			}
			var pathSource *secret.Bytes
			if test.prompted {
				pathSource, err = secret.New([]byte("/prompted/profile.conf"))
				if err != nil {
					t.Fatal(err)
				}
			}
			var captured ValueRequest
			var prompt bytes.Buffer
			invoker := &ProductionInvoker{
				socketPath: filepath.Join(t.TempDir(), "control.sock"),
				stdin:      bytes.NewReader(nil),
				prompt:     &prompt,
				readInput: func(_ context.Context, request ValueRequest) (*secret.Bytes, error) {
					captured = request
					if request.Source == InputSourceTerminal {
						return pathSource, nil
					}
					return source, nil
				},
			}
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			if _, err := invoker.Invoke(ctx, CommandVPNImport, test.intent); err == nil {
				t.Fatal("missing daemon unexpectedly accepted VPN import")
			}
			if captured.Source != test.wantSource || captured.RequireOwnerOnly != test.ownerOnly || captured.MaxBytes != vpn.MaximumProfileBytes {
				t.Fatalf("sensitive input request = %+v", captured)
			}
			if test.prompted {
				if prompt.String() != "Proton WireGuard profile file path: " {
					t.Fatalf("interactive prompt = %q", prompt.String())
				}
				if _, err := pathSource.Equal([]byte("/prompted/profile.conf")); !errors.Is(err, secret.ErrDestroyed) {
					t.Fatalf("prompted path source was not destroyed: %v", err)
				}
			}
			if _, err := source.Equal(fixture); !errors.Is(err, secret.ErrDestroyed) {
				t.Fatalf("failed RPC source was not destroyed: %v", err)
			}
			clear(fixture)
		})
	}
}

func startVPNInvokerDaemon(t *testing.T) (string, func()) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := daemon.Authorizer{AllowedGroup: uint32(os.Getegid())}
	server := grpc.NewServer(
		grpc.Creds(daemon.NewUnixPeerCredentials()),
		grpc.ChainUnaryInterceptor(authorizer.UnaryInterceptor),
		grpc.StreamInterceptor(authorizer.StreamInterceptor),
	)
	store := vpn.NewMemoryStore()
	service := &daemon.Service{
		Profiles: store,
		VPNResolver: vpn.NewEndpointResolverWithLookup(cliVPNLookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		})),
	}
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
		store.Close()
	}
}

type rawVPNService struct {
	privatevmv1.UnimplementedPrivateVMDaemonServiceServer
}

func (rawVPNService) InspectVPNProfile(context.Context, *privatevmv1.VPNProfileRequest) (*privatevmv1.VPNProfileStatus, error) {
	return nil, status.Error(codes.Internal, "raw private daemon failure")
}

func startRawVPNInvokerDaemon(t *testing.T) (string, func()) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(daemon.NewUnixPeerCredentials()))
	privatevmv1.RegisterPrivateVMDaemonServiceServer(server, rawVPNService{})
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

func cliVPNFixture() string {
	return "[Interface]\nPrivateKey = " + cliVPNKey(0x11) +
		"\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\nPublicKey = " + cliVPNKey(0x22) +
		"\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.proton.test:51820\n"
}

func cliVPNKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}
