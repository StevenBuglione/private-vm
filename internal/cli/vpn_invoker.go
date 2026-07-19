package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"

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

const maximumVPNImportChunkBytes = 16 << 10

// ProductionInvoker connects semantic commands to the root daemon over its
// Unix socket. Commands not yet backed by a completed orchestration path remain
// fail closed.
type ProductionInvoker struct {
	socketPath string
	stdin      io.Reader
	prompt     io.Writer
	readInput  func(context.Context, ValueRequest) (*secret.Bytes, error)
	readStream func(context.Context, StreamRequest) (io.ReadCloser, error)
	torrents   TorrentSubmitter
	requestID  func() (string, error)
}

func NewProductionInvoker(socketPath string, stdin io.Reader, prompt io.Writer) Invoker {
	return NewProductionInvokerWithTorrent(socketPath, stdin, prompt, nil)
}

// NewProductionInvokerWithTorrent installs the authenticated torrent
// orchestrator handoff without changing the CLI's Unix-daemon VPN transport.
func NewProductionInvokerWithTorrent(socketPath string, stdin io.Reader, prompt io.Writer, torrents TorrentSubmitter) Invoker {
	if stdin == nil {
		stdin = os.Stdin
	}
	if prompt == nil {
		prompt = io.Discard
	}
	return &ProductionInvoker{socketPath: socketPath, stdin: stdin, prompt: prompt, readInput: SensitiveInput, readStream: SensitiveStream, torrents: torrents, requestID: newRequestID}
}

func (invoker *ProductionInvoker) Invoke(ctx context.Context, id CommandID, intent Intent) (Result, error) {
	switch id {
	case CommandWorkstationStart, "desktop.status", "desktop.stop", "session.list", "session.status", "session.stop", "session.abort", "session.cleanup":
		return invoker.invokeSession(ctx, id, intent)
	case CommandTorrentAdd:
		request, ok := intent.(TorrentInputIntent)
		if !ok {
			return Result{}, invalidTorrentIntent()
		}
		return invoker.submitTorrent(ctx, request)
	case CommandVPNImport, CommandVPNRotate:
		request, ok := intent.(VPNImportIntent)
		if !ok {
			return Result{}, invalidVPNIntent()
		}
		response, err := invoker.importProfile(ctx, request)
		return vpnResult(response, err)
	case CommandVPNInspect, CommandVPNTest, CommandVPNRemove:
		request, ok := intent.(VPNProfileIntent)
		if !ok {
			return Result{}, invalidVPNIntent()
		}
		response, err := invoker.profileOperation(ctx, id, request.ProfileName)
		return vpnResult(response, err)
	default:
		return failClosedInvoker{}.Invoke(ctx, id, intent)
	}
}

func (invoker *ProductionInvoker) importProfile(ctx context.Context, request VPNImportIntent) (*privatevmv1.VPNProfileStatus, error) {
	readInput := invoker.readInput
	if readInput == nil {
		readInput = SensitiveInput
	}
	sourceKind := InputSourceFile
	profilePath := request.FromFile
	if request.FromFile != "" {
		sourceKind = InputSourceFile
	} else if request.Stdin {
		sourceKind = InputSourceStdin
	} else {
		var pathErr error
		profilePath, pathErr = invoker.promptProfilePath(ctx, readInput)
		if pathErr != nil {
			return nil, pathErr
		}
	}
	source, err := readInput(ctx, ValueRequest{
		Source:           sourceKind,
		Stdin:            invoker.stdin,
		Path:             profilePath,
		MaxBytes:         vpn.MaximumProfileBytes,
		RequireOwnerOnly: sourceKind == InputSourceFile,
	})
	if err != nil {
		return nil, vpnInputError(err)
	}
	defer source.Destroy()

	connection, client, err := invoker.client()
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	stream, err := client.ImportVPNProfile(ctx, grpc.MaxCallSendMsgSize(vpn.MaximumProfileBytes+1024), grpc.MaxCallRecvMsgSize(64<<10))
	if err != nil {
		return nil, daemonRPCError(err)
	}
	requestID, err := invoker.nextRequestID()
	if err != nil {
		return nil, internalVPNError()
	}
	if err := stream.Send(&privatevmv1.VPNProfileImportFrame{Frame: &privatevmv1.VPNProfileImportFrame_Begin{Begin: &privatevmv1.VPNProfileImportBegin{
		Context: vpnRequestContext(requestID), ProfileName: request.ProfileName,
	}}}); err != nil {
		return nil, daemonRPCError(err)
	}
	if err := source.WithReader(func(reader io.Reader) error {
		buffer := make([]byte, maximumVPNImportChunkBytes)
		defer clear(buffer)
		for {
			n, readErr := reader.Read(buffer)
			if n > 0 {
				chunk := append([]byte(nil), buffer[:n]...)
				sendErr := stream.Send(&privatevmv1.VPNProfileImportFrame{Frame: &privatevmv1.VPNProfileImportFrame_Chunk{Chunk: &privatevmv1.VPNProfileChunk{Data: chunk}}})
				clear(chunk)
				clear(buffer[:n])
				if sendErr != nil {
					return sendErr
				}
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if readErr != nil {
				return readErr
			}
		}
	}); err != nil {
		return nil, daemonRPCError(err)
	}
	response, err := stream.CloseAndRecv()
	if err != nil {
		return nil, daemonRPCError(err)
	}
	return response, nil
}

func (invoker *ProductionInvoker) promptProfilePath(ctx context.Context, readInput func(context.Context, ValueRequest) (*secret.Bytes, error)) (string, error) {
	if readInput == nil {
		readInput = SensitiveInput
	}
	prompt := invoker.prompt
	if prompt == nil {
		prompt = io.Discard
	}
	if _, err := io.WriteString(prompt, "Proton WireGuard profile file path: "); err != nil {
		return "", vpnInputError(ErrInputUnavailable)
	}
	value, err := readInput(ctx, ValueRequest{Source: InputSourceTerminal, MaxBytes: 4096})
	if err != nil {
		return "", vpnInputError(err)
	}
	defer value.Destroy()
	var path string
	err = value.WithReader(func(reader io.Reader) error {
		raw, readErr := io.ReadAll(reader)
		defer clear(raw)
		if readErr != nil {
			return readErr
		}
		path = string(raw)
		return nil
	})
	if err != nil || validatePath(path) != nil {
		return "", vpnInputError(ErrInputUnavailable)
	}
	return path, nil
}

func (invoker *ProductionInvoker) profileOperation(ctx context.Context, id CommandID, profileName string) (*privatevmv1.VPNProfileStatus, error) {
	connection, client, err := invoker.client()
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	requestID, err := invoker.nextRequestID()
	if err != nil {
		return nil, internalVPNError()
	}
	request := &privatevmv1.VPNProfileRequest{Context: vpnRequestContext(requestID), ProfileName: profileName}
	switch id {
	case CommandVPNInspect:
		return client.InspectVPNProfile(ctx, request)
	case CommandVPNTest:
		return client.TestVPNProfile(ctx, request)
	case CommandVPNRemove:
		return client.RemoveVPNProfile(ctx, request)
	default:
		return nil, invalidVPNIntent()
	}
}

func (invoker *ProductionInvoker) client() (*grpc.ClientConn, privatevmv1.PrivateVMDaemonServiceClient, error) {
	if invoker == nil || !filepath.IsAbs(invoker.socketPath) || filepath.Clean(invoker.socketPath) != invoker.socketPath || filepath.Base(invoker.socketPath) != "control.sock" {
		return nil, nil, invalidVPNIntent()
	}
	connection, err := grpc.NewClient(
		"passthrough:///private-vmd",
		grpc.WithTransportCredentials(daemon.NewUnixPeerCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", invoker.socketPath)
		}),
	)
	if err != nil {
		return nil, nil, daemonRPCError(err)
	}
	return connection, privatevmv1.NewPrivateVMDaemonServiceClient(connection), nil
}

func newRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func vpnRequestContext(requestID string) *privatevmv1.RequestContext {
	return &privatevmv1.RequestContext{
		ApiVersion: &privatevmv1.ApiVersion{Major: 1, Minor: 0},
		RequestId:  requestID,
	}
}

func (invoker *ProductionInvoker) nextRequestID() (string, error) {
	if invoker != nil && invoker.requestID != nil {
		return invoker.requestID()
	}
	return newRequestID()
}

func vpnResult(response *privatevmv1.VPNProfileStatus, err error) (Result, error) {
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	if response == nil {
		return Result{}, internalVPNError()
	}
	payload := VPNStatusPayload{
		SchemaVersion: response.GetSchemaVersion(), Present: response.GetPresent(), Generation: response.GetGeneration(),
		Rotation: response.GetRotation(), Code: response.GetCode(), Remediation: response.GetRemediation(),
	}
	if response.GetPresent() {
		payload.Profile = &VPNInspectionPayload{
			SchemaVersion: 1, IPv4Enabled: response.GetIpv4Enabled(), IPv6Enabled: response.GetIpv6Enabled(),
			InterfaceAddressCount: response.GetInterfaceAddressCount(), DNSServerCount: response.GetDnsServerCount(),
		}
	}
	return Result{Code: CodeVPNProfile, Data: payload}, nil
}

func daemonRPCError(err error) error {
	if err == nil {
		return nil
	}
	var application *apperror.Error
	if errors.As(err, &application) {
		return application
	}
	if errors.Is(err, secret.ErrUnavailable) || errors.Is(err, secret.ErrDestroyed) || errors.Is(err, secret.ErrCallback) {
		return internalVPNError()
	}
	if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
		return contextError(context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded {
		return contextError(context.DeadlineExceeded)
	}
	value, ok := status.FromError(err)
	if ok {
		for _, detail := range value.Details() {
			if safe, matched := detail.(*privatevmv1.ErrorDetail); matched &&
				validCode(Code(safe.GetCode())) && validRequiredString(safe.GetSafeMessage(), 512) && validRequiredString(safe.GetRemediation(), 1024) {
				return apperror.New(safe.GetCode(), daemonDetailExitCode(safe.GetCode()), safe.GetSafeMessage(), safe.GetRemediation())
			}
		}
	}
	return apperror.New("DAEMON_UNAVAILABLE", exitcode.Network, "The private-vm daemon could not complete the request.", "Verify private-vmd is running and the Unix control socket is accessible, then retry.")
}

func daemonDetailExitCode(code string) int {
	switch code {
	case "AUTHORIZATION_DENIED", "SESSION_OWNER_MISMATCH":
		return exitcode.Authorization
	case "WORKSPACE_DIRTY", "WORKSPACE_UNREACHABLE":
		return exitcode.DirtyWorkspace
	case "CLEANUP_INCOMPLETE":
		return exitcode.Cleanup
	case "ROLE_START_FAILED", "SESSION_TRANSITION_INVALID", "SESSION_NOT_FOUND", "SESSION_SELECTION_REQUIRED":
		return exitcode.Runtime
	case "INTERNAL_ERROR", "RPC_CONTEXT_CONTRACT_INVALID":
		return exitcode.Internal
	case "PROTOCOL_VERSION_MISMATCH":
		return exitcode.Runtime
	default:
		return exitcode.Network
	}
}

func vpnInputError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return contextError(err)
	case errors.Is(err, ErrInputTooLarge):
		return apperror.New("VPN_PROFILE_TOO_LARGE", exitcode.Network, "The VPN profile exceeds its 64 KiB limit.", "Generate a standard bounded Proton WireGuard profile and retry.")
	case errors.Is(err, ErrUnsafeInputFile):
		return apperror.New("VPN_PROFILE_SOURCE_UNSAFE", exitcode.Network, "The VPN profile source file is unsafe.", "Use a regular caller-owned file with mode 0600 and no symlinks, then retry.")
	default:
		return apperror.New("VPN_PROFILE_READ_FAILED", exitcode.Network, "The VPN profile could not be read securely.", "Select a readable owner-only file or bounded standard input and retry.")
	}
}

func invalidVPNIntent() error {
	return apperror.New("VPN_REQUEST_INVALID", exitcode.Network, "The VPN request contract is invalid.", "Use the documented VPN command syntax with a valid configured profile name.")
}

func internalVPNError() error {
	return apperror.New("INTERNAL_ERROR", exitcode.Internal, "The VPN request could not be prepared safely.", "Retry once; if the error persists, export a redacted diagnostic bundle.")
}

var _ Invoker = (*ProductionInvoker)(nil)
