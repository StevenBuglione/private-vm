package cli

import (
	"context"
	"errors"
	"io"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"github.com/StevenBuglione/private-vm/internal/torrent"
	"google.golang.org/grpc"
)

// TorrentSubmitter is the synchronous host-orchestrator handoff. The caller
// owns reader lifetime; implementations must consume it before returning and
// may not retain it. The production orchestrator supplies the authenticated
// daemon/guest stream rather than exposing VSOCK to the CLI.
type TorrentSubmitter interface {
	Submit(context.Context, torrent.InputKind, io.Reader) (Result, error)
}

func (invoker *ProductionInvoker) submitTorrent(ctx context.Context, request TorrentInputIntent) (Result, error) {
	if invoker == nil {
		return Result{}, invalidTorrentIntent()
	}
	submitter := invoker.torrents
	if submitter == nil {
		submitter = daemonTorrentSubmitter{invoker: invoker}
	}
	readInput := invoker.readInput
	if readInput == nil {
		readInput = SensitiveInput
	}
	readStream := invoker.readStream
	if readStream == nil {
		readStream = SensitiveStream
	}
	switch {
	case request.MagnetTTY || request.MagnetStdin:
		source := InputSourceTerminal
		if request.MagnetStdin {
			source = InputSourceStdin
		}
		if request.MagnetTTY {
			if _, err := io.WriteString(invoker.prompt, "Magnet URI: "); err != nil {
				return Result{}, torrentInputError(ErrInputUnavailable)
			}
		}
		value, err := readInput(ctx, ValueRequest{Source: source, Stdin: invoker.stdin, MaxBytes: torrent.MaximumMagnetBytes})
		if err != nil {
			return Result{}, torrentInputError(err)
		}
		defer value.Destroy()
		var result Result
		err = value.WithReader(func(reader io.Reader) error {
			raw, readErr := io.ReadAll(io.LimitReader(reader, torrent.MaximumMagnetBytes+1))
			defer clear(raw)
			if readErr != nil {
				return readErr
			}
			input, parseErr := torrent.NewInput(torrent.InputMagnet, raw)
			if parseErr != nil {
				return parseErr
			}
			defer input.Destroy()
			return input.WithReader(ctx, func(_ context.Context, protected io.Reader) error {
				result, parseErr = submitter.Submit(ctx, torrent.InputMagnet, protected)
				return parseErr
			})
		})
		if err != nil {
			return Result{}, torrentInputError(err)
		}
		return result, nil
	case request.TorrentFile != "":
		stream, err := readStream(ctx, StreamRequest{Source: InputSourceFile, Path: request.TorrentFile, MaxBytes: torrent.MaximumMetainfoBytes})
		if err != nil {
			return Result{}, torrentInputError(err)
		}
		result, submitErr := submitter.Submit(ctx, torrent.InputMetainfo, stream)
		closeErr := stream.Close()
		if submitErr != nil {
			return Result{}, torrentInputError(submitErr)
		}
		if closeErr != nil {
			return Result{}, torrentInputError(closeErr)
		}
		return result, nil
	default:
		return Result{}, invalidTorrentIntent()
	}
}

func torrentInputError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return contextError(err)
	case errors.Is(err, torrent.ErrInputTooLarge), errors.Is(err, ErrInputTooLarge):
		return apperror.New("TORRENT_INPUT_TOO_LARGE", exitcode.Torrent, "The torrent input exceeds its fixed size limit.", "Use a magnet no larger than 8 KiB or a .torrent file no larger than 16 MiB.")
	case errors.Is(err, torrent.ErrInvalidInput), errors.Is(err, ErrInputEmpty):
		return apperror.New("TORRENT_INPUT_INVALID", exitcode.Torrent, "The bounded torrent input is malformed.", "Supply one valid magnet through hidden terminal input or stdin, or one regular .torrent file.")
	case errors.Is(err, ErrUnsafeInputFile):
		return apperror.New("TORRENT_SOURCE_UNSAFE", exitcode.Torrent, "The .torrent source file is unsafe.", "Use a regular local file without symlinks or remote-filesystem indirection.")
	default:
		var application *apperror.Error
		if errors.As(err, &application) {
			return application
		}
		return apperror.New("TORRENT_INPUT_READ_FAILED", exitcode.Torrent, "The torrent input could not be read or transferred safely.", "Retry with bounded hidden terminal input, standard input, or one readable regular .torrent file.")
	}
}

func invalidTorrentIntent() error {
	return apperror.New("TORRENT_REQUEST_INVALID", exitcode.Torrent, "The torrent input request contract is invalid.", "Use exactly one documented secure torrent input source.")
}

type daemonTorrentSubmitter struct{ invoker *ProductionInvoker }

func (submitter daemonTorrentSubmitter) Submit(ctx context.Context, kind torrent.InputKind, reader io.Reader) (Result, error) {
	if submitter.invoker == nil || reader == nil {
		return Result{}, invalidTorrentIntent()
	}
	connection, client, requestID, current, err := submitter.invoker.downloaderClient(ctx)
	if err != nil {
		return Result{}, err
	}
	defer connection.Close()
	stream, err := client.AddTorrent(ctx,
		grpc.MaxCallSendMsgSize(torrent.MaximumMetainfoBytes+64<<10),
		grpc.MaxCallRecvMsgSize(4<<20),
	)
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	protoKind := privatevmv1.TorrentInputKind_TORRENT_INPUT_KIND_UNSPECIFIED
	switch kind {
	case torrent.InputMagnet:
		protoKind = privatevmv1.TorrentInputKind_TORRENT_INPUT_KIND_MAGNET
	case torrent.InputMetainfo:
		protoKind = privatevmv1.TorrentInputKind_TORRENT_INPUT_KIND_METAINFO
	default:
		return Result{}, invalidTorrentIntent()
	}
	if err := stream.Send(&privatevmv1.HostTorrentInputFrame{Frame: &privatevmv1.HostTorrentInputFrame_Begin{Begin: &privatevmv1.HostTorrentInputBegin{
		Context: sessionRequestContext(requestID, current.GetId()), Kind: protoKind,
	}}}); err != nil {
		return Result{}, daemonRPCError(err)
	}
	buffer := make([]byte, maximumHostTorrentInputChunkBytes)
	defer clear(buffer)
	for {
		n, readErr := reader.Read(buffer)
		if n > 0 {
			chunk := append([]byte(nil), buffer[:n]...)
			sendErr := stream.Send(&privatevmv1.HostTorrentInputFrame{Frame: &privatevmv1.HostTorrentInputFrame_Chunk{Chunk: &privatevmv1.HostTorrentChunk{Data: chunk}}})
			clear(chunk)
			clear(buffer[:n])
			if sendErr != nil {
				return Result{}, daemonRPCError(sendErr)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil || n == 0 {
			return Result{}, torrentInputError(readErr)
		}
	}
	metadata, err := stream.CloseAndRecv()
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	return torrentMetadataResult(metadata)
}

const maximumHostTorrentInputChunkBytes = 16 << 10

func (invoker *ProductionInvoker) invokeTorrent(ctx context.Context, id CommandID, intent Intent) (Result, error) {
	switch id {
	case CommandTorrentRun, CommandTorrentStart:
		request, ok := intent.(TorrentIntent)
		if !ok {
			return Result{}, invalidTorrentIntent()
		}
		return invoker.startDownloader(ctx, request)
	}

	connection, client, requestID, current, err := invoker.downloaderClient(ctx)
	if err != nil {
		return Result{}, err
	}
	defer connection.Close()
	request := &privatevmv1.TorrentControlRequest{Context: sessionRequestContext(requestID, current.GetId())}
	switch id {
	case CommandTorrentMetadata, CommandTorrentPlan:
		metadata, err := client.GetTorrentMetadata(ctx, request)
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		return torrentMetadataResult(metadata)
	case CommandTorrentSelect:
		selection, ok := intent.(TorrentSelectionIntent)
		if !ok || len(selection.Files) == 0 {
			return Result{}, invalidTorrentIntent()
		}
		metadata, err := client.SelectTorrentFiles(ctx, &privatevmv1.HostSelectTorrentFilesRequest{
			Context: request.Context, Indexes: append([]uint32(nil), selection.Files...),
		})
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		return torrentMetadataResult(metadata)
	case CommandTorrentDownload, CommandTorrentResume:
		stream, err := client.StartTorrentDownload(ctx, request)
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		for {
			event, recvErr := stream.Recv()
			if errors.Is(recvErr, io.EOF) {
				break
			}
			if recvErr != nil {
				return Result{}, daemonRPCError(recvErr)
			}
			if event == nil || event.GetProgress() == nil || event.GetProgress().GetCompleted() > event.GetProgress().GetTotal() {
				return Result{}, internalTorrentError()
			}
		}
		status, err := client.GetTorrentStatus(ctx, request)
		return torrentStatusResult(status, err)
	case CommandTorrentPause:
		status, err := client.PauseTorrentDownload(ctx, request)
		return torrentStatusResult(status, err)
	case CommandTorrentStatus:
		status, err := client.GetTorrentStatus(ctx, request)
		return torrentStatusResult(status, err)
	case CommandTorrentComplete:
		status, err := client.SealTorrentQuarantine(ctx, request)
		return torrentStatusResult(status, err)
	default:
		return Result{}, invalidTorrentIntent()
	}
}

func (invoker *ProductionInvoker) startDownloader(ctx context.Context, intent TorrentIntent) (Result, error) {
	if intent.Policy != "safe" && intent.Policy != "quarantine" {
		return Result{}, invalidTorrentIntent()
	}
	connection, client, err := invoker.client()
	if err != nil {
		return Result{}, err
	}
	defer connection.Close()
	requestID, err := invoker.nextRequestID()
	if err != nil {
		return Result{}, internalTorrentError()
	}
	resources := &privatevmv1.ResourceRequest{Vcpus: 4, MemoryBytes: 4 << 30, RootBytes: 32 << 30}
	plan, err := client.PlanSession(ctx, &privatevmv1.PlanSessionRequest{
		Context: sessionRequestContext(requestID, ""), Role: privatevmv1.GuestRole_GUEST_ROLE_DOWNLOADER,
		PolicyName: intent.Policy, Resources: resources,
	})
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	if !plan.GetRunnable() {
		return Result{}, apperror.New("HOST_PREFLIGHT_FAILED", exitcode.Preflight, "The host did not pass the strict downloader preflight.", "Run private-vm doctor --strict --json, correct every blocking diagnostic, and retry.")
	}
	created, err := client.CreateSession(ctx, &privatevmv1.CreateSessionRequest{
		Context: sessionRequestContext(requestID, ""), Role: privatevmv1.GuestRole_GUEST_ROLE_DOWNLOADER,
		PolicyName: intent.Policy, Resources: resources,
	})
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	started, err := client.StartRole(ctx, &privatevmv1.StartRoleRequest{Context: sessionRequestContext(requestID, created.GetId())})
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = client.AbortSession(cleanupCtx, &privatevmv1.AbortSessionRequest{Context: sessionRequestContext(requestID, created.GetId()), ReasonCode: "CLIENT_START_FAILED"})
		cancel()
		return Result{}, daemonRPCError(err)
	}
	return sessionResult(started, nil)
}

func (invoker *ProductionInvoker) downloaderClient(ctx context.Context) (*grpc.ClientConn, privatevmv1.PrivateVMDaemonServiceClient, string, *privatevmv1.Session, error) {
	connection, client, err := invoker.client()
	if err != nil {
		return nil, nil, "", nil, err
	}
	requestID, err := invoker.nextRequestID()
	if err != nil {
		connection.Close()
		return nil, nil, "", nil, internalTorrentError()
	}
	response, err := client.ListSessions(ctx, &privatevmv1.ListSessionsRequest{Context: sessionRequestContext(requestID, "")})
	if err != nil {
		connection.Close()
		return nil, nil, "", nil, daemonRPCError(err)
	}
	var selected *privatevmv1.Session
	for _, current := range response.GetSessions() {
		if current.GetRole() != privatevmv1.GuestRole_GUEST_ROLE_DOWNLOADER || current.GetPhase() != privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE {
			continue
		}
		if selected != nil {
			connection.Close()
			return nil, nil, "", nil, apperror.New("SESSION_SELECTION_REQUIRED", exitcode.Torrent, "More than one downloader session is active.", "Stop the extra downloader and retry with exactly one active workflow.")
		}
		selected = current
	}
	if selected == nil {
		connection.Close()
		return nil, nil, "", nil, apperror.New("SESSION_NOT_FOUND", exitcode.Torrent, "No active downloader session exists.", "Start a torrent workflow and verify its VPN before continuing.")
	}
	return connection, client, requestID, selected, nil
}

func torrentMetadataResult(metadata *privatevmv1.TorrentMetadata) (Result, error) {
	if metadata == nil || len(metadata.GetFiles()) == 0 || !metadata.GetPayloadPaused() {
		return Result{}, internalTorrentError()
	}
	var selected uint32
	var total uint64
	for _, file := range metadata.GetFiles() {
		if file == nil || file.GetSizeBytes() == 0 || total > ^uint64(0)-file.GetSizeBytes() {
			return Result{}, internalTorrentError()
		}
		total += file.GetSizeBytes()
		if file.GetSelected() {
			selected++
		}
	}
	state := "FILE_SELECTION_REQUIRED"
	code := "TORRENT_SELECTION_REQUIRED"
	remediation := "Review the exact file list in the isolated downloader and select only approved indexes."
	if metadata.GetSelectedSizeBytes() > 0 {
		state = "CAPACITY_VERIFIED"
		code = "TORRENT_CAPACITY_VERIFIED"
		remediation = "Start payload transfer only while the VPN remains verified."
	}
	payload := TorrentStatusPayload{
		SchemaVersion: 1, State: state, TotalBytes: total, FileCount: uint32(len(metadata.GetFiles())),
		SelectedCount: selected, PayloadPaused: true, Code: code, Remediation: remediation,
	}
	return Result{Code: CodeTorrentStatus, Data: payload}, nil
}

func torrentStatusResult(status *privatevmv1.TorrentStatus, err error) (Result, error) {
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	if status == nil || status.GetProgress() == nil || status.GetProgress().GetCompleted() > status.GetProgress().GetTotal() {
		return Result{}, internalTorrentError()
	}
	code, remediation := "TORRENT_STATE_INVALID", "Abort and clean the session."
	if diagnostics := status.GetDiagnostics(); len(diagnostics) == 1 && diagnostics[0] != nil {
		code, remediation = diagnostics[0].GetCode(), diagnostics[0].GetRemediation()
	}
	payload := TorrentStatusPayload{
		SchemaVersion: 1, State: status.GetState(), CompletedBytes: status.GetProgress().GetCompleted(),
		TotalBytes: status.GetProgress().GetTotal(), PayloadPaused: status.GetState() != "DOWNLOADING",
		Code: code, Remediation: remediation,
	}
	return Result{Code: CodeTorrentStatus, Data: payload}, nil
}

func internalTorrentError() error {
	return apperror.New("INTERNAL_ERROR", exitcode.Internal, "The torrent response could not be represented safely.", "Inspect volatile session status and retry only if its documented state permits it.")
}
