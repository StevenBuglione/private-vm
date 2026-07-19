package daemon

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/torrent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maximumHostTorrentChunkBytes = 16 << 10
	maximumHostTorrentFrames     = 1024
)

// TorrentOrchestrator is the daemon's narrow downloader boundary. It exposes
// no qBittorrent URL, save path, guest CID, token, command, QEMU argument or
// device selector. Implementations synchronously relay through the already
// authenticated downloader guest belonging to the supplied session.
type TorrentOrchestrator interface {
	Add(context.Context, session.Snapshot, torrent.InputKind, io.Reader) (*privatevmv1.TorrentMetadata, error)
	Metadata(context.Context, session.Snapshot) (*privatevmv1.TorrentMetadata, error)
	Select(context.Context, session.Snapshot, []uint32) (*privatevmv1.TorrentMetadata, error)
	Start(context.Context, session.Snapshot, func(*privatevmv1.TorrentEvent) error) error
	Pause(context.Context, session.Snapshot) (*privatevmv1.TorrentStatus, error)
	Status(context.Context, session.Snapshot) (*privatevmv1.TorrentStatus, error)
	SealAndDestroy(context.Context, session.Snapshot) (*privatevmv1.TorrentStatus, error)
}

func (s *Service) AddTorrent(stream privatevmv1.PrivateVMDaemonService_AddTorrentServer) error {
	first, err := stream.Recv()
	if err != nil {
		return torrentServiceError(err)
	}
	begin := first.GetBegin()
	if begin == nil {
		clearHostTorrentFrame(first)
		return torrentStreamError()
	}
	ctx, err := requestContextWithMetadata(stream.Context(), begin.GetContext(), true)
	if err != nil {
		return err
	}
	kind, maximum, err := hostTorrentInputKind(begin.GetKind())
	if err != nil {
		return err
	}
	identity, snapshot, err := s.downloaderSession(ctx, begin.GetContext().GetSessionId())
	if err != nil {
		return err
	}
	if s.Torrents == nil {
		return unimplemented("Authenticated torrent relay")
	}

	lock := s.roleOperation(snapshot.ID)
	lock.Lock()
	defer lock.Unlock()
	if snapshot.WorkflowState != "VPN_VERIFIED" {
		return torrentStateError("VPN_VERIFIED")
	}
	snapshot, err = s.Sessions.TransitionWorkflow(ctx, snapshot.ID, identity.UID, "METADATA_FETCHING")
	if err != nil {
		return sessionError(err)
	}
	reader := &hostTorrentReader{stream: stream, maximum: maximum}
	metadata, operationErr := s.Torrents.Add(ctx, snapshot, kind, reader)
	if operationErr == nil && (!reader.complete || reader.total == 0) {
		operationErr = torrent.ErrInvalidInput
	}
	if operationErr != nil {
		return s.failedTorrentOperation(snapshot.ID, identity.UID, operationErr)
	}
	if metadata == nil || !metadata.GetPayloadPaused() || len(metadata.GetFiles()) == 0 {
		return s.failedTorrentOperation(snapshot.ID, identity.UID, torrent.ErrUnsafeMetadata)
	}
	if snapshot, err = s.Sessions.TransitionWorkflow(ctx, snapshot.ID, identity.UID, "METADATA_READY"); err != nil {
		return s.failedTorrentOperation(snapshot.ID, identity.UID, err)
	}
	if _, err = s.Sessions.TransitionWorkflow(ctx, snapshot.ID, identity.UID, "FILE_SELECTION_REQUIRED"); err != nil {
		return s.failedTorrentOperation(snapshot.ID, identity.UID, err)
	}
	return stream.SendAndClose(metadata)
}

func (s *Service) GetTorrentMetadata(ctx context.Context, request *privatevmv1.TorrentControlRequest) (*privatevmv1.TorrentMetadata, error) {
	identity, snapshot, err := s.validTorrentRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	lock := s.roleOperation(snapshot.ID)
	lock.Lock()
	defer lock.Unlock()
	if snapshot.WorkflowState != "FILE_SELECTION_REQUIRED" && snapshot.WorkflowState != "CAPACITY_VERIFIED" {
		return nil, torrentStateError("FILE_SELECTION_REQUIRED or CAPACITY_VERIFIED")
	}
	metadata, err := s.Torrents.Metadata(ctx, snapshot)
	if err != nil {
		return nil, torrentServiceError(err)
	}
	if metadata == nil || !metadata.GetPayloadPaused() {
		return nil, torrentServiceError(torrent.ErrUnsafeMetadata)
	}
	_ = identity
	return metadata, nil
}

func (s *Service) SelectTorrentFiles(ctx context.Context, request *privatevmv1.HostSelectTorrentFilesRequest) (*privatevmv1.TorrentMetadata, error) {
	if request == nil || len(request.GetIndexes()) == 0 || len(request.GetIndexes()) > torrent.MaximumFiles {
		return nil, torrentServiceError(torrent.ErrInvalidSelection)
	}
	identity, snapshot, err := s.downloaderSession(ctx, request.GetContext().GetSessionId())
	if err != nil {
		return nil, err
	}
	if s.Torrents == nil {
		return nil, unimplemented("Authenticated torrent relay")
	}
	lock := s.roleOperation(snapshot.ID)
	lock.Lock()
	defer lock.Unlock()
	if snapshot.WorkflowState != "FILE_SELECTION_REQUIRED" {
		return nil, torrentStateError("FILE_SELECTION_REQUIRED")
	}
	metadata, operationErr := s.Torrents.Select(ctx, snapshot, append([]uint32(nil), request.GetIndexes()...))
	if operationErr != nil {
		return nil, torrentServiceError(operationErr)
	}
	if metadata == nil || !metadata.GetPayloadPaused() || metadata.GetSelectedSizeBytes() == 0 {
		return nil, torrentServiceError(torrent.ErrInvalidSelection)
	}
	if _, err := s.Sessions.TransitionWorkflow(ctx, snapshot.ID, identity.UID, "CAPACITY_VERIFIED"); err != nil {
		return nil, sessionError(err)
	}
	return metadata, nil
}

func (s *Service) StartTorrentDownload(request *privatevmv1.TorrentControlRequest, stream privatevmv1.PrivateVMDaemonService_StartTorrentDownloadServer) error {
	ctx, err := requestContextWithMetadata(stream.Context(), request.GetContext(), true)
	if err != nil {
		return err
	}
	identity, snapshot, err := s.downloaderSession(ctx, request.GetContext().GetSessionId())
	if err != nil {
		return err
	}
	if s.Torrents == nil {
		return unimplemented("Authenticated torrent relay")
	}
	lock := s.roleOperation(snapshot.ID)
	lock.Lock()
	if snapshot.WorkflowState != "CAPACITY_VERIFIED" && snapshot.WorkflowState != "DOWNLOAD_PAUSED" {
		lock.Unlock()
		return torrentStateError("CAPACITY_VERIFIED or DOWNLOAD_PAUSED")
	}
	snapshot, err = s.Sessions.TransitionWorkflow(ctx, snapshot.ID, identity.UID, "DOWNLOADING")
	lock.Unlock()
	if err != nil {
		return sessionError(err)
	}

	operationErr := s.Torrents.Start(ctx, snapshot, func(event *privatevmv1.TorrentEvent) error {
		if event == nil || event.GetProgress() == nil || event.GetProgress().GetCompleted() > event.GetProgress().GetTotal() {
			return torrent.ErrDownloadFailed
		}
		return stream.Send(event)
	})
	lock.Lock()
	defer lock.Unlock()
	current, getErr := s.Sessions.Get(snapshot.ID, identity.UID)
	if getErr != nil {
		return sessionError(getErr)
	}
	if operationErr != nil {
		if current.WorkflowState == "DOWNLOADING" {
			if _, transitionErr := s.Sessions.TransitionWorkflow(context.WithoutCancel(ctx), snapshot.ID, identity.UID, "DOWNLOAD_PAUSED"); transitionErr != nil {
				return s.failedTorrentOperation(snapshot.ID, identity.UID, transitionErr)
			}
		}
		return torrentServiceError(operationErr)
	}
	if current.WorkflowState != "DOWNLOADING" {
		return torrentStateError("DOWNLOADING")
	}
	if _, err := s.Sessions.TransitionWorkflow(ctx, snapshot.ID, identity.UID, "DOWNLOAD_COMPLETE"); err != nil {
		return s.failedTorrentOperation(snapshot.ID, identity.UID, err)
	}
	return nil
}

func (s *Service) PauseTorrentDownload(ctx context.Context, request *privatevmv1.TorrentControlRequest) (*privatevmv1.TorrentStatus, error) {
	identity, snapshot, err := s.validTorrentRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	lock := s.roleOperation(snapshot.ID)
	lock.Lock()
	defer lock.Unlock()
	if snapshot.WorkflowState != "DOWNLOADING" {
		return nil, torrentStateError("DOWNLOADING")
	}
	status, operationErr := s.Torrents.Pause(ctx, snapshot)
	if operationErr != nil {
		return nil, torrentServiceError(operationErr)
	}
	if _, err := s.Sessions.TransitionWorkflow(ctx, snapshot.ID, identity.UID, "DOWNLOAD_PAUSED"); err != nil {
		return nil, sessionError(err)
	}
	return status, nil
}

func (s *Service) GetTorrentStatus(ctx context.Context, request *privatevmv1.TorrentControlRequest) (*privatevmv1.TorrentStatus, error) {
	_, snapshot, err := s.validTorrentRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	lock := s.roleOperation(snapshot.ID)
	lock.Lock()
	defer lock.Unlock()
	status, err := s.Torrents.Status(ctx, snapshot)
	if err != nil {
		return nil, torrentServiceError(err)
	}
	return status, nil
}

func (s *Service) SealTorrentQuarantine(ctx context.Context, request *privatevmv1.TorrentControlRequest) (*privatevmv1.TorrentStatus, error) {
	identity, snapshot, err := s.validTorrentRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	lock := s.roleOperation(snapshot.ID)
	lock.Lock()
	defer lock.Unlock()
	if snapshot.WorkflowState != "DOWNLOAD_COMPLETE" {
		return nil, torrentStateError("DOWNLOAD_COMPLETE")
	}
	status, operationErr := s.Torrents.SealAndDestroy(ctx, snapshot)
	if operationErr != nil {
		return nil, torrentServiceError(operationErr)
	}
	if status == nil || status.GetState() != "QUARANTINE_SEALED" {
		return nil, torrentServiceError(torrent.ErrSealFailed)
	}
	if snapshot, err = s.Sessions.TransitionWorkflow(ctx, snapshot.ID, identity.UID, "DOWNLOADER_STOPPED"); err != nil {
		return nil, sessionError(err)
	}
	if _, err = s.Sessions.TransitionWorkflow(ctx, snapshot.ID, identity.UID, "QUARANTINE_SEALED"); err != nil {
		return nil, sessionError(err)
	}
	return status, nil
}

func (s *Service) validTorrentRequest(ctx context.Context, request *privatevmv1.TorrentControlRequest) (PeerIdentity, session.Snapshot, error) {
	if request == nil {
		return PeerIdentity{}, session.Snapshot{}, torrentServiceError(torrent.ErrInvalidRequest)
	}
	identity, snapshot, err := s.downloaderSession(ctx, request.GetContext().GetSessionId())
	if err != nil {
		return PeerIdentity{}, session.Snapshot{}, err
	}
	if s.Torrents == nil {
		return PeerIdentity{}, session.Snapshot{}, unimplemented("Authenticated torrent relay")
	}
	return identity, snapshot, nil
}

func (s *Service) downloaderSession(ctx context.Context, id string) (PeerIdentity, session.Snapshot, error) {
	identity, err := identityFromContext(ctx)
	if err != nil {
		return PeerIdentity{}, session.Snapshot{}, sessionError(err)
	}
	snapshot, err := s.Sessions.Get(id, identity.UID)
	if err != nil {
		return PeerIdentity{}, session.Snapshot{}, sessionError(err)
	}
	if snapshot.Role != session.RoleDownloader || snapshot.Phase != session.PhaseActive {
		return PeerIdentity{}, session.Snapshot{}, torrentStateError("an active downloader session")
	}
	return identity, snapshot, nil
}

func (s *Service) failedTorrentOperation(id string, ownerUID uint32, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, cleanupErr := s.Sessions.Cleanup(cleanupCtx, id, ownerUID)
	cancel()
	if cleanupErr != nil {
		return sessionError(session.ErrCleanupIncomplete)
	}
	return torrentServiceError(cause)
}

func torrentServiceError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		status.Code(err) == codes.Canceled || status.Code(err) == codes.DeadlineExceeded {
		return sessionError(err)
	}
	application := apperror.From(torrent.NormalizeError(err))
	grpcCode := codes.FailedPrecondition
	switch {
	case errors.Is(err, torrent.ErrInvalidRequest), errors.Is(err, torrent.ErrInvalidInput), errors.Is(err, torrent.ErrInvalidSelection):
		grpcCode = codes.InvalidArgument
	case errors.Is(err, torrent.ErrInputTooLarge), errors.Is(err, torrent.ErrCapacity):
		grpcCode = codes.ResourceExhausted
	case errors.Is(err, torrent.ErrCleanupIncomplete):
		grpcCode = codes.Unavailable
	}
	return rpcError(grpcCode, application.Code, application.Message, application.Remediation, false)
}

func torrentStateError(expected string) error {
	return rpcError(codes.FailedPrecondition, "TORRENT_STATE_INVALID", "The downloader is not in the required workflow state.", "Inspect volatile session status and continue only from "+expected+".", false)
}

func torrentStreamError() error {
	return rpcError(codes.InvalidArgument, "TORRENT_STREAM_INVALID", "The bounded torrent stream framing is invalid.", "Send one begin frame followed only by non-empty chunks of at most 16 KiB.", false)
}

func hostTorrentInputKind(value privatevmv1.TorrentInputKind) (torrent.InputKind, int, error) {
	switch value {
	case privatevmv1.TorrentInputKind_TORRENT_INPUT_KIND_MAGNET:
		return torrent.InputMagnet, torrent.MaximumMagnetBytes, nil
	case privatevmv1.TorrentInputKind_TORRENT_INPUT_KIND_METAINFO:
		return torrent.InputMetainfo, torrent.MaximumMetainfoBytes, nil
	default:
		return "", 0, torrentStreamError()
	}
}

type hostTorrentReceiver interface {
	Recv() (*privatevmv1.HostTorrentInputFrame, error)
}

type hostTorrentReader struct {
	stream   hostTorrentReceiver
	maximum  int
	pending  []byte
	total    int
	frames   int
	complete bool
	mu       sync.Mutex
}

func (reader *hostTorrentReader) Read(destination []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if len(destination) == 0 {
		return 0, nil
	}
	for len(reader.pending) == 0 {
		if reader.complete {
			return 0, io.EOF
		}
		frame, err := reader.stream.Recv()
		if errors.Is(err, io.EOF) {
			reader.complete = true
			return 0, io.EOF
		}
		if err != nil {
			return 0, err
		}
		reader.frames++
		chunk := frame.GetChunk()
		if chunk == nil || len(chunk.GetData()) == 0 || len(chunk.GetData()) > maximumHostTorrentChunkBytes || reader.frames > maximumHostTorrentFrames || reader.total > reader.maximum-len(chunk.GetData()) {
			clearHostTorrentFrame(frame)
			return 0, torrent.ErrInvalidInput
		}
		reader.pending = append(reader.pending[:0], chunk.GetData()...)
		reader.total += len(reader.pending)
		clearHostTorrentFrame(frame)
	}
	written := copy(destination, reader.pending)
	clear(reader.pending[:written])
	reader.pending = reader.pending[written:]
	return written, nil
}

func clearHostTorrentFrame(frame *privatevmv1.HostTorrentInputFrame) {
	if frame == nil {
		return
	}
	if chunk := frame.GetChunk(); chunk != nil {
		clear(chunk.Data)
	}
	frame.Frame = nil
}
