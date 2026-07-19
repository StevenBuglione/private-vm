package guest

import (
	"context"
	"errors"
	"io"
	"slices"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/torrent"
	"google.golang.org/grpc/codes"
)

const maximumTorrentChunkBytes = 16 << 10

func (server *DownloaderVPNServer) AddTorrent(stream privatevmv1.DownloaderGuestService_AddTorrentServer) error {
	if server == nil || server.torrentController == nil || stream == nil {
		return torrentRPCError(torrent.ErrInvalidRequest)
	}
	var raw []byte
	var kind torrent.InputKind
	finalSeen := false
	frames := 0
	defer clear(raw)
	for {
		frame, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return torrentRPCError(err)
		}
		frames++
		if frames > torrent.MaximumInputFrames || finalSeen {
			clearTorrentFrame(frame)
			return torrentRPCError(torrent.ErrInvalidInput)
		}
		var chunk []byte
		currentKind := torrent.InputKind("")
		switch value := frame.GetFrame().(type) {
		case *privatevmv1.TorrentInputFrame_MagnetChunk:
			chunk, currentKind = value.MagnetChunk, torrent.InputMagnet
		case *privatevmv1.TorrentInputFrame_TorrentChunk:
			chunk, currentKind = value.TorrentChunk, torrent.InputMetainfo
		default:
			clearTorrentFrame(frame)
			return torrentRPCError(torrent.ErrInvalidInput)
		}
		frame.Frame = nil
		if len(chunk) == 0 || len(chunk) > maximumTorrentChunkBytes || (kind != "" && kind != currentKind) {
			clear(chunk)
			return torrentRPCError(torrent.ErrInvalidInput)
		}
		kind = currentKind
		maximum := torrent.MaximumMetainfoBytes
		if kind == torrent.InputMagnet {
			maximum = torrent.MaximumMagnetBytes
		}
		if len(raw) > maximum-len(chunk) {
			clear(chunk)
			return torrentRPCError(torrent.ErrInputTooLarge)
		}
		raw = append(raw, chunk...)
		clear(chunk)
		finalSeen = frame.GetFinal()
	}
	if !finalSeen || len(raw) == 0 {
		return torrentRPCError(torrent.ErrInvalidInput)
	}
	input, err := torrent.NewInput(kind, raw)
	if err != nil {
		return torrentRPCError(err)
	}
	defer input.Destroy()
	metadata, err := server.torrentController.Add(stream.Context(), input)
	if err != nil {
		return torrentRPCError(err)
	}
	return stream.SendAndClose(torrentMetadataToProto(metadata))
}

func (server *DownloaderVPNServer) GetTorrentMetadata(ctx context.Context, _ *privatevmv1.TorrentRequest) (*privatevmv1.TorrentMetadata, error) {
	if server == nil || server.torrentController == nil {
		return nil, torrentRPCError(torrent.ErrInvalidRequest)
	}
	metadata, err := server.torrentController.Metadata()
	if err != nil {
		return nil, torrentRPCError(err)
	}
	return torrentMetadataToProto(metadata), nil
}

func (server *DownloaderVPNServer) SelectTorrentFiles(ctx context.Context, request *privatevmv1.SelectTorrentFilesRequest) (*privatevmv1.TorrentMetadata, error) {
	if server == nil || server.torrentController == nil || request == nil || len(request.GetIndexes()) == 0 {
		return nil, torrentRPCError(torrent.ErrInvalidSelection)
	}
	metadata, _, err := server.torrentController.Select(ctx, slices.Clone(request.GetIndexes()))
	if err != nil {
		return nil, torrentRPCError(err)
	}
	return torrentMetadataToProto(metadata), nil
}

func (server *DownloaderVPNServer) StartDownload(request *privatevmv1.TorrentRequest, stream privatevmv1.DownloaderGuestService_StartDownloadServer) error {
	if server == nil || server.torrentController == nil || request == nil || stream == nil {
		return torrentRPCError(torrent.ErrInvalidRequest)
	}
	if err := server.torrentController.Start(stream.Context()); err != nil {
		return torrentRPCError(err)
	}
	return torrentRPCError(server.torrentController.Monitor(stream.Context(), func(status torrent.Status) error {
		return stream.Send(&privatevmv1.TorrentEvent{
			Progress:   &privatevmv1.Progress{Operation: "torrent-download", Completed: status.Progress.CompletedBytes, Total: status.Progress.TotalBytes, Unit: "bytes"},
			Diagnostic: torrentDiagnostic(status), Complete: status.State == torrent.StateDownloadComplete,
		})
	}))
}

func (server *DownloaderVPNServer) PauseDownload(ctx context.Context, _ *privatevmv1.TorrentRequest) (*privatevmv1.TorrentStatus, error) {
	if server == nil || server.torrentController == nil {
		return nil, torrentRPCError(torrent.ErrInvalidRequest)
	}
	if err := server.torrentController.Pause(ctx); err != nil {
		return nil, torrentRPCError(err)
	}
	status, err := server.torrentController.Status(ctx)
	if err != nil {
		return nil, torrentRPCError(err)
	}
	return torrentStatusToProto(status), nil
}

func (server *DownloaderVPNServer) GetDownloadStatus(ctx context.Context, _ *privatevmv1.TorrentRequest) (*privatevmv1.TorrentStatus, error) {
	if server == nil || server.torrentController == nil {
		return nil, torrentRPCError(torrent.ErrInvalidRequest)
	}
	status, err := server.torrentController.Status(ctx)
	if err != nil {
		return nil, torrentRPCError(err)
	}
	return torrentStatusToProto(status), nil
}

func (server *DownloaderVPNServer) SealQuarantine(ctx context.Context, _ *privatevmv1.TorrentRequest) (*privatevmv1.Empty, error) {
	if server == nil || server.torrentController == nil {
		return nil, torrentRPCError(torrent.ErrInvalidRequest)
	}
	manifest, err := server.torrentController.Seal(ctx)
	if err != nil {
		return nil, torrentRPCError(err)
	}
	manifest.Destroy()
	return &privatevmv1.Empty{}, nil
}

func torrentMetadataToProto(metadata torrent.Metadata) *privatevmv1.TorrentMetadata {
	result := &privatevmv1.TorrentMetadata{
		DisplayName: metadata.DisplayName, SelectedSizeBytes: metadata.SelectedSizeBytes,
		PayloadPaused: metadata.PayloadPaused, Files: make([]*privatevmv1.TorrentFile, len(metadata.Files)),
	}
	for index, file := range metadata.Files {
		hazards := slices.Clone(file.HazardCodes)
		if file.SuspectedType != "" {
			hazards = append(hazards, "SUSPECTED_"+safeTypeCode(file.SuspectedType))
		}
		result.Files[index] = &privatevmv1.TorrentFile{Index: file.Index, DisplayPath: file.DisplayPath, SizeBytes: file.SizeBytes, Selected: file.Selected, HazardCodes: hazards}
	}
	return result
}

func torrentStatusToProto(status torrent.Status) *privatevmv1.TorrentStatus {
	return &privatevmv1.TorrentStatus{
		State: string(status.State), Progress: &privatevmv1.Progress{Operation: "torrent-download", Completed: status.Progress.CompletedBytes, Total: status.Progress.TotalBytes, Unit: "bytes"},
		Diagnostics: []*privatevmv1.Diagnostic{torrentDiagnostic(status)},
	}
}

func torrentDiagnostic(status torrent.Status) *privatevmv1.Diagnostic {
	severity := privatevmv1.Diagnostic_SEVERITY_INFO
	if status.Code == "TORRENT_STATE_INVALID" {
		severity = privatevmv1.Diagnostic_SEVERITY_BLOCKING
	}
	return &privatevmv1.Diagnostic{Code: status.Code, Severity: severity, Summary: "The downloader torrent state changed.", Remediation: status.Remediation, Overridable: false}
}

func safeTypeCode(value string) string {
	result := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current >= 'a' && current <= 'z' {
			current -= 'a' - 'A'
		}
		if (current >= 'A' && current <= 'Z') || current == '_' {
			result = append(result, current)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}

func clearTorrentFrame(frame *privatevmv1.TorrentInputFrame) {
	if frame == nil {
		return
	}
	switch value := frame.GetFrame().(type) {
	case *privatevmv1.TorrentInputFrame_MagnetChunk:
		clear(value.MagnetChunk)
	case *privatevmv1.TorrentInputFrame_TorrentChunk:
		clear(value.TorrentChunk)
	}
	frame.Frame = nil
}

func torrentRPCError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return guestRPCError(codes.Canceled, "TORRENT_CANCELLED", "The torrent operation was cancelled and payload was paused.", "Inspect the volatile workflow state before retrying.", true)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return guestRPCError(codes.DeadlineExceeded, "TORRENT_TIMEOUT", "The torrent operation exceeded its bounded deadline and payload was paused.", "Inspect VPN and downloader status before retrying.", true)
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
	return guestRPCError(grpcCode, application.Code, application.Message, application.Remediation, false)
}
