package orchestrator

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/usb"
)

const (
	maximumApprovedSourceBytes  = uint64(8 << 30)
	maximumApprovedSourceFrames = maximumApprovedSourceBytes/usb.MaximumRelayChunk + 2
	approvedSourceCloseTimeout  = 30 * time.Second
)

var ErrApprovedSourceUnavailable = errors.New("authenticated approved source is unavailable")

type approvedFrameDelivery struct {
	frame *privatevmv1.TransferFrame
	err   error
}

type approvedFrameSource struct {
	mu sync.Mutex

	output   usb.ApprovedOutput
	frames   <-chan approvedFrameDelivery
	cancel   context.CancelFunc
	finalize func() error
	sequence uint64
	written  uint64
	count    uint64
	ended    bool
	closed   bool
	closeErr error
}

func openApprovedFrameSource(ctx context.Context, base usb.ApprovedOutput, frames <-chan approvedFrameDelivery, cancel context.CancelFunc, finalize func() error) (*approvedFrameSource, error) {
	if ctx == nil || frames == nil || cancel == nil {
		return nil, ErrApprovedSourceUnavailable
	}
	delivery, ok, err := receiveApprovedDelivery(ctx, frames)
	if err != nil || !ok || delivery.err != nil || delivery.frame == nil {
		cancel()
		return nil, errors.Join(ErrApprovedSourceUnavailable, err, delivery.err)
	}
	begin := delivery.frame.GetBegin()
	if begin == nil || begin.GetContext() != nil || begin.GetTransferId() != base.OutputID {
		clearApprovedFrame(delivery.frame)
		cancel()
		return nil, ErrApprovedSourceUnavailable
	}
	output, err := bindApprovedDescriptor(base, begin.GetDescriptor_())
	clearApprovedFrame(delivery.frame)
	if err != nil {
		cancel()
		return nil, err
	}
	return &approvedFrameSource{output: output, frames: frames, cancel: cancel, finalize: finalize, count: 1}, nil
}

func (source *approvedFrameSource) Output() usb.ApprovedOutput {
	if source == nil {
		return usb.ApprovedOutput{}
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.output
}

func (source *approvedFrameSource) Next(ctx context.Context) (usb.RelayChunk, error) {
	if source == nil || ctx == nil {
		return usb.RelayChunk{}, ErrApprovedSourceUnavailable
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed {
		return usb.RelayChunk{}, ErrApprovedSourceUnavailable
	}
	if source.ended {
		return usb.RelayChunk{}, io.EOF
	}
	delivery, ok, err := receiveApprovedDelivery(ctx, source.frames)
	if err != nil {
		return usb.RelayChunk{}, err
	}
	if !ok || delivery.err != nil || delivery.frame == nil {
		return usb.RelayChunk{}, errors.Join(ErrApprovedSourceUnavailable, delivery.err)
	}
	source.count++
	if source.count > maximumApprovedSourceFrames {
		clearApprovedFrame(delivery.frame)
		return usb.RelayChunk{}, ErrApprovedSourceUnavailable
	}
	if chunk := delivery.frame.GetChunk(); chunk != nil {
		data := append([]byte(nil), chunk.GetData()...)
		clearApprovedFrame(delivery.frame)
		if chunk.GetSequence() != source.sequence || len(data) == 0 || len(data) > usb.MaximumRelayChunk ||
			source.written > source.output.Size || uint64(len(data)) > source.output.Size-source.written {
			clear(data)
			return usb.RelayChunk{}, ErrApprovedSourceUnavailable
		}
		result := usb.RelayChunk{Sequence: source.sequence, Data: data}
		source.sequence++
		source.written += uint64(len(data))
		return result, nil
	}
	end := delivery.frame.GetEnd()
	if end == nil || end.GetTotalSize() != source.output.Size || source.written != source.output.Size ||
		!approvedDigestMatches(source.output.SourceDigest, end.GetDigest()) {
		clearApprovedFrame(delivery.frame)
		return usb.RelayChunk{}, ErrApprovedSourceUnavailable
	}
	clearApprovedFrame(delivery.frame)
	source.ended = true
	return usb.RelayChunk{}, io.EOF
}

func (source *approvedFrameSource) Close() error {
	if source == nil {
		return nil
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed {
		return source.closeErr
	}
	source.closed = true
	defer source.cancel()
	if !source.ended {
		source.closeErr = ErrApprovedSourceUnavailable
		return source.closeErr
	}
	closeContext, cancel := context.WithTimeout(context.Background(), approvedSourceCloseTimeout)
	delivery, ok, err := receiveApprovedDelivery(closeContext, source.frames)
	cancel()
	if err != nil || ok && (!errors.Is(delivery.err, io.EOF) || delivery.frame != nil) {
		clearApprovedFrame(delivery.frame)
		source.closeErr = errors.Join(ErrApprovedSourceUnavailable, err, delivery.err)
		return source.closeErr
	}
	if source.finalize != nil {
		source.closeErr = source.finalize()
	}
	return source.closeErr
}

func receiveApprovedDelivery(ctx context.Context, frames <-chan approvedFrameDelivery) (approvedFrameDelivery, bool, error) {
	select {
	case <-ctx.Done():
		return approvedFrameDelivery{}, false, ctx.Err()
	case delivery, ok := <-frames:
		return delivery, ok, nil
	}
}

func startApprovedFramePump(ctx context.Context, receive func() (*privatevmv1.TransferFrame, error)) <-chan approvedFrameDelivery {
	frames := make(chan approvedFrameDelivery, 1)
	go func() {
		defer close(frames)
		for count := uint64(0); count < maximumApprovedSourceFrames+1; count++ {
			frame, err := receive()
			delivery := approvedFrameDelivery{frame: cloneApprovedFrame(frame), err: err}
			clearApprovedFrame(frame)
			select {
			case frames <- delivery:
			case <-ctx.Done():
				clearApprovedFrame(delivery.frame)
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return frames
}

func bindApprovedDescriptor(base usb.ApprovedOutput, descriptor *privatevmv1.FileDescriptor) (usb.ApprovedOutput, error) {
	if descriptor == nil || descriptor.GetSizeBytes() != base.Size || !approvedDigestMatches(base.SourceDigest, descriptor.GetDigest()) {
		return usb.ApprovedOutput{}, ErrApprovedSourceUnavailable
	}
	if base.LogicalName != "" && base.LogicalName != descriptor.GetLogicalName() || base.MediaType != "" && base.MediaType != descriptor.GetDetectedMime() {
		return usb.ApprovedOutput{}, ErrApprovedSourceUnavailable
	}
	base.LogicalName = descriptor.GetLogicalName()
	base.MediaType = descriptor.GetDetectedMime()
	if err := base.Validate(maximumApprovedSourceBytes); err != nil {
		return usb.ApprovedOutput{}, errors.Join(ErrApprovedSourceUnavailable, err)
	}
	return base, nil
}

func approvedDigestMatches(expected usb.Digest, value *privatevmv1.Hash) bool {
	if value == nil || value.GetAlgorithm() != "sha256" || len(value.GetValue()) != sha256.Size {
		return false
	}
	matched := false
	_ = expected.WithBytes(func(bytes []byte) error {
		matched = subtle.ConstantTimeCompare(bytes, value.GetValue()) == 1
		return nil
	})
	return matched
}

func digestFromHex(value string) (usb.Digest, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		clear(decoded)
		return usb.Digest{}, ErrApprovedSourceUnavailable
	}
	var fixed [sha256.Size]byte
	copy(fixed[:], decoded)
	clear(decoded)
	result := usb.NewDigest(fixed)
	clear(fixed[:])
	return result, nil
}

func approvedDigestFromProto(value *privatevmv1.Hash) (usb.Digest, error) {
	if value == nil || value.GetAlgorithm() != "sha256" || len(value.GetValue()) != sha256.Size {
		return usb.Digest{}, ErrApprovedSourceUnavailable
	}
	var fixed [sha256.Size]byte
	copy(fixed[:], value.GetValue())
	result := usb.NewDigest(fixed)
	clear(fixed[:])
	return result, nil
}

func cloneApprovedFrame(frame *privatevmv1.TransferFrame) *privatevmv1.TransferFrame {
	if frame == nil {
		return nil
	}
	if begin := frame.GetBegin(); begin != nil {
		return &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{
			TransferId: begin.GetTransferId(), Descriptor_: cloneDescriptor(begin.GetDescriptor_()),
		}}}
	}
	if chunk := frame.GetChunk(); chunk != nil {
		return &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{
			Sequence: chunk.GetSequence(), Data: append([]byte(nil), chunk.GetData()...),
		}}}
	}
	if end := frame.GetEnd(); end != nil {
		return &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{
			TotalSize: end.GetTotalSize(), Digest: cloneHash(end.GetDigest()),
		}}}
	}
	return &privatevmv1.TransferFrame{}
}

func clearApprovedFrame(frame *privatevmv1.TransferFrame) {
	if frame != nil && frame.GetChunk() != nil {
		clear(frame.GetChunk().Data)
	}
}

// USBScannerPromotion registers exactly one reconstructed output from the
// authenticated report retained by GuestScannerRelay. The offline scanner is
// deliberately kept alive until the one-use factory is consumed or cleaned.
type USBScannerPromotion struct {
	Sources *usb.ApprovedSourceRegistry
}

func NewUSBScannerPromotion(sources *usb.ApprovedSourceRegistry) (*USBScannerPromotion, error) {
	if sources == nil {
		return nil, ErrApprovedSourceUnavailable
	}
	return &USBScannerPromotion{Sources: sources}, nil
}

func (promotion *USBScannerPromotion) Promote(ctx context.Context, scanner session.Snapshot, report scan.ScanReport, destination string, target session.Snapshot, client privatevmv1.ScannerGuestServiceClient) error {
	if promotion == nil || promotion.Sources == nil || ctx == nil || client == nil || destination != "usb" ||
		target.ID != "" ||
		scanner.Role != session.RoleScanner || scanner.Phase != session.PhaseActive || report.SessionID != scanner.ID ||
		report.Result != "approved" || !report.Complete || len(report.SanitizedOutputs) != 1 || report.Validate() != nil {
		return ErrApprovedSourceUnavailable
	}
	record := report.SanitizedOutputs[0]
	digest, err := digestFromHex(record.SHA256)
	if err != nil {
		return err
	}
	selection := usb.SourceSelection{Role: usb.SourceScanner, SessionID: scanner.ID, OutputID: record.OutputID}
	base := usb.ApprovedOutput{
		SourceRole: usb.SourceScanner, OutputID: record.OutputID, LogicalName: record.LogicalName,
		MediaType: record.DetectedMIME, Size: record.SizeBytes, SourceDigest: digest,
		ReportAuthenticated: true, ReportComplete: true, PolicyApproved: true, Reconstructed: true,
	}
	return promotion.Sources.Replace(selection, func(openContext context.Context) (usb.ApprovedSource, error) {
		requestID, requestErr := newGuestRequestID()
		if requestErr != nil {
			return nil, ErrApprovedSourceUnavailable
		}
		streamContext, cancel := context.WithCancel(openContext)
		request := &privatevmv1.ExportApprovedFileRequest{
			Context: &privatevmv1.GuestContext{Context: &privatevmv1.RequestContext{
				ApiVersion: &privatevmv1.ApiVersion{Major: guest.APIMajor, Minor: guest.APIMinor},
				RequestId:  requestID, SessionId: scanner.ID,
			}, ExpectedRole: privatevmv1.GuestRole_GUEST_ROLE_SCANNER},
			OutputId: record.OutputID,
		}
		stream, streamErr := client.ExportApprovedFile(streamContext, request)
		if streamErr != nil {
			cancel()
			return nil, errors.Join(ErrApprovedSourceUnavailable, streamErr)
		}
		return openApprovedFrameSource(openContext, base, startApprovedFramePump(streamContext, stream.Recv), cancel, nil)
	})
}

func (promotion *USBScannerPromotion) ForgetScanner(sessionID string) {
	if promotion != nil && promotion.Sources != nil {
		promotion.Sources.RemoveSession(usb.SourceScanner, sessionID)
	}
}

func registerWorkstationApprovedSource(registry *usb.ApprovedSourceRegistry, roles *HostRoles, snapshot session.Snapshot, outputID string, digest *privatevmv1.Hash, state *privatevmv1.WorkspaceState) error {
	if registry == nil || roles == nil || snapshot.Role != session.RoleWorkstation || snapshot.Phase != session.PhaseActive {
		return ErrApprovedSourceUnavailable
	}
	pinnedDigest, err := approvedDigestFromProto(digest)
	if err != nil {
		return err
	}
	pinned, err := currentWorkspaceEntry(state, outputID, 0)
	if err != nil {
		return err
	}
	pinnedSize := pinned.GetSizeBytes()
	selection := usb.SourceSelection{Role: usb.SourceWorkstation, SessionID: snapshot.ID, OutputID: outputID}
	return registry.Replace(selection, func(openContext context.Context) (usb.ApprovedSource, error) {
		inventory, inventoryErr := roles.WorkspaceInventory(openContext, snapshot)
		if inventoryErr != nil {
			return nil, errors.Join(ErrApprovedSourceUnavailable, inventoryErr)
		}
		if _, inventoryErr = currentWorkspaceEntry(inventory, outputID, pinnedSize); inventoryErr != nil {
			return nil, inventoryErr
		}
		streamContext, cancel := context.WithCancel(openContext)
		frames := make(chan approvedFrameDelivery, 1)
		completion := make(chan workstationSourceCompletion, 1)
		go func() {
			receipt, exportErr := roles.ExportWorkspace(streamContext, snapshot, outputID, func(frame *privatevmv1.TransferFrame) error {
				copy := cloneApprovedFrame(frame)
				select {
				case frames <- approvedFrameDelivery{frame: copy}:
					return nil
				case <-streamContext.Done():
					clearApprovedFrame(copy)
					return streamContext.Err()
				}
			})
			completion <- workstationSourceCompletion{receipt: receipt, err: exportErr}
			close(frames)
		}()
		base := usb.ApprovedOutput{
			SourceRole: usb.SourceWorkstation, OutputID: outputID, Size: pinnedSize, SourceDigest: pinnedDigest,
			ExportStateAuthenticated: true, ExportStateReady: true,
		}
		finalize := func() error {
			closeContext, closeCancel := context.WithTimeout(context.Background(), approvedSourceCloseTimeout)
			defer closeCancel()
			select {
			case <-closeContext.Done():
				return ErrApprovedSourceUnavailable
			case result := <-completion:
				if result.err != nil || result.receipt == nil || result.receipt.GetTransferId() != outputID ||
					!approvedDigestMatches(pinnedDigest, result.receipt.GetReceiverDigest()) {
					return errors.Join(ErrApprovedSourceUnavailable, result.err)
				}
				return nil
			}
		}
		return openApprovedFrameSource(openContext, base, frames, cancel, finalize)
	})
}

type workstationSourceCompletion struct {
	receipt *privatevmv1.TransferReceipt
	err     error
}

func currentWorkspaceEntry(state *privatevmv1.WorkspaceState, outputID string, expectedSize uint64) (*privatevmv1.WorkspaceEntry, error) {
	if state == nil || len(state.GetEntries()) == 0 || len(state.GetEntries()) > 1024 {
		return nil, ErrApprovedSourceUnavailable
	}
	var selected *privatevmv1.WorkspaceEntry
	for _, entry := range state.GetEntries() {
		if entry != nil && entry.GetOutputId() == outputID {
			if selected != nil {
				return nil, ErrApprovedSourceUnavailable
			}
			selected = entry
		}
	}
	if selected == nil || !selected.GetExported() || selected.GetChangedSinceExport() || selected.GetSizeBytes() == 0 ||
		selected.GetSizeBytes() > maximumApprovedSourceBytes || expectedSize != 0 && selected.GetSizeBytes() != expectedSize {
		return nil, ErrApprovedSourceUnavailable
	}
	return selected, nil
}

var _ ScannerPromotionRelay = (*USBScannerPromotion)(nil)
var _ usb.ApprovedSource = (*approvedFrameSource)(nil)
