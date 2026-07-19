package guest

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/transfer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	maximumExporterPassphraseBytes  = 1024
	maximumExporterSecretChunk      = 256
	maximumExporterSecretFrames     = 4
	defaultExporterOperationTimeout = 2 * time.Hour
	maximumExporterOperationTimeout = 24 * time.Hour
	defaultExporterCleanupTimeout   = 30 * time.Second
	maximumExporterFileBytes        = uint64(16 << 40)
)

var (
	exporterEnrollmentPattern = regexp.MustCompile(`^usb-[0-9a-f]{16}$`)
	exporterHexIDPattern      = regexp.MustCompile(`^[0-9a-f]{4}$`)
	exporterTransferPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)
)

type ExporterDeviceExpectation struct {
	EnrollmentID string
	VendorID     string
	ProductID    string
	Serial       string
	Capacity     uint64
}

func (expectation ExporterDeviceExpectation) validate() error {
	if !exporterEnrollmentPattern.MatchString(expectation.EnrollmentID) ||
		!exporterHexIDPattern.MatchString(expectation.VendorID) ||
		!exporterHexIDPattern.MatchString(expectation.ProductID) || expectation.Capacity == 0 ||
		len(expectation.Serial) > 256 || strings.ContainsAny(expectation.Serial, "\x00\r\n") {
		return errors.New("exporter USB identity expectation is invalid")
	}
	return nil
}

func (expectation ExporterDeviceExpectation) equal(other ExporterDeviceExpectation) bool {
	return subtle.ConstantTimeCompare([]byte(expectation.EnrollmentID), []byte(other.EnrollmentID)) == 1 &&
		subtle.ConstantTimeCompare([]byte(expectation.VendorID), []byte(other.VendorID)) == 1 &&
		subtle.ConstantTimeCompare([]byte(expectation.ProductID), []byte(other.ProductID)) == 1 &&
		subtle.ConstantTimeCompare([]byte(expectation.Serial), []byte(other.Serial)) == 1 &&
		expectation.Capacity == other.Capacity
}

type ExporterDeviceEvidence struct {
	Expectation     ExporterDeviceExpectation
	NoNetwork       bool
	HostPathAbsent  bool
	SingleDevice    bool
	MassStorageOnly bool
	Mounted         bool
}

type ExporterPrepareEvidence struct {
	IdentityVerified bool
	LUKS2            bool
	Ext4             bool
	Mounted          bool
}

type ExporterWriteEvidence struct {
	ReceiverDigest   [sha256.Size]byte
	FileSynced       bool
	FilesystemSynced bool
	AtomicRename     bool
}

type ExporterFinalizeEvidence struct {
	Unmounted  bool
	LUKSClosed bool
}

// ExporterWriter is a fixed-destination writer. It deliberately accepts no
// path, command, mount option, device selector or QEMU argument.
type ExporterWriter interface {
	WriteChunk(context.Context, uint64, []byte) error
	Commit(context.Context, uint64, [sha256.Size]byte) (ExporterWriteEvidence, error)
	Abort(context.Context) error
}

// ExporterAdapter is implemented only inside the networkless exporter image.
// The implementation owns fixed paths and fixed LUKS2/ext4 policy; the RPC
// caller cannot choose either.
type ExporterAdapter interface {
	Inspect(context.Context, ExporterDeviceExpectation) (ExporterDeviceEvidence, error)
	Prepare(context.Context, *secret.Bytes) (ExporterPrepareEvidence, error)
	BeginWrite(context.Context, transfer.Header, string) (ExporterWriter, error)
	Reread(context.Context, string) ([sha256.Size]byte, error)
	Finalize(context.Context) (ExporterFinalizeEvidence, error)
	Cleanup(context.Context) error
}

type ExporterServiceConfig struct {
	Identity         Identity
	Adapter          ExporterAdapter
	OperationTimeout time.Duration
	CleanupTimeout   time.Duration
	MaxFileBytes     uint64
}

type exporterRPCState string

const (
	exporterStateBoot       exporterRPCState = "BOOT"
	exporterStateInspected  exporterRPCState = "INSPECTED"
	exporterStatePrepared   exporterRPCState = "PREPARED"
	exporterStateWritten    exporterRPCState = "WRITTEN"
	exporterStateVerified   exporterRPCState = "VERIFIED"
	exporterStateFinalized  exporterRPCState = "FINALIZED"
	exporterStateIncomplete exporterRPCState = "INCOMPLETE"
	exporterStateClosed     exporterRPCState = "CLOSED"
)

type ExporterService struct {
	privatevmv1.UnimplementedExporterGuestServiceServer

	mu               sync.Mutex
	identity         Identity
	adapter          ExporterAdapter
	operationTimeout time.Duration
	cleanupTimeout   time.Duration
	maxFileBytes     uint64
	state            exporterRPCState
	sessionID        string
	expectation      ExporterDeviceExpectation
	receipt          *privatevmv1.USBTransferReceipt
	closed           bool
}

func NewExporterService(config ExporterServiceConfig) (*ExporterService, error) {
	if config.Identity.Role != session.RoleExporter {
		return nil, errors.New("exporter service requires the exporter compiled identity")
	}
	if err := config.Identity.Validate(); err != nil {
		return nil, err
	}
	if config.Adapter == nil {
		return nil, errors.New("exporter service requires a fixed-policy adapter")
	}
	operationTimeout := config.OperationTimeout
	if operationTimeout == 0 {
		operationTimeout = defaultExporterOperationTimeout
	}
	if operationTimeout < time.Millisecond || operationTimeout > maximumExporterOperationTimeout {
		return nil, errors.New("exporter operation timeout is outside supported bounds")
	}
	cleanupTimeout := config.CleanupTimeout
	if cleanupTimeout == 0 {
		cleanupTimeout = defaultExporterCleanupTimeout
	}
	if cleanupTimeout < time.Millisecond || cleanupTimeout > time.Minute {
		return nil, errors.New("exporter cleanup timeout is outside supported bounds")
	}
	maximum := config.MaxFileBytes
	if maximum == 0 {
		maximum = 4 << 40
	}
	if maximum > maximumExporterFileBytes {
		return nil, errors.New("exporter file bound exceeds the supported maximum")
	}
	return &ExporterService{identity: config.Identity, adapter: config.Adapter, operationTimeout: operationTimeout,
		cleanupTimeout: cleanupTimeout, maxFileBytes: maximum, state: exporterStateBoot}, nil
}

func (service *ExporterService) InspectUSB(ctx context.Context, request *privatevmv1.ExporterRequest) (*privatevmv1.USBStatus, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed || service.state != exporterStateBoot {
		return nil, service.stateError("USB inspection is unavailable in the current exporter state.")
	}
	expectation, err := expectationFromProto(request.GetExpectedDevice())
	if err != nil {
		return nil, service.invalidIdentity()
	}
	operation, cancel := context.WithTimeout(ctx, service.operationTimeout)
	defer cancel()
	evidence, err := service.adapter.Inspect(operation, expectation)
	if err != nil || operation.Err() != nil || !evidence.Expectation.equal(expectation) || !evidence.NoNetwork ||
		!evidence.HostPathAbsent || !evidence.SingleDevice || !evidence.MassStorageOnly || evidence.Mounted {
		return nil, service.fail(operation, "USB_EXPORTER_IDENTITY_MISMATCH", "The exporter could not verify the exact unmounted mass-storage device.", "Detach the device, clean the exporter session, and repeat exact host enrollment and claim.", errors.Join(err, operation.Err()))
	}
	service.expectation = expectation
	service.sessionID = request.GetContext().GetContext().GetSessionId()
	service.state = exporterStateInspected
	return &privatevmv1.USBStatus{NoNetwork: true, IdentityVerified: true, Unmounted: true}, nil
}

func (service *ExporterService) PrepareUSB(stream grpc.ClientStreamingServer[privatevmv1.PrepareUSBFrame, privatevmv1.USBStatus]) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed || service.state != exporterStateInspected {
		return service.stateError("USB preparation is unavailable in the current exporter state.")
	}
	first, err := stream.Recv()
	if err != nil || first.GetBegin() == nil {
		clearPrepareFrame(first)
		return guestRPCError(codes.InvalidArgument, "USB_PREPARE_BEGIN_REQUIRED", "USB preparation must begin with the exact authenticated device expectation.", "Retry the complete preparation stream from the beginning.", false)
	}
	expectation, err := expectationFromProto(first.GetBegin().GetExpectedDevice())
	if err != nil || !expectation.equal(service.expectation) || first.GetBegin().GetContext().GetContext().GetSessionId() != service.sessionID {
		return service.invalidIdentity()
	}
	buffer := make([]byte, 0, maximumExporterPassphraseBytes)
	defer clear(buffer)
	frames := 0
	for {
		frame, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			clearPrepareFrame(frame)
			return service.transportError(recvErr)
		}
		frames++
		chunk := frame.GetPassphraseChunk()
		if chunk == nil || len(chunk.Data) == 0 || len(chunk.Data) > maximumExporterSecretChunk ||
			frames > maximumExporterSecretFrames || len(chunk.Data) > maximumExporterPassphraseBytes-len(buffer) {
			clearPrepareFrame(frame)
			return guestRPCError(codes.InvalidArgument, "USB_PASSPHRASE_STREAM_INVALID", "The bounded passphrase stream is invalid.", "Retry from a protected terminal with a passphrase of at most 1024 bytes.", false)
		}
		buffer = append(buffer, chunk.Data...)
		clear(chunk.Data)
	}
	if len(buffer) < 8 {
		return guestRPCError(codes.InvalidArgument, "USB_PASSPHRASE_INVALID", "The encryption passphrase is missing or too short.", "Enter a passphrase of at least eight bytes through the protected prompt.", false)
	}
	passphrase, err := secret.New(buffer)
	if err != nil {
		return guestRPCError(codes.Internal, "USB_SECRET_UNAVAILABLE", "Protected passphrase memory is unavailable.", "Destroy the exporter and retry after checking memory-lock and memfd support.", false)
	}
	defer passphrase.Destroy()
	operation, cancel := context.WithTimeout(stream.Context(), service.operationTimeout)
	defer cancel()
	evidence, err := service.adapter.Prepare(operation, passphrase)
	if err != nil || operation.Err() != nil || !evidence.IdentityVerified || !evidence.LUKS2 || !evidence.Ext4 || !evidence.Mounted {
		return service.fail(operation, "USB_PREPARE_INCOMPLETE", "The exporter did not prove complete LUKS2 and ext4 preparation.", "Keep the device attached, clean the exporter session, and inspect it again before retrying.", errors.Join(err, operation.Err()))
	}
	service.state = exporterStatePrepared
	return stream.SendAndClose(&privatevmv1.USBStatus{NoNetwork: true, Mounted: true, IdentityVerified: true, Luks2: true, Ext4: true})
}

func (service *ExporterService) WriteFile(stream grpc.ClientStreamingServer[privatevmv1.TransferFrame, privatevmv1.USBTransferReceipt]) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed || service.state != exporterStatePrepared {
		return service.stateError("USB writing is unavailable in the current exporter state.")
	}
	first, err := stream.Recv()
	if err != nil || first.GetBegin() == nil {
		return guestRPCError(codes.InvalidArgument, "TRANSFER_BEGIN_REQUIRED", "The USB write must begin with one bounded descriptor.", "Retry the approved scanner export from its first frame.", false)
	}
	begin := first.GetBegin()
	if begin.GetContext().GetSessionId() != service.sessionID || !exporterTransferPattern.MatchString(begin.GetTransferId()) {
		return guestRPCError(codes.InvalidArgument, "USB_TRANSFER_CONTEXT_INVALID", "The USB transfer context is invalid.", "Retry through the owning exporter session.", false)
	}
	header, expected, err := exporterHeader(begin.GetDescriptor_(), service.maxFileBytes)
	if err != nil || header.Size == 0 {
		return guestRPCError(codes.InvalidArgument, "USB_TRANSFER_DESCRIPTOR_INVALID", "The approved output descriptor is invalid.", "Repeat scanner approval and start a fresh bounded export.", false)
	}
	operation, cancel := context.WithTimeout(stream.Context(), service.operationTimeout)
	defer cancel()
	writer, err := service.adapter.BeginWrite(operation, header, begin.GetTransferId())
	if err != nil || writer == nil {
		return service.fail(operation, "USB_WRITE_FAILED", "The exporter could not open its fixed destination writer.", "Keep the device attached and clean the exporter session before retrying.", err)
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, cleanupCancel := context.WithTimeout(context.Background(), service.cleanupTimeout)
			_ = writer.Abort(cleanup)
			cleanupCancel()
		}
	}()
	hash := sha256.New()
	var sequence, written uint64
	for {
		frame, recvErr := stream.Recv()
		if recvErr != nil {
			return service.fail(operation, "USB_TRANSFER_INCOMPLETE", "The approved output stream ended before its final frame.", "Clean the incomplete exporter destination and repeat the complete stream.", recvErr)
		}
		if chunk := frame.GetChunk(); chunk != nil {
			data := chunk.Data
			if chunk.GetSequence() != sequence || len(data) == 0 || len(data) > transfer.DefaultMaxChunk || uint64(len(data)) > header.Size-written {
				clear(data)
				return service.fail(operation, "USB_TRANSFER_INVALID", "The approved output stream violated its sequence or byte bounds.", "Clean the incomplete exporter destination and repeat the complete stream.", nil)
			}
			if err := writer.WriteChunk(operation, sequence, data); err != nil {
				clear(data)
				return service.fail(operation, "USB_WRITE_FAILED", "The fixed exporter destination rejected a stream chunk.", "Keep the device attached and clean the exporter session before retrying.", err)
			}
			_, _ = hash.Write(data)
			written += uint64(len(data))
			sequence++
			clear(data)
			continue
		}
		end := frame.GetEnd()
		if end == nil || end.GetTotalSize() != header.Size || !constantHash(end.GetDigest(), expected) || written != header.Size ||
			subtle.ConstantTimeCompare(hash.Sum(nil), expected[:]) != 1 {
			return service.fail(operation, "USB_TRANSFER_DIGEST_MISMATCH", "The approved output stream failed its sender digest check.", "Do not trust the destination; clean it and repeat a new export.", nil)
		}
		break
	}
	evidence, err := writer.Commit(operation, written, expected)
	if err != nil || operation.Err() != nil || subtle.ConstantTimeCompare(evidence.ReceiverDigest[:], expected[:]) != 1 ||
		!evidence.FileSynced || !evidence.FilesystemSynced || !evidence.AtomicRename {
		return service.fail(operation, "USB_WRITE_EVIDENCE_INCOMPLETE", "The exporter did not prove receive hashing, fsync and atomic rename.", "Do not trust the destination; clean it and repeat a new export.", errors.Join(err, operation.Err()))
	}
	committed = true
	service.receipt = &privatevmv1.USBTransferReceipt{TransferId: begin.GetTransferId(), Descriptor_: cloneDescriptor(begin.GetDescriptor_()),
		ReceiverDigest: protoSHA256(expected), FileSynced: true, FilesystemSynced: true, AtomicRename: true}
	service.state = exporterStateWritten
	return stream.SendAndClose(cloneUSBReceipt(service.receipt))
}

func (service *ExporterService) VerifyFile(ctx context.Context, request *privatevmv1.VerifyExportRequest) (*privatevmv1.USBTransferReceipt, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed || service.state != exporterStateWritten || service.receipt == nil || request.GetTransferId() != service.receipt.GetTransferId() ||
		request.GetContext().GetContext().GetSessionId() != service.sessionID {
		return nil, service.stateError("USB reread verification is unavailable for this transfer.")
	}
	operation, cancel := context.WithTimeout(ctx, service.operationTimeout)
	defer cancel()
	reread, err := service.adapter.Reread(operation, request.GetTransferId())
	expected := service.receipt.GetReceiverDigest().GetValue()
	if err != nil || operation.Err() != nil || subtle.ConstantTimeCompare(reread[:], expected) != 1 {
		return nil, service.fail(operation, "USB_HASH_MISMATCH", "The exporter reread hash does not match the received output.", "Do not trust the destination; finalize cleanup and perform a new export.", errors.Join(err, operation.Err()))
	}
	service.receipt.RereadDigest = protoSHA256(reread)
	service.state = exporterStateVerified
	return cloneUSBReceipt(service.receipt), nil
}

func (service *ExporterService) FinalizeUSB(ctx context.Context, request *privatevmv1.ExporterRequest) (*privatevmv1.USBStatus, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	expectation, err := expectationFromProto(request.GetExpectedDevice())
	if service.closed || service.state != exporterStateVerified || err != nil || !expectation.equal(service.expectation) ||
		request.GetContext().GetContext().GetSessionId() != service.sessionID {
		return nil, service.stateError("USB finalization is unavailable for this exporter identity.")
	}
	operation, cancel := context.WithTimeout(ctx, service.operationTimeout)
	defer cancel()
	evidence, err := service.adapter.Finalize(operation)
	if err != nil || operation.Err() != nil || !evidence.Unmounted || !evidence.LUKSClosed {
		return nil, service.fail(operation, "USB_FINALIZE_INCOMPLETE", "The exporter did not prove unmount and LUKS close.", "Keep the device attached and retry exporter cleanup.", errors.Join(err, operation.Err()))
	}
	service.state = exporterStateFinalized
	return &privatevmv1.USBStatus{NoNetwork: true, Unmounted: true, IdentityVerified: true, Luks2: true, Ext4: true, Flushed: true, LuksClosed: true}, nil
}

func (service *ExporterService) Close(ctx context.Context) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed {
		return nil
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.cleanupTimeout)
	defer cancel()
	if err := service.adapter.Cleanup(cleanup); err != nil || cleanup.Err() != nil {
		service.state = exporterStateIncomplete
		return errors.New("exporter cleanup incomplete")
	}
	service.closed = true
	service.state = exporterStateClosed
	return nil
}

func (service *ExporterService) fail(ctx context.Context, code, message, remediation string, cause error) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.cleanupTimeout)
	defer cancel()
	if err := service.adapter.Cleanup(cleanup); err != nil || cleanup.Err() != nil {
		service.state = exporterStateIncomplete
		return guestRPCError(codes.FailedPrecondition, "USB_CLEANUP_INCOMPLETE", "Exporter cleanup did not prove resource absence.", "Keep the device attached and retry session cleanup.", true)
	}
	service.state = exporterStateIncomplete
	grpcCode := codes.FailedPrecondition
	if errors.Is(cause, context.Canceled) {
		grpcCode = codes.Canceled
	} else if errors.Is(cause, context.DeadlineExceeded) {
		grpcCode = codes.DeadlineExceeded
	}
	return guestRPCError(grpcCode, code, message, remediation, false)
}

func (service *ExporterService) stateError(message string) error {
	return guestRPCError(codes.FailedPrecondition, "USB_EXPORTER_STATE_INVALID", message, "Use the owning exporter session in documented order or destroy it after an incomplete operation.", false)
}

func (service *ExporterService) invalidIdentity() error {
	return guestRPCError(codes.FailedPrecondition, "USB_EXPORTER_IDENTITY_MISMATCH", "The exporter USB identity expectation is invalid or changed.", "Destroy the exporter and repeat exact host enrollment and claim.", false)
}

func (service *ExporterService) transportError(err error) error {
	if errors.Is(err, context.Canceled) {
		return guestRPCError(codes.Canceled, "USB_PREPARE_CANCELED", "USB preparation was canceled.", "Inspect the preparation state before retrying.", true)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return guestRPCError(codes.DeadlineExceeded, "USB_PREPARE_TIMEOUT", "USB preparation timed out.", "Inspect the preparation state and run cleanup before retrying.", true)
	}
	return guestRPCError(codes.InvalidArgument, "USB_PASSPHRASE_STREAM_INVALID", "The passphrase stream ended unexpectedly.", "Retry the complete protected preparation stream.", false)
}

func expectationFromProto(value *privatevmv1.USBDeviceExpectation) (ExporterDeviceExpectation, error) {
	expectation := ExporterDeviceExpectation{EnrollmentID: value.GetEnrollmentId(), VendorID: strings.ToLower(value.GetVendorId()),
		ProductID: strings.ToLower(value.GetProductId()), Serial: value.GetSerial(), Capacity: value.GetCapacityBytes()}
	return expectation, expectation.validate()
}

func exporterHeader(value *privatevmv1.FileDescriptor, maximum uint64) (transfer.Header, [sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if value == nil || value.GetDigest() == nil || value.GetDigest().GetAlgorithm() != "sha256" || len(value.GetDigest().GetValue()) != sha256.Size {
		return transfer.Header{}, digest, errors.New("sha256 descriptor required")
	}
	copy(digest[:], value.GetDigest().GetValue())
	header := transfer.Header{Name: value.GetLogicalName(), Size: value.GetSizeBytes(), SHA256: digest, MediaType: value.GetDetectedMime()}
	return header, digest, header.Validate(maximum)
}

func constantHash(value *privatevmv1.Hash, expected [sha256.Size]byte) bool {
	return value != nil && value.GetAlgorithm() == "sha256" && subtle.ConstantTimeCompare(value.GetValue(), expected[:]) == 1
}

func protoSHA256(value [sha256.Size]byte) *privatevmv1.Hash {
	return &privatevmv1.Hash{Algorithm: "sha256", Value: append([]byte(nil), value[:]...)}
}

func cloneDescriptor(value *privatevmv1.FileDescriptor) *privatevmv1.FileDescriptor {
	if value == nil {
		return nil
	}
	return &privatevmv1.FileDescriptor{LogicalName: value.GetLogicalName(), SizeBytes: value.GetSizeBytes(), DetectedMime: value.GetDetectedMime(),
		Digest: &privatevmv1.Hash{Algorithm: value.GetDigest().GetAlgorithm(), Value: append([]byte(nil), value.GetDigest().GetValue()...)}}
}

func cloneUSBReceipt(value *privatevmv1.USBTransferReceipt) *privatevmv1.USBTransferReceipt {
	if value == nil {
		return nil
	}
	result := &privatevmv1.USBTransferReceipt{TransferId: value.GetTransferId(), Descriptor_: cloneDescriptor(value.GetDescriptor_()),
		FileSynced: value.GetFileSynced(), FilesystemSynced: value.GetFilesystemSynced(), AtomicRename: value.GetAtomicRename()}
	if value.GetReceiverDigest() != nil {
		result.ReceiverDigest = &privatevmv1.Hash{Algorithm: value.GetReceiverDigest().GetAlgorithm(), Value: append([]byte(nil), value.GetReceiverDigest().GetValue()...)}
	}
	if value.GetRereadDigest() != nil {
		result.RereadDigest = &privatevmv1.Hash{Algorithm: value.GetRereadDigest().GetAlgorithm(), Value: append([]byte(nil), value.GetRereadDigest().GetValue()...)}
	}
	return result
}

func clearPrepareFrame(frame *privatevmv1.PrepareUSBFrame) {
	if frame != nil && frame.GetPassphraseChunk() != nil {
		clear(frame.GetPassphraseChunk().Data)
	}
}

var _ privatevmv1.ExporterGuestServiceServer = (*ExporterService)(nil)
