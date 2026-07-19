package orchestrator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/qemu"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/transfer"
	"github.com/StevenBuglione/private-vm/internal/usb"
	"google.golang.org/grpc"
)

const exporterGuestOperationTimeout = 2 * time.Hour

// ExporterRuntimeStack is the sole production owner of exporter QEMU, token,
// VSOCK, hotplug, and volatile image resources. The exact USB bus/address
// comes only from a freshly revalidated daemon claim.
type ExporterRuntimeStack struct {
	Roles       *HostRoles
	RuntimeRoot string
	QEMUBinary  string
	CIDs        *guest.CIDAllocator
	Launcher    *qemu.Launcher

	mu       sync.Mutex
	runtimes map[string]*exporterRuntime
}

func NewExporterRuntimeStack(roles *HostRoles, runtimeRoot, qemuBinary string, cids *guest.CIDAllocator, launcher *qemu.Launcher) (*ExporterRuntimeStack, error) {
	if roles == nil || runtimeRoot == "" || qemuBinary == "" || cids == nil || launcher == nil {
		return nil, errors.New("exporter runtime stack is incomplete")
	}
	return &ExporterRuntimeStack{Roles: roles, RuntimeRoot: runtimeRoot, QEMUBinary: qemuBinary, CIDs: cids, Launcher: launcher, runtimes: make(map[string]*exporterRuntime)}, nil
}

func (stack *ExporterRuntimeStack) Preflight(ctx context.Context, snapshot session.Snapshot) error {
	if snapshot.Role != session.RoleExporter {
		return ErrHostRoleUnavailable
	}
	return stack.Roles.Preflight(ctx, snapshot)
}

func (stack *ExporterRuntimeStack) VerifyImage(ctx context.Context, snapshot session.Snapshot) error {
	return stack.Roles.VerifyImages(ctx, snapshot)
}

func (stack *ExporterRuntimeStack) StorageAllocation(snapshot session.Snapshot) session.AllocateFunc {
	return stack.Roles.StorageAllocation(snapshot)
}

func (stack *ExporterRuntimeStack) RuntimeAllocation(snapshot session.Snapshot, claim usb.Claim, enrollment usb.Enrollment) session.AllocateFunc {
	return func(ctx context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		if snapshot.Role != session.RoleExporter || claim.SessionID != snapshot.ID || claim.OwnerUID != snapshot.OwnerUID || enrollment.EnrollmentID != claim.EnrollmentID {
			return nil, nil, errors.New("exporter runtime claim identity is invalid")
		}
		request, err := stack.Roles.ExporterRequest(snapshot)
		if err != nil {
			return nil, nil, err
		}
		runtime := &exporterRuntime{stack: stack, request: request, claim: claim, enrollment: enrollment}
		if err := runtime.start(ctx); err != nil {
			cleanupErr := runtime.StopExporter(context.Background())
			return runtime.StopExporter, runtime.AuditAbsent, errors.Join(err, cleanupErr)
		}
		stack.mu.Lock()
		if stack.runtimes[snapshot.ID] != nil {
			stack.mu.Unlock()
			cleanupErr := runtime.StopExporter(context.Background())
			return runtime.StopExporter, runtime.AuditAbsent, errors.Join(ErrHostRuntimeUnavailable, cleanupErr)
		}
		stack.runtimes[snapshot.ID] = runtime
		stack.mu.Unlock()
		cleanup := func(cleanupCtx context.Context) error {
			if err := runtime.StopExporter(cleanupCtx); err != nil {
				return err
			}
			stack.mu.Lock()
			if stack.runtimes[snapshot.ID] == runtime {
				delete(stack.runtimes, snapshot.ID)
			}
			stack.mu.Unlock()
			return nil
		}
		return cleanup, runtime.AuditAbsent, nil
	}
}

func (stack *ExporterRuntimeStack) Runtime(sessionID string) (usb.ExporterRuntime, error) {
	stack.mu.Lock()
	defer stack.mu.Unlock()
	runtime := stack.runtimes[sessionID]
	if runtime == nil {
		return nil, ErrHostRuntimeUnavailable
	}
	return runtime, nil
}

type exporterRuntime struct {
	mu sync.Mutex

	stack       *ExporterRuntimeStack
	request     HostRuntimeRequest
	claim       usb.Claim
	enrollment  usb.Enrollment
	cid         uint32
	token       *guest.Token
	directories *runtimeSocketDirectories
	images      qemu.RuntimeImageLease
	process     *qemu.Process
	connection  *grpc.ClientConn
	client      privatevmv1.ExporterGuestServiceClient
	cleanup     exporterCleanupHooks

	booted           bool
	attached         bool
	inspected        bool
	directoriesOwned bool
	imagesOwned      bool
	processOwned     bool
	connectionOwned  bool
	stopped          bool
}

// exporterCleanupHooks are deliberately private test seams for failure
// injection. Production always uses the concrete handles retained above.
type exporterCleanupHooks struct {
	detach             func(context.Context) error
	closeConnection    func() error
	stopProcess        func(context.Context) error
	destroyImages      func() error
	releaseCID         func(uint32) bool
	cleanupDirectories func() error
}

func (runtime *exporterRuntime) start(ctx context.Context) error {
	cid, err := runtime.stack.CIDs.Allocate()
	if err != nil {
		return err
	}
	runtime.cid = cid
	token, err := guest.NewToken()
	if err != nil {
		return err
	}
	runtime.token = token
	directories, err := createRuntimeSocketDirectories(runtime.stack.RuntimeRoot, runtime.request.Snapshot.ID)
	if directories != nil {
		runtime.directories = directories
		runtime.directoriesOwned = true
	}
	if err != nil {
		return err
	}
	images, err := runtime.request.Storage.ActivateImages()
	if images != nil {
		runtime.images = images
		runtime.imagesOwned = true
	}
	if err != nil {
		return err
	}
	if images == nil {
		return errors.New("exporter image lease is unavailable")
	}
	capability, err := token.DupFile()
	if err != nil {
		return err
	}
	defer capability.Close()
	specification := qemu.Spec{
		Binary: runtime.stack.QEMUBinary, SessionID: runtime.request.Snapshot.ID, Name: runtime.request.Snapshot.ID,
		Role: session.RoleExporter, CPUs: runtime.request.Plan.VCPUs, MemoryBytes: runtime.request.Plan.MemoryBytes,
		Root:      qemu.Disk{Path: runtime.request.Storage.RootPath(), Format: "qcow2", Serial: "root"},
		QMPSocket: directories.QMPSocket(), VSOCKCID: cid, Networked: false, FWCfgTokenFD: 3,
	}
	if err := specification.Validate(); err != nil {
		return err
	}
	process, err := runtime.stack.Launcher.Launch(ctx, specification, qemu.InheritedFiles{Capability: capability})
	if err != nil {
		return err
	}
	runtime.process = process
	runtime.processOwned = true
	runtime.booted = true
	connection, err := guest.Dial(guest.ClientConfig{CID: cid, Token: token, MaxMessageSize: guest.MaximumMessageSize})
	if err != nil {
		return err
	}
	runtime.connection = connection
	runtime.connectionOwned = true
	handshakeContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	requestID, err := exporterRequestID()
	if err != nil {
		return err
	}
	_, err = guest.Handshake(handshakeContext, privatevmv1.NewGuestCommonServiceClient(connection), guest.HandshakeExpectation{
		SessionID: runtime.request.Snapshot.ID, RequestID: requestID, Role: session.RoleExporter,
		ImageDigest: runtime.request.Image.ImageDigest, SourceCommit: runtime.request.Image.SourceCommit,
		Capabilities: runtime.request.Image.Capabilities, MinimumProtocolMinor: 0,
	})
	if err != nil {
		return err
	}
	runtime.client = privatevmv1.NewExporterGuestServiceClient(connection)
	// device_add can take effect before QMP reports a timeout or disconnect.
	// Mark the device owned first so every ambiguous result is detached or is
	// proven absent by terminating the owning QEMU process.
	runtime.attached = true
	if err := process.AttachUSB(handshakeContext, runtime.claim.Device.Bus, runtime.claim.Device.Address); err != nil {
		return err
	}
	status, err := runtime.client.InspectUSB(handshakeContext, &privatevmv1.ExporterRequest{Context: runtime.context(requestID), ExpectedDevice: runtime.expectation()})
	if err != nil || status == nil || !status.GetNoNetwork() || !status.GetIdentityVerified() || !status.GetUnmounted() {
		return errors.Join(errors.New("exporter guest USB inspection failed"), err)
	}
	runtime.inspected = true
	return nil
}

func (runtime *exporterRuntime) VerifyHostAndSourceIsolation(_ context.Context, claim usb.Claim) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.booted || runtime.stopped || !sameExporterClaim(runtime.claim, claim) || runtime.request.Snapshot.Role != session.RoleExporter {
		return errors.New("exporter role-boundary proof is incomplete")
	}
	return nil
}

func (runtime *exporterRuntime) BootNetworkless(context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.booted || runtime.stopped || runtime.request.Snapshot.Role != session.RoleExporter {
		return errors.New("networkless exporter is unavailable")
	}
	return nil
}

func (runtime *exporterRuntime) VerifyNoNetwork(context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.booted || runtime.stopped || !runtime.inspected || runtime.request.Snapshot.Role != session.RoleExporter {
		return errors.New("exporter guest no-network evidence is absent")
	}
	return nil
}

func (runtime *exporterRuntime) AttachExactUSB(_ context.Context, claim usb.Claim) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.attached || runtime.stopped || !sameExporterClaim(runtime.claim, claim) {
		return errors.New("exact exporter USB is not attached")
	}
	return nil
}

func (runtime *exporterRuntime) InspectAttachedUSB(ctx context.Context, claim usb.Claim) error {
	if err := runtime.AttachExactUSB(ctx, claim); err != nil {
		return err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.inspected {
		return errors.New("exporter USB inspection evidence is absent")
	}
	return nil
}

func (runtime *exporterRuntime) Prepare(ctx context.Context, claim usb.Claim, filesystem string, passphrase *secret.Bytes, _ func(usb.PrepareEvent) error) (usb.PrepareReceipt, error) {
	if filesystem != usb.DefaultFilesystem || passphrase == nil || !sameExporterClaim(runtime.claim, claim) {
		return usb.PrepareReceipt{}, errors.New("exporter preparation request is invalid")
	}
	runtime.mu.Lock()
	client := runtime.client
	inspected := runtime.inspected && !runtime.stopped
	runtime.mu.Unlock()
	if client == nil || !inspected {
		return usb.PrepareReceipt{}, errors.New("exporter guest is not ready")
	}
	operationContext, cancel := context.WithTimeout(ctx, exporterGuestOperationTimeout)
	defer cancel()
	stream, err := client.PrepareExactUSB(operationContext)
	if err != nil {
		return usb.PrepareReceipt{}, err
	}
	requestID, err := exporterRequestID()
	if err != nil {
		return usb.PrepareReceipt{}, err
	}
	if err := stream.Send(&privatevmv1.PrepareUSBFrame{Frame: &privatevmv1.PrepareUSBFrame_Begin{Begin: &privatevmv1.PrepareUSBBegin{Context: runtime.context(requestID), ExpectedDevice: runtime.expectation()}}}); err != nil {
		return usb.PrepareReceipt{}, err
	}
	err = passphrase.WithReader(func(reader io.Reader) error {
		buffer := make([]byte, 256)
		defer clear(buffer)
		for {
			count, readErr := reader.Read(buffer)
			if count > 0 {
				chunk := append([]byte(nil), buffer[:count]...)
				sendErr := stream.Send(&privatevmv1.PrepareUSBFrame{Frame: &privatevmv1.PrepareUSBFrame_PassphraseChunk{PassphraseChunk: &privatevmv1.PrepareUSBSecretChunk{Data: chunk}}})
				clear(chunk)
				clear(buffer[:count])
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
	})
	if err != nil {
		return usb.PrepareReceipt{}, err
	}
	status, err := stream.CloseAndRecv()
	if err != nil || status == nil || !status.GetNoNetwork() || !status.GetIdentityVerified() || !status.GetMounted() || !status.GetLuks2() || !status.GetExt4() {
		return usb.PrepareReceipt{}, errors.Join(errors.New("exporter preparation evidence is incomplete"), err)
	}
	fingerprint, err := runtime.enrollment.Identity.Fingerprint()
	if err != nil {
		return usb.PrepareReceipt{}, err
	}
	return usb.PrepareReceipt{SchemaVersion: usb.PrepareSchemaVersion, EnrollmentID: runtime.enrollment.EnrollmentID, Filesystem: usb.DefaultFilesystem, CapacityBytes: runtime.enrollment.Identity.Capacity, Fingerprint: fingerprint, State: usb.PrepareDestinationReady}, nil
}

func (runtime *exporterRuntime) Begin(ctx context.Context, output usb.ApprovedOutput) (usb.DestinationWriter, error) {
	if err := output.Validate(16 << 40); err != nil {
		return nil, err
	}
	runtime.mu.Lock()
	client := runtime.client
	ready := runtime.inspected && !runtime.stopped
	runtime.mu.Unlock()
	if client == nil || !ready {
		return nil, errors.New("exporter destination is unavailable")
	}
	streamContext, cancel := context.WithCancel(ctx)
	stream, err := client.WriteVerifiedFile(streamContext)
	if err != nil {
		cancel()
		return nil, err
	}
	transferID, err := exporterRequestID()
	if err != nil {
		cancel()
		return nil, err
	}
	transferID = "export-" + transferID
	var digest []byte
	err = output.SourceDigest.WithBytes(func(value []byte) error { digest = append([]byte(nil), value...); return nil })
	if err != nil {
		cancel()
		return nil, err
	}
	begin := &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{Context: runtime.context(transferID).GetContext(), TransferId: transferID, Descriptor_: &privatevmv1.FileDescriptor{LogicalName: output.LogicalName, SizeBytes: output.Size, DetectedMime: output.MediaType, Digest: &privatevmv1.Hash{Algorithm: "sha256", Value: digest}}}}}
	if err := stream.Send(begin); err != nil {
		clear(digest)
		cancel()
		return nil, err
	}
	clear(digest)
	return &exporterDestinationWriter{runtime: runtime, stream: stream, cancel: cancel, transferID: transferID, expectedSize: output.Size}, nil
}

func (runtime *exporterRuntime) Finalize(ctx context.Context) (usb.FinalizeEvidence, error) {
	requestID, err := exporterRequestID()
	if err != nil {
		return usb.FinalizeEvidence{}, err
	}
	status, err := runtime.client.FinalizeUSB(ctx, &privatevmv1.ExporterRequest{Context: runtime.context(requestID), ExpectedDevice: runtime.expectation()})
	if err != nil || status == nil {
		return usb.FinalizeEvidence{}, err
	}
	return usb.FinalizeEvidence{Unmounted: status.GetUnmounted(), LUKSClosed: status.GetLuksClosed()}, nil
}

func (runtime *exporterRuntime) DetachUSB(ctx context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.attached {
		return nil
	}
	if err := runtime.detach(ctx); err != nil {
		return errors.New("exporter USB hot-unplug failed")
	}
	runtime.attached = false
	return nil
}

func (runtime *exporterRuntime) StopExporter(ctx context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.stopped {
		return nil
	}
	var detachErr error
	if runtime.attached {
		detachErr = runtime.detach(ctx)
		if detachErr == nil {
			runtime.attached = false
		}
	}
	var connectionErr error
	if runtime.connectionOwned {
		connectionErr = runtime.closeConnection()
		if connectionErr == nil {
			runtime.connectionOwned = false
			runtime.connection = nil
			runtime.client = nil
		}
	}
	var processErr error
	if runtime.processOwned {
		processErr = runtime.stopProcess(ctx)
		if processErr == nil {
			runtime.processOwned = false
			runtime.booted = false
			runtime.attached = false
			runtime.inspected = false
			// Process absence proves the ambiguous device_add/device_del result
			// can no longer leave the physical USB attached to this guest.
			detachErr = nil
		}
	}
	var imageErr error
	if runtime.imagesOwned {
		imageErr = runtime.destroyImages()
		if imageErr == nil {
			runtime.imagesOwned = false
		}
	}
	if runtime.token != nil {
		runtime.token.Destroy()
		runtime.token = nil
	}
	var cidErr error
	if runtime.cid != 0 {
		if runtime.releaseCID(runtime.cid) {
			runtime.cid = 0
		} else {
			cidErr = guest.ErrCIDUnavailable
		}
	}
	var directoryErr error
	if runtime.directoriesOwned {
		directoryErr = runtime.cleanupDirectories()
		if directoryErr == nil {
			runtime.directoriesOwned = false
		}
	}
	runtime.stopped = !runtime.attached && !runtime.connectionOwned && !runtime.processOwned &&
		!runtime.imagesOwned && runtime.token == nil && runtime.cid == 0 && !runtime.directoriesOwned
	return errors.Join(detachErr, connectionErr, processErr, imageErr, cidErr, directoryErr)
}

func (runtime *exporterRuntime) AuditAbsent(ctx context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	var audits []error
	if !runtime.stopped || runtime.attached || runtime.connectionOwned || runtime.processOwned || runtime.imagesOwned || runtime.directoriesOwned || runtime.cid != 0 || runtime.token != nil {
		audits = append(audits, errors.New("exporter volatile resources remain"))
	}
	if runtime.process != nil {
		audits = append(audits, runtime.process.Audit(ctx))
	}
	if runtime.images != nil {
		audits = append(audits, runtime.images.Audit())
	}
	if runtime.directories != nil {
		audits = append(audits, runtime.directories.Audit())
	}
	return errors.Join(audits...)
}

func (runtime *exporterRuntime) detach(ctx context.Context) error {
	if runtime.cleanup.detach != nil {
		return runtime.cleanup.detach(ctx)
	}
	if runtime.process == nil {
		return errors.New("exporter QEMU process handle is absent")
	}
	return runtime.process.DetachUSB(ctx)
}

func (runtime *exporterRuntime) closeConnection() error {
	if runtime.cleanup.closeConnection != nil {
		return runtime.cleanup.closeConnection()
	}
	if runtime.connection == nil {
		return errors.New("exporter VSOCK connection handle is absent")
	}
	return runtime.connection.Close()
}

func (runtime *exporterRuntime) stopProcess(ctx context.Context) error {
	if runtime.cleanup.stopProcess != nil {
		return runtime.cleanup.stopProcess(ctx)
	}
	if runtime.process == nil {
		return errors.New("exporter QEMU process handle is absent")
	}
	return runtime.process.Cleanup(ctx)
}

func (runtime *exporterRuntime) destroyImages() error {
	if runtime.cleanup.destroyImages != nil {
		return runtime.cleanup.destroyImages()
	}
	if runtime.images == nil {
		return errors.New("exporter image lease handle is absent")
	}
	return runtime.images.Destroy()
}

func (runtime *exporterRuntime) releaseCID(cid uint32) bool {
	if runtime.cleanup.releaseCID != nil {
		return runtime.cleanup.releaseCID(cid)
	}
	return runtime.stack != nil && runtime.stack.CIDs != nil && runtime.stack.CIDs.Release(cid)
}

func (runtime *exporterRuntime) cleanupDirectories() error {
	if runtime.cleanup.cleanupDirectories != nil {
		return runtime.cleanup.cleanupDirectories()
	}
	if runtime.directories == nil {
		return errors.New("exporter runtime directory handle is absent")
	}
	return runtime.directories.Cleanup()
}

func (runtime *exporterRuntime) expectation() *privatevmv1.USBDeviceExpectation {
	return &privatevmv1.USBDeviceExpectation{EnrollmentId: runtime.enrollment.EnrollmentID, VendorId: runtime.enrollment.Identity.VendorID, ProductId: runtime.enrollment.Identity.ProductID, Serial: runtime.enrollment.Identity.Serial, CapacityBytes: runtime.enrollment.Identity.Capacity}
}

func (runtime *exporterRuntime) context(requestID string) *privatevmv1.GuestContext {
	return &privatevmv1.GuestContext{Context: &privatevmv1.RequestContext{ApiVersion: &privatevmv1.ApiVersion{Major: guest.APIMajor, Minor: guest.APIMinor}, RequestId: requestID, SessionId: runtime.request.Snapshot.ID}, ExpectedRole: privatevmv1.GuestRole_GUEST_ROLE_EXPORTER}
}

type exporterDestinationWriter struct {
	runtime      *exporterRuntime
	stream       grpc.ClientStreamingClient[privatevmv1.TransferFrame, privatevmv1.USBTransferReceipt]
	cancel       context.CancelFunc
	transferID   string
	expectedSize uint64
	next         uint64
	closed       bool
}

func (writer *exporterDestinationWriter) WriteChunk(_ context.Context, sequence uint64, data []byte) error {
	if writer.closed || sequence != writer.next || len(data) == 0 || len(data) > transfer.DefaultMaxChunk {
		return errors.New("exporter relay chunk is invalid")
	}
	copy := append([]byte(nil), data...)
	err := writer.stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Sequence: sequence, Data: copy}}})
	clear(copy)
	if err == nil {
		writer.next++
	}
	return err
}

func (writer *exporterDestinationWriter) Commit(ctx context.Context, total uint64, expected usb.Digest) (usb.DestinationEvidence, error) {
	if writer.closed || total != writer.expectedSize {
		return usb.DestinationEvidence{}, errors.New("exporter relay total is invalid")
	}
	var digest []byte
	if err := expected.WithBytes(func(value []byte) error { digest = append([]byte(nil), value...); return nil }); err != nil {
		return usb.DestinationEvidence{}, err
	}
	if err := writer.stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{TotalSize: total, Digest: &privatevmv1.Hash{Algorithm: "sha256", Value: digest}}}}); err != nil {
		clear(digest)
		return usb.DestinationEvidence{}, err
	}
	clear(digest)
	received, err := writer.stream.CloseAndRecv()
	writer.closed = true
	writer.cancel()
	if err != nil {
		return usb.DestinationEvidence{}, err
	}
	verified, err := writer.runtime.client.VerifyWrittenFile(ctx, &privatevmv1.VerifyExportRequest{Context: writer.runtime.context(writer.transferID), TransferId: writer.transferID})
	if err != nil {
		return usb.DestinationEvidence{}, err
	}
	receivedDigest, err := digestFromProto(received.GetReceiverDigest())
	if err != nil {
		return usb.DestinationEvidence{}, err
	}
	rereadDigest, err := digestFromProto(verified.GetRereadDigest())
	if err != nil {
		return usb.DestinationEvidence{}, err
	}
	return usb.DestinationEvidence{BytesWritten: total, ReceivedDigest: receivedDigest, RereadDigest: rereadDigest, FileSynced: received.GetFileSynced(), FilesystemSynced: received.GetFilesystemSynced(), AtomicRename: received.GetAtomicRename()}, nil
}

func (writer *exporterDestinationWriter) Abort(context.Context) error {
	if writer.closed {
		return nil
	}
	writer.closed = true
	writer.cancel()
	return nil
}

func digestFromProto(value *privatevmv1.Hash) (usb.Digest, error) {
	if value == nil || value.GetAlgorithm() != "sha256" || len(value.GetValue()) != sha256.Size {
		return usb.Digest{}, errors.New("exporter digest evidence is invalid")
	}
	var digest [sha256.Size]byte
	copy(digest[:], value.GetValue())
	result := usb.NewDigest(digest)
	clear(digest[:])
	return result, nil
}

func exporterRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "host-" + hex.EncodeToString(value[:]), nil
}

func sameExporterClaim(left, right usb.Claim) bool {
	return left.ID == right.ID && left.EnrollmentID == right.EnrollmentID && left.SessionID == right.SessionID && left.OwnerUID == right.OwnerUID && left.Device.Bus == right.Device.Bus && left.Device.Address == right.Device.Address && left.Device.DeviceID == right.Device.DeviceID
}

var _ usb.ExporterRuntimeCoordinator = (*ExporterRuntimeStack)(nil)
var _ usb.ExporterRuntime = (*exporterRuntime)(nil)
