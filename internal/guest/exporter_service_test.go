package guest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/transfer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type exporterAdapterFixture struct {
	expected     ExporterDeviceExpectation
	data         []byte
	cleanup      int
	blockInspect bool
}

func (adapter *exporterAdapterFixture) Inspect(ctx context.Context, expected ExporterDeviceExpectation) (ExporterDeviceEvidence, error) {
	if adapter.blockInspect {
		<-ctx.Done()
		return ExporterDeviceEvidence{}, ctx.Err()
	}
	adapter.expected = expected
	return ExporterDeviceEvidence{Expectation: expected, NoNetwork: true, HostPathAbsent: true, SingleDevice: true, MassStorageOnly: true}, nil
}
func (*exporterAdapterFixture) Prepare(_ context.Context, value *secret.Bytes) (ExporterPrepareEvidence, error) {
	if value == nil {
		return ExporterPrepareEvidence{}, errors.New("missing")
	}
	return ExporterPrepareEvidence{IdentityVerified: true, LUKS2: true, Ext4: true, Mounted: true}, nil
}
func (adapter *exporterAdapterFixture) BeginWrite(_ context.Context, _ transfer.Header, _ string) (ExporterWriter, error) {
	return &exporterWriterFixture{adapter: adapter}, nil
}
func (adapter *exporterAdapterFixture) Reread(context.Context, string) ([sha256.Size]byte, error) {
	return sha256.Sum256(adapter.data), nil
}
func (*exporterAdapterFixture) Finalize(context.Context) (ExporterFinalizeEvidence, error) {
	return ExporterFinalizeEvidence{Unmounted: true, LUKSClosed: true}, nil
}
func (adapter *exporterAdapterFixture) Cleanup(context.Context) error {
	adapter.cleanup++
	adapter.data = nil
	return nil
}

type exporterWriterFixture struct {
	adapter  *exporterAdapterFixture
	sequence uint64
}

func (writer *exporterWriterFixture) WriteChunk(_ context.Context, sequence uint64, data []byte) error {
	if sequence != writer.sequence {
		return errors.New("sequence")
	}
	writer.adapter.data = append(writer.adapter.data, data...)
	writer.sequence++
	return nil
}
func (writer *exporterWriterFixture) Commit(_ context.Context, size uint64, digest [sha256.Size]byte) (ExporterWriteEvidence, error) {
	actual := sha256.Sum256(writer.adapter.data)
	if uint64(len(writer.adapter.data)) != size || actual != digest {
		return ExporterWriteEvidence{}, errors.New("digest")
	}
	return ExporterWriteEvidence{ReceiverDigest: actual, FileSynced: true, FilesystemSynced: true, AtomicRename: true}, nil
}
func (writer *exporterWriterFixture) Abort(context.Context) error {
	writer.adapter.data = nil
	return nil
}

func TestExporterAuthenticatedPrepareWriteVerifyFinalize(t *testing.T) {
	token := mustToken(t, 0x71)
	config := testConfig(t, session.RoleExporter, token)
	adapter := &exporterAdapterFixture{}
	service, err := NewExporterService(ExporterServiceConfig{Identity: config.Identity, Adapter: adapter})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close(t.Context()) })
	config.Exporter = service
	_, connection := startTestServer(t, config, token)
	client := privatevmv1.NewExporterGuestServiceClient(connection)
	expected := &privatevmv1.USBDeviceExpectation{EnrollmentId: "usb-0123456789abcdef", VendorId: "1234", ProductId: "5678", Serial: "serial", CapacityBytes: 8 << 30}
	ctx := helloRequest(session.RoleExporter, APIMajor, APIMinor).GetContext()
	statusValue, err := client.InspectUSB(t.Context(), &privatevmv1.ExporterRequest{Context: ctx, ExpectedDevice: expected})
	if err != nil || !statusValue.GetIdentityVerified() || !statusValue.GetNoNetwork() {
		t.Fatalf("inspect=%v err=%v", statusValue, err)
	}
	prepare, err := client.PrepareExactUSB(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := prepare.Send(&privatevmv1.PrepareUSBFrame{Frame: &privatevmv1.PrepareUSBFrame_Begin{Begin: &privatevmv1.PrepareUSBBegin{Context: ctx, ExpectedDevice: expected}}}); err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("correct horse battery staple")
	frameData := append([]byte(nil), passphrase...)
	if err := prepare.Send(&privatevmv1.PrepareUSBFrame{Frame: &privatevmv1.PrepareUSBFrame_PassphraseChunk{PassphraseChunk: &privatevmv1.PrepareUSBSecretChunk{Data: frameData}}}); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepare.CloseAndRecv()
	if err != nil || !prepared.GetLuks2() || !prepared.GetExt4() {
		t.Fatalf("prepare=%v err=%v", prepared, err)
	}
	content := []byte("approved reconstructed output")
	digest := sha256.Sum256(content)
	write, err := client.WriteVerifiedFile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	begin := &privatevmv1.TransferBegin{Context: ctx.GetContext(), TransferId: "transfer-12345678", Descriptor_: &privatevmv1.FileDescriptor{LogicalName: "approved.bin", SizeBytes: uint64(len(content)), DetectedMime: "application/octet-stream", Digest: protoSHA256(digest)}}
	if err := write.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: begin}}); err != nil {
		t.Fatal(err)
	}
	if err := write.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Data: append([]byte(nil), content...)}}}); err != nil {
		t.Fatal(err)
	}
	if err := write.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{TotalSize: uint64(len(content)), Digest: protoSHA256(digest)}}}); err != nil {
		t.Fatal(err)
	}
	receipt, err := write.CloseAndRecv()
	if err != nil || !receipt.GetFileSynced() || !receipt.GetFilesystemSynced() || !receipt.GetAtomicRename() {
		t.Fatalf("write=%v err=%v", receipt, err)
	}
	verified, err := client.VerifyWrittenFile(t.Context(), &privatevmv1.VerifyExportRequest{Context: ctx, TransferId: begin.TransferId})
	if err != nil || !bytes.Equal(verified.GetReceiverDigest().GetValue(), verified.GetRereadDigest().GetValue()) {
		t.Fatalf("verify=%v err=%v", verified, err)
	}
	finalized, err := client.FinalizeUSB(t.Context(), &privatevmv1.ExporterRequest{Context: ctx, ExpectedDevice: expected})
	if err != nil || !finalized.GetUnmounted() || !finalized.GetLuksClosed() {
		t.Fatalf("finalize=%v err=%v", finalized, err)
	}
}

func TestExporterFailureTimeoutAndCleanupAreFailClosed(t *testing.T) {
	identity := testConfig(t, session.RoleExporter, mustToken(t, 0x72)).Identity
	adapter := &exporterAdapterFixture{blockInspect: true}
	service, err := NewExporterService(ExporterServiceConfig{Identity: identity, Adapter: adapter, OperationTimeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	request := &privatevmv1.ExporterRequest{Context: helloRequest(session.RoleExporter, APIMajor, APIMinor).GetContext(), ExpectedDevice: &privatevmv1.USBDeviceExpectation{EnrollmentId: "usb-0123456789abcdef", VendorId: "1234", ProductId: "5678", CapacityBytes: 1}}
	_, err = service.InspectUSB(t.Context(), request)
	if status.Code(err) != codes.DeadlineExceeded || !strings.Contains(err.Error(), "USB_EXPORTER_IDENTITY_MISMATCH") || adapter.cleanup != 1 {
		t.Fatalf("error=%v cleanup=%d", err, adapter.cleanup)
	}
	if err := service.Close(t.Context()); err != nil || adapter.cleanup != 2 {
		t.Fatalf("close=%v cleanup=%d", err, adapter.cleanup)
	}
}
