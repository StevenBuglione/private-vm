package daemon

import (
	"context"
	"io"
	"os"
	"slices"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/usb"
)

type usbWorkflowFixture struct {
	plan     usb.PreparePlan
	prepared bool
	exported bool
}

func (fixture *usbWorkflowFixture) PlanPreparation(_ context.Context, _ session.Snapshot, _ string, enrollment usb.Enrollment) (usb.PreparePlan, error) {
	fingerprint, _ := enrollment.Identity.Fingerprint()
	fixture.plan = usb.PreparePlan{SchemaVersion: usb.PrepareSchemaVersion, EnrollmentID: enrollment.EnrollmentID, Fingerprint: fingerprint,
		CapacityBytes: enrollment.Identity.Capacity, Filesystem: usb.DefaultFilesystem, Challenge: "0123456789abcdef0123456789abcdef",
		CreatedAt: time.Now().UTC(), FirstPrompt: "ERASE " + enrollment.EnrollmentID, SecondPrompt: "ERASE exact second confirmation"}
	return fixture.plan, nil
}

func (fixture *usbWorkflowFixture) Prepare(ctx context.Context, _ session.Snapshot, _ string, enrollment usb.Enrollment, challenge string, confirmation usb.Confirmation, passphrase *secret.Bytes, authorizer usb.PrepareAuthorizer) (usb.PrepareReceipt, error) {
	var size int
	_ = passphrase.WithReader(func(reader io.Reader) error {
		value, _ := io.ReadAll(reader)
		size = len(value)
		clear(value)
		return nil
	})
	if challenge != fixture.plan.Challenge || confirmation.First != fixture.plan.FirstPrompt || confirmation.Second != fixture.plan.SecondPrompt || size < 8 {
		return usb.PrepareReceipt{}, context.Canceled
	}
	if err := authorizer.AuthorizePrepare(ctx); err != nil {
		return usb.PrepareReceipt{}, err
	}
	fixture.prepared = true
	return usb.PrepareReceipt{SchemaVersion: usb.PrepareSchemaVersion, EnrollmentID: enrollment.EnrollmentID, Filesystem: usb.DefaultFilesystem,
		CapacityBytes: enrollment.Identity.Capacity, Fingerprint: fixture.plan.Fingerprint, State: usb.PrepareDestinationReady}, nil
}

func (fixture *usbWorkflowFixture) Export(_ context.Context, _ session.Snapshot, _ string, selection usb.SourceSelection, enrollment usb.Enrollment) (usb.ExportReceipt, error) {
	if selection.Role != usb.SourceScanner || selection.SessionID == "" || selection.OutputID == "" {
		return usb.ExportReceipt{}, context.Canceled
	}
	fixture.exported = true
	return usb.ExportReceipt{SchemaVersion: usb.ExportReceiptSchemaVersion, EnrollmentID: enrollment.EnrollmentID, BytesWritten: 64,
		ScannerRelayHashEqual: true, RelayExporterHashEqual: true, ExporterRereadHashEqual: true,
		FileSynced: true, FilesystemSynced: true, AtomicRename: true, USBUnmounted: true, USBDetached: true,
		ExporterStopped: true, CleanupComplete: true}, nil
}

func TestUSBSemanticPlanPrepareAndExportTransport(t *testing.T) {
	server, socket, _ := newUnstartedTestServer(t, 0)
	manager := server.options.Service.Sessions
	owner := uint32(os.Geteuid())
	exporter, err := manager.Create(owner, session.RoleExporter)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := usb.NewEnrollment(usb.Identity{VendorID: "1234", ProductID: "5678", Serial: "SERIAL", USBGuardHash: "abcdefghijklmnop",
		Interfaces: []string{"08:06:50"}, Capacity: 8 << 30, PortPath: "1-2", Model: "fixture"}, "EXPORT")
	if err != nil {
		t.Fatal(err)
	}
	claims := &usbClaimsFixture{claim: usb.Claim{ID: "usbclaim-0123456789abcdef0123456789abcdef", EnrollmentID: enrollment.EnrollmentID, SessionID: exporter.ID, OwnerUID: owner}}
	workflow := &usbWorkflowFixture{}
	scannerRuntime := &fakeScannerOrchestrator{}
	server.options.Service.USBEnrollments = usbEnrollmentFixture{enrollment: enrollment}
	server.options.Service.USBClaims = claims
	server.options.Service.USBWorkflows = workflow
	server.options.Service.Scanners = scannerRuntime
	done := startTestServer(t, server)
	connection, client := dialTestDaemon(t, socket)
	defer connection.Close()
	claim, err := client.ClaimUSB(t.Context(), &privatevmv1.ClaimUSBRequest{Context: validRequestContext(exporter.ID), EnrollmentId: enrollment.EnrollmentID})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := client.PlanUSBPreparation(t.Context(), &privatevmv1.PlanUSBPreparationRequest{Context: validRequestContext(exporter.ID), ClaimId: claim.GetClaimId()})
	if err != nil || plan.GetChallenge() == "" {
		t.Fatalf("plan=%v err=%v", plan, err)
	}
	stream, err := client.PrepareUSB(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&privatevmv1.HostUSBPrepareFrame{Frame: &privatevmv1.HostUSBPrepareFrame_Begin{Begin: &privatevmv1.HostUSBPrepareBegin{Context: validRequestContext(exporter.ID), ClaimId: claim.GetClaimId(), Challenge: plan.GetChallenge(), FirstConfirmation: plan.GetFirstConfirmation(), SecondConfirmation: plan.GetSecondConfirmation()}}}); err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("correct horse battery staple")
	if err := stream.Send(&privatevmv1.HostUSBPrepareFrame{Frame: &privatevmv1.HostUSBPrepareFrame_PassphraseChunk{PassphraseChunk: &privatevmv1.HostUSBPrepareSecretChunk{Data: append([]byte(nil), passphrase...)}}}); err != nil {
		t.Fatal(err)
	}
	receipt, err := stream.CloseAndRecv()
	if err != nil || receipt.GetState() != string(usb.PrepareDestinationReady) || !workflow.prepared {
		t.Fatalf("prepare=%v err=%v", receipt, err)
	}
	scanner, err := manager.Create(owner, session.RoleScanner)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []session.Phase{session.PhasePreflighted, session.PhaseImagesVerified, session.PhaseStorageReady, session.PhaseActive} {
		scanner, err = manager.Transition(t.Context(), scanner.ID, owner, phase)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, state := range []string{"UPDATE_VM_BOOTING", "DEFINITIONS_UPDATING", "DEFINITIONS_VERIFIED", "UPDATE_VM_STOPPED", "SCAN_VM_BOOTING_OFFLINE", "OFFLINE_VERIFIED", "QUARANTINE_ATTACHED_READ_ONLY", "INVENTORY_COMPLETE", "MALWARE_SCAN_COMPLETE", "RECONSTRUCTION_COMPLETE", "REPORT_COMPLETE", "POLICY_APPROVED"} {
		if _, err := manager.TransitionWorkflow(t.Context(), scanner.ID, owner, state); err != nil {
			t.Fatal(err)
		}
	}
	exported, err := client.ExportApprovedToUSB(t.Context(), &privatevmv1.USBExportRequest{Context: validRequestContext(exporter.ID), ClaimId: claim.GetClaimId(), ScannerSessionId: scanner.ID, OutputId: "output-12345678"})
	if err != nil || !exported.GetCleanupComplete() || !workflow.exported {
		t.Fatalf("export=%v err=%v", exported, err)
	}
	current, _ := manager.Get(exporter.ID, owner)
	if current.WorkflowState != "EXPORTER_STOPPED" {
		t.Fatalf("workflow=%s", current.WorkflowState)
	}
	cleanedScanner, scannerErr := manager.Get(scanner.ID, owner)
	if scannerErr != nil || cleanedScanner.Phase != session.PhaseDestroyed || !slices.Contains(scannerRuntime.log(), "stop-offline") {
		t.Fatalf("scanner cleanup=%+v log=%v err=%v", cleanedScanner, scannerRuntime.log(), scannerErr)
	}
	stopTestServer(t, server, done)
}
