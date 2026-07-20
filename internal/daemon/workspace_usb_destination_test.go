package daemon

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/usb"
	"google.golang.org/grpc/codes"
)

type workspaceUSBEnrollmentFixture struct{ enrollment usb.Enrollment }

func (fixture workspaceUSBEnrollmentFixture) Load(uint32) (usb.Enrollment, error) {
	return fixture.enrollment, nil
}

type workspaceUSBClaimFixture struct {
	claim      usb.Claim
	calls      int
	beforeRead func()
}

func (fixture *workspaceUSBClaimFixture) RevalidateOnlySessionClaim(context.Context, string, uint32, usb.Enrollment) (usb.Claim, error) {
	fixture.calls++
	if fixture.beforeRead != nil {
		fixture.beforeRead()
	}
	return fixture.claim, nil
}

type workspaceUSBExporterFixture struct {
	resultErr error
	mismatch  bool
	calls     int
}

func (fixture *workspaceUSBExporterFixture) ExportWorkspaceDestination(ctx context.Context, _ session.Snapshot, _ string, source usb.ApprovedSource, enrollment usb.Enrollment) (usb.VerifiedExport, error) {
	fixture.calls++
	_ = source.Output()
	hasher := sha256.New()
	var written uint64
	for {
		chunk, err := source.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = source.Close()
			return usb.VerifiedExport{}, err
		}
		written += uint64(len(chunk.Data))
		_, _ = hasher.Write(chunk.Data)
	}
	if err := source.Close(); err != nil {
		return usb.VerifiedExport{}, err
	}
	if fixture.resultErr != nil {
		return usb.VerifiedExport{}, fixture.resultErr
	}
	var sum [sha256.Size]byte
	copy(sum[:], hasher.Sum(nil))
	if fixture.mismatch {
		sum[0] ^= 0xff
	}
	digest := usb.NewDigest(sum)
	return usb.VerifiedExport{
		Receipt: usb.ExportReceipt{
			SchemaVersion: usb.ExportReceiptSchemaVersion, EnrollmentID: enrollment.EnrollmentID, BytesWritten: written,
			ScannerRelayHashEqual: true, RelayExporterHashEqual: true, ExporterRereadHashEqual: true,
			FileSynced: true, FilesystemSynced: true, AtomicRename: true, USBUnmounted: true,
			USBDetached: true, ExporterStopped: true, CleanupComplete: true,
		},
		RereadDigest: digest,
	}, nil
}

func TestWorkspaceUSBProviderSuccessFailureCancellationTimeoutAndCleanup(t *testing.T) {
	for _, test := range []struct {
		name      string
		resultErr error
		mismatch  bool
		wantCode  codes.Code
		wantID    string
		verified  bool
	}{
		{name: "success", verified: true},
		{name: "write-failure", resultErr: errors.New("fixture write failure"), wantCode: codes.FailedPrecondition, wantID: "WORKSPACE_DESTINATION_FAILED"},
		{name: "reread-mismatch", mismatch: true, wantCode: codes.FailedPrecondition, wantID: "WORKSPACE_DESTINATION_FAILED"},
		{name: "canceled", resultErr: context.Canceled, wantCode: codes.Canceled, wantID: "REQUEST_CANCELED"},
		{name: "timeout", resultErr: context.DeadlineExceeded, wantCode: codes.DeadlineExceeded, wantID: "REQUEST_TIMEOUT"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, identity, workstation := activeWorkspaceSession(t)
			exporter := preparedWorkspaceUSBExporter(t, manager, identity.UID, true)
			enrollment := workspaceUSBEnrollment(t)
			roles := &workspaceServiceRoles{data: []byte("safe")}
			claims := &workspaceUSBClaimFixture{claim: usb.Claim{ID: "claim-fixture", EnrollmentID: enrollment.EnrollmentID, SessionID: exporter.ID, OwnerUID: identity.UID}}
			claims.beforeRead = func() {
				if roles.exported {
					t.Fatal("claim was not revalidated before source consumption")
				}
			}
			exportFlow := &workspaceUSBExporterFixture{resultErr: test.resultErr, mismatch: test.mismatch}
			service := &Service{Sessions: manager, Roles: roles}
			service.WorkspaceDestinations = &workspaceUSBProvider{
				service: service, enrollments: workspaceUSBEnrollmentFixture{enrollment}, claims: claims, exporter: exportFlow,
			}
			ctx := context.WithValue(t.Context(), identityContextKey{}, identity)
			state, err := service.ExportWorkspaceToDestination(ctx, workspaceDestinationRequest(workstation.ID, privatevmv1.WorkspaceExportDestination_WORKSPACE_EXPORT_DESTINATION_USB))
			if test.wantID == "" {
				if err != nil || state.GetState() != "READY" {
					t.Fatalf("state=%#v err=%v", state, err)
				}
			} else {
				assertRPCError(t, err, test.wantCode, test.wantID)
			}
			if claims.calls != 2 || exportFlow.calls != 1 || roles.verified != test.verified {
				t.Fatalf("claims=%d exports=%d verified=%v", claims.calls, exportFlow.calls, roles.verified)
			}
			destroyed, getErr := manager.Get(exporter.ID, identity.UID)
			if getErr != nil || destroyed.Phase != session.PhaseDestroyed {
				t.Fatalf("exporter cleanup=%#v err=%v", destroyed, getErr)
			}
		})
	}
}

func TestWorkspaceUSBProviderRejectsUnpreparedAndAmbiguousDestinationsBeforeSource(t *testing.T) {
	for _, test := range []struct {
		name     string
		prepared int
	}{
		{name: "unprepared", prepared: 0},
		{name: "ambiguous", prepared: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, identity, workstation := activeWorkspaceSession(t)
			if test.prepared == 0 {
				preparedWorkspaceUSBExporter(t, manager, identity.UID, false)
			} else {
				for range test.prepared {
					preparedWorkspaceUSBExporter(t, manager, identity.UID, true)
				}
			}
			enrollment := workspaceUSBEnrollment(t)
			roles := &workspaceServiceRoles{data: []byte("safe")}
			claims := &workspaceUSBClaimFixture{}
			exportFlow := &workspaceUSBExporterFixture{}
			service := &Service{Sessions: manager, Roles: roles}
			service.WorkspaceDestinations = &workspaceUSBProvider{
				service: service, enrollments: workspaceUSBEnrollmentFixture{enrollment}, claims: claims, exporter: exportFlow,
			}
			ctx := context.WithValue(t.Context(), identityContextKey{}, identity)
			_, err := service.ExportWorkspaceToDestination(ctx, workspaceDestinationRequest(workstation.ID, privatevmv1.WorkspaceExportDestination_WORKSPACE_EXPORT_DESTINATION_USB))
			assertRPCError(t, err, codes.FailedPrecondition, "WORKSPACE_DESTINATION_FAILED")
			if roles.exported || roles.verified || claims.calls != 0 || exportFlow.calls != 0 {
				t.Fatalf("source or destination opened: roles=%#v claims=%d exports=%d", roles, claims.calls, exportFlow.calls)
			}
		})
	}
}

func preparedWorkspaceUSBExporter(t *testing.T, manager *session.Manager, ownerUID uint32, ready bool) session.Snapshot {
	t.Helper()
	snapshot, err := manager.Create(ownerUID, session.RoleExporter)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []session.Phase{session.PhasePreflighted, session.PhaseImagesVerified, session.PhaseStorageReady, session.PhaseActive} {
		snapshot, err = manager.Transition(t.Context(), snapshot.ID, ownerUID, phase)
		if err != nil {
			t.Fatal(err)
		}
	}
	states := []string{"PLANNED", "USB_IDENTIFIED", "USB_CLAIMED", "EXPORTER_BOOTING", "GUEST_AUTHENTICATED", "NO_NETWORK_VERIFIED", "USB_ATTACHED"}
	if ready {
		states = append(states, "DESTINATION_PREPARED")
	}
	for _, state := range states {
		snapshot, err = manager.TransitionWorkflow(t.Context(), snapshot.ID, ownerUID, state)
		if err != nil {
			t.Fatal(err)
		}
	}
	return snapshot
}

func workspaceUSBEnrollment(t *testing.T) usb.Enrollment {
	t.Helper()
	enrollment, err := usb.NewEnrollment(usb.Identity{
		VendorID: "1234", ProductID: "5678", Serial: "fixture", USBGuardHash: "abcdefghijklmnop",
		Interfaces: []string{"08:06:50"}, Capacity: 64 << 20, PortPath: "1-2", Model: "fixture",
	}, "PRIVATE_VM_TRANSFER")
	if err != nil {
		t.Fatal(err)
	}
	return enrollment
}
