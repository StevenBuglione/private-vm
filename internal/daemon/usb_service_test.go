package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/usb"
	"google.golang.org/grpc/codes"
)

type usbEnrollmentFixture struct {
	enrollment usb.Enrollment
	err        error
}

func (s usbEnrollmentFixture) Load() (usb.Enrollment, error) { return s.enrollment, s.err }

type usbClaimsFixture struct {
	claim       usb.Claim
	claimErr    error
	present     bool
	cleanupRuns int
	releaseRuns int
}

func (f *usbClaimsFixture) Claim(context.Context, string, uint32, usb.Enrollment) (usb.Claim, error) {
	f.present = true
	return f.claim, f.claimErr
}

func (f *usbClaimsFixture) Release(context.Context, string, string, uint32) error {
	f.releaseRuns++
	f.present = false
	return nil
}

func (f *usbClaimsFixture) CleanupSession(context.Context, string, uint32) error {
	f.cleanupRuns++
	f.present = false
	return nil
}

func (f *usbClaimsFixture) AuditAbsent(context.Context, string, string, uint32) error {
	if f.present {
		return errors.New("claim remains")
	}
	return nil
}

func (f *usbClaimsFixture) AuditSessionAbsent(context.Context, string, uint32) error {
	if f.present {
		return errors.New("session claim remains")
	}
	return nil
}

func usbServiceFixture(t *testing.T, role session.Role, claims *usbClaimsFixture) (*Service, context.Context, session.Snapshot, usb.Enrollment) {
	t.Helper()
	store, err := session.NewStore(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(store, 4)
	if err != nil {
		t.Fatal(err)
	}
	identity := currentProcessIdentity(t)
	snapshot, err := manager.Create(identity.UID, role)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := usb.NewEnrollment(usb.Identity{
		VendorID: "1234", ProductID: "5678", Serial: "SERIAL",
		USBGuardHash: "abcdefghijklmnop", Interfaces: []string{"08:06:50"},
		Capacity: 8 << 30, PortPath: "1-2", Model: "fixture",
	}, "EXPORT")
	if err != nil {
		t.Fatal(err)
	}
	claims.claim = usb.Claim{ID: "usbclaim-0123456789abcdef0123456789abcdef", EnrollmentID: enrollment.EnrollmentID, SessionID: snapshot.ID, OwnerUID: identity.UID}
	service := &Service{Sessions: manager, USBEnrollments: usbEnrollmentFixture{enrollment: enrollment}, USBClaims: claims}
	ctx := context.WithValue(t.Context(), identityContextKey{}, identity)
	return service, ctx, snapshot, enrollment
}

func TestUSBClaimIsExporterSessionOwnedAndReleaseIsIdempotent(t *testing.T) {
	claims := &usbClaimsFixture{}
	service, ctx, snapshot, enrollment := usbServiceFixture(t, session.RoleExporter, claims)
	requestContext := validRequestContext(snapshot.ID)
	claimed, err := service.ClaimUSB(ctx, &privatevmv1.ClaimUSBRequest{Context: requestContext, EnrollmentId: enrollment.EnrollmentID})
	if err != nil {
		t.Fatal(err)
	}
	if claimed.GetClaimId() != claims.claim.ID || !claims.present {
		t.Fatalf("claim = %+v, present=%v", claimed, claims.present)
	}
	current, err := service.Sessions.Get(snapshot.ID, snapshot.OwnerUID)
	if err != nil || current.WorkflowState != "USB_CLAIMED" {
		t.Fatalf("workflow = %q, err=%v", current.WorkflowState, err)
	}
	if _, err := service.ReleaseUSB(ctx, &privatevmv1.ReleaseUSBRequest{Context: requestContext, ClaimId: claimed.GetClaimId()}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Sessions.Cleanup(t.Context(), snapshot.ID, snapshot.OwnerUID); err != nil {
		t.Fatal(err)
	}
	if claims.releaseRuns != 2 || claims.present {
		t.Fatalf("release runs=%d present=%v", claims.releaseRuns, claims.present)
	}
}

func TestUSBClaimFailureRunsSessionOwnedPartialCleanup(t *testing.T) {
	claims := &usbClaimsFixture{claimErr: errors.New("fixture acquisition failed")}
	service, ctx, snapshot, enrollment := usbServiceFixture(t, session.RoleExporter, claims)
	_, err := service.ClaimUSB(ctx, &privatevmv1.ClaimUSBRequest{Context: validRequestContext(snapshot.ID), EnrollmentId: enrollment.EnrollmentID})
	assertRPCError(t, err, codes.Internal, "INTERNAL_ERROR")
	if claims.cleanupRuns != 1 || claims.present {
		t.Fatalf("cleanup runs=%d present=%v", claims.cleanupRuns, claims.present)
	}
	current := service.Sessions.List(snapshot.OwnerUID)
	if len(current) != 0 {
		t.Fatalf("failed claim left %d active session records", len(current))
	}
}

func TestUSBClaimRejectsWrongRoleAndEnrollmentBeforeAcquisition(t *testing.T) {
	claims := &usbClaimsFixture{}
	service, ctx, snapshot, enrollment := usbServiceFixture(t, session.RoleWorkstation, claims)
	_, err := service.ClaimUSB(ctx, &privatevmv1.ClaimUSBRequest{Context: validRequestContext(snapshot.ID), EnrollmentId: enrollment.EnrollmentID})
	assertRPCError(t, err, codes.FailedPrecondition, "USB_EXPORTER_SESSION_REQUIRED")
	if claims.present {
		t.Fatal("wrong role reached USB acquisition")
	}

	claims = &usbClaimsFixture{}
	service, ctx, snapshot, _ = usbServiceFixture(t, session.RoleExporter, claims)
	_, err = service.ClaimUSB(ctx, &privatevmv1.ClaimUSBRequest{Context: validRequestContext(snapshot.ID), EnrollmentId: "usb-0000000000000000"})
	assertRPCError(t, err, codes.FailedPrecondition, "USB_IDENTITY_MISMATCH")
	if claims.present {
		t.Fatal("mismatched enrollment reached USB acquisition")
	}
}
