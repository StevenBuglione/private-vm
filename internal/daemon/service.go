package daemon

import (
	"context"
	"errors"
	"io"
	"regexp"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/buildinfo"
	"github.com/StevenBuglione/private-vm/internal/config"
	"github.com/StevenBuglione/private-vm/internal/preflight"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/usb"
	"github.com/StevenBuglione/private-vm/internal/vpn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	protocolMajor               = 1
	protocolMinor               = 0
	maximumVPNProfileChunkBytes = 16 << 10
	maximumVPNProfileFrames     = 64
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)

type Service struct {
	privatevmv1.UnimplementedPrivateVMDaemonServiceServer
	Sessions              *session.Manager
	Config                config.Config
	DoctorRun             func(context.Context, bool) preflight.Report
	Polkit                Polkit
	Profiles              *vpn.MemoryStore
	VPNResolver           *vpn.EndpointResolver
	USBEnrollments        USBEnrollmentStore
	USBRegistry           USBRegistry
	USBClaims             USBClaimCoordinator
	USBWorkflows          USBWorkflowOrchestrator
	Roles                 RoleOrchestrator
	Torrents              TorrentOrchestrator
	Scanners              ScannerOrchestrator
	WorkspaceDestinations WorkspaceDestinationProvider
	roleOperations        *roleOperationSet
	afterCreate           func()
	cleanupCanceledCreate func(context.Context, string, uint32) error
}

// USBEnrollmentStore and USBClaimCoordinator form the complete semantic USB
// boundary exposed to the privileged service. Neither interface permits an
// arbitrary device path, mount request, USBGuard rule or command argument.
type USBEnrollmentStore interface {
	Load() (usb.Enrollment, error)
}

type USBRegistry interface {
	List(context.Context, uint32) ([]usb.DeviceStatus, error)
	Inspect(context.Context, uint32, string) (usb.DeviceStatus, error)
	Enroll(context.Context, uint32, string, string, bool) (usb.EnrollmentStatus, error)
	Get(context.Context, uint32) (usb.EnrollmentStatus, error)
	Verify(context.Context, uint32) (usb.EnrollmentStatus, error)
	Forget(context.Context, uint32) error
	Load(uint32) (usb.Enrollment, error)
}

type USBClaimCoordinator interface {
	Claim(context.Context, string, uint32, usb.Enrollment) (usb.Claim, error)
	Revalidate(context.Context, string, string, uint32, usb.Enrollment) (usb.Claim, error)
	Release(context.Context, string, string, uint32) error
	CleanupSession(context.Context, string, uint32) error
	AuditAbsent(context.Context, string, string, uint32) error
	AuditSessionAbsent(context.Context, string, uint32) error
}

func (s *Service) GetVersion(context.Context, *privatevmv1.Empty) (*privatevmv1.VersionResponse, error) {
	info := buildinfo.Current()
	return &privatevmv1.VersionResponse{Version: info.Version, Commit: info.Commit, ApiVersion: apiVersion()}, nil
}

func (s *Service) Doctor(ctx context.Context, request *privatevmv1.DoctorRequest) (*privatevmv1.DoctorResponse, error) {
	if err := validateRequestContext(request.GetContext(), false); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, sessionError(err)
	}
	run := s.DoctorRun
	if run == nil {
		run = func(ctx context.Context, strict bool) preflight.Report {
			return preflight.Doctor{Strict: strict}.RunContext(ctx)
		}
	}
	report := run(ctx, s.Config.Strict() || request.GetStrict())
	if err := ctx.Err(); err != nil {
		return nil, sessionError(err)
	}
	return &privatevmv1.DoctorResponse{Diagnostics: diagnosticsToProto(report.Diagnostics), Runnable: report.Runnable}, nil
}

func (s *Service) PlanSession(ctx context.Context, request *privatevmv1.PlanSessionRequest) (*privatevmv1.PlanSessionResponse, error) {
	if err := validateRequestContext(request.GetContext(), false); err != nil {
		return nil, err
	}
	role, err := roleFromProto(request.GetRole())
	if err != nil {
		return nil, err
	}
	if err := validateSelectors(role, request.GetImageBundle(), request.GetPolicyName(), s.Config); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, sessionError(err)
	}
	resources, err := validateResources(request.GetResources(), resourceDefaults(role, s.Config))
	if err != nil {
		return nil, err
	}
	run := s.DoctorRun
	if run == nil {
		run = func(ctx context.Context, strict bool) preflight.Report {
			return preflight.Doctor{Strict: strict}.RunContext(ctx)
		}
	}
	report := run(ctx, true)
	if err := ctx.Err(); err != nil {
		return nil, sessionError(err)
	}
	return &privatevmv1.PlanSessionResponse{
		Diagnostics: diagnosticsToProto(report.Diagnostics), ResolvedResources: resources, Runnable: report.Runnable,
	}, nil
}

func (s *Service) CreateSession(ctx context.Context, request *privatevmv1.CreateSessionRequest) (*privatevmv1.Session, error) {
	if err := validateRequestContext(request.GetContext(), false); err != nil {
		return nil, err
	}
	role, err := roleFromProto(request.GetRole())
	if err != nil {
		return nil, err
	}
	if err := validateSelectors(role, request.GetImageBundle(), request.GetPolicyName(), s.Config); err != nil {
		return nil, err
	}
	resources, err := validateResources(request.GetResources(), resourceDefaults(role, s.Config))
	if err != nil {
		return nil, err
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, sessionError(err)
	}
	snapshot, err := s.Sessions.Create(identity.UID, role)
	if err != nil {
		return nil, sessionError(err)
	}
	if s.afterCreate != nil {
		s.afterCreate()
	}
	if s.Roles != nil {
		plan := session.LaunchPlan{
			Role: role, ImageBundle: resolvedBundle(role, request.GetImageBundle(), s.Config),
			PolicyName: request.GetPolicyName(), VCPUs: resources.GetVcpus(),
			MemoryBytes: resources.GetMemoryBytes(), RootBytes: resources.GetRootBytes(),
			ScratchBytes: resources.GetScratchBytes(),
		}
		allocation := s.Roles.PlanAllocation(snapshot, plan)
		if allocation == nil {
			return nil, s.cleanupFailedCreate(snapshot, identity.UID, errors.New("role plan allocation is unavailable"))
		}
		if err := s.Sessions.AcquireResource(ctx, snapshot.ID, identity.UID, "session-plan", allocation); err != nil {
			return nil, s.cleanupFailedCreate(snapshot, identity.UID, err)
		}
	}
	if err := ctx.Err(); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cleanup := func(ctx context.Context, id string, ownerUID uint32) error {
			_, cleanupErr := s.Sessions.Cleanup(ctx, id, ownerUID)
			return cleanupErr
		}
		if s.cleanupCanceledCreate != nil {
			cleanup = s.cleanupCanceledCreate
		}
		if cleanupErr := cleanup(cleanupCtx, snapshot.ID, identity.UID); cleanupErr != nil {
			return nil, sessionError(cleanupErr)
		}
		return nil, sessionError(err)
	}
	return sessionToProto(snapshot), nil
}

func (s *Service) cleanupFailedCreate(snapshot session.Snapshot, ownerUID uint32, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, cleanupErr := s.Sessions.Cleanup(cleanupCtx, snapshot.ID, ownerUID); cleanupErr != nil {
		return sessionError(session.ErrCleanupIncomplete)
	}
	return sessionError(cause)
}

func (s *Service) GetSession(ctx context.Context, request *privatevmv1.GetSessionRequest) (*privatevmv1.Session, error) {
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return nil, err
	}
	if request.GetAfterSequence() != 0 {
		return nil, rpcError(codes.InvalidArgument, "EVENT_CURSOR_NOT_ALLOWED", "An event cursor is not valid for GetSession.", "Use after_sequence only with StreamEvents.", false)
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	snapshot, err := s.Sessions.Get(request.GetContext().GetSessionId(), identity.UID)
	if err != nil {
		return nil, sessionError(err)
	}
	return sessionToProto(snapshot), nil
}

func (s *Service) ListSessions(ctx context.Context, request *privatevmv1.ListSessionsRequest) (*privatevmv1.ListSessionsResponse, error) {
	if err := validateRequestContext(request.GetContext(), false); err != nil {
		return nil, err
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	snapshots := s.Sessions.List(identity.UID)
	result := &privatevmv1.ListSessionsResponse{Sessions: make([]*privatevmv1.Session, 0, len(snapshots))}
	for _, snapshot := range snapshots {
		result.Sessions = append(result.Sessions, sessionToProto(snapshot))
	}
	return result, nil
}

func (s *Service) ImportVPNProfile(stream privatevmv1.PrivateVMDaemonService_ImportVPNProfileServer) error {
	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return sessionError(err)
		}
		return rpcError(codes.InvalidArgument, "VPN_PROFILE_BEGIN_REQUIRED", "The first VPN import frame must contain its request context and profile name.", "Start the bounded stream with VPNProfileImportBegin.", false)
	}
	if first.GetBegin() == nil {
		if chunk := first.GetChunk(); chunk != nil {
			clear(chunk.Data)
		}
		return rpcError(codes.InvalidArgument, "VPN_PROFILE_BEGIN_REQUIRED", "The first VPN import frame must contain its request context and profile name.", "Start the bounded stream with VPNProfileImportBegin.", false)
	}
	ctx, err := requestContextWithMetadata(stream.Context(), first.GetBegin().GetContext(), false)
	if err != nil {
		return err
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return sessionError(err)
	}
	if s.Profiles == nil {
		return vpnRPCError(vpn.ErrStoreClosed)
	}
	buffer := make([]byte, vpn.MaximumProfileBytes+1)
	defer func() { clear(buffer) }()
	used := 0
	frames := 0
	for {
		frame, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return sessionError(recvErr)
		}
		frames++
		chunk := frame.GetChunk()
		if chunk == nil || len(chunk.GetData()) == 0 || len(chunk.GetData()) > maximumVPNProfileChunkBytes || frames > maximumVPNProfileFrames {
			if chunk != nil {
				clear(chunk.Data)
			}
			return rpcError(codes.InvalidArgument, "VPN_PROFILE_STREAM_INVALID", "The VPN profile stream framing is invalid.", "Send one begin frame followed by at most 64 non-empty chunks of at most 16 KiB.", false)
		}
		data := chunk.Data
		if len(data) > len(buffer)-used {
			clear(data)
			return rpcError(codes.ResourceExhausted, "VPN_PROFILE_TOO_LARGE", "The VPN profile exceeds its 64 KiB limit.", "Generate a standard bounded Proton WireGuard profile.", false)
		}
		used += copy(buffer[used:], data)
		clear(data)
		if err := ctx.Err(); err != nil {
			return sessionError(err)
		}
	}
	if used == 0 || used > vpn.MaximumProfileBytes {
		return rpcError(codes.InvalidArgument, "VPN_PROFILE_INVALID", "The Proton WireGuard profile is invalid.", "Generate a current bounded Proton WireGuard profile and retry.", false)
	}
	if err := ctx.Err(); err != nil {
		return sessionError(err)
	}
	source, err := secret.New(buffer[:used])
	if err != nil {
		return vpnRPCError(err)
	}
	defer source.Destroy()
	status, err := s.Profiles.Import(identity.UID, first.GetBegin().GetProfileName(), source)
	if err != nil {
		return vpnRPCError(err)
	}
	return stream.SendAndClose(vpnStatusToProto(status))
}

func (s *Service) InspectVPNProfile(ctx context.Context, request *privatevmv1.VPNProfileRequest) (*privatevmv1.VPNProfileStatus, error) {
	if err := validateRequestContext(request.GetContext(), false); err != nil {
		return nil, err
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	if s.Profiles == nil {
		return nil, vpnRPCError(vpn.ErrStoreClosed)
	}
	return vpnStatusToProto(s.Profiles.Inspect(identity.UID, request.GetProfileName())), nil
}

func (s *Service) TestVPNProfile(ctx context.Context, request *privatevmv1.VPNProfileRequest) (*privatevmv1.VPNProfileStatus, error) {
	if err := validateRequestContext(request.GetContext(), false); err != nil {
		return nil, err
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	if s.Profiles == nil {
		return nil, vpnRPCError(vpn.ErrStoreClosed)
	}
	resolver := s.VPNResolver
	if resolver == nil {
		resolver = vpn.NewEndpointResolver()
	}
	_, status, err := s.Profiles.Resolve(ctx, identity.UID, request.GetProfileName(), resolver)
	if err != nil {
		return nil, vpnRPCError(err)
	}
	return vpnStatusToProto(status), nil
}

func (s *Service) RemoveVPNProfile(ctx context.Context, request *privatevmv1.VPNProfileRequest) (*privatevmv1.VPNProfileStatus, error) {
	if err := validateRequestContext(request.GetContext(), false); err != nil {
		return nil, err
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	if s.Profiles == nil {
		return nil, vpnRPCError(vpn.ErrStoreClosed)
	}
	if err := ctx.Err(); err != nil {
		return nil, sessionError(err)
	}
	s.Profiles.Remove(identity.UID, request.GetProfileName())
	return vpnStatusToProto(s.Profiles.Inspect(identity.UID, request.GetProfileName())), nil
}

func vpnStatusToProto(status vpn.Status) *privatevmv1.VPNProfileStatus {
	result := &privatevmv1.VPNProfileStatus{
		SchemaVersion: uint32(status.SchemaVersion),
		Present:       status.Present,
		Generation:    status.Generation,
		Rotation:      string(status.Rotation),
		Code:          status.Code,
		Remediation:   status.Remediation,
	}
	if status.Profile != nil {
		result.Ipv4Enabled = status.Profile.IPv4Enabled
		result.Ipv6Enabled = status.Profile.IPv6Enabled
		result.InterfaceAddressCount = uint32(status.Profile.InterfaceAddressCount)
		result.DnsServerCount = uint32(status.Profile.DNSServerCount)
	}
	return result
}

func (s *Service) StartRole(ctx context.Context, request *privatevmv1.StartRoleRequest) (*privatevmv1.Session, error) {
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return nil, err
	}
	if s.Roles == nil {
		return nil, unimplemented("Role launch")
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	lock := s.roleOperation(request.GetContext().GetSessionId())
	lock.Lock()
	defer lock.Unlock()
	snapshot, err := s.startRole(ctx, request.GetContext().GetSessionId(), identity.UID)
	if err != nil {
		return nil, roleStartRPCError(err)
	}
	return sessionToProto(*snapshot), nil
}

func (s *Service) StopRole(ctx context.Context, request *privatevmv1.StopRoleRequest) (*privatevmv1.Session, error) {
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return nil, err
	}
	if s.Roles == nil {
		return nil, unimplemented("Protected role stop")
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	id := request.GetContext().GetSessionId()
	lock := s.roleOperation(id)
	lock.Lock()
	defer lock.Unlock()
	snapshot, err := s.Sessions.Get(id, identity.UID)
	if err != nil {
		return nil, sessionError(err)
	}
	if snapshot.Phase != session.PhaseActive {
		return nil, sessionError(session.ErrInvalidTransition)
	}
	if snapshot.Role == session.RoleWorkstation {
		state, stateErr := s.Roles.WorkspaceState(ctx, snapshot)
		if stateErr != nil && !request.GetDiscardUnexported() {
			return nil, rpcError(codes.FailedPrecondition, "WORKSPACE_UNREACHABLE", "The workstation output state could not be verified.", "Restore the authenticated guest connection, or explicitly confirm destructive discard.", false)
		}
		if err := validateWorkspaceStop(state, request.GetRequireClean(), request.GetDiscardUnexported()); err != nil {
			return nil, err
		}
	}
	if _, err := s.Sessions.Transition(ctx, id, identity.UID, session.PhaseStopping); err != nil {
		return nil, sessionError(err)
	}
	return s.cleanupLocked(ctx, id)
}

func (s *Service) AbortSession(ctx context.Context, request *privatevmv1.AbortSessionRequest) (*privatevmv1.Session, error) {
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return nil, err
	}
	return s.cleanup(ctx, request.GetContext().GetSessionId())
}

func (s *Service) CleanupSession(ctx context.Context, request *privatevmv1.CleanupSessionRequest) (*privatevmv1.Session, error) {
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return nil, err
	}
	return s.cleanup(ctx, request.GetContext().GetSessionId())
}

func (s *Service) cleanup(ctx context.Context, id string) (*privatevmv1.Session, error) {
	lock := s.roleOperation(id)
	lock.Lock()
	defer lock.Unlock()
	return s.cleanupLocked(ctx, id)
}

func (s *Service) cleanupLocked(ctx context.Context, id string) (*privatevmv1.Session, error) {
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	snapshot, err := s.Sessions.Cleanup(ctx, id, identity.UID)
	if err != nil {
		return nil, sessionError(err)
	}
	return sessionToProto(snapshot), nil
}

func (s *Service) StreamEvents(request *privatevmv1.GetSessionRequest, stream privatevmv1.PrivateVMDaemonService_StreamEventsServer) error {
	ctx, err := requestContextWithMetadata(stream.Context(), request.GetContext(), true)
	if err != nil {
		return err
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return sessionError(err)
	}
	subscription, err := s.Sessions.Subscribe(ctx, request.GetContext().GetSessionId(), identity.UID, request.GetAfterSequence())
	if err != nil {
		return sessionError(err)
	}
	defer subscription.Close()
	snapshot := subscription.Snapshot()
	expected := request.GetAfterSequence() + 1
	send := func(event session.Event) error {
		if event.Sequence != expected {
			return sessionError(session.ErrEventCursor)
		}
		if err := stream.Send(eventToProto(snapshot, event)); err != nil {
			return sessionError(err)
		}
		expected++
		return nil
	}
	for _, event := range subscription.Replay() {
		if err := send(event); err != nil {
			return err
		}
	}
	for {
		select {
		case <-ctx.Done():
			return sessionError(ctx.Err())
		case event, ok := <-subscription.Events():
			if !ok {
				if err := subscription.Err(); err != nil {
					return sessionError(err)
				}
				return nil
			}
			if err := send(event); err != nil {
				return err
			}
		}
	}
}

func (s *Service) ClaimUSB(ctx context.Context, request *privatevmv1.ClaimUSBRequest) (*privatevmv1.USBClaim, error) {
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return nil, err
	}
	if s.USBEnrollments == nil && s.USBRegistry == nil || s.USBClaims == nil {
		return nil, rpcError(codes.Unavailable, "USB_INTEGRATION_UNAVAILABLE", "The exact USB claim integration is unavailable.", "Install and configure the USBGuard-backed exporter integration before retrying.", false)
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	id := request.GetContext().GetSessionId()
	lock := s.roleOperation(id)
	lock.Lock()
	defer lock.Unlock()

	snapshot, err := s.Sessions.Get(id, identity.UID)
	if err != nil {
		return nil, sessionError(err)
	}
	if snapshot.Role != session.RoleExporter || snapshot.Phase != session.PhaseCreated {
		return nil, rpcError(codes.FailedPrecondition, "USB_EXPORTER_SESSION_REQUIRED", "USB claims are permitted only for a newly created exporter session.", "Create a dedicated exporter session and claim the enrolled device before starting its guest.", false)
	}
	var enrollment usb.Enrollment
	if s.USBRegistry != nil {
		enrollment, err = s.USBRegistry.Load(identity.UID)
	} else {
		enrollment, err = s.USBEnrollments.Load()
	}
	if err != nil {
		return nil, usbRPCError(err)
	}
	if request.GetEnrollmentId() == "" || request.GetEnrollmentId() != enrollment.EnrollmentID {
		return nil, rpcError(codes.FailedPrecondition, "USB_IDENTITY_MISMATCH", "The requested USB enrollment does not match the reviewed record.", "Inspect the current enrollment and retry with its opaque enrollment ID.", false)
	}
	if snapshot.WorkflowState == "" {
		if _, err = s.Sessions.TransitionWorkflow(ctx, id, identity.UID, "PLANNED"); err != nil {
			return nil, sessionError(err)
		}
		snapshot.WorkflowState = "PLANNED"
	}
	if snapshot.WorkflowState == "PLANNED" {
		if _, err = s.Sessions.TransitionWorkflow(ctx, id, identity.UID, "USB_IDENTIFIED"); err != nil {
			return nil, sessionError(err)
		}
	} else if snapshot.WorkflowState != "USB_IDENTIFIED" {
		return nil, sessionError(session.ErrInvalidWorkflow)
	}

	var claim usb.Claim
	var allocationErr error
	allocate := func(operation context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		allocated, claimErr := s.USBClaims.Claim(operation, id, identity.UID, enrollment)
		if claimErr != nil {
			allocationErr = claimErr
			return func(cleanup context.Context) error {
					return s.USBClaims.CleanupSession(cleanup, id, identity.UID)
				}, func(audit context.Context) error {
					return s.USBClaims.AuditSessionAbsent(audit, id, identity.UID)
				}, claimErr
		}
		claim = allocated
		return func(cleanup context.Context) error {
				return s.USBClaims.Release(cleanup, claim.ID, id, identity.UID)
			}, func(audit context.Context) error {
				return s.USBClaims.AuditAbsent(audit, claim.ID, id, identity.UID)
			}, nil
	}
	if err := s.Sessions.AcquireResource(ctx, id, identity.UID, "usb-claim", allocate); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, cleanupErr := s.Sessions.Cleanup(cleanupCtx, id, identity.UID)
		cancel()
		if cleanupErr != nil {
			return nil, sessionError(session.ErrCleanupIncomplete)
		}
		if allocationErr != nil {
			return nil, usbRPCError(allocationErr)
		}
		return nil, usbRPCError(err)
	}
	if _, err := s.Sessions.TransitionWorkflow(ctx, id, identity.UID, "USB_CLAIMED"); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, cleanupErr := s.Sessions.Cleanup(cleanupCtx, id, identity.UID)
		cancel()
		if cleanupErr != nil {
			return nil, sessionError(session.ErrCleanupIncomplete)
		}
		return nil, sessionError(err)
	}
	return &privatevmv1.USBClaim{ClaimId: claim.ID, EnrollmentId: claim.EnrollmentID}, nil
}

func (s *Service) ReleaseUSB(ctx context.Context, request *privatevmv1.ReleaseUSBRequest) (*privatevmv1.Empty, error) {
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return nil, err
	}
	if s.USBClaims == nil {
		return nil, rpcError(codes.Unavailable, "USB_INTEGRATION_UNAVAILABLE", "The exact USB claim integration is unavailable.", "Install and configure the USBGuard-backed exporter integration before retrying.", false)
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	id := request.GetContext().GetSessionId()
	lock := s.roleOperation(id)
	lock.Lock()
	defer lock.Unlock()
	snapshot, err := s.Sessions.Get(id, identity.UID)
	if err != nil {
		return nil, sessionError(err)
	}
	if snapshot.Role != session.RoleExporter {
		return nil, rpcError(codes.FailedPrecondition, "USB_EXPORTER_SESSION_REQUIRED", "USB claims are permitted only for an exporter session.", "Use the exporter session that owns this claim.", false)
	}
	if request.GetClaimId() == "" {
		return nil, rpcError(codes.InvalidArgument, "USB_CLAIM_ID_REQUIRED", "An opaque USB claim ID is required.", "Use the claim ID returned by ClaimUSB for this exporter session.", false)
	}
	if err := s.USBClaims.Release(ctx, request.GetClaimId(), id, identity.UID); err != nil {
		return nil, usbRPCError(err)
	}
	if err := s.USBClaims.AuditAbsent(ctx, request.GetClaimId(), id, identity.UID); err != nil {
		return nil, usbRPCError(err)
	}
	return &privatevmv1.Empty{}, nil
}

func validateRequestContext(value *privatevmv1.RequestContext, requireSession bool) error {
	if value == nil || value.GetApiVersion() == nil || value.GetApiVersion().GetMajor() != protocolMajor || value.GetApiVersion().GetMinor() > protocolMinor {
		return rpcError(codes.FailedPrecondition, "PROTOCOL_VERSION_MISMATCH", "The client protocol is not compatible with this daemon.", "Upgrade private-vm and private-vmd together.", false)
	}
	if !requestIDPattern.MatchString(value.GetRequestId()) {
		return rpcError(codes.InvalidArgument, "REQUEST_ID_INVALID", "The request ID is missing or malformed.", "Use an opaque 8-128 character request identifier.", false)
	}
	if value.GetSessionId() != "" {
		if err := session.ValidateID(value.GetSessionId()); err != nil {
			return rpcError(codes.InvalidArgument, "SESSION_ID_INVALID", "The session ID is malformed.", "Use the opaque session ID returned by CreateSession.", false)
		}
	}
	if requireSession {
		if value.GetSessionId() == "" {
			return rpcError(codes.InvalidArgument, "SESSION_ID_REQUIRED", "A session ID is required.", "Supply an active session ID returned by CreateSession.", false)
		}
	}
	return nil
}

func validateResources(value, defaults *privatevmv1.ResourceRequest) (*privatevmv1.ResourceRequest, error) {
	if value == nil {
		return defaults, nil
	}
	copy := privatevmv1.ResourceRequest{
		Vcpus: value.GetVcpus(), MemoryBytes: value.GetMemoryBytes(),
		RootBytes: value.GetRootBytes(), ScratchBytes: value.GetScratchBytes(),
	}
	if copy.Vcpus == 0 {
		copy.Vcpus = defaults.GetVcpus()
	}
	if copy.MemoryBytes == 0 {
		copy.MemoryBytes = defaults.GetMemoryBytes()
	}
	if copy.RootBytes == 0 {
		copy.RootBytes = defaults.GetRootBytes()
	}
	if copy.Vcpus > 64 || copy.MemoryBytes < 512<<20 || copy.MemoryBytes > 256<<30 || copy.RootBytes > 2<<40 || copy.ScratchBytes > 16<<40 {
		return nil, rpcError(codes.InvalidArgument, "RESOURCE_REQUEST_INVALID", "Requested resources are outside supported bounds.", "Use at most 64 vCPUs, 256 GiB RAM, 2 TiB root and 16 TiB scratch.", false)
	}
	return &copy, nil
}

func resourceDefaults(role session.Role, snapshot config.Config) *privatevmv1.ResourceRequest {
	result := &privatevmv1.ResourceRequest{Vcpus: 4, MemoryBytes: 4 << 30, RootBytes: 32 << 30}
	switch role {
	case session.RoleWorkstation:
		result.Vcpus = snapshot.Desktop().VCPUs()
		result.MemoryBytes = snapshot.Desktop().MemoryBytes()
	case session.RoleExporter:
		result.Vcpus = 2
		result.MemoryBytes = 1 << 30
	}
	return result
}

func validateSelectors(role session.Role, bundle, policyName string, snapshot config.Config) error {
	if role == session.RoleWorkstation {
		if bundle == "" {
			bundle = snapshot.Desktop().Bundle()
		}
		if bundle != "basic" && bundle != "office" && bundle != "development" {
			return rpcError(codes.InvalidArgument, "IMAGE_BUNDLE_INVALID", "The workstation image bundle is unsupported.", "Choose basic, office, or development.", false)
		}
	} else if bundle != "" {
		return rpcError(codes.InvalidArgument, "IMAGE_BUNDLE_INVALID", "Image bundles apply only to workstation sessions.", "Omit the image bundle for non-workstation roles.", false)
	}
	if policyName != "" && policyName != "safe" && policyName != "quarantine" {
		return rpcError(codes.InvalidArgument, "POLICY_NAME_INVALID", "The policy name is unsupported.", "Choose safe or quarantine.", false)
	}
	return nil
}

func resolvedBundle(role session.Role, requested string, snapshot config.Config) string {
	if role != session.RoleWorkstation {
		return ""
	}
	if requested != "" {
		return requested
	}
	return snapshot.Desktop().Bundle()
}

type requestMetadata struct {
	requestID string
	sessionID string
}

type requestMetadataKey struct{}

type contextualDaemonRequest interface {
	GetContext() *privatevmv1.RequestContext
}

var unarySessionRequirement = map[string]bool{
	privatevmv1.PrivateVMDaemonService_Doctor_FullMethodName:                       false,
	privatevmv1.PrivateVMDaemonService_PlanSession_FullMethodName:                  false,
	privatevmv1.PrivateVMDaemonService_CreateSession_FullMethodName:                false,
	privatevmv1.PrivateVMDaemonService_GetSession_FullMethodName:                   true,
	privatevmv1.PrivateVMDaemonService_ListSessions_FullMethodName:                 false,
	privatevmv1.PrivateVMDaemonService_InspectVPNProfile_FullMethodName:            false,
	privatevmv1.PrivateVMDaemonService_TestVPNProfile_FullMethodName:               false,
	privatevmv1.PrivateVMDaemonService_RemoveVPNProfile_FullMethodName:             false,
	privatevmv1.PrivateVMDaemonService_ListUSBDevices_FullMethodName:               false,
	privatevmv1.PrivateVMDaemonService_InspectUSBDevice_FullMethodName:             false,
	privatevmv1.PrivateVMDaemonService_EnrollUSBDevice_FullMethodName:              false,
	privatevmv1.PrivateVMDaemonService_GetUSBEnrollment_FullMethodName:             false,
	privatevmv1.PrivateVMDaemonService_VerifyUSBEnrollment_FullMethodName:          false,
	privatevmv1.PrivateVMDaemonService_ForgetUSBEnrollment_FullMethodName:          false,
	privatevmv1.PrivateVMDaemonService_GetTorrentMetadata_FullMethodName:           true,
	privatevmv1.PrivateVMDaemonService_SelectTorrentFiles_FullMethodName:           true,
	privatevmv1.PrivateVMDaemonService_PauseTorrentDownload_FullMethodName:         true,
	privatevmv1.PrivateVMDaemonService_GetTorrentStatus_FullMethodName:             true,
	privatevmv1.PrivateVMDaemonService_SealTorrentQuarantine_FullMethodName:        true,
	privatevmv1.PrivateVMDaemonService_GetScannerStatus_FullMethodName:             true,
	privatevmv1.PrivateVMDaemonService_GetScannerReport_FullMethodName:             true,
	privatevmv1.PrivateVMDaemonService_ApproveScanner_FullMethodName:               true,
	privatevmv1.PrivateVMDaemonService_RejectScanner_FullMethodName:                true,
	privatevmv1.PrivateVMDaemonService_StartRole_FullMethodName:                    true,
	privatevmv1.PrivateVMDaemonService_StopRole_FullMethodName:                     true,
	privatevmv1.PrivateVMDaemonService_AbortSession_FullMethodName:                 true,
	privatevmv1.PrivateVMDaemonService_CleanupSession_FullMethodName:               true,
	privatevmv1.PrivateVMDaemonService_GetWorkspaceState_FullMethodName:            true,
	privatevmv1.PrivateVMDaemonService_VerifyWorkspaceExport_FullMethodName:        true,
	privatevmv1.PrivateVMDaemonService_ExportWorkspaceToDestination_FullMethodName: true,
	privatevmv1.PrivateVMDaemonService_ClaimUSB_FullMethodName:                     true,
	privatevmv1.PrivateVMDaemonService_PlanUSBPreparation_FullMethodName:           true,
	privatevmv1.PrivateVMDaemonService_ExportApprovedToUSB_FullMethodName:          true,
	privatevmv1.PrivateVMDaemonService_ReleaseUSB_FullMethodName:                   true,
}

func requestContextUnaryInterceptor(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if info.FullMethod == privatevmv1.PrivateVMDaemonService_GetVersion_FullMethodName {
		return handler(ctx, request)
	}
	requireSession, known := unarySessionRequirement[info.FullMethod]
	contextual, ok := request.(contextualDaemonRequest)
	if !known || !ok {
		return nil, rpcError(codes.Internal, "RPC_CONTEXT_CONTRACT_INVALID", "The daemon request contract is invalid.", "Install matching verified private-vm binaries.", false)
	}
	ctx, err := requestContextWithMetadata(ctx, contextual.GetContext(), requireSession)
	if err != nil {
		return nil, err
	}
	return handler(ctx, request)
}

func requestContextWithMetadata(ctx context.Context, value *privatevmv1.RequestContext, requireSession bool) (context.Context, error) {
	if err := validateRequestContext(value, requireSession); err != nil {
		return nil, err
	}
	metadata := requestMetadata{requestID: value.GetRequestId(), sessionID: value.GetSessionId()}
	return context.WithValue(ctx, requestMetadataKey{}, metadata), nil
}

func roleFromProto(role privatevmv1.GuestRole) (session.Role, error) {
	switch role {
	case privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION:
		return session.RoleWorkstation, nil
	case privatevmv1.GuestRole_GUEST_ROLE_DOWNLOADER:
		return session.RoleDownloader, nil
	case privatevmv1.GuestRole_GUEST_ROLE_SCANNER:
		return session.RoleScanner, nil
	case privatevmv1.GuestRole_GUEST_ROLE_EXPORTER:
		return session.RoleExporter, nil
	default:
		return "", rpcError(codes.InvalidArgument, "GUEST_ROLE_INVALID", "A supported guest role is required.", "Choose workstation, downloader, scanner, or exporter.", false)
	}
}

func roleToProto(role session.Role) privatevmv1.GuestRole {
	switch role {
	case session.RoleWorkstation:
		return privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION
	case session.RoleDownloader:
		return privatevmv1.GuestRole_GUEST_ROLE_DOWNLOADER
	case session.RoleScanner:
		return privatevmv1.GuestRole_GUEST_ROLE_SCANNER
	case session.RoleExporter:
		return privatevmv1.GuestRole_GUEST_ROLE_EXPORTER
	default:
		return privatevmv1.GuestRole_GUEST_ROLE_UNSPECIFIED
	}
}

func phaseToProto(phase session.Phase) privatevmv1.SessionPhase {
	switch phase {
	case session.PhaseCreated:
		return privatevmv1.SessionPhase_SESSION_PHASE_CREATED
	case session.PhasePreflighted:
		return privatevmv1.SessionPhase_SESSION_PHASE_PREFLIGHTED
	case session.PhaseImagesVerified:
		return privatevmv1.SessionPhase_SESSION_PHASE_IMAGES_VERIFIED
	case session.PhaseStorageReady:
		return privatevmv1.SessionPhase_SESSION_PHASE_STORAGE_READY
	case session.PhaseActive:
		return privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE
	case session.PhaseStopping:
		return privatevmv1.SessionPhase_SESSION_PHASE_STOPPING
	case session.PhaseAborting:
		return privatevmv1.SessionPhase_SESSION_PHASE_ABORTING
	case session.PhaseDestroying:
		return privatevmv1.SessionPhase_SESSION_PHASE_DESTROYING
	case session.PhaseDestroyed:
		return privatevmv1.SessionPhase_SESSION_PHASE_DESTROYED
	default:
		return privatevmv1.SessionPhase_SESSION_PHASE_UNSPECIFIED
	}
}

func sessionToProto(snapshot session.Snapshot) *privatevmv1.Session {
	return &privatevmv1.Session{Id: snapshot.ID, OwnerUid: snapshot.OwnerUID, Role: roleToProto(snapshot.Role), Phase: phaseToProto(snapshot.Phase), WorkflowState: snapshot.WorkflowState}
}

func eventToProto(snapshot session.Snapshot, event session.Event) *privatevmv1.SessionEvent {
	copy := snapshot
	copy.Phase = event.Phase
	copy.WorkflowState = event.WorkflowState
	return &privatevmv1.SessionEvent{
		Sequence: event.Sequence, EventCode: event.Code, Session: sessionToProto(copy),
		UnixNanos: event.Time.UnixNano(), SafeMessage: event.Message,
	}
}

func diagnosticsToProto(values []preflight.Diagnostic) []*privatevmv1.Diagnostic {
	result := make([]*privatevmv1.Diagnostic, 0, len(values))
	for _, diagnostic := range values {
		severity := privatevmv1.Diagnostic_SEVERITY_UNSPECIFIED
		switch diagnostic.Severity {
		case preflight.SeverityInfo:
			severity = privatevmv1.Diagnostic_SEVERITY_INFO
		case preflight.SeverityWarning:
			severity = privatevmv1.Diagnostic_SEVERITY_WARNING
		case preflight.SeverityBlocking:
			severity = privatevmv1.Diagnostic_SEVERITY_BLOCKING
		}
		result = append(result, &privatevmv1.Diagnostic{Code: diagnostic.Code, Severity: severity, Summary: diagnostic.Summary, Remediation: diagnostic.Remediation, Overridable: diagnostic.Overridable})
	}
	return result
}

func apiVersion() *privatevmv1.ApiVersion {
	return &privatevmv1.ApiVersion{Major: protocolMajor, Minor: protocolMinor}
}
