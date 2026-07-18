package daemon

import (
	"context"
	"errors"
	"regexp"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/buildinfo"
	"github.com/StevenBuglione/private-vm/internal/preflight"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc/codes"
)

const (
	protocolMajor = 1
	protocolMinor = 0
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)

type Service struct {
	privatevmv1.UnimplementedPrivateVMDaemonServiceServer
	Sessions  *session.Manager
	DoctorRun func(bool) preflight.Report
	Polkit    Polkit
}

func (s *Service) GetVersion(context.Context, *privatevmv1.Empty) (*privatevmv1.VersionResponse, error) {
	info := buildinfo.Current()
	return &privatevmv1.VersionResponse{Version: info.Version, Commit: info.Commit, ApiVersion: apiVersion()}, nil
}

func (s *Service) Doctor(ctx context.Context, request *privatevmv1.DoctorRequest) (*privatevmv1.DoctorResponse, error) {
	if err := validateRequestContext(request.GetContext(), false); err != nil {
		return nil, err
	}
	run := s.DoctorRun
	if run == nil {
		run = func(strict bool) preflight.Report { return preflight.Doctor{Strict: strict}.Run() }
	}
	report := run(request.GetStrict())
	return &privatevmv1.DoctorResponse{Diagnostics: diagnosticsToProto(report.Diagnostics), Runnable: report.Runnable}, nil
}

func (s *Service) PlanSession(ctx context.Context, request *privatevmv1.PlanSessionRequest) (*privatevmv1.PlanSessionResponse, error) {
	if err := validateRequestContext(request.GetContext(), false); err != nil {
		return nil, err
	}
	if _, err := roleFromProto(request.GetRole()); err != nil {
		return nil, err
	}
	resources, err := validateResources(request.GetResources())
	if err != nil {
		return nil, err
	}
	run := s.DoctorRun
	if run == nil {
		run = func(strict bool) preflight.Report { return preflight.Doctor{Strict: strict}.Run() }
	}
	report := run(true)
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
	if _, err := validateResources(request.GetResources()); err != nil {
		return nil, err
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	snapshot, err := s.Sessions.Create(identity.UID, role)
	if err != nil {
		return nil, sessionError(err)
	}
	return sessionToProto(snapshot), nil
}

func (s *Service) GetSession(ctx context.Context, request *privatevmv1.GetSessionRequest) (*privatevmv1.Session, error) {
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return nil, err
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

func (s *Service) StartRole(context.Context, *privatevmv1.StartRoleRequest) (*privatevmv1.Session, error) {
	return nil, unimplemented("Role launch")
}

func (s *Service) StopRole(ctx context.Context, request *privatevmv1.StopRoleRequest) (*privatevmv1.Session, error) {
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return nil, err
	}
	return nil, unimplemented("Protected role stop")
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
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return err
	}
	identity, err := identityFromContext(stream.Context())
	if err != nil {
		return sessionError(err)
	}
	var sent uint64
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot, getErr := s.Sessions.Get(request.GetContext().GetSessionId(), identity.UID)
		if errors.Is(getErr, session.ErrNotFound) {
			return nil
		}
		if getErr != nil {
			return sessionError(getErr)
		}
		for _, event := range snapshot.Events {
			if event.Sequence <= sent {
				continue
			}
			if err := stream.Send(eventToProto(snapshot, event)); err != nil {
				return err
			}
			sent = event.Sequence
		}
		if snapshot.Phase == session.PhaseDestroyed {
			return nil
		}
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) ImportWorkspaceFile(privatevmv1.PrivateVMDaemonService_ImportWorkspaceFileServer) error {
	return unimplemented("Workspace import")
}

func (s *Service) ExportWorkspaceFile(*privatevmv1.ExportWorkspaceRequest, privatevmv1.PrivateVMDaemonService_ExportWorkspaceFileServer) error {
	return unimplemented("Workspace export")
}

func (s *Service) ClaimUSB(ctx context.Context, request *privatevmv1.ClaimUSBRequest) (*privatevmv1.USBClaim, error) {
	if err := validateRequestContext(request.GetContext(), true); err != nil {
		return nil, err
	}
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, sessionError(err)
	}
	if s.Polkit == nil || s.Polkit.Authorize(ctx, identity, "org.private-vm.usb.prepare") != nil {
		return nil, rpcError(codes.PermissionDenied, "POLKIT_AUTHORIZATION_DENIED", "Destructive USB authorization was denied.", "Retry interactively and approve the exact displayed USB identity.", false)
	}
	return nil, unimplemented("USB claim")
}

func (s *Service) ReleaseUSB(context.Context, *privatevmv1.ReleaseUSBRequest) (*privatevmv1.Empty, error) {
	return nil, unimplemented("USB release")
}

func validateRequestContext(value *privatevmv1.RequestContext, requireSession bool) error {
	if value == nil || value.GetApiVersion() == nil || value.GetApiVersion().GetMajor() != protocolMajor || value.GetApiVersion().GetMinor() > protocolMinor {
		return rpcError(codes.FailedPrecondition, "PROTOCOL_VERSION_MISMATCH", "The client protocol is not compatible with this daemon.", "Upgrade private-vm and private-vmd together.", false)
	}
	if !requestIDPattern.MatchString(value.GetRequestId()) {
		return rpcError(codes.InvalidArgument, "REQUEST_ID_INVALID", "The request ID is missing or malformed.", "Use an opaque 8-128 character request identifier.", false)
	}
	if requireSession && value.GetSessionId() == "" {
		return rpcError(codes.InvalidArgument, "SESSION_ID_REQUIRED", "A session ID is required.", "Supply an active session ID returned by CreateSession.", false)
	}
	return nil
}

func validateResources(value *privatevmv1.ResourceRequest) (*privatevmv1.ResourceRequest, error) {
	if value == nil {
		return &privatevmv1.ResourceRequest{Vcpus: 4, MemoryBytes: 8 << 30, RootBytes: 32 << 30}, nil
	}
	copy := privatevmv1.ResourceRequest{
		Vcpus: value.GetVcpus(), MemoryBytes: value.GetMemoryBytes(),
		RootBytes: value.GetRootBytes(), ScratchBytes: value.GetScratchBytes(),
	}
	if copy.Vcpus == 0 {
		copy.Vcpus = 4
	}
	if copy.MemoryBytes == 0 {
		copy.MemoryBytes = 8 << 30
	}
	if copy.RootBytes == 0 {
		copy.RootBytes = 32 << 30
	}
	if copy.Vcpus > 64 || copy.MemoryBytes < 512<<20 || copy.MemoryBytes > 256<<30 || copy.RootBytes > 2<<40 || copy.ScratchBytes > 16<<40 {
		return nil, rpcError(codes.InvalidArgument, "RESOURCE_REQUEST_INVALID", "Requested resources are outside supported bounds.", "Use at most 64 vCPUs, 256 GiB RAM, 2 TiB root and 16 TiB scratch.", false)
	}
	return &copy, nil
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
	return &privatevmv1.SessionEvent{Sequence: event.Sequence, EventCode: event.Code, Session: sessionToProto(copy), UnixNanos: event.Time.UnixNano()}
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
