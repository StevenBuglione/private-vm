package daemon

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/config"
	"github.com/StevenBuglione/private-vm/internal/preflight"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestUnaryRequestContextContractCoversEveryContextualMethod(t *testing.T) {
	tests := []struct {
		method  string
		request any
	}{
		{privatevmv1.PrivateVMDaemonService_Doctor_FullMethodName, &privatevmv1.DoctorRequest{}},
		{privatevmv1.PrivateVMDaemonService_PlanSession_FullMethodName, &privatevmv1.PlanSessionRequest{}},
		{privatevmv1.PrivateVMDaemonService_CreateSession_FullMethodName, &privatevmv1.CreateSessionRequest{}},
		{privatevmv1.PrivateVMDaemonService_GetSession_FullMethodName, &privatevmv1.GetSessionRequest{}},
		{privatevmv1.PrivateVMDaemonService_ListSessions_FullMethodName, &privatevmv1.ListSessionsRequest{}},
		{privatevmv1.PrivateVMDaemonService_InspectVPNProfile_FullMethodName, &privatevmv1.VPNProfileRequest{}},
		{privatevmv1.PrivateVMDaemonService_TestVPNProfile_FullMethodName, &privatevmv1.VPNProfileRequest{}},
		{privatevmv1.PrivateVMDaemonService_RemoveVPNProfile_FullMethodName, &privatevmv1.VPNProfileRequest{}},
		{privatevmv1.PrivateVMDaemonService_GetTorrentMetadata_FullMethodName, &privatevmv1.TorrentControlRequest{}},
		{privatevmv1.PrivateVMDaemonService_SelectTorrentFiles_FullMethodName, &privatevmv1.HostSelectTorrentFilesRequest{}},
		{privatevmv1.PrivateVMDaemonService_PauseTorrentDownload_FullMethodName, &privatevmv1.TorrentControlRequest{}},
		{privatevmv1.PrivateVMDaemonService_GetTorrentStatus_FullMethodName, &privatevmv1.TorrentControlRequest{}},
		{privatevmv1.PrivateVMDaemonService_SealTorrentQuarantine_FullMethodName, &privatevmv1.TorrentControlRequest{}},
		{privatevmv1.PrivateVMDaemonService_GetScannerStatus_FullMethodName, &privatevmv1.HostScannerControlRequest{}},
		{privatevmv1.PrivateVMDaemonService_GetScannerReport_FullMethodName, &privatevmv1.HostScannerControlRequest{}},
		{privatevmv1.PrivateVMDaemonService_ApproveScanner_FullMethodName, &privatevmv1.HostScannerApprovalRequest{}},
		{privatevmv1.PrivateVMDaemonService_RejectScanner_FullMethodName, &privatevmv1.HostScannerControlRequest{}},
		{privatevmv1.PrivateVMDaemonService_StartRole_FullMethodName, &privatevmv1.StartRoleRequest{}},
		{privatevmv1.PrivateVMDaemonService_StopRole_FullMethodName, &privatevmv1.StopRoleRequest{}},
		{privatevmv1.PrivateVMDaemonService_AbortSession_FullMethodName, &privatevmv1.AbortSessionRequest{}},
		{privatevmv1.PrivateVMDaemonService_CleanupSession_FullMethodName, &privatevmv1.CleanupSessionRequest{}},
		{privatevmv1.PrivateVMDaemonService_GetWorkspaceState_FullMethodName, &privatevmv1.HostWorkspaceStateRequest{}},
		{privatevmv1.PrivateVMDaemonService_VerifyWorkspaceExport_FullMethodName, &privatevmv1.VerifyWorkspaceExportRequest{}},
		{privatevmv1.PrivateVMDaemonService_ExportWorkspaceToDestination_FullMethodName, &privatevmv1.ExportWorkspaceToDestinationRequest{}},
		{privatevmv1.PrivateVMDaemonService_ClaimUSB_FullMethodName, &privatevmv1.ClaimUSBRequest{}},
		{privatevmv1.PrivateVMDaemonService_ReleaseUSB_FullMethodName, &privatevmv1.ReleaseUSBRequest{}},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			called := false
			_, err := requestContextUnaryInterceptor(t.Context(), test.request, &grpc.UnaryServerInfo{FullMethod: test.method}, func(context.Context, any) (any, error) {
				called = true
				return &privatevmv1.Empty{}, nil
			})
			if called {
				t.Fatal("contextless request reached handler")
			}
			assertRPCError(t, err, codes.FailedPrecondition, "PROTOCOL_VERSION_MISMATCH")
		})
	}
}

func TestGetVersionIsSoleContextlessUnaryException(t *testing.T) {
	called := false
	_, err := requestContextUnaryInterceptor(t.Context(), &privatevmv1.Empty{}, &grpc.UnaryServerInfo{FullMethod: privatevmv1.PrivateVMDaemonService_GetVersion_FullMethodName}, func(context.Context, any) (any, error) {
		called = true
		return &privatevmv1.Empty{}, nil
	})
	if err != nil || !called {
		t.Fatalf("GetVersion bootstrap request: called=%v err=%v", called, err)
	}
	_, err = requestContextUnaryInterceptor(t.Context(), &privatevmv1.Empty{}, &grpc.UnaryServerInfo{FullMethod: "/privatevm.v1.PrivateVMDaemonService/Unexpected"}, func(context.Context, any) (any, error) {
		return nil, nil
	})
	assertRPCError(t, err, codes.Internal, "RPC_CONTEXT_CONTRACT_INVALID")
}

func TestUnaryRequestMetadataIsOpaqueAndAttached(t *testing.T) {
	request := &privatevmv1.DoctorRequest{Context: validRequestContext("")}
	_, err := requestContextUnaryInterceptor(t.Context(), request, &grpc.UnaryServerInfo{FullMethod: privatevmv1.PrivateVMDaemonService_Doctor_FullMethodName}, func(ctx context.Context, _ any) (any, error) {
		metadata, ok := ctx.Value(requestMetadataKey{}).(requestMetadata)
		if !ok || metadata.requestID != request.GetContext().GetRequestId() || metadata.sessionID != "" {
			t.Fatalf("request metadata = %+v, present=%v", metadata, ok)
		}
		return &privatevmv1.Empty{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSessionContextAndResourceValidationFailClosed(t *testing.T) {
	invalidSession := validRequestContext("../../host")
	assertRPCError(t, validateRequestContext(invalidSession, true), codes.InvalidArgument, "SESSION_ID_INVALID")
	assertRPCError(t, validateRequestContext(invalidSession, false), codes.InvalidArgument, "SESSION_ID_INVALID")
	assertRPCError(t, validateRequestContext(validRequestContext(""), true), codes.InvalidArgument, "SESSION_ID_REQUIRED")
	assertRPCError(t, validateRequestContext(&privatevmv1.RequestContext{ApiVersion: apiVersion(), RequestId: "short"}, false), codes.InvalidArgument, "REQUEST_ID_INVALID")

	defaults := resourceDefaults("workstation", config.Defaults())
	resolved, err := validateResources(&privatevmv1.ResourceRequest{}, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.GetVcpus() != config.Defaults().Desktop().VCPUs() || resolved.GetMemoryBytes() != config.Defaults().Desktop().MemoryBytes() || resolved.GetRootBytes() != 32<<30 {
		t.Fatalf("resolved resources = %+v", resolved)
	}
	_, err = validateResources(&privatevmv1.ResourceRequest{Vcpus: 65}, defaults)
	assertRPCError(t, err, codes.InvalidArgument, "RESOURCE_REQUEST_INVALID")
}

func TestPackagedRoleDefaultsFitTheSixteenGiBStrictBaseline(t *testing.T) {
	configuration := config.Defaults()
	tests := []struct {
		role   session.Role
		vcpus  uint32
		memory uint64
	}{
		{session.RoleWorkstation, 2, 4 << 30},
		{session.RoleDownloader, 4, 4 << 30},
		{session.RoleScanner, 4, 4 << 30},
		{session.RoleExporter, 2, 1 << 30},
	}
	for _, test := range tests {
		resources := resourceDefaults(test.role, configuration)
		if resources.GetVcpus() != test.vcpus || resources.GetMemoryBytes() != test.memory || resources.GetRootBytes() != 32<<30 {
			t.Fatalf("%s defaults = %+v", test.role, resources)
		}
		if resources.GetMemoryBytes()+(4<<30) > 16<<30 {
			t.Fatalf("%s defaults cannot preserve the strict host reserve", test.role)
		}
	}
}

func TestPlanUsesImmutableDaemonConfigAndStrictDoctor(t *testing.T) {
	strictSeen := false
	service := &Service{
		Config: config.Defaults(),
		DoctorRun: func(ctx context.Context, strict bool) preflight.Report {
			strictSeen = strict
			return preflight.Report{SchemaVersion: 1, Runnable: true}
		},
	}
	response, err := service.PlanSession(t.Context(), &privatevmv1.PlanSessionRequest{
		Context: validRequestContext(""), Role: privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strictSeen || response.GetResolvedResources().GetVcpus() != config.Defaults().Desktop().VCPUs() || response.GetResolvedResources().GetMemoryBytes() != config.Defaults().Desktop().MemoryBytes() {
		t.Fatalf("plan did not use strict immutable defaults: strict=%v resources=%+v", strictSeen, response.GetResolvedResources())
	}

	_, err = service.PlanSession(t.Context(), &privatevmv1.PlanSessionRequest{
		Context: validRequestContext(""), Role: privatevmv1.GuestRole_GUEST_ROLE_DOWNLOADER, ImageBundle: "private-name",
	})
	assertRPCError(t, err, codes.InvalidArgument, "IMAGE_BUNDLE_INVALID")
	if err != nil && containsAny(err.Error(), "private-name") {
		t.Fatal("selector validation exposed raw input")
	}
	_, err = service.PlanSession(t.Context(), &privatevmv1.PlanSessionRequest{
		Context: validRequestContext(""), Role: privatevmv1.GuestRole_GUEST_ROLE_SCANNER, PolicyName: "private-policy",
	})
	assertRPCError(t, err, codes.InvalidArgument, "POLICY_NAME_INVALID")
}

func TestDoctorCancellationAndStrictModeCannotBeWeakened(t *testing.T) {
	strictSeen := false
	service := &Service{Config: config.Defaults(), DoctorRun: func(ctx context.Context, strict bool) preflight.Report {
		strictSeen = strict
		return preflight.Report{SchemaVersion: 1, Runnable: true}
	}}
	_, err := service.Doctor(t.Context(), &privatevmv1.DoctorRequest{Context: validRequestContext("")})
	if err != nil || !strictSeen {
		t.Fatalf("strict doctor: strict=%v err=%v", strictSeen, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = service.Doctor(canceled, &privatevmv1.DoctorRequest{Context: validRequestContext("")})
	assertRPCError(t, err, codes.Canceled, "REQUEST_CANCELED")
	assertRPCError(t, sessionError(context.DeadlineExceeded), codes.DeadlineExceeded, "REQUEST_TIMEOUT")
	assertRPCError(t, sessionError(status.Error(codes.Canceled, "transport canceled")), codes.Canceled, "REQUEST_CANCELED")
	assertRPCError(t, sessionError(status.Error(codes.DeadlineExceeded, "transport deadline")), codes.DeadlineExceeded, "REQUEST_TIMEOUT")
}

func TestCanceledCreateSessionDoesNotCreateState(t *testing.T) {
	store, err := session.NewStore(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(store, 4)
	if err != nil {
		t.Fatal(err)
	}
	identity := currentProcessIdentity(t)
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), identityContextKey{}, identity))
	service := &Service{Sessions: manager, Config: config.Defaults(), afterCreate: cancel}
	_, err = service.CreateSession(ctx, &privatevmv1.CreateSessionRequest{
		Context: validRequestContext(""), Role: privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION,
	})
	assertRPCError(t, err, codes.Canceled, "REQUEST_CANCELED")
	if snapshots := manager.List(identity.UID); len(snapshots) != 0 {
		t.Fatalf("canceled create left %d sessions", len(snapshots))
	}
	ids, err := store.ListIDs()
	if err != nil || len(ids) != 0 {
		t.Fatalf("canceled create left volatile records %v: %v", ids, err)
	}

	cleanupFailure := errors.New("public cleanup fixture failure")
	ctx, cancel = context.WithCancel(context.WithValue(context.Background(), identityContextKey{}, identity))
	service.afterCreate = cancel
	service.cleanupCanceledCreate = func(context.Context, string, uint32) error { return cleanupFailure }
	_, err = service.CreateSession(ctx, &privatevmv1.CreateSessionRequest{
		Context: validRequestContext(""), Role: privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION,
	})
	assertRPCError(t, err, codes.Internal, "INTERNAL_ERROR")
	if strings.Contains(err.Error(), cleanupFailure.Error()) {
		t.Fatal("canceled-create cleanup failure escaped normalization")
	}
	remaining := manager.List(identity.UID)
	if len(remaining) != 1 {
		t.Fatalf("cleanup failure evidence has %d sessions, want one for explicit retry", len(remaining))
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
	defer cleanupCancel()
	if _, err := manager.Cleanup(cleanupCtx, remaining[0].ID, identity.UID); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRequestMetadataAndInitialDeadline(t *testing.T) {
	request := validRequestContext("pvm-00000000000000000000000000000000")
	ctx, err := requestContextWithMetadata(t.Context(), request, true)
	if err != nil {
		t.Fatal(err)
	}
	metadata, ok := ctx.Value(requestMetadataKey{}).(requestMetadata)
	if !ok || metadata.requestID != request.GetRequestId() || metadata.sessionID != request.GetSessionId() {
		t.Fatalf("stream metadata = %+v, present=%v", metadata, ok)
	}

	identity := currentProcessIdentity(t)
	authorizer := Authorizer{AllowedGroup: identity.GID}
	stream := &contextOnlyServerStream{ctx: peer.NewContext(context.Background(), &peer.Peer{AuthInfo: PeerAuthInfo{PeerIdentity: identity}})}
	for _, method := range []string{
		privatevmv1.PrivateVMDaemonService_ImportWorkspaceFile_FullMethodName,
		privatevmv1.PrivateVMDaemonService_ImportVPNProfile_FullMethodName,
	} {
		err = authorizer.StreamInterceptor(nil, stream, &grpc.StreamServerInfo{FullMethod: method}, func(_ any, wrapped grpc.ServerStream) error {
			deadline, present := wrapped.Context().Deadline()
			if !present || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Second {
				t.Fatalf("import first-frame deadline = %v, present=%v", deadline, present)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestStreamEventsReturnsTypedNotFoundForMissingInitialSession(t *testing.T) {
	store, err := session.NewStore(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(store, 4)
	if err != nil {
		t.Fatal(err)
	}
	identity := currentProcessIdentity(t)
	ctx := context.WithValue(t.Context(), identityContextKey{}, identity)
	service := &Service{Sessions: manager}
	err = service.StreamEvents(
		&privatevmv1.GetSessionRequest{Context: validRequestContext("pvm-00000000000000000000000000000000")},
		&eventFixtureStream{ctx: ctx},
	)
	assertRPCError(t, err, codes.NotFound, "SESSION_NOT_FOUND")
}

func TestStreamEventsReplaysFollowsAndDeliversTerminalEvent(t *testing.T) {
	store, err := session.NewStore(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(store, session.DefaultMaxSessionsPerOwner)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Create(uint32(os.Geteuid()), session.RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	identity := currentProcessIdentity(t)
	ctx := context.WithValue(t.Context(), identityContextKey{}, identity)
	stream := &recordingEventStream{ctx: ctx, events: make(chan *privatevmv1.SessionEvent, 8)}
	service := &Service{Sessions: manager}
	done := make(chan error, 1)
	go func() {
		done <- service.StreamEvents(
			&privatevmv1.GetSessionRequest{Context: validRequestContext(snapshot.ID)},
			stream,
		)
	}()
	assertEvent := func(sequence uint64, code string) {
		t.Helper()
		select {
		case event := <-stream.events:
			if event.GetSequence() != sequence || event.GetEventCode() != code || event.GetSafeMessage() == "" {
				t.Fatalf("unexpected event: %+v", event)
			}
		case <-time.After(time.Second):
			t.Fatalf("event %d was not delivered", sequence)
		}
	}
	assertEvent(1, "SESSION_CREATED")
	if _, err := manager.Transition(t.Context(), snapshot.ID, identity.UID, session.PhasePreflighted); err != nil {
		t.Fatal(err)
	}
	assertEvent(2, "SESSION_PREFLIGHTED")
	if _, err := manager.Cleanup(t.Context(), snapshot.ID, identity.UID); err != nil {
		t.Fatal(err)
	}
	assertEvent(3, "SESSION_ABORTING")
	assertEvent(4, "SESSION_DESTROYING")
	assertEvent(5, "SESSION_DESTROYED")
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("terminal stream error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("event stream did not close after the terminal event")
	}
}

func TestStreamEventsRejectsFutureCursor(t *testing.T) {
	store, err := session.NewStore(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(store, session.DefaultMaxSessionsPerOwner)
	if err != nil {
		t.Fatal(err)
	}
	identity := currentProcessIdentity(t)
	snapshot, err := manager.Create(identity.UID, session.RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), identityContextKey{}, identity)
	err = (&Service{Sessions: manager}).StreamEvents(
		&privatevmv1.GetSessionRequest{Context: validRequestContext(snapshot.ID), AfterSequence: 99},
		&eventFixtureStream{ctx: ctx},
	)
	assertRPCError(t, err, codes.InvalidArgument, "EVENT_CURSOR_INVALID")
}

func TestStreamInputsRequireValidContextBeforeUnimplementedBoundary(t *testing.T) {
	service := &Service{}
	for _, test := range []struct {
		name  string
		frame *privatevmv1.TransferFrame
		code  string
	}{
		{"empty", nil, "TRANSFER_BEGIN_REQUIRED"},
		{"data-first", &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{}}}, "TRANSFER_BEGIN_REQUIRED"},
		{"contextless-begin", &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{}}}, "PROTOCOL_VERSION_MISMATCH"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := &importFixtureStream{ctx: t.Context()}
			if test.frame != nil {
				stream.frames = []*privatevmv1.TransferFrame{test.frame}
			}
			err := service.ImportWorkspaceFile(stream)
			if test.code == "TRANSFER_BEGIN_REQUIRED" {
				assertRPCError(t, err, codes.InvalidArgument, test.code)
			} else {
				assertRPCError(t, err, codes.FailedPrecondition, test.code)
			}
		})
	}
	valid := &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{Context: validRequestContext("pvm-00000000000000000000000000000000")}}}
	assertRPCError(t, service.ImportWorkspaceFile(&importFixtureStream{ctx: t.Context(), frames: []*privatevmv1.TransferFrame{valid}}), codes.Unimplemented, "NOT_IMPLEMENTED")
	assertRPCError(t, service.ExportWorkspaceFile(&privatevmv1.ExportWorkspaceRequest{}, &exportFixtureStream{ctx: t.Context()}), codes.FailedPrecondition, "PROTOCOL_VERSION_MISMATCH")
}

func TestClaimUSBUnavailableDoesNotPromptForDestructiveAuthorization(t *testing.T) {
	polkit := &recordingPolkit{}
	service := &Service{Polkit: polkit}
	_, err := service.ClaimUSB(t.Context(), &privatevmv1.ClaimUSBRequest{Context: validRequestContext("pvm-00000000000000000000000000000000")})
	assertRPCError(t, err, codes.Unavailable, "USB_INTEGRATION_UNAVAILABLE")
	if polkit.called {
		t.Fatal("USB claim prompted for destructive preparation authorization")
	}
}

func validRequestContext(sessionID string) *privatevmv1.RequestContext {
	return &privatevmv1.RequestContext{ApiVersion: apiVersion(), RequestId: "request-contract-0001", SessionId: sessionID}
}

func containsAny(value string, values ...string) bool {
	for _, candidate := range values {
		if candidate != "" && strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

type importFixtureStream struct {
	grpc.ServerStream
	ctx    context.Context
	frames []*privatevmv1.TransferFrame
	index  int
}

func (s *importFixtureStream) Context() context.Context                        { return s.ctx }
func (s *importFixtureStream) SendAndClose(*privatevmv1.TransferReceipt) error { return nil }
func (s *importFixtureStream) Recv() (*privatevmv1.TransferFrame, error) {
	if s.index >= len(s.frames) {
		return nil, io.EOF
	}
	frame := s.frames[s.index]
	s.index++
	return frame, nil
}

type recordingPolkit struct{ called bool }

func (p *recordingPolkit) Authorize(context.Context, PeerIdentity, string) error {
	p.called = true
	return nil
}

type exportFixtureStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *exportFixtureStream) Context() context.Context              { return s.ctx }
func (s *exportFixtureStream) Send(*privatevmv1.TransferFrame) error { return nil }

type contextOnlyServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextOnlyServerStream) Context() context.Context { return s.ctx }

type eventFixtureStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *eventFixtureStream) Context() context.Context             { return s.ctx }
func (s *eventFixtureStream) Send(*privatevmv1.SessionEvent) error { return nil }

type recordingEventStream struct {
	grpc.ServerStream
	ctx    context.Context
	events chan *privatevmv1.SessionEvent
}

func (s *recordingEventStream) Context() context.Context { return s.ctx }
func (s *recordingEventStream) Send(event *privatevmv1.SessionEvent) error {
	s.events <- event
	return nil
}
