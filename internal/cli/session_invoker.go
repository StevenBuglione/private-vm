package cli

import (
	"context"
	"errors"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

func (invoker *ProductionInvoker) invokeSession(ctx context.Context, id CommandID, intent Intent) (Result, error) {
	connection, client, err := invoker.client()
	if err != nil {
		return Result{}, err
	}
	defer connection.Close()
	requestID, err := invoker.nextRequestID()
	if err != nil {
		return Result{}, internalSessionError()
	}

	switch id {
	case CommandWorkstationStart:
		request, ok := intent.(WorkstationIntent)
		if !ok {
			return Result{}, invalidSessionIntent()
		}
		return invoker.startWorkstation(ctx, client, requestID, request)
	case CommandDesktopConnect, CommandDesktopRestart:
		request, ok := intent.(SessionIntent)
		if !ok {
			return Result{}, invalidSessionIntent()
		}
		current, err := invoker.resolveSession(ctx, client, requestID, request.SessionID, true)
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		if current.GetPhase() != privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE {
			return Result{}, apperror.New("DISPLAY_UNAVAILABLE", exitcode.Runtime, "The workstation display is not active.", "Start the workstation successfully before connecting the viewer.")
		}
		viewer := invoker.viewer
		if viewer == nil {
			viewer = launchRemoteViewer
		}
		if err := viewer(ctx, current.GetId()); err != nil {
			return Result{}, apperror.Wrap("DISPLAY_VIEWER_FAILED", exitcode.Runtime, "The user-owned SPICE viewer did not complete normally.", "Install the configured remote-viewer package, confirm the workstation remains active, and retry.", err)
		}
		return sessionResult(current, nil)
	case "desktop.status", "session.status":
		request, ok := intent.(SessionIntent)
		if !ok {
			return Result{}, invalidSessionIntent()
		}
		current, err := invoker.resolveSession(ctx, client, requestID, request.SessionID, id == "desktop.status")
		return sessionResult(current, err)
	case "session.list":
		response, err := client.ListSessions(ctx, &privatevmv1.ListSessionsRequest{Context: sessionRequestContext(requestID, "")})
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		return sessionListResult(response.GetSessions())
	case "desktop.stop":
		request, ok := intent.(DesktopStopIntent)
		if !ok {
			return Result{}, invalidSessionIntent()
		}
		current, err := invoker.resolveSession(ctx, client, requestID, request.SessionID, true)
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		response, err := client.StopRole(ctx, &privatevmv1.StopRoleRequest{
			Context: sessionRequestContext(requestID, current.GetId()), RequireClean: request.RequireClean, DiscardUnexported: request.Discard,
		})
		return sessionResult(response, err)
	case "session.stop":
		request, ok := intent.(SessionIntent)
		if !ok || request.SessionID == "" {
			return Result{}, invalidSessionIntent()
		}
		response, err := client.StopRole(ctx, &privatevmv1.StopRoleRequest{Context: sessionRequestContext(requestID, request.SessionID)})
		return sessionResult(response, err)
	case "session.abort":
		request, ok := intent.(SessionIntent)
		if !ok || request.SessionID == "" {
			return Result{}, invalidSessionIntent()
		}
		response, err := client.AbortSession(ctx, &privatevmv1.AbortSessionRequest{Context: sessionRequestContext(requestID, request.SessionID), ReasonCode: "USER_REQUEST"})
		return sessionResult(response, err)
	case "session.cleanup":
		request, ok := intent.(SessionCleanupIntent)
		if !ok {
			return Result{}, invalidSessionIntent()
		}
		return invoker.cleanupSessions(ctx, client, requestID, request)
	default:
		return failClosedInvoker{}.Invoke(ctx, id, intent)
	}
}

func (invoker *ProductionInvoker) startWorkstation(ctx context.Context, client privatevmv1.PrivateVMDaemonServiceClient, requestID string, intent WorkstationIntent) (Result, error) {
	memory, err := parseIECSize(intent.Memory)
	if err != nil || intent.CPUs < 1 {
		return Result{}, invalidSessionIntent()
	}
	resources := &privatevmv1.ResourceRequest{Vcpus: uint32(intent.CPUs), MemoryBytes: memory, RootBytes: 32 << 30}
	plan, err := client.PlanSession(ctx, &privatevmv1.PlanSessionRequest{
		Context: sessionRequestContext(requestID, ""), Role: privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION,
		ImageBundle: intent.Bundle, Resources: resources,
	})
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	if !plan.GetRunnable() {
		return Result{}, apperror.New("HOST_PREFLIGHT_FAILED", exitcode.Preflight, "The host did not pass the strict workstation preflight.", "Run private-vm doctor --strict --json, correct every blocking diagnostic, and retry.")
	}
	created, err := client.CreateSession(ctx, &privatevmv1.CreateSessionRequest{
		Context: sessionRequestContext(requestID, ""), Role: privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION,
		ImageBundle: intent.Bundle, Resources: resources,
	})
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	started, err := client.StartRole(ctx, &privatevmv1.StartRoleRequest{Context: sessionRequestContext(requestID, created.GetId())})
	if err != nil {
		// A disconnect after session creation must not strand a record. The
		// daemon owns cleanup after StartRole admission; this bounded abort also
		// covers failures before the start request reached it.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = client.AbortSession(cleanupCtx, &privatevmv1.AbortSessionRequest{Context: sessionRequestContext(requestID, created.GetId()), ReasonCode: "CLIENT_START_FAILED"})
		cancel()
		return Result{}, daemonRPCError(err)
	}
	return sessionResult(started, nil)
}

func (invoker *ProductionInvoker) resolveSession(ctx context.Context, client privatevmv1.PrivateVMDaemonServiceClient, requestID, id string, workstationOnly bool) (*privatevmv1.Session, error) {
	if id != "" {
		return client.GetSession(ctx, &privatevmv1.GetSessionRequest{Context: sessionRequestContext(requestID, id)})
	}
	response, err := client.ListSessions(ctx, &privatevmv1.ListSessionsRequest{Context: sessionRequestContext(requestID, "")})
	if err != nil {
		return nil, err
	}
	var selected *privatevmv1.Session
	for _, current := range response.GetSessions() {
		if workstationOnly && current.GetRole() != privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION {
			continue
		}
		if selected != nil {
			return nil, apperror.New("SESSION_SELECTION_REQUIRED", exitcode.Runtime, "More than one matching session is active.", "Select one exact session with --session.")
		}
		selected = current
	}
	if selected == nil {
		return nil, apperror.New("SESSION_NOT_FOUND", exitcode.Runtime, "No matching active session exists.", "Start a session or supply an exact active session ID.")
	}
	return selected, nil
}

func (invoker *ProductionInvoker) cleanupSessions(ctx context.Context, client privatevmv1.PrivateVMDaemonServiceClient, requestID string, intent SessionCleanupIntent) (Result, error) {
	ids := []string{}
	if intent.SessionID != "" {
		ids = append(ids, intent.SessionID)
	} else if intent.All {
		response, err := client.ListSessions(ctx, &privatevmv1.ListSessionsRequest{Context: sessionRequestContext(requestID, "")})
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		for _, current := range response.GetSessions() {
			ids = append(ids, current.GetId())
		}
	} else {
		return Result{}, invalidSessionIntent()
	}
	result := make([]*privatevmv1.Session, 0, len(ids))
	for _, current := range ids {
		cleaned, err := client.CleanupSession(ctx, &privatevmv1.CleanupSessionRequest{Context: sessionRequestContext(requestID, current)})
		if err != nil {
			return Result{}, daemonRPCError(err)
		}
		result = append(result, cleaned)
	}
	return sessionListResult(result)
}

func sessionRequestContext(requestID, sessionID string) *privatevmv1.RequestContext {
	return &privatevmv1.RequestContext{ApiVersion: &privatevmv1.ApiVersion{Major: 1, Minor: 0}, RequestId: requestID, SessionId: sessionID}
}

func sessionResult(response *privatevmv1.Session, err error) (Result, error) {
	if err != nil {
		return Result{}, daemonRPCError(err)
	}
	if response == nil {
		return Result{}, internalSessionError()
	}
	return sessionListResult([]*privatevmv1.Session{response})
}

func sessionListResult(values []*privatevmv1.Session) (Result, error) {
	payload := SessionPayload{Sessions: make([]SessionView, 0, len(values))}
	for _, value := range values {
		view, err := sessionView(value)
		if err != nil {
			return Result{}, internalSessionError()
		}
		payload.Sessions = append(payload.Sessions, view)
	}
	return Result{Code: CodeSessionStatus, Data: payload}, nil
}

func sessionView(value *privatevmv1.Session) (SessionView, error) {
	if value == nil || value.GetId() == "" {
		return SessionView{}, errors.New("session response is incomplete")
	}
	role := map[privatevmv1.GuestRole]string{
		privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION: "workstation",
		privatevmv1.GuestRole_GUEST_ROLE_DOWNLOADER:  "downloader",
		privatevmv1.GuestRole_GUEST_ROLE_SCANNER:     "scanner",
		privatevmv1.GuestRole_GUEST_ROLE_EXPORTER:    "exporter",
	}[value.GetRole()]
	phase := map[privatevmv1.SessionPhase]string{
		privatevmv1.SessionPhase_SESSION_PHASE_CREATED:         "CREATED",
		privatevmv1.SessionPhase_SESSION_PHASE_PREFLIGHTED:     "PREFLIGHTED",
		privatevmv1.SessionPhase_SESSION_PHASE_IMAGES_VERIFIED: "IMAGES_VERIFIED",
		privatevmv1.SessionPhase_SESSION_PHASE_STORAGE_READY:   "STORAGE_READY",
		privatevmv1.SessionPhase_SESSION_PHASE_ACTIVE:          "ACTIVE",
		privatevmv1.SessionPhase_SESSION_PHASE_STOPPING:        "STOPPING",
		privatevmv1.SessionPhase_SESSION_PHASE_ABORTING:        "ABORTING",
		privatevmv1.SessionPhase_SESSION_PHASE_DESTROYING:      "DESTROYING",
		privatevmv1.SessionPhase_SESSION_PHASE_DESTROYED:       "DESTROYED",
	}[value.GetPhase()]
	if role == "" || phase == "" {
		return SessionView{}, errors.New("session response enum is invalid")
	}
	return SessionView{ID: value.GetId(), Role: role, Phase: phase, WorkflowState: value.GetWorkflowState()}, nil
}

func invalidSessionIntent() error {
	return apperror.New("SESSION_REQUEST_INVALID", exitcode.Runtime, "The session request contract is invalid.", "Use the documented session or desktop command syntax.")
}

func internalSessionError() error {
	return apperror.New("INTERNAL_ERROR", exitcode.Internal, "The session response could not be represented safely.", "Retry once; if the error persists, export a redacted diagnostic bundle.")
}
