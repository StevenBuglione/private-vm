package guestvpn

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/StevenBuglione/private-vm/internal/vpn"
)

const (
	maximumOperationDuration = 30 * time.Second
	maximumResponseDuration  = 5 * time.Second
	maximumMonitorInterval   = 5 * time.Minute
)

// Backend implements only the reviewed semantic mutations. Implementations do
// not receive arbitrary interface names, rules, routes, commands, or arguments.
type Backend interface {
	ArmKillSwitch(context.Context, vpn.GuestSetup) error
	ConfigureTunnel(context.Context, Underlay, vpn.GuestSetup) error
	RemoveTunnel(context.Context) error
	RemoveKillSwitch(context.Context) error
}

// Verifier proves the configured network against controlled fixtures. A nil
// or incomplete verifier can never result in a successful configuration.
type Verifier interface {
	Verify(context.Context, RolePolicy) (Proof, error)
}

// LossResponder performs the role-specific reaction before Monitor reports a
// tunnel loss: pause downloader work or display a workstation warning.
type LossResponder interface {
	OnVPNLoss(ctx context.Context, sessionStatus Status) error
}

// OnlineService is a single fixed local application whose process may start
// only after the kill switch and tunnel are configured. The production
// downloader uses it for the loopback-only qBittorrent child.
type OnlineService interface {
	Start(context.Context) error
	Stop(context.Context) error
}

// Controller is the single serialized owner of the guest VPN state machine.
// It intentionally keeps an armed kill switch after configuration or
// verification failure.
type Controller struct {
	mu              sync.Mutex
	backend         Backend
	verifier        Verifier
	online          OnlineService
	policy          RolePolicy
	underlay        Underlay
	state           State
	proof           Proof
	requireIPv6     bool
	killSwitchArmed bool
	configured      bool
	onlineActive    bool
}

func NewController(backend Backend, verifier Verifier, policy RolePolicy, underlay Underlay) (*Controller, error) {
	return newController(backend, verifier, nil, policy, underlay)
}

// NewControllerWithOnlineService composes the fixed downloader application
// into the same serialized VPN lifecycle owner.
func NewControllerWithOnlineService(backend Backend, verifier Verifier, online OnlineService, policy RolePolicy, underlay Underlay) (*Controller, error) {
	if isNilLike(online) {
		return nil, invalidRequest()
	}
	return newController(backend, verifier, online, policy, underlay)
}

func newController(backend Backend, verifier Verifier, online OnlineService, policy RolePolicy, underlay Underlay) (*Controller, error) {
	if isNilLike(backend) || isNilLike(verifier) {
		return nil, invalidRequest()
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	if err := underlay.validate(); err != nil {
		return nil, err
	}
	return &Controller{backend: backend, verifier: verifier, online: online, policy: policy, underlay: underlay, state: StateUnconfigured}, nil
}

// Configure always arms the kill switch before configuring the underlay,
// WireGuard, routes or DNS. It does not return success until all required
// verification gates pass.
func (controller *Controller) Configure(ctx context.Context, profile vpn.Profile) (Status, error) {
	if ctx == nil || controller == nil || profile == nil {
		return Status{}, invalidRequest()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.state != StateUnconfigured && controller.state != StateStopped {
		return controller.statusLocked(), invalidRequest()
	}
	inspection, err := profile.Inspect()
	if err != nil {
		return controller.statusLocked(), invalidRequest()
	}
	controller.requireIPv6 = inspection.IPv6Enabled
	operationCtx, cancel := boundedContext(ctx, maximumOperationDuration)
	defer cancel()
	if err := profile.WithGuestSetup(operationCtx, func(callbackCtx context.Context, setup vpn.GuestSetup) error {
		return controller.backend.ArmKillSwitch(callbackCtx, setup)
	}); err != nil {
		return controller.statusLocked(), killSwitchFailed(err)
	}
	controller.state = StateKillSwitchArmed
	controller.killSwitchArmed = true
	if err := profile.WithGuestSetup(operationCtx, func(callbackCtx context.Context, setup vpn.GuestSetup) error {
		return controller.backend.ConfigureTunnel(callbackCtx, controller.underlay, setup)
	}); err != nil {
		controller.removeTunnelDetached()
		return controller.statusLocked(), configurationFailed(err)
	}
	controller.state = StateConfigured
	controller.configured = true
	if controller.online != nil {
		controller.onlineActive = true
		if err := controller.online.Start(operationCtx); err != nil {
			controller.state = StateDegraded
			controller.stopOnlineDetached()
			return controller.statusLocked(), verificationFailed(err)
		}
	}
	proof, err := controller.verifier.Verify(operationCtx, controller.verificationPolicyLocked())
	controller.proof = proof
	if err != nil || !proof.complete(controller.requireIPv6, controller.policy.RequireTorrentBinding) {
		controller.state = StateDegraded
		controller.stopOnlineDetached()
		return controller.statusLocked(), verificationFailed(err)
	}
	controller.state = StateVerified
	return controller.statusLocked(), nil
}

func (controller *Controller) Verify(ctx context.Context) (Status, error) {
	if ctx == nil || controller == nil {
		return Status{}, invalidRequest()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.state != StateConfigured && controller.state != StateVerified && controller.state != StateDegraded {
		return controller.statusLocked(), invalidRequest()
	}
	operationCtx, cancel := boundedContext(ctx, maximumOperationDuration)
	defer cancel()
	if controller.online != nil && !controller.onlineActive {
		controller.onlineActive = true
		if err := controller.online.Start(operationCtx); err != nil {
			controller.state = StateDegraded
			controller.stopOnlineDetached()
			return controller.statusLocked(), verificationFailed(err)
		}
	}
	proof, err := controller.verifier.Verify(operationCtx, controller.verificationPolicyLocked())
	controller.proof = proof
	// The profile's IPv6 requirement is already reflected by the verifier's
	// role-specific contract: both bypass families always remain mandatory.
	if err != nil || !proof.complete(controller.requireIPv6, controller.policy.RequireTorrentBinding) {
		controller.state = StateDegraded
		return controller.statusLocked(), verificationFailed(err)
	}
	controller.state = StateVerified
	return controller.statusLocked(), nil
}

func (controller *Controller) Status() Status {
	if controller == nil {
		return Status{SchemaVersion: 1, State: StateUnconfigured, Code: "GUEST_VPN_UNCONFIGURED", Remediation: "Configure and verify the guest VPN before starting network applications."}
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.statusLocked()
}

// Stop is idempotent. It never removes the kill switch if tunnel removal
// failed, so a partial cleanup remains fail closed.
func (controller *Controller) Stop(ctx context.Context) error {
	if ctx == nil || controller == nil {
		return invalidRequest()
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.state == StateUnconfigured || controller.state == StateStopped {
		if controller.online != nil && controller.onlineActive {
			cleanupCtx, cancel := boundedContext(context.Background(), maximumOperationDuration)
			err := controller.online.Stop(cleanupCtx)
			cancel()
			if err != nil {
				return cleanupIncomplete()
			}
			controller.onlineActive = false
		}
		controller.state = StateStopped
		controller.proof = Proof{}
		controller.requireIPv6 = false
		controller.killSwitchArmed = false
		controller.configured = false
		return nil
	}
	cleanupCtx, cancel := boundedContext(context.Background(), maximumOperationDuration)
	defer cancel()
	if controller.online != nil && controller.onlineActive {
		if err := controller.online.Stop(cleanupCtx); err != nil {
			controller.state = StateDegraded
			return cleanupIncomplete()
		}
		controller.onlineActive = false
	}
	if err := controller.backend.RemoveTunnel(cleanupCtx); err != nil {
		controller.state = StateDegraded
		return cleanupIncomplete()
	}
	controller.proof = Proof{}
	controller.requireIPv6 = false
	controller.configured = false
	controller.state = StateKillSwitchArmed
	if err := controller.backend.RemoveKillSwitch(cleanupCtx); err != nil {
		controller.state = StateDegraded
		return cleanupIncomplete()
	}
	controller.killSwitchArmed = false
	controller.state = StateStopped
	return nil
}

// Monitor verifies continuously until cancellation. The first failed proof
// triggers the bounded role-specific fail-closed response and returns a stable
// tunnel-loss error. The kill switch remains armed.
func (controller *Controller) Monitor(ctx context.Context, interval time.Duration, responder LossResponder) error {
	if ctx == nil || controller == nil || responder == nil || interval <= 0 || interval > maximumMonitorInterval {
		return invalidRequest()
	}
	if controller.Status().State != StateVerified {
		return invalidRequest()
	}
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			status, err := controller.Verify(ctx)
			if err == nil {
				continue
			}
			if isContextError(err) {
				return err
			}
			responseCtx, cancel := boundedContext(ctx, maximumResponseDuration)
			responseErr := responder.OnVPNLoss(responseCtx, status)
			cancel()
			if responseErr != nil && isContextError(responseErr) {
				return responseErr
			}
			return tunnelLost()
		}
	}
}

func (controller *Controller) removeTunnelDetached() {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), maximumResponseDuration)
	defer cancel()
	_ = controller.backend.RemoveTunnel(cleanupCtx)
}

func (controller *Controller) stopOnlineDetached() {
	if controller.online == nil || !controller.onlineActive {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), maximumResponseDuration)
	defer cancel()
	if controller.online.Stop(cleanupCtx) == nil {
		controller.onlineActive = false
	}
}

func (controller *Controller) statusLocked() Status {
	status := Status{
		SchemaVersion:     1,
		State:             controller.state,
		KillSwitchArmed:   controller.killSwitchArmed,
		Configured:        controller.configured,
		Handshake:         controller.proof.Handshake,
		DNSThroughTunnel:  controller.proof.DNSThroughTunnel,
		DNSBypassBlocked:  controller.proof.DNSBypassBlocked,
		IPv4ThroughTunnel: controller.proof.IPv4ThroughTunnel,
		IPv6ThroughTunnel: controller.proof.IPv6ThroughTunnel,
		IPv4BypassBlocked: controller.proof.IPv4BypassBlocked,
		IPv6BypassBlocked: controller.proof.IPv6BypassBlocked,
		TorrentBound:      controller.proof.TorrentBound,
	}
	switch controller.state {
	case StateVerified:
		status.Code = "GUEST_VPN_VERIFIED"
		status.Remediation = "No action is required while continuous verification remains healthy."
	case StateDegraded:
		status.Code = "GUEST_VPN_DEGRADED"
		status.Remediation = "Keep the kill switch armed, pause network work, and reconnect or stop the session."
	case StateKillSwitchArmed, StateConfigured:
		status.Code = "GUEST_VPN_NOT_VERIFIED"
		status.Remediation = "Do not start network applications until every VPN verification gate passes."
	case StateStopped:
		status.Code = "GUEST_VPN_STOPPED"
		status.Remediation = "Configure and verify a new tunnel before starting network applications."
	default:
		status.Code = "GUEST_VPN_UNCONFIGURED"
		status.Remediation = "Configure and verify the guest VPN before starting network applications."
	}
	return status
}

func (proof Proof) complete(requireIPv6, requireTorrent bool) bool {
	return proof.Handshake && proof.DNSThroughTunnel && proof.DNSBypassBlocked && proof.IPv4ThroughTunnel && proof.IPv4BypassBlocked && proof.IPv6BypassBlocked &&
		(!requireIPv6 || proof.IPv6ThroughTunnel) && (!requireTorrent || proof.TorrentBound)
}

func (controller *Controller) verificationPolicyLocked() RolePolicy {
	policy := controller.policy
	policy.RequireIPv6Tunnel = controller.requireIPv6
	return policy
}

func boundedContext(ctx context.Context, maximum time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.WithCancel(context.Background())
	}
	deadline := time.Now().Add(maximum)
	if current, ok := ctx.Deadline(); ok && current.Before(deadline) {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, deadline)
}

func isNilLike(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
