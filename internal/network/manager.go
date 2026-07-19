package network

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/vpn"
)

const (
	maximumCreateDuration  = 30 * time.Second
	maximumCleanupDuration = 30 * time.Second
	maximumHandoffDuration = 30 * time.Second
	redactedHandle         = "[REDACTED SESSION NETWORK]"
)

// Manager is the sole owner of session network allocation and cleanup.
type Manager struct {
	backend backend

	allocationMu sync.Mutex
	mu           sync.Mutex
	states       map[string]*networkState
	reservations map[uint16]string
	names        map[string]string
}

type networkState struct {
	// lifecycleMu is acquired before the state becomes visible. It serializes
	// provisioning, bounded descriptor/configuration handoffs and cleanup.
	lifecycleMu sync.Mutex
	mu          sync.Mutex

	sessionID   string
	owner       uint32
	profileName string
	profiles    *vpn.MemoryStore
	plan        vpn.ResolutionPlan
	spec        topologySpec
	policy      endpointPolicy

	ready                    bool
	namespaceAttempted       bool
	vethAttempted            bool
	tapAttempted             bool
	namespacePolicyAttempted bool
	hostPolicyAttempted      bool
	tapFile                  *os.File
}

// Handle is a sealed, opaque reference to one ready session network. It has no
// endpoint, interface-name, namespace-name or address formatter.
type Handle struct {
	manager *Manager
	state   *networkState
}

// GuestAddressing is a sealed callback-only static underlay plan. It contains
// no Proton endpoint or profile association.
type GuestAddressing interface {
	IPv4Address() netip.Prefix
	IPv4Gateway() netip.Addr
	IPv6Address() netip.Prefix
	IPv6Gateway() netip.Addr
	privateGuestAddressing()
}

type guestAddressing struct{ spec topologySpec }

func (value guestAddressing) IPv4Address() netip.Prefix { return value.spec.guestAddress4 }
func (value guestAddressing) IPv4Gateway() netip.Addr   { return value.spec.guestGateway4.Addr() }
func (value guestAddressing) IPv6Address() netip.Prefix { return value.spec.guestAddress6 }
func (value guestAddressing) IPv6Gateway() netip.Addr   { return value.spec.guestGateway6.Addr() }
func (guestAddressing) privateGuestAddressing()         {}

func NewManager(paths ToolPaths) (*Manager, error) {
	implementation, err := newPlatformBackend(paths)
	if err != nil {
		return nil, err
	}
	return newManager(implementation), nil
}

func newManager(implementation backend) *Manager {
	return &Manager{
		backend: implementation, states: make(map[string]*networkState),
		reservations: make(map[uint16]string), names: make(map[string]string),
	}
}

// Create consumes the VPN store's exact opaque plan while the store serializes
// it against rotation. No overload accepts endpoint strings or addresses.
func (manager *Manager) Create(
	ctx context.Context,
	sessionID string,
	owner uint32,
	profileName string,
	profiles *vpn.MemoryStore,
	plan vpn.ResolutionPlan,
) (*Handle, error) {
	if ctx == nil || manager == nil || manager.backend == nil || profiles == nil || plan == nil || session.ValidateID(sessionID) != nil {
		return nil, invalidRequest()
	}
	manager.mu.Lock()
	if manager.states[sessionID] != nil {
		manager.mu.Unlock()
		return nil, topologyExists()
	}
	manager.mu.Unlock()

	createCtx, cancel := boundedContext(ctx, maximumCreateDuration)
	defer cancel()
	var state *networkState
	operationErr := profiles.UsePlan(createCtx, owner, profileName, plan, func(resolved vpn.ResolvedProfile) error {
		var endpoints []endpointTuple
		if err := resolved.Endpoints(createCtx, func(address netip.Addr, port uint16) error {
			if len(endpoints) >= maximumEndpointTuples {
				return invalidRequest()
			}
			endpoints = append(endpoints, endpointTupleFor(address, port))
			return nil
		}); err != nil {
			return err
		}
		policy, err := collectPolicy(endpoints)
		clear(endpoints)
		if err != nil {
			return err
		}
		state, err = manager.reserve(createCtx, sessionID, owner, profileName, profiles, plan, policy)
		if err != nil {
			policy.destroy()
			return err
		}
		return manager.provision(createCtx, state)
	})
	if operationErr != nil {
		if state != nil {
			cleanupErr := manager.cleanupState(context.Background(), state)
			if cleanupErr != nil {
				return nil, cleanupErr
			}
		}
		return nil, normalizeCreateError(operationErr)
	}
	return &Handle{manager: manager, state: state}, nil
}

func (manager *Manager) reserve(
	ctx context.Context,
	sessionID string,
	owner uint32,
	profileName string,
	profiles *vpn.MemoryStore,
	plan vpn.ResolutionPlan,
	policy endpointPolicy,
) (*networkState, error) {
	manager.allocationMu.Lock()
	defer manager.allocationMu.Unlock()
	for attempt := uint8(0); attempt < maximumAllocationAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		spec := candidateFor(sessionID, attempt)
		manager.mu.Lock()
		_, reserved := manager.reservations[spec.slot]
		_, nameReserved := manager.names[spec.namespace]
		manager.mu.Unlock()
		if reserved || nameReserved {
			continue
		}
		available, err := manager.backend.Available(ctx, spec)
		if err != nil {
			return nil, topologyFailed(err)
		}
		if !available {
			continue
		}
		state := &networkState{
			sessionID: sessionID, owner: owner, profileName: profileName,
			profiles: profiles, plan: plan, spec: spec, policy: policy,
		}
		// Cleanup cannot pass this point until provisioning has finished. The
		// state is inserted while born lifecycle-locked.
		state.lifecycleMu.Lock()
		manager.mu.Lock()
		if manager.states[sessionID] != nil || manager.reservations[spec.slot] != "" || manager.names[spec.namespace] != "" {
			manager.mu.Unlock()
			state.lifecycleMu.Unlock()
			continue
		}
		manager.states[sessionID] = state
		manager.reservations[spec.slot] = sessionID
		manager.names[spec.namespace] = sessionID
		manager.mu.Unlock()
		return state, nil
	}
	return nil, collisionExhausted()
}

func (manager *Manager) provision(ctx context.Context, state *networkState) error {
	defer state.lifecycleMu.Unlock()
	state.namespaceAttempted = true
	if err := manager.backend.CreateNamespace(ctx, state.spec); err != nil {
		return topologyFailed(err)
	}
	state.vethAttempted = true
	if err := manager.backend.CreateVeth(ctx, state.spec); err != nil {
		return topologyFailed(err)
	}
	if err := manager.backend.ConfigureHost(ctx, state.spec); err != nil {
		return topologyFailed(err)
	}
	if err := manager.backend.ConfigureNamespace(ctx, state.spec); err != nil {
		return topologyFailed(err)
	}
	state.tapAttempted = true
	tap, err := manager.backend.CreateTAP(ctx, state.spec)
	if err != nil {
		return topologyFailed(err)
	}
	state.mu.Lock()
	state.tapFile = tap
	state.mu.Unlock()
	if err := manager.backend.ConfigureTAP(ctx, state.spec); err != nil {
		return topologyFailed(err)
	}
	state.namespacePolicyAttempted = true
	if err := manager.backend.ApplyNamespacePolicy(ctx, state.spec, state.policy); err != nil {
		return policyFailed(err)
	}
	state.hostPolicyAttempted = true
	if err := manager.backend.ApplyHostPolicy(ctx, state.spec, state.policy); err != nil {
		return policyFailed(err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	state.mu.Lock()
	state.ready = true
	state.mu.Unlock()
	return nil
}

// Cleanup is retryable, serialized and idempotent. It first severs the host
// veth so a partial cleanup cannot widen guest egress, then removes owned
// policy and topology resources and verifies complete absence.
func (manager *Manager) Cleanup(ctx context.Context, sessionID string) error {
	if ctx == nil || manager == nil || session.ValidateID(sessionID) != nil {
		return invalidRequest()
	}
	manager.mu.Lock()
	state := manager.states[sessionID]
	manager.mu.Unlock()
	if state == nil {
		return nil
	}
	// Once a valid owned state is accepted, cleanup has its own bounded
	// lifetime. Caller cancellation cannot abandon mandatory teardown.
	return manager.cleanupState(context.Background(), state)
}

func (manager *Manager) cleanupState(ctx context.Context, state *networkState) error {
	state.lifecycleMu.Lock()
	defer state.lifecycleMu.Unlock()
	cleanupCtx, cancel := boundedContext(ctx, maximumCleanupDuration)
	defer cancel()
	var failures []error
	state.mu.Lock()
	state.ready = false
	tapFile := state.tapFile
	state.tapFile = nil
	state.mu.Unlock()

	if state.vethAttempted {
		if err := manager.backend.DisableEgress(cleanupCtx, state.spec); err != nil {
			failures = append(failures, err)
		}
		if err := manager.backend.DeleteVeth(cleanupCtx, state.spec); err != nil {
			failures = append(failures, err)
		}
	}
	if state.hostPolicyAttempted {
		if err := manager.backend.DeleteHostPolicy(cleanupCtx, state.spec); err != nil {
			failures = append(failures, err)
		}
	}
	if state.namespacePolicyAttempted {
		if err := manager.backend.DeleteNamespacePolicy(cleanupCtx, state.spec); err != nil {
			failures = append(failures, err)
		}
	}
	if tapFile != nil {
		if err := tapFile.Close(); err != nil {
			failures = append(failures, ErrCommandFailed)
		}
	}
	if state.tapAttempted {
		if err := manager.backend.DeleteTAP(cleanupCtx, state.spec); err != nil {
			failures = append(failures, err)
		}
	}
	if state.namespaceAttempted {
		if err := manager.backend.DeleteNamespace(cleanupCtx, state.spec); err != nil {
			failures = append(failures, err)
		}
	}
	absent, auditErr := manager.backend.AuditAbsent(cleanupCtx, state.spec)
	if auditErr != nil || !absent {
		failures = append(failures, ErrCleanupIncomplete)
	}
	if cleanupCtx.Err() != nil {
		failures = append(failures, ErrCleanupIncomplete)
	}
	if len(failures) > 0 {
		return cleanupIncomplete()
	}
	state.namespaceAttempted = false
	state.vethAttempted = false
	state.tapAttempted = false
	state.namespacePolicyAttempted = false
	state.hostPolicyAttempted = false
	state.mu.Lock()
	state.policy.destroy()
	state.mu.Unlock()
	manager.mu.Lock()
	if manager.states[state.sessionID] == state {
		delete(manager.states, state.sessionID)
	}
	if manager.reservations[state.spec.slot] == state.sessionID {
		delete(manager.reservations, state.spec.slot)
	}
	if manager.names[state.spec.namespace] == state.sessionID {
		delete(manager.names, state.spec.namespace)
	}
	manager.mu.Unlock()
	return nil
}

func (handle *Handle) Inspect() Inspection {
	if handle == nil || handle.state == nil {
		return Inspection{SchemaVersion: 1}
	}
	handle.state.mu.Lock()
	defer handle.state.mu.Unlock()
	return Inspection{
		SchemaVersion: 1, Ready: handle.state.ready,
		IPv4EndpointCount: len(handle.state.policy.v4), IPv6EndpointCount: len(handle.state.policy.v6),
		TAPReady: handle.state.ready && handle.state.tapFile != nil,
	}
}

// WithTAP proves the exact VPN plan remains current and supplies a scoped
// duplicate of the retained TAP descriptor after the interface has moved into
// its namespace. The duplicate is always closed before the lifecycle lease is
// released. QEMU startup may inherit it through ExtraFiles; it never names the
// TAP. Process ownership must stop QEMU before calling network cleanup.
func (handle *Handle) WithTAP(ctx context.Context, fn func(context.Context, *os.File) error) error {
	if ctx == nil || fn == nil || handle == nil || handle.state == nil {
		return invalidRequest()
	}
	handoffCtx, cancel := boundedContext(ctx, maximumHandoffDuration)
	defer cancel()
	return handle.state.profiles.UsePlan(handoffCtx, handle.state.owner, handle.state.profileName, handle.state.plan, func(vpn.ResolvedProfile) error {
		handle.state.lifecycleMu.Lock()
		defer handle.state.lifecycleMu.Unlock()
		handle.state.mu.Lock()
		if !handle.state.ready || handle.state.tapFile == nil {
			handle.state.mu.Unlock()
			return topologyNotReady()
		}
		duplicate, err := duplicateTAPFile(handle.state.tapFile)
		handle.state.mu.Unlock()
		if err != nil {
			return topologyFailed(err)
		}
		defer duplicate.Close()
		if err := fn(handoffCtx, duplicate); err != nil {
			return err
		}
		return handoffCtx.Err()
	})
}

func (handle *Handle) WithGuestAddressing(ctx context.Context, fn func(context.Context, GuestAddressing) error) error {
	if ctx == nil || fn == nil || handle == nil || handle.state == nil {
		return invalidRequest()
	}
	handoffCtx, cancel := boundedContext(ctx, maximumHandoffDuration)
	defer cancel()
	return handle.state.profiles.UsePlan(handoffCtx, handle.state.owner, handle.state.profileName, handle.state.plan, func(vpn.ResolvedProfile) error {
		handle.state.lifecycleMu.Lock()
		defer handle.state.lifecycleMu.Unlock()
		handle.state.mu.Lock()
		if !handle.state.ready {
			handle.state.mu.Unlock()
			return topologyNotReady()
		}
		addressing := guestAddressing{spec: handle.state.spec}
		handle.state.mu.Unlock()
		if err := fn(handoffCtx, addressing); err != nil {
			return err
		}
		return handoffCtx.Err()
	})
}

func (handle *Handle) WithGuestVPNConfig(ctx context.Context, fn func(context.Context, io.Reader) error) error {
	if ctx == nil || fn == nil || handle == nil || handle.state == nil {
		return invalidRequest()
	}
	handoffCtx, cancel := boundedContext(ctx, maximumHandoffDuration)
	defer cancel()
	return handle.state.profiles.UsePlan(handoffCtx, handle.state.owner, handle.state.profileName, handle.state.plan, func(resolved vpn.ResolvedProfile) error {
		handle.state.lifecycleMu.Lock()
		defer handle.state.lifecycleMu.Unlock()
		handle.state.mu.Lock()
		ready := handle.state.ready
		handle.state.mu.Unlock()
		if !ready {
			return topologyNotReady()
		}
		if err := resolved.WithGuestConfig(handoffCtx, fn); err != nil {
			return err
		}
		return handoffCtx.Err()
	})
}

func (handle *Handle) Cleanup(ctx context.Context) error {
	if handle == nil || handle.manager == nil || handle.state == nil {
		return nil
	}
	return handle.manager.Cleanup(ctx, handle.state.sessionID)
}

func normalizeCreateError(err error) error {
	var application *apperror.Error
	if errors.As(err, &application) {
		return application
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return topologyFailed(err)
}

func boundedContext(ctx context.Context, maximum time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(maximum)
	if current, ok := ctx.Deadline(); ok && current.Before(deadline) {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, deadline)
}

func (*Handle) String() string   { return redactedHandle }
func (*Handle) GoString() string { return redactedHandle }
func (*Handle) Format(formatter fmt.State, _ rune) {
	_, _ = formatter.Write([]byte(redactedHandle))
}
func (*Handle) MarshalJSON() ([]byte, error)   { return nil, secret.ErrSerialization }
func (*Handle) MarshalText() ([]byte, error)   { return nil, secret.ErrSerialization }
func (*Handle) MarshalBinary() ([]byte, error) { return nil, secret.ErrSerialization }
func (*Handle) GobEncode() ([]byte, error)     { return nil, secret.ErrSerialization }
func (*Handle) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

var _ fmt.Formatter = (*Handle)(nil)
var _ json.Marshaler = (*Handle)(nil)
