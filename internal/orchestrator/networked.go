package orchestrator

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"github.com/StevenBuglione/private-vm/internal/network"
	"github.com/StevenBuglione/private-vm/internal/qemu"
	"github.com/StevenBuglione/private-vm/internal/session"
)

const (
	networkedStartTimeout   = 60 * time.Second
	networkedCleanupTimeout = 30 * time.Second
	defaultMonitorInterval  = 10 * time.Second
)

var (
	ErrNetworkedStart       = errors.New("networked guest start failed")
	ErrNetworkedCleanup     = errors.New("networked guest cleanup incomplete")
	ErrNetworkedNotVerified = errors.New("networked guest not verified")
	ErrDirtyWorkspace       = errors.New("workstation has unexported or changed output")
)

type Capability interface {
	DupFile() (*os.File, error)
	Destroy()
}

type NetworkLease interface {
	WithTAP(context.Context, func(context.Context, *os.File) error) error
	WithUnderlay(context.Context, func(context.Context, guestvpn.Underlay) error) error
	WithGuestVPNConfig(context.Context, func(context.Context, io.Reader) error) error
	Cleanup(context.Context) error
}

type ManagedProcess interface {
	Stop(context.Context) error
	Wait(context.Context) error
}

type QEMULauncher interface {
	Launch(context.Context, qemu.Spec, qemu.InheritedFiles) (ManagedProcess, error)
}

type GuestConnection interface {
	Handshake(context.Context) error
	ConfigureVPN(context.Context, guestvpn.Underlay, io.Reader) (guestvpn.Status, error)
	VerifyVPN(context.Context) (guestvpn.Status, error)
	MonitorVPN(context.Context, time.Duration, guestvpn.LossResponder) error
	WorkspaceDirty(context.Context) (bool, error)
	Shutdown(context.Context) error
	Close() error
}

type GuestConnector interface {
	Connect(context.Context, uint32, session.Role, Capability) (GuestConnection, error)
}

// EgressProof is deliberately boolean-only; table names, packet targets,
// counters, endpoint values and raw nft output cannot enter orchestration state.
type EgressProof struct {
	NamespacePolicyPresent bool
	HostPolicyPresent      bool
	ForbiddenEgressZero    bool
}

func (proof EgressProof) complete() bool {
	return proof.NamespacePolicyPresent && proof.HostPolicyPresent && proof.ForbiddenEgressZero
}

type EgressAuditor interface {
	Verify(context.Context, string) (EgressProof, error)
}

type StartNetworkedRequest struct {
	SessionID       string
	Role            session.Role
	ScannerUpdate   bool
	Spec            qemu.Spec
	Network         NetworkLease
	Capability      Capability
	Launcher        QEMULauncher
	Guests          GuestConnector
	Egress          EgressAuditor
	LossResponder   guestvpn.LossResponder
	MonitorInterval time.Duration
}

type NetworkedRuntime struct {
	mu sync.Mutex

	sessionID  string
	role       session.Role
	network    NetworkLease
	capability Capability
	process    ManagedProcess
	guest      GuestConnection
	display    *displayProxy

	monitorCancel  context.CancelFunc
	monitorErr     error
	processStopped bool
	guestClosed    bool
	capDestroyed   bool
	networkCleaned bool
	cleanupErr     error
}

func StartNetworked(ctx context.Context, request StartNetworkedRequest) (result *NetworkedRuntime, resultErr error) {
	if ctx == nil || validateStartRequest(request) != nil {
		return nil, ErrNetworkedStart
	}
	startCtx, cancel := boundedContext(ctx, networkedStartTimeout)
	defer cancel()
	runtime := &NetworkedRuntime{
		sessionID: request.SessionID, role: request.Role,
		network: request.Network, capability: request.Capability,
	}
	failed := true
	defer func() {
		if failed {
			if cleanupErr := runtime.cleanupFailedStart(); cleanupErr != nil {
				// Return the sole cleanup owner when teardown is incomplete so the
				// session owner can retry instead of orphaning resources.
				result = runtime
				resultErr = ErrNetworkedCleanup
			}
		}
	}()

	var underlay guestvpn.Underlay
	if err := request.Network.WithUnderlay(startCtx, func(callbackCtx context.Context, addressing guestvpn.Underlay) error {
		if err := callbackCtx.Err(); err != nil {
			return err
		}
		underlay = addressing
		return nil
	}); err != nil {
		return nil, normalizeStartError(startCtx)
	}
	capabilityFile, err := request.Capability.DupFile()
	if err != nil {
		return nil, ErrNetworkedStart
	}
	defer capabilityFile.Close()
	if err := request.Network.WithTAP(startCtx, func(callbackCtx context.Context, tap *os.File) error {
		process, launchErr := request.Launcher.Launch(callbackCtx, request.Spec, qemu.InheritedFiles{Capability: capabilityFile, TAP: tap})
		if launchErr == nil {
			runtime.process = process
		}
		return launchErr
	}); err != nil || runtime.process == nil {
		return nil, normalizeStartError(startCtx)
	}
	runtime.guest, err = request.Guests.Connect(startCtx, request.Spec.VSOCKCID, request.Role, request.Capability)
	if err != nil || runtime.guest == nil {
		return nil, normalizeStartError(startCtx)
	}
	if err := runtime.guest.Handshake(startCtx); err != nil {
		return nil, normalizeStartError(startCtx)
	}
	var configured guestvpn.Status
	if err := request.Network.WithGuestVPNConfig(startCtx, func(callbackCtx context.Context, profile io.Reader) error {
		var configureErr error
		configured, configureErr = runtime.guest.ConfigureVPN(callbackCtx, underlay, profile)
		return configureErr
	}); err != nil || !verifiedStatus(configured, request.Role) {
		return nil, ErrNetworkedNotVerified
	}
	verified, err := runtime.guest.VerifyVPN(startCtx)
	if err != nil || !verifiedStatus(verified, request.Role) {
		return nil, ErrNetworkedNotVerified
	}
	egress, err := request.Egress.Verify(startCtx, request.SessionID)
	if err != nil || !egress.complete() {
		return nil, ErrNetworkedNotVerified
	}
	monitorInterval := request.MonitorInterval
	if monitorInterval <= 0 {
		monitorInterval = defaultMonitorInterval
	}
	monitorCtx, monitorCancel := context.WithCancel(context.Background())
	runtime.monitorCancel = monitorCancel
	go runtime.monitor(monitorCtx, monitorInterval, request.LossResponder)
	go runtime.watchProcess()
	failed = false
	return runtime, nil
}

func validateStartRequest(request StartNetworkedRequest) error {
	if session.ValidateID(request.SessionID) != nil || request.Spec.Validate() != nil || request.Spec.SessionID != request.SessionID || request.Spec.Role != request.Role ||
		isNilLike(request.Network) || isNilLike(request.Capability) || isNilLike(request.Launcher) ||
		isNilLike(request.Guests) || isNilLike(request.Egress) || isNilLike(request.LossResponder) ||
		!request.Spec.Networked || request.Spec.NetworkFD != 4 || request.Spec.FWCfgTokenFD != 3 ||
		request.MonitorInterval < 0 || request.MonitorInterval > 5*time.Minute {
		return ErrNetworkedStart
	}
	switch request.Role {
	case session.RoleWorkstation, session.RoleDownloader:
		return nil
	case session.RoleScanner:
		if request.ScannerUpdate && request.Spec.ScannerMode == qemu.ScannerModeUpdate {
			return nil
		}
	}
	return ErrNetworkedStart
}

func verifiedStatus(status guestvpn.Status, role session.Role) bool {
	verified := status.SchemaVersion == 1 && status.State == guestvpn.StateVerified && status.KillSwitchArmed && status.Configured &&
		status.Handshake && status.DNSThroughTunnel && status.DNSBypassBlocked && status.IPv4ThroughTunnel &&
		status.IPv4BypassBlocked && status.IPv6ThroughTunnel && status.IPv6BypassBlocked && status.Code == "GUEST_VPN_VERIFIED"
	return verified && (role != session.RoleDownloader || status.TorrentBound)
}

func (runtime *NetworkedRuntime) Stop(ctx context.Context, discardDirty bool) error {
	if ctx == nil || runtime == nil {
		return ErrNetworkedCleanup
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.processStopped && runtime.guestClosed && runtime.capDestroyed && runtime.networkCleaned {
		return runtime.cleanupErr
	}
	if runtime.role == session.RoleWorkstation && !discardDirty && runtime.guest != nil && !runtime.processStopped {
		checkCtx, cancel := boundedContext(ctx, vpnLossResponseTimeout)
		dirty, err := runtime.guest.WorkspaceDirty(checkCtx)
		cancel()
		if err != nil {
			return ErrNetworkedCleanup
		}
		if dirty {
			return ErrDirtyWorkspace
		}
	}
	return runtime.stopAndCleanupLocked()
}

func (runtime *NetworkedRuntime) stopAndCleanupLocked() error {
	if runtime.monitorCancel != nil {
		runtime.monitorCancel()
		runtime.monitorCancel = nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), networkedCleanupTimeout)
	defer cancel()
	if !runtime.processStopped {
		if runtime.guest != nil {
			_ = runtime.guest.Shutdown(cleanupCtx)
		}
		if runtime.process != nil && runtime.process.Stop(cleanupCtx) != nil {
			runtime.cleanupErr = ErrNetworkedCleanup
			return runtime.cleanupErr
		}
		runtime.processStopped = true
	}
	return runtime.cleanupAfterProcessLocked(cleanupCtx)
}

func (runtime *NetworkedRuntime) cleanupAfterProcessLocked(ctx context.Context) error {
	cleanupFailed := false
	if !runtime.guestClosed && runtime.guest != nil {
		if runtime.guest.Close() != nil {
			cleanupFailed = true
		} else {
			runtime.guestClosed = true
		}
	} else if runtime.guest == nil {
		runtime.guestClosed = true
	}
	if !runtime.capDestroyed && runtime.capability != nil {
		runtime.capability.Destroy()
		runtime.capDestroyed = true
	} else if runtime.capability == nil {
		runtime.capDestroyed = true
	}
	if !runtime.networkCleaned {
		if runtime.network == nil || runtime.network.Cleanup(ctx) != nil {
			cleanupFailed = true
		} else {
			runtime.networkCleaned = true
		}
	}
	if cleanupFailed {
		runtime.cleanupErr = ErrNetworkedCleanup
		return runtime.cleanupErr
	}
	runtime.cleanupErr = nil
	return nil
}

func (runtime *NetworkedRuntime) cleanupFailedStart() error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.stopAndCleanupLocked()
}

func (runtime *NetworkedRuntime) monitor(ctx context.Context, interval time.Duration, responder guestvpn.LossResponder) {
	err := runtime.guest.MonitorVPN(ctx, interval, responder)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	runtime.mu.Lock()
	runtime.monitorErr = err
	runtime.mu.Unlock()
}

func (runtime *NetworkedRuntime) watchProcess() {
	err := runtime.process.Wait(context.Background())
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.processStopped = true
	displayFailed := false
	if runtime.display != nil {
		if displayErr := runtime.display.Stop(); displayErr != nil {
			displayFailed = true
		}
	}
	if runtime.monitorCancel != nil {
		runtime.monitorCancel()
		runtime.monitorCancel = nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), networkedCleanupTimeout)
	defer cancel()
	if cleanupErr := runtime.cleanupAfterProcessLocked(cleanupCtx); cleanupErr != nil || err != nil || displayFailed {
		runtime.cleanupErr = ErrNetworkedCleanup
	}
}

func (runtime *NetworkedRuntime) attachDisplay(display *displayProxy) error {
	if runtime == nil || display == nil || runtime.role != session.RoleWorkstation {
		return ErrNetworkedStart
	}
	runtime.mu.Lock()
	if runtime.display != nil || runtime.processStopped {
		runtime.mu.Unlock()
		_ = display.Stop()
		return ErrNetworkedCleanup
	}
	runtime.display = display
	runtime.mu.Unlock()
	return nil
}

func (runtime *NetworkedRuntime) MonitorError() error {
	if runtime == nil {
		return ErrNetworkedStart
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.monitorErr
}

func (runtime *NetworkedRuntime) Audit(context.Context) error {
	if runtime == nil {
		return ErrNetworkedCleanup
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.processStopped || !runtime.guestClosed || !runtime.capDestroyed || !runtime.networkCleaned || runtime.cleanupErr != nil {
		return ErrNetworkedCleanup
	}
	return nil
}

func (runtime *NetworkedRuntime) WorkspaceState(ctx context.Context) (string, error) {
	if runtime == nil || runtime.role != session.RoleWorkstation {
		return "", ErrNetworkedStart
	}
	runtime.mu.Lock()
	guestConnection := runtime.guest
	stopped := runtime.processStopped || runtime.guestClosed
	runtime.mu.Unlock()
	if stopped || guestConnection == nil {
		return "", ErrNetworkedCleanup
	}
	if stateGuest, ok := guestConnection.(interface {
		WorkspaceState(context.Context) (string, error)
	}); ok {
		return stateGuest.WorkspaceState(ctx)
	}
	dirty, err := guestConnection.WorkspaceDirty(ctx)
	if err != nil {
		return "", err
	}
	if dirty {
		return "UNEXPORTED", nil
	}
	return "CLEAN", nil
}

func (runtime *NetworkedRuntime) Torrent() (TorrentRelay, error) {
	if runtime == nil || runtime.role != session.RoleDownloader {
		return nil, ErrNetworkedStart
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.processStopped || runtime.guestClosed || runtime.guest == nil {
		return nil, ErrNetworkedCleanup
	}
	relay, ok := runtime.guest.(TorrentRelay)
	if !ok || relay == nil {
		return nil, ErrNetworkedStart
	}
	return relay, nil
}

func (runtime *NetworkedRuntime) ScannerClient() (privatevmv1.ScannerGuestServiceClient, error) {
	if runtime == nil || runtime.role != session.RoleScanner {
		return nil, ErrNetworkedStart
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.processStopped || runtime.guestClosed || runtime.guest == nil {
		return nil, ErrNetworkedCleanup
	}
	provider, ok := runtime.guest.(interface {
		ScannerClient() (privatevmv1.ScannerGuestServiceClient, error)
	})
	if !ok {
		return nil, ErrNetworkedStart
	}
	return provider.ScannerClient()
}

func normalizeStartError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrNetworkedStart
}

// QEMUAdapter gives the concrete launcher the interface-returning boundary used
// by the orchestration tests without weakening qemu.Launcher's typed API.
type QEMUAdapter struct{ Launcher *qemu.Launcher }

func (adapter QEMUAdapter) Launch(ctx context.Context, spec qemu.Spec, files qemu.InheritedFiles) (ManagedProcess, error) {
	if adapter.Launcher == nil {
		return nil, ErrNetworkedStart
	}
	return adapter.Launcher.Launch(ctx, spec, files)
}

var _ QEMULauncher = QEMUAdapter{}

// NetworkAdapter converts the network package's sealed addressing view into
// the guest VPN's immutable typed underlay at the narrow orchestration boundary.
type NetworkAdapter struct{ Handle *network.Handle }

func (adapter NetworkAdapter) WithTAP(ctx context.Context, fn func(context.Context, *os.File) error) error {
	if adapter.Handle == nil {
		return ErrNetworkedStart
	}
	return adapter.Handle.WithTAP(ctx, fn)
}

func (adapter NetworkAdapter) WithUnderlay(ctx context.Context, fn func(context.Context, guestvpn.Underlay) error) error {
	if adapter.Handle == nil || fn == nil {
		return ErrNetworkedStart
	}
	return adapter.Handle.WithGuestAddressing(ctx, func(callbackCtx context.Context, addressing network.GuestAddressing) error {
		return fn(callbackCtx, guestvpn.Underlay{
			IPv4Address: addressing.IPv4Address(), IPv4Gateway: addressing.IPv4Gateway(),
			IPv6Address: addressing.IPv6Address(), IPv6Gateway: addressing.IPv6Gateway(),
		})
	})
}

func (adapter NetworkAdapter) WithGuestVPNConfig(ctx context.Context, fn func(context.Context, io.Reader) error) error {
	if adapter.Handle == nil {
		return ErrNetworkedStart
	}
	return adapter.Handle.WithGuestVPNConfig(ctx, fn)
}

func (adapter NetworkAdapter) Cleanup(ctx context.Context) error {
	if adapter.Handle == nil {
		return nil
	}
	return adapter.Handle.Cleanup(ctx)
}

var _ NetworkLease = NetworkAdapter{}
