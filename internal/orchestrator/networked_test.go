package orchestrator

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"github.com/StevenBuglione/private-vm/internal/qemu"
	"github.com/StevenBuglione/private-vm/internal/session"
)

const networkedSessionID = "pvm-22222222222222222222222222222222"

type operationLog struct {
	mu     sync.Mutex
	values []string
}

func (log *operationLog) add(value string) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.values = append(log.values, value)
}

func (log *operationLog) index(value string) int {
	log.mu.Lock()
	defer log.mu.Unlock()
	for index, current := range log.values {
		if current == value {
			return index
		}
	}
	return -1
}

type fakeCapability struct {
	log     *operationLog
	failDup bool
}

func (capability *fakeCapability) DupFile() (*os.File, error) {
	capability.log.add("capability.duplicate")
	if capability.failDup {
		return nil, errors.New("opaque duplicate failure")
	}
	return os.Open("/dev/null")
}

func (capability *fakeCapability) Destroy() { capability.log.add("capability.destroy") }

type fakeNetworkLease struct {
	log             *operationLog
	failAt          string
	cleanupFailures int
	cleanupDone     chan struct{}
	cleanupOnce     sync.Once
}

func newFakeNetwork(log *operationLog) *fakeNetworkLease {
	return &fakeNetworkLease{log: log, cleanupDone: make(chan struct{})}
}

func (network *fakeNetworkLease) WithUnderlay(ctx context.Context, fn func(context.Context, guestvpn.Underlay) error) error {
	network.log.add("network.underlay")
	if network.failAt == "underlay" {
		return errors.New("opaque underlay failure")
	}
	return fn(ctx, guestvpn.Underlay{
		IPv4Address: netip.MustParsePrefix("192.0.2.2/30"),
		IPv4Gateway: netip.MustParseAddr("192.0.2.1"),
		IPv6Address: netip.MustParsePrefix("2001:db8::2/126"),
		IPv6Gateway: netip.MustParseAddr("2001:db8::1"),
	})
}

func (network *fakeNetworkLease) WithTAP(ctx context.Context, fn func(context.Context, *os.File) error) error {
	network.log.add("network.tap")
	if network.failAt == "tap" {
		return errors.New("opaque TAP failure")
	}
	file, err := os.Open("/dev/null")
	if err != nil {
		return err
	}
	defer file.Close()
	return fn(ctx, file)
}

func (network *fakeNetworkLease) WithGuestVPNConfig(ctx context.Context, fn func(context.Context, io.Reader) error) error {
	network.log.add("network.profile")
	if network.failAt == "profile" {
		return errors.New("opaque profile failure")
	}
	return fn(ctx, &oneShotReader{data: []byte("synthetic-profile")})
}

func (network *fakeNetworkLease) Cleanup(context.Context) error {
	network.log.add("network.cleanup")
	if network.cleanupFailures > 0 {
		network.cleanupFailures--
		return errors.New("opaque cleanup failure")
	}
	network.cleanupOnce.Do(func() { close(network.cleanupDone) })
	return nil
}

type oneShotReader struct{ data []byte }

func (reader *oneShotReader) Read(output []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	count := copy(output, reader.data)
	reader.data = reader.data[count:]
	return count, nil
}

type fakeProcess struct {
	log      *operationLog
	done     chan struct{}
	stopOnce sync.Once
	waitErr  error
	stopErr  error
}

func newFakeProcess(log *operationLog) *fakeProcess {
	return &fakeProcess{log: log, done: make(chan struct{})}
}

func (process *fakeProcess) Stop(context.Context) error {
	process.log.add("qemu.stop")
	if process.stopErr != nil {
		return process.stopErr
	}
	process.stopOnce.Do(func() { close(process.done) })
	return nil
}

func (process *fakeProcess) Wait(ctx context.Context) error {
	select {
	case <-process.done:
		return process.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (process *fakeProcess) crash(err error) {
	process.waitErr = err
	process.stopOnce.Do(func() { close(process.done) })
}

type fakeLauncher struct {
	log     *operationLog
	process *fakeProcess
	fail    bool
}

func (launcher *fakeLauncher) Launch(_ context.Context, _ qemu.Spec, files qemu.InheritedFiles) (ManagedProcess, error) {
	launcher.log.add("qemu.launch")
	if files.Capability == nil || files.TAP == nil {
		return nil, errors.New("missing inherited descriptor")
	}
	if launcher.fail {
		return nil, errors.New("opaque launch failure")
	}
	return launcher.process, nil
}

type fakeGuest struct {
	log            *operationLog
	failAt         string
	dirty          bool
	monitorStarted chan struct{}
	monitorOnce    sync.Once
	monitorErr     error
}

func newFakeGuest(log *operationLog) *fakeGuest {
	return &fakeGuest{log: log, monitorStarted: make(chan struct{})}
}

func (guest *fakeGuest) Handshake(context.Context) error {
	guest.log.add("guest.handshake")
	if guest.failAt == "handshake" {
		return errors.New("opaque handshake failure")
	}
	return nil
}

func (guest *fakeGuest) ConfigureVPN(_ context.Context, _ guestvpn.Underlay, profile io.Reader) (guestvpn.Status, error) {
	guest.log.add("guest.configure")
	if _, err := io.Copy(io.Discard, profile); err != nil {
		return guestvpn.Status{}, err
	}
	if guest.failAt == "configure" {
		return guestvpn.Status{}, errors.New("opaque configure failure")
	}
	return completeNetworkedStatus(), nil
}

func (guest *fakeGuest) VerifyVPN(context.Context) (guestvpn.Status, error) {
	guest.log.add("guest.verify")
	if guest.failAt == "verify" {
		return guestvpn.Status{}, errors.New("opaque verification failure")
	}
	return completeNetworkedStatus(), nil
}

func (guest *fakeGuest) MonitorVPN(ctx context.Context, _ time.Duration, _ guestvpn.LossResponder) error {
	guest.log.add("guest.monitor")
	guest.monitorOnce.Do(func() { close(guest.monitorStarted) })
	if guest.monitorErr != nil {
		return guest.monitorErr
	}
	<-ctx.Done()
	return ctx.Err()
}

func (guest *fakeGuest) WorkspaceDirty(context.Context) (bool, error) {
	guest.log.add("guest.dirty")
	return guest.dirty, nil
}

func (guest *fakeGuest) Shutdown(context.Context) error {
	guest.log.add("guest.shutdown")
	return nil
}

func (guest *fakeGuest) Close() error {
	guest.log.add("guest.close")
	return nil
}

type fakeGuestConnector struct {
	log   *operationLog
	guest *fakeGuest
	fail  bool
}

func (connector *fakeGuestConnector) Connect(context.Context, uint32, session.Role, Capability) (GuestConnection, error) {
	connector.log.add("guest.connect")
	if connector.fail {
		return nil, errors.New("opaque connection failure")
	}
	return connector.guest, nil
}

type fakeEgressAuditor struct {
	log      *operationLog
	proof    EgressProof
	verifier error
}

func (auditor *fakeEgressAuditor) Verify(context.Context, string) (EgressProof, error) {
	auditor.log.add("egress.verify")
	return auditor.proof, auditor.verifier
}

type inertLossResponder struct{}

func (inertLossResponder) OnVPNLoss(context.Context, guestvpn.Status) error { return nil }

func completeNetworkedStatus() guestvpn.Status {
	return guestvpn.Status{
		SchemaVersion: 1, State: guestvpn.StateVerified, KillSwitchArmed: true, Configured: true,
		Handshake: true, DNSThroughTunnel: true, DNSBypassBlocked: true, IPv4ThroughTunnel: true,
		IPv4BypassBlocked: true, IPv6BypassBlocked: true, Code: "GUEST_VPN_VERIFIED",
	}
}

func networkedSpec(t *testing.T) qemu.Spec {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "pvm-orchestrator-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	return qemu.Spec{
		Binary: binary, SessionID: networkedSessionID, Name: "private-vm-test",
		Role: session.RoleWorkstation, CPUs: 1, MemoryBytes: 512 << 20,
		Root:      qemu.Disk{Path: filepath.Join(directory, "root.qcow2"), Format: "qcow2", Serial: "root"},
		QMPSocket: filepath.Join(directory, "qmp.sock"), SPICESocket: filepath.Join(directory, "spice.sock"),
		VSOCKCID: 42, Networked: true, NetworkFD: 4, FWCfgTokenFD: 3,
	}
}

func networkedFixture(t *testing.T) (StartNetworkedRequest, *fakeNetworkLease, *fakeCapability, *fakeLauncher, *fakeGuest) {
	t.Helper()
	log := &operationLog{}
	network := newFakeNetwork(log)
	capability := &fakeCapability{log: log}
	process := newFakeProcess(log)
	launcher := &fakeLauncher{log: log, process: process}
	guest := newFakeGuest(log)
	request := StartNetworkedRequest{
		SessionID: networkedSessionID, Role: session.RoleWorkstation, Spec: networkedSpec(t),
		Network: network, Capability: capability, Launcher: launcher,
		Guests:        &fakeGuestConnector{log: log, guest: guest},
		Egress:        &fakeEgressAuditor{log: log, proof: EgressProof{NamespacePolicyPresent: true, HostPolicyPresent: true, ForbiddenEgressZero: true}},
		LossResponder: inertLossResponder{}, MonitorInterval: time.Millisecond,
	}
	if err := request.Spec.Validate(); err != nil {
		t.Fatalf("networked test spec: %v", err)
	}
	return request, network, capability, launcher, guest
}

func TestNetworkedRuntimeOrdersVerifiedStartAndIdempotentCleanup(t *testing.T) {
	request, network, _, launcher, guest := networkedFixture(t)
	runtime, err := StartNetworked(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-guest.monitorStarted:
	case <-time.After(time.Second):
		t.Fatal("monitor did not start")
	}
	if err := runtime.Stop(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stop(context.Background(), false); err != nil {
		t.Fatalf("repeated stop: %v", err)
	}
	for before, after := range map[string]string{
		"network.underlay": "qemu.launch", "qemu.launch": "guest.handshake",
		"guest.handshake": "guest.configure", "guest.configure": "guest.verify",
		"guest.verify": "egress.verify", "guest.shutdown": "qemu.stop",
		"qemu.stop": "capability.destroy", "capability.destroy": "network.cleanup",
	} {
		if request.Network.(*fakeNetworkLease).log.index(before) < 0 || request.Network.(*fakeNetworkLease).log.index(before) >= request.Network.(*fakeNetworkLease).log.index(after) {
			t.Fatalf("operation order %s before %s was not preserved", before, after)
		}
	}
	select {
	case <-network.cleanupDone:
	default:
		t.Fatal("network was not cleaned")
	}
	select {
	case <-launcher.process.done:
	default:
		t.Fatal("QEMU was not stopped")
	}
}

func TestNetworkedStartFailureMatrixAlwaysCleansOwnedResources(t *testing.T) {
	for _, stage := range []string{"underlay", "duplicate", "tap", "launch", "connect", "handshake", "profile", "configure", "verify", "egress"} {
		t.Run(stage, func(t *testing.T) {
			request, network, capability, launcher, guest := networkedFixture(t)
			switch stage {
			case "underlay", "tap", "profile":
				network.failAt = stage
			case "duplicate":
				capability.failDup = true
			case "launch":
				launcher.fail = true
			case "connect":
				request.Guests.(*fakeGuestConnector).fail = true
			case "handshake", "configure", "verify":
				guest.failAt = stage
			case "egress":
				request.Egress.(*fakeEgressAuditor).proof.ForbiddenEgressZero = false
			}
			if runtime, err := StartNetworked(context.Background(), request); err == nil || runtime != nil {
				t.Fatalf("failed stage %s returned runtime=%v err=%v", stage, runtime, err)
			}
			select {
			case <-network.cleanupDone:
			default:
				t.Fatal("network was not cleaned after failed start")
			}
			if request.Network.(*fakeNetworkLease).log.index("capability.destroy") < 0 {
				t.Fatal("capability was not destroyed after failed start")
			}
			if request.Network.(*fakeNetworkLease).log.index("qemu.launch") >= 0 && !launcher.fail && request.Network.(*fakeNetworkLease).log.index("qemu.stop") < 0 {
				t.Fatal("launched QEMU was not stopped after failed start")
			}
		})
	}
}

func TestNetworkedFailedStartReturnsCleanupOwnerWhenCleanupMustRetry(t *testing.T) {
	request, network, _, _, guest := networkedFixture(t)
	guest.failAt = "verify"
	network.cleanupFailures = 1
	runtime, err := StartNetworked(context.Background(), request)
	if runtime == nil || !errors.Is(err, ErrNetworkedCleanup) {
		t.Fatalf("incomplete failed-start cleanup = runtime %v, error %v", runtime, err)
	}
	if err := runtime.Stop(context.Background(), true); err != nil {
		t.Fatalf("failed-start cleanup retry = %v", err)
	}
	select {
	case <-network.cleanupDone:
	default:
		t.Fatal("failed-start cleanup retry did not clean network")
	}
}

func TestNetworkedDownloaderRequiresTorrentBindingProof(t *testing.T) {
	status := completeNetworkedStatus()
	if verifiedStatus(status, session.RoleDownloader) {
		t.Fatal("downloader passed without qBittorrent binding")
	}
	status.TorrentBound = true
	if !verifiedStatus(status, session.RoleDownloader) {
		t.Fatal("complete downloader proof was rejected")
	}
}

func TestNetworkedStopProtectsDirtyWorkstationAndRetriesCleanup(t *testing.T) {
	request, network, _, _, guest := networkedFixture(t)
	guest.dirty = true
	runtime, err := StartNetworked(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stop(context.Background(), false); !errors.Is(err, ErrDirtyWorkspace) {
		t.Fatalf("dirty stop = %v", err)
	}
	select {
	case <-network.cleanupDone:
		t.Fatal("dirty workstation was cleaned without confirmation")
	default:
	}
	network.cleanupFailures = 1
	if err := runtime.Stop(context.Background(), true); !errors.Is(err, ErrNetworkedCleanup) {
		t.Fatalf("first cleanup = %v", err)
	}
	if err := runtime.Stop(context.Background(), true); err != nil {
		t.Fatalf("retry cleanup = %v", err)
	}
}

func TestNetworkedRuntimeCleansAfterUnexpectedQEMUExit(t *testing.T) {
	request, network, _, launcher, _ := networkedFixture(t)
	runtime, err := StartNetworked(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	launcher.process.crash(errors.New("synthetic crash"))
	select {
	case <-network.cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("unexpected QEMU exit did not clean network")
	}
	if err := runtime.Stop(context.Background(), true); !errors.Is(err, ErrNetworkedCleanup) {
		t.Fatalf("crash cleanup status = %v", err)
	}
}

func TestNetworkedStartCancellationAndValidationFailClosed(t *testing.T) {
	request, network, _, _, _ := networkedFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if runtime, err := StartNetworked(ctx, request); runtime != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled start = runtime %v, error %v", runtime, err)
	}
	select {
	case <-network.cleanupDone:
	default:
		t.Fatal("canceled start did not clean network")
	}

	request, network, _, _, _ = networkedFixture(t)
	request.MonitorInterval = 6 * time.Minute
	if runtime, err := StartNetworked(context.Background(), request); runtime != nil || !errors.Is(err, ErrNetworkedStart) {
		t.Fatalf("invalid interval = runtime %v, error %v", runtime, err)
	}
	select {
	case <-network.cleanupDone:
		t.Fatal("validation failure mutated network")
	default:
	}
}
