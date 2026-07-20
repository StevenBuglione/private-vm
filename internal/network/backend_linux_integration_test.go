//go:build linux

package network

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	integrationEnabledEnv  = "PRIVATE_VM_NETWORK_INTEGRATION"
	integrationChildEnv    = "PRIVATE_VM_NETWORK_INTEGRATION_CHILD"
	integrationEndpointEnv = "PRIVATE_VM_NETWORK_ENDPOINT_HELPER"
	integrationIPEnv       = "PRIVATE_VM_NETWORK_IP_BINARY"
	integrationNFTEnv      = "PRIVATE_VM_NETWORK_NFT_BINARY"
	integrationSysctlEnv   = "PRIVATE_VM_NETWORK_SYSCTL_BINARY"
	integrationUnshareEnv  = "PRIVATE_VM_NETWORK_UNSHARE_BINARY"

	integrationEndpointNamespace = "pvm-test-endpoint"
	integrationEndpointHostLink  = "pvmtestout"
	integrationEndpointPeerLink  = "pvmtestin"
	integrationEvidence          = `{"schema_version":1,"code":"NETWORK_NAMESPACE_INTEGRATION_VERIFIED","topology":true,"ipv4_endpoint_only":true,"ipv4_global_forwarding_off":true,"ipv6_endpoint_only":true,"ipv6_global_forwarding_fixture":true,"forbidden_paths_blocked":true,"live_counters_zero":true,"cancellation":true,"timeout":true,"cleanup_absent":true}`
	integrationReady             = "PRIVATE_VM_ENDPOINT_READY"
)

var (
	integrationAllowedIPv4    = netip.MustParseAddr("1.1.1.1")
	integrationHostIPv4       = netip.MustParseAddr("1.1.1.2")
	integrationAllowedIPv6    = netip.MustParseAddr("2606:4700:4700::1")
	integrationHostIPv6       = netip.MustParseAddr("2606:4700:4700::2")
	integrationLANIPv4        = netip.MustParseAddr("192.168.77.2")
	integrationMetadataIPv4   = netip.MustParseAddr("169.254.169.254")
	integrationUnrelatedIPv4  = netip.MustParseAddr("8.8.8.8")
	integrationLANIPv6        = netip.MustParseAddr("fd00::2")
	integrationUnrelatedIPv6  = netip.MustParseAddr("2001:4860:4860::8888")
	integrationGuestSourceMAC = net.HardwareAddr{0x02, 0x50, 0x56, 0x4d, 0x00, 0x01}
)

type integrationProbe struct {
	name    string
	network string
	address netip.Addr
	port    uint16
	payload byte
	allowed bool
}

func integrationProbes() []integrationProbe {
	return []integrationProbe{
		{name: "allowed_ipv4", network: "udp4", address: integrationAllowedIPv4, port: 51820, payload: 0x11, allowed: true},
		{name: "allowed_ipv6", network: "udp6", address: integrationAllowedIPv6, port: 51820, payload: 0x12, allowed: true},
		{name: "dns", network: "udp4", address: integrationAllowedIPv4, port: 53, payload: 0x21},
		{name: "lan_ipv4", network: "udp4", address: integrationLANIPv4, port: 40001, payload: 0x22},
		{name: "metadata", network: "udp4", address: integrationMetadataIPv4, port: 40002, payload: 0x23},
		{name: "unrelated_ipv4", network: "udp4", address: integrationUnrelatedIPv4, port: 40003, payload: 0x24},
		{name: "lan_ipv6", network: "udp6", address: integrationLANIPv6, port: 40004, payload: 0x25},
		{name: "unrelated_ipv6", network: "udp6", address: integrationUnrelatedIPv6, port: 40005, payload: 0x26},
	}
}

// TestLinuxBackendIsolatedIntegration is opt-in. The parent re-executes this
// exact test inside user, mount and network namespaces, so the real ip/nft/TUN
// backend cannot mutate host networking. All addresses are fixed synthetic
// fixtures and no VPN profile or WireGuard credential is constructed.
func TestLinuxBackendIsolatedIntegration(t *testing.T) {
	if os.Getenv(integrationEndpointEnv) == "1" {
		runIntegrationEndpoint(t)
		return
	}
	if os.Getenv(integrationEnabledEnv) != "1" {
		t.Skip("set PRIVATE_VM_NETWORK_INTEGRATION=1 to run the isolated Linux backend gate")
	}
	paths, unshare := integrationToolPaths(t)
	if os.Getenv(integrationChildEnv) != "1" {
		runIntegrationParent(t, paths, unshare)
		return
	}
	runIntegrationChild(t, paths)
}

func integrationToolPaths(t *testing.T) (ToolPaths, string) {
	t.Helper()
	paths := ToolPaths{
		IP: os.Getenv(integrationIPEnv), NFT: os.Getenv(integrationNFTEnv),
		Sysctl: os.Getenv(integrationSysctlEnv), Tun: "/dev/net/tun",
	}
	unshare := os.Getenv(integrationUnshareEnv)
	if err := paths.validate(); err != nil || !exactToolPath(unshare, "unshare") {
		t.Fatal("isolated network gate requires exact absolute pinned ip/nft/sysctl/unshare paths")
	}
	return paths, unshare
}

func exactToolPath(path, base string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Base(path) == base
}

func runIntegrationParent(t *testing.T, paths ToolPaths, unshare string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		t.Fatal("isolated network gate could not pin its test executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, unshare,
		"--user", "--map-root-user", "--mount", "--net",
		executable, "-test.run=^TestLinuxBackendIsolatedIntegration$", "-test.count=1",
	)
	command.Env = integrationEnvironment(paths,
		integrationEnabledEnv+"=1",
		integrationChildEnv+"=1",
	)
	var output limitedBuffer
	output.limit = networkCommandOutputLimit
	defer func() { clear(output.Bytes()) }()
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || ctx.Err() != nil || output.exceeded ||
		!bytesContainLine(output.Bytes(), integrationEvidence) {
		t.Fatal("isolated network child failed; no raw child output is exposed")
	}
	t.Log(integrationEvidence)
}

func runIntegrationChild(t *testing.T, paths ToolPaths) {
	t.Helper()
	if err := unix.Mount("tmpfs", "/run", "tmpfs", uintptr(unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC), "mode=0755,size=16m"); err != nil {
		t.Fatal("isolated network gate could not create its volatile /run")
	}
	defer func() {
		if err := unix.Unmount("/run", unix.MNT_DETACH); err != nil {
			t.Error("isolated network gate could not detach its volatile /run")
		}
	}()
	if err := os.Mkdir("/run/netns", 0o700); err != nil {
		t.Fatal("isolated network gate could not create its private netns directory")
	}

	backend := &linuxBackend{paths: paths, runner: osCommandRunner{}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := createIntegrationEndpoint(ctx, backend); err != nil {
		t.Fatal("isolated endpoint setup failed")
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if err := cleanupIntegrationEndpoint(cleanupCtx, backend); err != nil {
			t.Error("isolated endpoint cleanup failed")
		}
	}()

	spec := candidateFor("pvm-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0)
	policy, err := collectPolicy([]endpointTuple{
		endpointTupleFor(integrationAllowedIPv4, 51820),
		endpointTupleFor(integrationAllowedIPv6, 51820),
	})
	if err != nil {
		t.Fatal("synthetic endpoint policy was rejected")
	}
	defer policy.destroy()
	var tap *os.File
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if err := cleanupIntegrationTopology(cleanupCtx, backend, spec, &tap); err != nil {
			t.Error("isolated topology cleanup failed")
		}
	}()

	available, err := backend.Available(ctx, spec)
	if err != nil || !available {
		t.Fatal("isolated topology candidate was unavailable")
	}
	if err := backend.CreateNamespace(ctx, spec); err != nil {
		t.Fatal("isolated namespace creation failed")
	}
	if err := backend.CreateVeth(ctx, spec); err != nil {
		t.Fatal("isolated veth creation failed")
	}
	if err := backend.ConfigureHost(ctx, spec); err != nil {
		t.Fatal("isolated host-link configuration failed")
	}
	if err := backend.ConfigureNamespace(ctx, spec); err != nil {
		t.Fatal("isolated namespace configuration failed")
	}
	tap, err = backend.CreateTAP(ctx, spec)
	if err != nil || tap == nil {
		t.Fatal("isolated TAP creation failed")
	}
	if err := backend.ConfigureTAP(ctx, spec); err != nil {
		t.Fatal("isolated TAP configuration failed")
	}
	if err := backend.ApplyNamespacePolicy(ctx, spec, policy); err != nil {
		t.Fatal("isolated namespace policy failed")
	}
	if err := backend.ApplyHostPolicy(ctx, spec, policy); err != nil {
		t.Fatal("isolated host policy failed")
	}
	if err := verifyIntegrationTopology(ctx, backend, spec); err != nil {
		t.Fatal("isolated topology inventory was incomplete")
	}
	if err := enableIntegrationIPv6Forwarding(ctx, backend); err != nil {
		t.Fatal("isolated IPv6 forwarding fixture failed")
	}
	if err := waitIntegrationIPv6Ready(ctx, backend, spec); err != nil {
		t.Fatal("isolated IPv6 topology did not leave tentative state")
	}

	endpoint, ready, err := startIntegrationEndpoint(ctx, paths)
	if err != nil {
		t.Fatal("isolated endpoint helper did not start")
	}
	defer stopIntegrationEndpoint(endpoint)
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal("isolated endpoint helper did not become ready")
		}
	case <-ctx.Done():
		t.Fatal("isolated endpoint helper readiness timed out")
	}

	tapMAC, err := integrationTAPMAC(ctx, backend, spec)
	if err != nil {
		t.Fatal("isolated TAP identity could not be read")
	}
	defer clear(tapMAC)
	for _, probe := range integrationProbes() {
		frame, err := integrationFrame(spec, tapMAC, probe)
		if err != nil {
			t.Fatal("synthetic probe frame could not be constructed")
		}
		if err := writeIntegrationFrame(ctx, tap, frame); err != nil {
			clear(frame)
			t.Fatal("synthetic probe frame could not be delivered")
		}
		clear(frame)
	}
	if err := waitIntegrationEndpoint(ctx, endpoint); err != nil {
		t.Fatal("endpoint-only forwarding or a forbidden-path assertion failed")
	}
	endpoint = nil

	proof, err := backend.AuditPolicy(ctx, spec)
	if err != nil || !proof.NamespacePolicyPresent || !proof.HostPolicyPresent || !proof.ForbiddenEgressZero {
		t.Fatal("live nftables counter proof was incomplete")
	}
	canceled, cancelCanceled := context.WithCancel(context.Background())
	cancelCanceled()
	if _, err := backend.Available(canceled, spec); !errors.Is(err, context.Canceled) {
		t.Fatal("real backend did not preserve cancellation")
	}
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if _, err := backend.AuditPolicy(expired, spec); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("real backend did not preserve timeout")
	}

	if err := cleanupIntegrationTopology(ctx, backend, spec, &tap); err != nil {
		t.Fatal("first isolated topology cleanup failed")
	}
	if err := cleanupIntegrationTopology(ctx, backend, spec, &tap); err != nil {
		t.Fatal("repeated isolated topology cleanup failed")
	}
	absent, err := backend.AuditAbsent(ctx, spec)
	if err != nil || !absent {
		t.Fatal("isolated topology remained after cleanup")
	}
	if err := cleanupIntegrationEndpoint(ctx, backend); err != nil {
		t.Fatal("isolated endpoint teardown failed")
	}
	if err := verifyIntegrationAbsence(ctx, backend, spec); err != nil {
		t.Fatal("owned network resources remained after teardown")
	}
	fmt.Fprintln(os.Stdout, integrationEvidence)
}

func integrationEnvironment(paths ToolPaths, additional ...string) []string {
	environment := []string{
		"LANG=C.UTF-8",
		integrationIPEnv + "=" + paths.IP,
		integrationNFTEnv + "=" + paths.NFT,
		integrationSysctlEnv + "=" + paths.Sysctl,
		integrationUnshareEnv + "=" + os.Getenv(integrationUnshareEnv),
	}
	return append(environment, additional...)
}

func createIntegrationEndpoint(ctx context.Context, backend *linuxBackend) error {
	commands := [][]string{
		{"netns", "add", integrationEndpointNamespace},
		{"link", "add", integrationEndpointHostLink, "type", "veth", "peer", "name", integrationEndpointPeerLink},
		{"link", "set", integrationEndpointPeerLink, "netns", integrationEndpointNamespace},
		{"addr", "add", integrationHostIPv4.String() + "/30", "dev", integrationEndpointHostLink},
		{"-6", "addr", "add", integrationHostIPv6.String() + "/126", "dev", integrationEndpointHostLink, "nodad"},
		{"link", "set", integrationEndpointHostLink, "up"},
	}
	for _, arguments := range commands {
		if err := integrationCommand(ctx, backend.paths.IP, arguments...); err != nil {
			return err
		}
	}
	namespaceCommands := [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "add", integrationAllowedIPv4.String() + "/30", "dev", integrationEndpointPeerLink},
		{"-6", "addr", "add", integrationAllowedIPv6.String() + "/126", "dev", integrationEndpointPeerLink, "nodad"},
		{"addr", "add", integrationLANIPv4.String() + "/32", "dev", integrationEndpointPeerLink},
		{"addr", "add", integrationMetadataIPv4.String() + "/32", "dev", integrationEndpointPeerLink},
		{"addr", "add", integrationUnrelatedIPv4.String() + "/32", "dev", integrationEndpointPeerLink},
		{"-6", "addr", "add", integrationLANIPv6.String() + "/128", "dev", integrationEndpointPeerLink, "nodad"},
		{"-6", "addr", "add", integrationUnrelatedIPv6.String() + "/128", "dev", integrationEndpointPeerLink, "nodad"},
		{"link", "set", integrationEndpointPeerLink, "up"},
	}
	for _, arguments := range namespaceCommands {
		command := append([]string{"netns", "exec", integrationEndpointNamespace, backend.paths.IP}, arguments...)
		if err := integrationCommand(ctx, backend.paths.IP, command...); err != nil {
			return err
		}
	}
	for _, address := range []netip.Addr{integrationLANIPv4, integrationMetadataIPv4, integrationUnrelatedIPv4} {
		if err := integrationCommand(ctx, backend.paths.IP, "route", "add", address.String()+"/32", "dev", integrationEndpointHostLink); err != nil {
			return err
		}
	}
	for _, address := range []netip.Addr{integrationLANIPv6, integrationUnrelatedIPv6} {
		if err := integrationCommand(ctx, backend.paths.IP, "-6", "route", "add", address.String()+"/128", "dev", integrationEndpointHostLink); err != nil {
			return err
		}
	}
	return nil
}

func cleanupIntegrationEndpoint(ctx context.Context, backend *linuxBackend) error {
	if backend == nil {
		return nil
	}
	var failures []error
	links, err := backend.linkNames(ctx, "")
	if err != nil {
		failures = append(failures, err)
	} else if links[integrationEndpointHostLink] {
		if err := integrationCommand(ctx, backend.paths.IP, "link", "del", integrationEndpointHostLink); err != nil {
			failures = append(failures, err)
		}
	}
	namespaces, err := backend.namespaceNames(ctx)
	if err != nil {
		failures = append(failures, err)
	} else if namespaces[integrationEndpointNamespace] {
		if err := integrationCommand(ctx, backend.paths.IP, "netns", "del", integrationEndpointNamespace); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func cleanupIntegrationTopology(ctx context.Context, backend *linuxBackend, spec topologySpec, tap **os.File) error {
	var failures []error
	for _, operation := range []func(context.Context, topologySpec) error{
		backend.DisableEgress,
		backend.DeleteHostPolicy,
		backend.DeleteNamespacePolicy,
	} {
		if err := operation(ctx, spec); err != nil {
			failures = append(failures, err)
		}
	}
	if tap != nil && *tap != nil {
		if err := (*tap).Close(); err != nil {
			failures = append(failures, err)
		}
		*tap = nil
	}
	for _, operation := range []func(context.Context, topologySpec) error{
		backend.DeleteTAP,
		backend.DeleteVeth,
		backend.DeleteNamespace,
	} {
		if err := operation(ctx, spec); err != nil {
			failures = append(failures, err)
		}
	}
	absent, err := backend.AuditAbsent(ctx, spec)
	if err != nil || !absent {
		failures = append(failures, ErrCleanupIncomplete)
	}
	return errors.Join(failures...)
}

func verifyIntegrationTopology(ctx context.Context, backend *linuxBackend, spec topologySpec) error {
	namespaces, err := backend.namespaceNames(ctx)
	if err != nil || !namespaces[spec.namespace] || !namespaces[integrationEndpointNamespace] {
		return ErrCommandFailed
	}
	hostLinks, err := backend.linkNames(ctx, "")
	if err != nil || !hostLinks[spec.hostVeth] || !hostLinks[integrationEndpointHostLink] {
		return ErrCommandFailed
	}
	namespaceLinks, err := backend.linkNames(ctx, spec.namespace)
	if err != nil || !namespaceLinks[spec.namespaceVeth] || !namespaceLinks[spec.tap] {
		return ErrCommandFailed
	}
	hostTables, err := backend.tableNames(ctx, "")
	if err != nil || !hostTables[tableKey("inet", spec.hostTable)] {
		return ErrCommandFailed
	}
	namespaceTables, err := backend.tableNames(ctx, spec.namespace)
	if err != nil || !namespaceTables[tableKey("inet", spec.namespaceTable)] {
		return ErrCommandFailed
	}
	return nil
}

func waitIntegrationIPv6Ready(ctx context.Context, backend *linuxBackend, spec topologySpec) error {
	for {
		ready := true
		for _, arguments := range [][]string{
			{"-6", "addr", "show", "tentative"},
			{"netns", "exec", spec.namespace, backend.paths.IP, "-6", "addr", "show", "tentative"},
		} {
			result, err := backend.run(ctx, backend.paths.IP, arguments, nil)
			if err != nil || result.exitCode != 0 {
				clear(result.stdout)
				return ErrCommandFailed
			}
			if len(strings.TrimSpace(string(result.stdout))) != 0 {
				ready = false
			}
			clear(result.stdout)
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func enableIntegrationIPv6Forwarding(ctx context.Context, backend *linuxBackend) error {
	const (
		ipv4ForwardingPath = "/proc/sys/net/ipv4/ip_forward"
		ipv6ForwardingPath = "/proc/sys/net/ipv6/conf/all/forwarding"
	)
	ipv4Before, err := os.ReadFile(ipv4ForwardingPath)
	if err != nil || string(ipv4Before) != "0\n" {
		clear(ipv4Before)
		return ErrCommandFailed
	}
	clear(ipv4Before)
	before, err := os.ReadFile(ipv6ForwardingPath)
	if err != nil || string(before) != "0\n" {
		clear(before)
		return ErrCommandFailed
	}
	clear(before)
	if err := integrationCommand(ctx, backend.paths.Sysctl, "-q", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
		return err
	}
	after, err := os.ReadFile(ipv6ForwardingPath)
	defer clear(after)
	if err != nil || string(after) != "1\n" {
		return ErrCommandFailed
	}
	ipv4After, err := os.ReadFile(ipv4ForwardingPath)
	defer clear(ipv4After)
	if err != nil || string(ipv4After) != "0\n" {
		return ErrCommandFailed
	}
	return nil
}

func verifyIntegrationAbsence(ctx context.Context, backend *linuxBackend, spec topologySpec) error {
	absent, err := backend.AuditAbsent(ctx, spec)
	if err != nil || !absent {
		return ErrCleanupIncomplete
	}
	namespaces, err := backend.namespaceNames(ctx)
	if err != nil || namespaces[spec.namespace] || namespaces[integrationEndpointNamespace] {
		return ErrCleanupIncomplete
	}
	links, err := backend.linkNames(ctx, "")
	if err != nil || links[spec.hostVeth] || links[integrationEndpointHostLink] {
		return ErrCleanupIncomplete
	}
	return nil
}

func startIntegrationEndpoint(ctx context.Context, paths ToolPaths) (*exec.Cmd, <-chan error, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	command := exec.CommandContext(ctx, paths.IP,
		"netns", "exec", integrationEndpointNamespace,
		executable, "-test.run=^TestLinuxBackendIsolatedIntegration$", "-test.count=1",
	)
	command.Env = integrationEnvironment(paths,
		integrationEnabledEnv+"=1",
		integrationChildEnv+"=1",
		integrationEndpointEnv+"=1",
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return nil, nil, err
	}
	ready := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(io.LimitReader(stdout, networkCommandOutputLimit))
		line, readErr := reader.ReadString('\n')
		if readErr != nil || strings.TrimSpace(line) != integrationReady {
			ready <- ErrCommandFailed
			_, _ = io.Copy(io.Discard, reader)
			return
		}
		ready <- nil
		// Only category names and Go test status can follow readiness; endpoint
		// values and raw command output are never written by the helper.
		_, _ = io.Copy(os.Stdout, reader)
	}()
	return command, ready, nil
}

func waitIntegrationEndpoint(ctx context.Context, command *exec.Cmd) error {
	if command == nil {
		return ErrCommandFailed
	}
	result := make(chan error, 1)
	go func() { result <- command.Wait() }()
	select {
	case err := <-result:
		if err != nil {
			return ErrCommandFailed
		}
		return nil
	case <-ctx.Done():
		_ = command.Process.Kill()
		<-result
		return ctx.Err()
	}
}

func stopIntegrationEndpoint(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Kill()
	_ = command.Wait()
}

func runIntegrationEndpoint(t *testing.T) {
	t.Helper()
	probes := integrationProbes()
	type listener struct {
		probe      integrationProbe
		connection *net.UDPConn
	}
	listeners := make([]listener, 0, len(probes))
	for _, probe := range probes {
		address := net.UDPAddrFromAddrPort(netip.AddrPortFrom(probe.address, probe.port))
		connection, err := net.ListenUDP(probe.network, address)
		if err != nil {
			t.Fatal("isolated endpoint listener setup failed")
		}
		listeners = append(listeners, listener{probe: probe, connection: connection})
	}
	defer func() {
		for _, current := range listeners {
			_ = current.connection.Close()
		}
	}()
	fmt.Fprintln(os.Stdout, integrationReady)
	deadline := time.Now().Add(2 * time.Second)
	type probeResult struct {
		name string
		err  error
	}
	results := make(chan probeResult, len(listeners))
	for _, current := range listeners {
		go func(current listener) {
			_ = current.connection.SetReadDeadline(deadline)
			buffer := make([]byte, 8)
			count, _, err := current.connection.ReadFromUDP(buffer)
			if current.probe.allowed {
				if err != nil || count != 1 || buffer[0] != current.probe.payload {
					results <- probeResult{name: current.probe.name, err: ErrCommandFailed}
					return
				}
				results <- probeResult{name: current.probe.name}
				return
			}
			if err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
				results <- probeResult{name: current.probe.name, err: ErrCommandFailed}
				return
			}
			results <- probeResult{name: current.probe.name}
		}(current)
	}
	for range listeners {
		result := <-results
		if result.err != nil {
			t.Fatalf("isolated endpoint observed invalid category %s", result.name)
		}
	}
}

func integrationTAPMAC(ctx context.Context, backend *linuxBackend, spec topologySpec) (net.HardwareAddr, error) {
	result, err := backend.run(ctx, backend.paths.IP, []string{
		"netns", "exec", spec.namespace, backend.paths.IP,
		"-j", "link", "show", "dev", spec.tap,
	}, nil)
	defer clear(result.stdout)
	if err != nil || result.exitCode != 0 {
		return nil, ErrCommandFailed
	}
	var records []struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(result.stdout, &records); err != nil || len(records) != 1 {
		return nil, ErrCommandFailed
	}
	address, err := net.ParseMAC(records[0].Address)
	if err != nil || len(address) != 6 {
		return nil, ErrCommandFailed
	}
	return address, nil
}

func integrationFrame(spec topologySpec, destinationMAC net.HardwareAddr, probe integrationProbe) ([]byte, error) {
	if len(destinationMAC) != 6 {
		return nil, ErrCommandFailed
	}
	payload := []byte{probe.payload}
	if probe.address.Is4() {
		packet := make([]byte, 14+20+8+len(payload))
		copy(packet[0:6], destinationMAC)
		copy(packet[6:12], integrationGuestSourceMAC)
		binary.BigEndian.PutUint16(packet[12:14], 0x0800)
		header := packet[14:34]
		header[0] = 0x45
		binary.BigEndian.PutUint16(header[2:4], uint16(20+8+len(payload)))
		binary.BigEndian.PutUint16(header[4:6], uint16(probe.payload))
		header[8], header[9] = 64, 17
		source := spec.guestAddress4.Addr().As4()
		destination := probe.address.As4()
		copy(header[12:16], source[:])
		copy(header[16:20], destination[:])
		binary.BigEndian.PutUint16(header[10:12], integrationChecksum(header))
		udp := packet[34:]
		binary.BigEndian.PutUint16(udp[0:2], 41000+uint16(probe.payload))
		binary.BigEndian.PutUint16(udp[2:4], probe.port)
		binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
		copy(udp[8:], payload)
		return packet, nil
	}
	if !probe.address.Is6() || probe.address.Is4In6() {
		return nil, ErrCommandFailed
	}
	packet := make([]byte, 14+40+8+len(payload))
	copy(packet[0:6], destinationMAC)
	copy(packet[6:12], integrationGuestSourceMAC)
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
	header := packet[14:54]
	header[0] = 0x60
	binary.BigEndian.PutUint16(header[4:6], uint16(8+len(payload)))
	header[6], header[7] = 17, 64
	source := spec.guestAddress6.Addr().As16()
	destination := probe.address.As16()
	copy(header[8:24], source[:])
	copy(header[24:40], destination[:])
	udp := packet[54:]
	binary.BigEndian.PutUint16(udp[0:2], 41000+uint16(probe.payload))
	binary.BigEndian.PutUint16(udp[2:4], probe.port)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	pseudo := make([]byte, 40+len(udp))
	copy(pseudo[0:16], source[:])
	copy(pseudo[16:32], destination[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udp)))
	pseudo[39] = 17
	copy(pseudo[40:], udp)
	checksum := integrationChecksum(pseudo)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	copy(pseudo[40:], udp)
	if integrationChecksum(pseudo) != 0 {
		clear(pseudo)
		clear(packet)
		return nil, ErrCommandFailed
	}
	clear(pseudo)
	return packet, nil
}

func integrationChecksum(value []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(value); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(value[index : index+2]))
	}
	if len(value)%2 != 0 {
		sum += uint32(value[len(value)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func writeIntegrationFrame(ctx context.Context, tap *os.File, frame []byte) error {
	if tap == nil || len(frame) == 0 {
		return ErrCommandFailed
	}
	for {
		count, err := tap.Write(frame)
		if err == nil && count == len(frame) {
			return nil
		}
		if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			return ErrCommandFailed
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

func integrationCommand(ctx context.Context, path string, arguments ...string) error {
	if ctx == nil || !filepath.IsAbs(path) {
		return ErrCommandFailed
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"LANG=C.UTF-8"}
	var output limitedBuffer
	output.limit = networkCommandOutputLimit
	defer func() { clear(output.Bytes()) }()
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || output.exceeded || ctx.Err() != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrCommandFailed
	}
	return nil
}

func bytesContainLine(value []byte, expected string) bool {
	for _, line := range strings.Split(string(value), "\n") {
		if strings.TrimSpace(line) == expected {
			return true
		}
	}
	return false
}
