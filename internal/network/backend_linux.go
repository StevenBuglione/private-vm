//go:build linux

package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type linuxBackend struct {
	paths  ToolPaths
	runner commandRunner
}

func newPlatformBackend(paths ToolPaths) (backend, error) {
	if err := paths.validate(); err != nil {
		return nil, err
	}
	return &linuxBackend{paths: paths, runner: osCommandRunner{}}, nil
}

func (backend *linuxBackend) Available(ctx context.Context, spec topologySpec) (bool, error) {
	namespaces, err := backend.namespaceNames(ctx)
	if err != nil {
		return false, err
	}
	if namespaces[spec.namespace] {
		return false, nil
	}
	links, err := backend.linkNames(ctx, "")
	if err != nil {
		return false, err
	}
	for _, name := range []string{spec.hostVeth, spec.namespaceVeth, spec.tap} {
		if links[name] {
			return false, nil
		}
	}
	routes4, err := backend.routePrefixes(ctx, "-4")
	if err != nil {
		return false, err
	}
	routes6, err := backend.routePrefixes(ctx, "-6")
	if err != nil {
		return false, err
	}
	for _, candidate := range []struct {
		prefixes []netip.Prefix
		value    netip.Prefix
	}{
		{routes4, spec.guestNetwork4}, {routes4, spec.uplinkNetwork4},
		{routes6, spec.guestNetwork6}, {routes6, spec.uplinkNetwork6},
	} {
		for _, existing := range candidate.prefixes {
			if existing.Overlaps(candidate.value) {
				return false, nil
			}
		}
	}
	tables, err := backend.tableNames(ctx, "")
	if err != nil {
		return false, err
	}
	return !tables[tableKey("inet", spec.hostTable)], nil
}

func (backend *linuxBackend) exactResourcesAbsent(ctx context.Context, spec topologySpec) (bool, error) {
	namespaces, err := backend.namespaceNames(ctx)
	if err != nil {
		return false, err
	}
	if namespaces[spec.namespace] {
		return false, nil
	}
	links, err := backend.linkNames(ctx, "")
	if err != nil {
		return false, err
	}
	for _, name := range []string{spec.hostVeth, spec.namespaceVeth, spec.tap} {
		if links[name] {
			return false, nil
		}
	}
	routes4, err := backend.routePrefixes(ctx, "-4")
	if err != nil {
		return false, err
	}
	routes6, err := backend.routePrefixes(ctx, "-6")
	if err != nil {
		return false, err
	}
	for _, expected := range []struct {
		prefixes []netip.Prefix
		value    netip.Prefix
	}{
		{routes4, spec.guestNetwork4}, {routes4, spec.uplinkNetwork4},
		{routes6, spec.guestNetwork6}, {routes6, spec.uplinkNetwork6},
	} {
		for _, existing := range expected.prefixes {
			if existing == expected.value {
				return false, nil
			}
		}
	}
	tables, err := backend.tableNames(ctx, "")
	if err != nil {
		return false, err
	}
	return !tables[tableKey("inet", spec.hostTable)], nil
}

func (backend *linuxBackend) CreateNamespace(ctx context.Context, spec topologySpec) error {
	return backend.commandSuccess(ctx, backend.paths.IP, "netns", "add", spec.namespace)
}

func (backend *linuxBackend) CreateVeth(ctx context.Context, spec topologySpec) error {
	if err := backend.commandSuccess(ctx, backend.paths.IP, "link", "add", spec.hostVeth, "type", "veth", "peer", "name", spec.namespaceVeth); err != nil {
		return err
	}
	return backend.commandSuccess(ctx, backend.paths.IP, "link", "set", spec.namespaceVeth, "netns", spec.namespace)
}

func (backend *linuxBackend) ConfigureHost(ctx context.Context, spec topologySpec) error {
	commands := [][]string{
		{"addr", "add", spec.hostUplink4.String(), "dev", spec.hostVeth},
		{"-6", "addr", "add", spec.hostUplink6.String(), "dev", spec.hostVeth},
		{"link", "set", spec.hostVeth, "up"},
		{"route", "add", spec.guestNetwork4.String(), "via", spec.namespaceUplink4.Addr().String(), "dev", spec.hostVeth},
		{"-6", "route", "add", spec.guestNetwork6.String(), "via", spec.namespaceUplink6.Addr().String(), "dev", spec.hostVeth},
	}
	for _, arguments := range commands {
		if err := backend.commandSuccess(ctx, backend.paths.IP, arguments...); err != nil {
			return err
		}
	}
	for _, setting := range []string{
		"net.ipv4.conf." + spec.hostVeth + ".forwarding=1",
		"net.ipv4.conf." + spec.hostVeth + ".rp_filter=0",
		"net.ipv6.conf." + spec.hostVeth + ".forwarding=1",
	} {
		if err := backend.commandSuccess(ctx, backend.paths.Sysctl, "-q", "-w", setting); err != nil {
			return err
		}
	}
	return nil
}

func (backend *linuxBackend) ConfigureNamespace(ctx context.Context, spec topologySpec) error {
	commands := [][]string{
		{"addr", "add", spec.namespaceUplink4.String(), "dev", spec.namespaceVeth},
		{"-6", "addr", "add", spec.namespaceUplink6.String(), "dev", spec.namespaceVeth},
		{"link", "set", "lo", "up"},
		{"link", "set", spec.namespaceVeth, "up"},
		{"route", "add", "default", "via", spec.hostUplink4.Addr().String(), "dev", spec.namespaceVeth},
		{"-6", "route", "add", "default", "via", spec.hostUplink6.Addr().String(), "dev", spec.namespaceVeth},
	}
	for _, arguments := range commands {
		if err := backend.namespaceCommandSuccess(ctx, spec.namespace, backend.paths.IP, arguments...); err != nil {
			return err
		}
	}
	for _, setting := range []string{"net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"} {
		if err := backend.namespaceCommandSuccess(ctx, spec.namespace, backend.paths.Sysctl, "-q", "-w", setting); err != nil {
			return err
		}
	}
	return nil
}

func (backend *linuxBackend) CreateTAP(ctx context.Context, spec topologySpec) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Open(backend.paths.Tun, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrBackendUnavailable
	}
	request, err := unix.NewIfreq(spec.tap)
	if err != nil {
		_ = unix.Close(fd)
		return nil, ErrBackendUnavailable
	}
	request.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		_ = unix.Close(fd)
		return nil, ErrCommandFailed
	}
	if request.Name() != spec.tap {
		_ = unix.Close(fd)
		return nil, ErrCommandFailed
	}
	return os.NewFile(uintptr(fd), spec.tap), nil
}

func (backend *linuxBackend) ConfigureTAP(ctx context.Context, spec topologySpec) error {
	if err := backend.commandSuccess(ctx, backend.paths.IP, "link", "set", spec.tap, "netns", spec.namespace); err != nil {
		return err
	}
	commands := [][]string{
		{"addr", "add", spec.guestGateway4.String(), "dev", spec.tap},
		{"-6", "addr", "add", spec.guestGateway6.String(), "dev", spec.tap},
		{"link", "set", spec.tap, "up"},
	}
	for _, arguments := range commands {
		if err := backend.namespaceCommandSuccess(ctx, spec.namespace, backend.paths.IP, arguments...); err != nil {
			return err
		}
	}
	return nil
}

func (backend *linuxBackend) ApplyNamespacePolicy(ctx context.Context, spec topologySpec, policy endpointPolicy) error {
	rules := namespaceRules(spec, policy)
	defer clear(rules)
	return backend.namespaceStdinSuccess(ctx, spec.namespace, backend.paths.NFT, []string{"-f", "-"}, rules)
}

func (backend *linuxBackend) ApplyHostPolicy(ctx context.Context, spec topologySpec, policy endpointPolicy) error {
	rules := hostRules(spec, policy)
	defer clear(rules)
	return backend.stdinSuccess(ctx, backend.paths.NFT, []string{"-f", "-"}, rules)
}

func (backend *linuxBackend) DisableEgress(ctx context.Context, spec topologySpec) error {
	links, err := backend.linkNames(ctx, "")
	if err != nil || !links[spec.hostVeth] {
		return err
	}
	return backend.commandSuccess(ctx, backend.paths.IP, "link", "set", spec.hostVeth, "down")
}

func (backend *linuxBackend) DeleteHostPolicy(ctx context.Context, spec topologySpec) error {
	tables, err := backend.tableNames(ctx, "")
	if err != nil || !tables[tableKey("inet", spec.hostTable)] {
		return err
	}
	rules := deleteTableRules(spec.hostTable)
	defer clear(rules)
	return backend.stdinSuccess(ctx, backend.paths.NFT, []string{"-f", "-"}, rules)
}

func (backend *linuxBackend) DeleteNamespacePolicy(ctx context.Context, spec topologySpec) error {
	namespaces, err := backend.namespaceNames(ctx)
	if err != nil || !namespaces[spec.namespace] {
		return err
	}
	tables, err := backend.tableNames(ctx, spec.namespace)
	if err != nil || !tables[tableKey("inet", spec.namespaceTable)] {
		return err
	}
	rules := deleteTableRules(spec.namespaceTable)
	defer clear(rules)
	return backend.namespaceStdinSuccess(ctx, spec.namespace, backend.paths.NFT, []string{"-f", "-"}, rules)
}

func (backend *linuxBackend) DeleteTAP(ctx context.Context, spec topologySpec) error {
	namespaces, err := backend.namespaceNames(ctx)
	if err != nil {
		return err
	}
	if namespaces[spec.namespace] {
		links, linkErr := backend.linkNames(ctx, spec.namespace)
		if linkErr != nil {
			return linkErr
		}
		if links[spec.tap] {
			if deleteErr := backend.namespaceCommandSuccess(ctx, spec.namespace, backend.paths.IP, "link", "del", spec.tap); deleteErr != nil {
				return deleteErr
			}
		}
	}
	links, err := backend.linkNames(ctx, "")
	if err != nil {
		return err
	}
	if links[spec.tap] {
		return backend.commandSuccess(ctx, backend.paths.IP, "link", "del", spec.tap)
	}
	return nil
}

func (backend *linuxBackend) DeleteVeth(ctx context.Context, spec topologySpec) error {
	links, err := backend.linkNames(ctx, "")
	if err != nil || !links[spec.hostVeth] {
		return err
	}
	return backend.commandSuccess(ctx, backend.paths.IP, "link", "del", spec.hostVeth)
}

func (backend *linuxBackend) DeleteNamespace(ctx context.Context, spec topologySpec) error {
	namespaces, err := backend.namespaceNames(ctx)
	if err != nil || !namespaces[spec.namespace] {
		return err
	}
	return backend.commandSuccess(ctx, backend.paths.IP, "netns", "del", spec.namespace)
}

func (backend *linuxBackend) AuditAbsent(ctx context.Context, spec topologySpec) (bool, error) {
	return backend.exactResourcesAbsent(ctx, spec)
}

func (backend *linuxBackend) commandSuccess(ctx context.Context, path string, arguments ...string) error {
	return backend.stdinSuccess(ctx, path, arguments, nil)
}

func (backend *linuxBackend) namespaceCommandSuccess(ctx context.Context, namespace, path string, arguments ...string) error {
	return backend.namespaceStdinSuccess(ctx, namespace, path, arguments, nil)
}

func (backend *linuxBackend) stdinSuccess(ctx context.Context, path string, arguments []string, stdin []byte) error {
	result, err := backend.run(ctx, path, arguments, stdin)
	defer clear(result.stdout)
	if err != nil {
		return backendError(err)
	}
	if result.exitCode != 0 {
		return ErrCommandFailed
	}
	return nil
}

func (backend *linuxBackend) namespaceStdinSuccess(ctx context.Context, namespace, path string, arguments []string, stdin []byte) error {
	return backend.stdinSuccess(ctx, backend.paths.IP, append([]string{"netns", "exec", namespace, path}, arguments...), stdin)
}

func (backend *linuxBackend) namespaceNames(ctx context.Context) (map[string]bool, error) {
	result, err := backend.run(ctx, backend.paths.IP, []string{"netns", "list"}, nil)
	defer clear(result.stdout)
	if err != nil {
		return nil, backendError(err)
	}
	if result.exitCode != 0 {
		return nil, ErrCommandFailed
	}
	names := make(map[string]bool)
	for _, line := range bytes.Split(result.stdout, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) > 0 {
			names[string(fields[0])] = true
		}
	}
	return names, nil
}

func (backend *linuxBackend) linkNames(ctx context.Context, namespace string) (map[string]bool, error) {
	arguments := []string{"-j", "link", "show"}
	path := backend.paths.IP
	if namespace != "" {
		arguments = append([]string{"netns", "exec", namespace, backend.paths.IP}, arguments...)
		path = backend.paths.IP
	}
	result, err := backend.run(ctx, path, arguments, nil)
	defer clear(result.stdout)
	if err != nil {
		return nil, backendError(err)
	}
	if result.exitCode != 0 {
		return nil, ErrCommandFailed
	}
	var records []struct {
		Name string `json:"ifname"`
	}
	if err := json.Unmarshal(result.stdout, &records); err != nil {
		return nil, ErrCommandFailed
	}
	names := make(map[string]bool, len(records))
	for _, record := range records {
		if record.Name == "" {
			return nil, ErrCommandFailed
		}
		names[record.Name] = true
	}
	return names, nil
}

func (backend *linuxBackend) tableNames(ctx context.Context, namespace string) (map[string]bool, error) {
	arguments := []string{"list", "tables"}
	path := backend.paths.NFT
	if namespace != "" {
		arguments = append([]string{"netns", "exec", namespace, backend.paths.NFT}, arguments...)
		path = backend.paths.IP
	}
	result, err := backend.run(ctx, path, arguments, nil)
	defer clear(result.stdout)
	if err != nil {
		return nil, backendError(err)
	}
	if result.exitCode != 0 {
		return nil, ErrCommandFailed
	}
	tables := make(map[string]bool)
	for _, line := range strings.Split(string(result.stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 || fields[0] != "table" {
			return nil, ErrCommandFailed
		}
		tables[tableKey(fields[1], fields[2])] = true
	}
	return tables, nil
}

func (backend *linuxBackend) routePrefixes(ctx context.Context, family string) ([]netip.Prefix, error) {
	if family != "-4" && family != "-6" {
		return nil, ErrCommandFailed
	}
	result, err := backend.run(ctx, backend.paths.IP, []string{"-j", family, "route", "show", "table", "all"}, nil)
	defer clear(result.stdout)
	if err != nil {
		return nil, backendError(err)
	}
	if result.exitCode != 0 {
		return nil, ErrCommandFailed
	}
	var records []struct {
		Destination string `json:"dst"`
	}
	if err := json.Unmarshal(result.stdout, &records); err != nil {
		return nil, ErrCommandFailed
	}
	prefixes := make([]netip.Prefix, 0, len(records))
	for _, record := range records {
		if record.Destination == "default" {
			continue
		}
		if record.Destination == "" {
			return nil, ErrCommandFailed
		}
		prefix, parseErr := netip.ParsePrefix(record.Destination)
		if parseErr != nil {
			address, addressErr := netip.ParseAddr(record.Destination)
			if addressErr != nil || address.Zone() != "" || address.Is4In6() {
				return nil, ErrCommandFailed
			}
			bits := 128
			if address.Is4() {
				bits = 32
			}
			prefix = netip.PrefixFrom(address, bits)
		}
		if !prefix.IsValid() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() ||
			(family == "-4") != prefix.Addr().Is4() {
			return nil, ErrCommandFailed
		}
		prefix = prefix.Masked()
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func tableKey(family, name string) string { return family + "\x00" + name }

func (backend *linuxBackend) run(ctx context.Context, path string, arguments []string, stdin []byte) (commandResult, error) {
	if ctx == nil || backend == nil || backend.runner == nil {
		return commandResult{}, ErrBackendUnavailable
	}
	if path != backend.paths.IP && path != backend.paths.NFT && path != backend.paths.Sysctl {
		return commandResult{}, ErrBackendUnavailable
	}
	result, err := backend.runner.Run(ctx, command{path: path, args: append([]string(nil), arguments...), stdin: stdin})
	if err != nil {
		clear(result.stdout)
		return commandResult{}, backendError(err)
	}
	return result, nil
}

func backendError(err error) error {
	switch {
	case err == nil:
		return ErrCommandFailed
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrCommandOutputBound):
		return ErrCommandOutputBound
	default:
		return ErrCommandFailed
	}
}

var _ backend = (*linuxBackend)(nil)
