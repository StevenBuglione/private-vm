//go:build linux

package network

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type recordingRunner struct {
	requests []command
	run      func(command) commandResult
}

type errorRunner func(command) (commandResult, error)

type contextRunner func(context.Context, command) (commandResult, error)

func (runner errorRunner) Run(_ context.Context, request command) (commandResult, error) {
	return runner(request)
}

func (runner contextRunner) Run(ctx context.Context, request command) (commandResult, error) {
	return runner(ctx, request)
}

func (runner *recordingRunner) Run(_ context.Context, request command) (commandResult, error) {
	runner.requests = append(runner.requests, command{path: request.path, args: slices.Clone(request.args), stdin: request.stdin})
	if runner.run != nil {
		return runner.run(request), nil
	}
	return commandResult{}, nil
}

func testLinuxBackend(runner commandRunner) *linuxBackend {
	return &linuxBackend{
		paths:  ToolPaths{IP: "/run/current-system/sw/bin/ip", NFT: "/run/current-system/sw/bin/nft", Sysctl: "/run/current-system/sw/bin/sysctl", Tun: "/dev/net/tun"},
		runner: runner,
	}
}

func TestToolPathsAndCommandOutputBoundsFailClosed(t *testing.T) {
	valid := ToolPaths{IP: "/nix/store/test/bin/ip", NFT: "/nix/store/test/bin/nft", Sysctl: "/nix/store/test/bin/sysctl", Tun: "/dev/net/tun"}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []ToolPaths{
		{IP: "ip", NFT: valid.NFT, Sysctl: valid.Sysctl, Tun: valid.Tun},
		{IP: "/nix/store/test/bin/not-ip", NFT: valid.NFT, Sysctl: valid.Sysctl, Tun: valid.Tun},
		{IP: valid.IP, NFT: valid.NFT, Sysctl: valid.Sysctl, Tun: "/tmp/tun"},
	} {
		if err := invalid.validate(); !errors.Is(err, ErrBackendUnavailable) {
			t.Fatalf("unsafe tool paths accepted: %#v, %v", invalid, err)
		}
	}
	buffer := limitedBuffer{limit: 4}
	if written, err := buffer.Write([]byte("oversized")); err != nil || written != len("oversized") || !buffer.exceeded || buffer.Len() != 4 {
		t.Fatalf("bounded output = %d bytes, exceeded=%v, write=%d, err=%v", buffer.Len(), buffer.exceeded, written, err)
	}
}

func TestNftTransactionsUseStdinAndClearItWithoutEndpointInArguments(t *testing.T) {
	const endpoint = "1.1.1.1"
	runner := &recordingRunner{}
	backend := testLinuxBackend(runner)
	policy, err := collectPolicy([]endpointTuple{endpointTupleFor(netip.MustParseAddr(endpoint), 51820)})
	if err != nil {
		t.Fatal(err)
	}
	spec := candidateFor(testSessionID, 0)
	if err := backend.ApplyNamespacePolicy(context.Background(), spec, policy); err != nil {
		t.Fatal(err)
	}
	if err := backend.ApplyHostPolicy(context.Background(), spec, policy); err != nil {
		t.Fatal(err)
	}
	if len(runner.requests) != 2 {
		t.Fatalf("nft request count = %d", len(runner.requests))
	}
	for _, request := range runner.requests {
		if strings.Contains(strings.Join(request.args, " "), endpoint) {
			t.Fatal("endpoint appeared in process arguments")
		}
		if !allZero(request.stdin) {
			t.Fatal("nft stdin remained live after transaction")
		}
	}
}

func TestLiveNftCounterAuditUsesExactOwnedTablesAndClearsOutput(t *testing.T) {
	spec := candidateFor(testSessionID, 0)
	var outputs [][]byte
	runner := &recordingRunner{run: func(request command) commandResult {
		arguments := strings.Join(request.args, " ")
		var table, primary string
		switch arguments {
		case "-j list table inet " + spec.hostTable:
			table, primary = spec.hostTable, "accept"
		case "netns exec " + spec.namespace + " /run/current-system/sw/bin/nft -j list table inet " + spec.namespaceTable:
			table, primary = spec.namespaceTable, "drop"
		default:
			t.Fatalf("unexpected audit command: %s %s", request.path, arguments)
		}
		output := policyAuditFixture(table, primary, "", 0)
		outputs = append(outputs, output)
		return commandResult{stdout: output}
	}}
	proof, err := testLinuxBackend(runner).AuditPolicy(context.Background(), spec)
	if err != nil || !proof.NamespacePolicyPresent || !proof.HostPolicyPresent || !proof.ForbiddenEgressZero {
		t.Fatalf("live policy audit = %#v, %v", proof, err)
	}
	if len(runner.requests) != 2 || len(outputs) != 2 {
		t.Fatalf("audit request/output count = %d/%d", len(runner.requests), len(outputs))
	}
	for _, output := range outputs {
		if !allZero(output) {
			t.Fatal("nft JSON remained live after audit")
		}
	}
}

func TestNftCounterEvidenceFailsClosed(t *testing.T) {
	table := candidateFor(testSessionID, 0).hostTable
	for _, test := range []struct {
		name    string
		value   []byte
		table   string
		primary string
	}{
		{"empty", nil, table, "accept"},
		{"malformed", []byte(`{"nftables":`), table, "accept"},
		{"trailing", append(policyAuditFixture(table, "accept", "", 0), []byte(`{}`)...), table, "accept"},
		{"unowned_table", policyAuditFixture("pvmh_unowned", "accept", "", 0), table, "accept"},
		{"wrong_primary_policy", policyAuditFixture(table, "drop", "", 0), table, "accept"},
		{"missing_counter", policyAuditFixture(table, "accept", auditForbiddenDNS, 0), table, "accept"},
		{"duplicate_counter", duplicatePolicyAuditFixture(table), table, "accept"},
		{"nonzero_packets", policyAuditFixture(table, "accept", "", 1), table, "accept"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if verified, err := parsePolicyAudit(test.value, test.table, test.primary); err == nil || verified || !errors.Is(err, ErrCommandFailed) {
				t.Fatalf("unsafe evidence passed: %v, %v", verified, err)
			}
		})
	}
}

func TestNftCounterAuditCancellationTimeoutFailureAndOutputCleanup(t *testing.T) {
	spec := candidateFor(testSessionID, 0)
	for _, expected := range []error{context.Canceled, context.DeadlineExceeded} {
		backend := testLinuxBackend(contextRunner(func(ctx context.Context, _ command) (commandResult, error) {
			<-ctx.Done()
			return commandResult{}, ctx.Err()
		}))
		var ctx context.Context
		var cancel context.CancelFunc
		if errors.Is(expected, context.Canceled) {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		} else {
			ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
		}
		if _, err := backend.AuditPolicy(ctx, spec); !errors.Is(err, expected) {
			t.Fatalf("audit context result %v mapped to %v", expected, err)
		}
	}

	const sensitive = "198.51.100.77:51820"
	output := []byte(`{"nftables":[{"table":{"family":"inet","name":"` + sensitive + `"}}]}`)
	backend := testLinuxBackend(&recordingRunner{run: func(command) commandResult {
		return commandResult{stdout: output}
	}})
	if _, err := backend.AuditPolicy(context.Background(), spec); !errors.Is(err, ErrCommandFailed) || strings.Contains(err.Error(), sensitive) {
		t.Fatalf("unredacted audit failure = %v", err)
	}
	if !allZero(output) {
		t.Fatal("failed nft JSON remained live")
	}
}

func policyAuditFixture(table, primaryPolicy, omittedCounter string, packets uint64) []byte {
	objects := []string{
		`{"metainfo":{"version":"1.1.6","release_name":"Commodore Bullmoose #7","json_schema_version":1}}`,
		`{"table":{"family":"inet","name":"` + table + `","handle":1,"comment":"` + policyOwnerComment + `"}}`,
		`{"set":{"family":"inet","name":"proton4","table":"` + table + `","type":["ipv4_addr","inet_service"],"handle":4}}`,
		`{"set":{"family":"inet","name":"proton6","table":"` + table + `","type":["ipv6_addr","inet_service"],"handle":5}}`,
		`{"chain":{"family":"inet","table":"` + table + `","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"` + primaryPolicy + `"}}`,
		`{"chain":{"family":"inet","table":"` + table + `","name":"` + policyAuditChain + `","handle":3,"type":"filter","hook":"forward","prio":1,"policy":"drop"}}`,
	}
	for _, comment := range auditCounterComments() {
		if comment == omittedCounter {
			continue
		}
		count := uint64(0)
		if packets > 0 && comment == auditUnrelatedPublic {
			count = packets
		}
		objects = append(objects, `{"rule":{"family":"inet","table":"`+table+`","chain":"`+policyAuditChain+`","handle":`+strconv.Itoa(10+len(objects))+`,"expr":[{"counter":{"packets":`+strconv.FormatUint(count, 10)+`,"bytes":0}}],"comment":"`+comment+`"}}`)
	}
	return []byte(`{"nftables":[` + strings.Join(objects, ",") + `]}`)
}

func duplicatePolicyAuditFixture(table string) []byte {
	value := strings.TrimSuffix(string(policyAuditFixture(table, "accept", "", 0)), "]}")
	duplicate := `{"rule":{"family":"inet","table":"` + table + `","chain":"` + policyAuditChain + `","handle":99,"expr":[{"counter":{"packets":0,"bytes":0}}],"comment":"` + auditForbiddenDNS + `"}}`
	return []byte(value + "," + duplicate + "]}")
}

func TestCommandFailureNeverReturnsCapturedEndpointOutput(t *testing.T) {
	const endpoint = "1.1.1.1"
	runner := &recordingRunner{run: func(request command) commandResult {
		if !bytes.Contains(request.stdin, []byte(endpoint)) {
			t.Fatal("nft transaction did not contain the exact endpoint")
		}
		return commandResult{stdout: []byte("synthetic failure " + endpoint), exitCode: 2}
	}}
	backend := testLinuxBackend(runner)
	policy, err := collectPolicy([]endpointTuple{endpointTupleFor(netip.MustParseAddr(endpoint), 51820)})
	if err != nil {
		t.Fatal(err)
	}
	err = backend.ApplyHostPolicy(context.Background(), candidateFor(testSessionID, 0), policy)
	if !errors.Is(err, ErrCommandFailed) || strings.Contains(err.Error(), endpoint) {
		t.Fatalf("unsafe command error = %v", err)
	}
	if !allZero(runner.requests[0].stdin) {
		t.Fatal("failed nft transaction buffer was not cleared")
	}
}

func TestRunnerErrorDestroysCapturedOutput(t *testing.T) {
	captured := []byte("synthetic 1.1.1.1 output")
	backend := testLinuxBackend(errorRunner(func(command) (commandResult, error) {
		return commandResult{stdout: captured}, errors.New("synthetic runner failure with endpoint")
	}))
	err := backend.commandSuccess(context.Background(), backend.paths.IP, "netns", "list")
	if !errors.Is(err, ErrCommandFailed) || strings.Contains(err.Error(), "1.1.1.1") {
		t.Fatalf("unsafe runner error = %v", err)
	}
	if !allZero(captured) {
		t.Fatal("runner output was not destroyed on adapter error")
	}
}

func TestExitOneIsNeverClassifiedAsVerifiedAbsence(t *testing.T) {
	runner := &recordingRunner{run: func(command) commandResult { return commandResult{exitCode: 1} }}
	backend := testLinuxBackend(runner)
	err := backend.DeleteHostPolicy(context.Background(), candidateFor(testSessionID, 0))
	if !errors.Is(err, ErrCommandFailed) {
		t.Fatalf("generic exit 1 was treated as absence: %v", err)
	}
}

func TestAbsentCleanupUsesExactSuccessfulInventoryAndIsRepeatable(t *testing.T) {
	runner := &recordingRunner{run: func(request command) commandResult {
		joined := strings.Join(request.args, " ")
		switch {
		case joined == "netns list", joined == "list tables":
			return commandResult{}
		case joined == "-j link show":
			return commandResult{stdout: []byte("[]")}
		default:
			t.Fatalf("unexpected mutation for absent resource: %s %s", request.path, joined)
			return commandResult{exitCode: 2}
		}
	}}
	backend := testLinuxBackend(runner)
	spec := candidateFor(testSessionID, 0)
	for iteration := 0; iteration < 2; iteration++ {
		for _, operation := range []func(context.Context, topologySpec) error{
			backend.DisableEgress, backend.DeleteHostPolicy, backend.DeleteNamespacePolicy,
			backend.DeleteTAP, backend.DeleteVeth, backend.DeleteNamespace,
		} {
			if err := operation(context.Background(), spec); err != nil {
				t.Fatalf("repeat %d absent cleanup: %v", iteration, err)
			}
		}
	}
}

func TestAllocationRejectsOverlappingRoutesButAuditChecksOnlyOwnedPrefixes(t *testing.T) {
	spec := candidateFor(testSessionID, 0)
	broadRoute := []byte(`[{"dst":"10.0.0.0/8"}]`)
	runner := &recordingRunner{run: func(request command) commandResult {
		switch strings.Join(request.args, " ") {
		case "netns list", "list tables":
			return commandResult{}
		case "-j link show":
			return commandResult{stdout: []byte("[]")}
		case "-j -4 route show table all":
			return commandResult{stdout: slices.Clone(broadRoute)}
		case "-j -6 route show table all":
			return commandResult{stdout: []byte("[]")}
		default:
			t.Fatalf("unexpected inventory command: %s", strings.Join(request.args, " "))
			return commandResult{exitCode: 2}
		}
	}}
	backend := testLinuxBackend(runner)
	available, err := backend.Available(context.Background(), spec)
	if err != nil || available {
		t.Fatalf("overlapping /8 allocation result = %v, %v", available, err)
	}
	absent, err := backend.AuditAbsent(context.Background(), spec)
	if err != nil || !absent {
		t.Fatalf("unrelated broad route was mistaken for an owned leftover: %v, %v", absent, err)
	}

	runner.run = func(request command) commandResult {
		switch strings.Join(request.args, " ") {
		case "netns list", "list tables":
			return commandResult{}
		case "-j link show":
			return commandResult{stdout: []byte("[]")}
		case "-j -4 route show table all":
			return commandResult{stdout: []byte(`[{"dst":"` + spec.guestNetwork4.String() + `"}]`)}
		case "-j -6 route show table all":
			return commandResult{stdout: []byte("[]")}
		default:
			t.Fatalf("unexpected inventory command: %s", strings.Join(request.args, " "))
			return commandResult{exitCode: 2}
		}
	}
	absent, err = backend.AuditAbsent(context.Background(), spec)
	if err != nil || absent {
		t.Fatalf("exact owned route passed final audit: %v, %v", absent, err)
	}
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}
