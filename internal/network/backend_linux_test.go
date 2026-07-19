//go:build linux

package network

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

type recordingRunner struct {
	requests []command
	run      func(command) commandResult
}

type errorRunner func(command) (commandResult, error)

func (runner errorRunner) Run(_ context.Context, request command) (commandResult, error) {
	return runner(request)
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
