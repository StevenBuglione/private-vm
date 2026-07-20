package network

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEndpointPoliciesAreExactAndFailClosedForBothFamilies(t *testing.T) {
	spec := candidateFor(testSessionID, 0)
	policy, err := collectPolicy([]endpointTuple{
		endpointTupleFor(netip.MustParseAddr("1.1.1.1"), 51820),
		endpointTupleFor(netip.MustParseAddr("2606:4700:4700::1111"), 51820),
	})
	if err != nil {
		t.Fatal(err)
	}
	namespace := string(namespaceRules(spec, policy))
	host := string(hostRules(spec, policy))
	namespaceEnforcement := strings.Split(namespace, " chain "+policyAuditChain+" {")[0]
	hostEnforcement := strings.Split(host, " chain "+policyAuditChain+" {")[0]

	for _, rule := range []string{
		"policy drop",
		"ip saddr " + spec.guestAddress4.Addr().String() + " ip daddr . udp dport @proton4 accept",
		"ip6 saddr " + spec.guestAddress6.Addr().String() + " ip6 daddr . udp dport @proton6 accept",
		"ip daddr " + spec.guestAddress4.Addr().String() + " ct state { established, related } accept",
		"ip6 daddr " + spec.guestAddress6.Addr().String() + " ct state { established, related } accept",
	} {
		if !strings.Contains(namespace, rule) {
			t.Fatalf("namespace policy lacks exact rule %q\n%s", rule, namespace)
		}
	}
	for _, rule := range []string{
		"ip saddr " + spec.guestAddress4.Addr().String() + " ip daddr . udp dport @proton4 accept",
		"ip6 saddr " + spec.guestAddress6.Addr().String() + " ip6 daddr . udp dport @proton6 accept",
		"ip daddr " + spec.guestAddress4.Addr().String() + " ct state { established, related } accept",
		"ip6 daddr " + spec.guestAddress6.Addr().String() + " ct state { established, related } accept",
		"ip saddr " + spec.guestAddress4.Addr().String() + " ip daddr . udp dport @proton4 masquerade",
		"ip6 saddr " + spec.guestAddress6.Addr().String() + " ip6 daddr . udp dport @proton6 masquerade",
		"iifname \"" + spec.hostVeth + "\" drop",
		"oifname \"" + spec.hostVeth + "\" drop",
	} {
		if !strings.Contains(host, rule) {
			t.Fatalf("host policy lacks exact rule %q\n%s", rule, host)
		}
	}
	for _, forbidden := range []string{" dport 53 ", " tcp ", "0.0.0.0/0", "::/0"} {
		if strings.Contains(namespaceEnforcement, forbidden) || strings.Contains(hostEnforcement, forbidden) {
			t.Fatalf("policy contains broad or bootstrap bypass %q", forbidden)
		}
	}
	for _, marker := range auditCounterComments() {
		if strings.Count(namespace, marker) != 1 || strings.Count(host, marker) != 1 {
			t.Fatalf("audit counter %q is not exact in both policies", marker)
		}
	}
	for name, generated := range map[string]string{"namespace": namespace, "host": host} {
		audit := strings.Split(generated, " chain "+policyAuditChain+" {")[1]
		ordered := []string{"@proton4 accept", "@proton6 accept", auditForbiddenIPv4, auditForbiddenIPv6, auditForbiddenDNS, auditForbiddenLANIPv4, auditForbiddenLANIPv6, auditUnrelatedPublic}
		previous := -1
		for _, marker := range ordered {
			index := strings.Index(audit, marker)
			if index <= previous {
				t.Fatalf("%s audit rule %q is missing or out of order", name, marker)
			}
			previous = index
		}
		for _, marker := range []string{auditForbiddenDNS, auditForbiddenLANIPv4, auditForbiddenLANIPv6} {
			lineStart := strings.LastIndex(audit[:strings.Index(audit, marker)], "\n") + 1
			lineEnd := strings.Index(audit[strings.Index(audit, marker):], "\n") + strings.Index(audit, marker)
			if !strings.Contains(audit[lineStart:lineEnd], "counter return comment") {
				t.Fatalf("%s audit classifier %q does not return to default drop", name, marker)
			}
		}
	}
}

func TestGeneratedPoliciesPassPinnedNftCheck(t *testing.T) {
	nft := os.Getenv("PRIVATE_VM_NFT_CHECK_BINARY")
	unshare := os.Getenv("PRIVATE_VM_UNSHARE_BINARY")
	if nft == "" || unshare == "" {
		t.Skip("set PRIVATE_VM_NFT_CHECK_BINARY and PRIVATE_VM_UNSHARE_BINARY for the pinned nft syntax gate")
	}
	if !filepath.IsAbs(nft) || filepath.Clean(nft) != nft || filepath.Base(nft) != "nft" ||
		!filepath.IsAbs(unshare) || filepath.Clean(unshare) != unshare || filepath.Base(unshare) != "unshare" {
		t.Fatal("nft syntax gate requires exact absolute tool paths")
	}
	spec := candidateFor(testSessionID, 0)
	policy, err := collectPolicy([]endpointTuple{
		endpointTupleFor(netip.MustParseAddr("1.1.1.1"), 51820),
		endpointTupleFor(netip.MustParseAddr("2606:4700:4700::1111"), 51820),
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, rules := range map[string][]byte{
		"host":      hostRules(spec, policy),
		"namespace": namespaceRules(spec, policy),
	} {
		t.Run(name, func(t *testing.T) {
			defer clear(rules)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, unshare, "--user", "--map-root-user", "--net", nft, "--check", "--file", "-")
			command.Env = []string{"LANG=C.UTF-8"}
			command.Stdin = bytes.NewReader(rules)
			command.Stdout = io.Discard
			command.Stderr = io.Discard
			if err := command.Run(); err != nil || ctx.Err() != nil {
				t.Fatal("generated nft policy failed the isolated pinned syntax gate")
			}
		})
	}
}

func TestEndpointCollectionRejectsUnsafeOrEmptyPolicy(t *testing.T) {
	for _, endpoints := range [][]endpointTuple{
		nil,
		{endpointTupleFor(netip.MustParseAddr("127.0.0.1"), 51820)},
		{endpointTupleFor(netip.MustParseAddr("1.1.1.1"), 0)},
		{endpointTupleFor(netip.MustParseAddr("::ffff:1.1.1.1"), 51820)},
	} {
		if _, err := collectPolicy(endpoints); err == nil {
			t.Fatalf("collectPolicy(%v) succeeded", endpoints)
		}
	}
}

func TestGeneratedNamesAndAddressPlansAreBoundedAndDeterministic(t *testing.T) {
	first := candidateFor(testSessionID, 0)
	again := candidateFor(testSessionID, 0)
	second := candidateFor(testSessionID, 1)
	if first != again || first == second {
		t.Fatal("allocation candidate is not deterministic and attempt-specific")
	}
	for _, name := range []string{first.namespace, first.hostVeth, first.namespaceVeth, first.tap} {
		if len(name) > interfaceNameLimit {
			t.Fatalf("generated name %q exceeds Linux interface limit", name)
		}
	}
	if first.guestNetwork4.Overlaps(first.uplinkNetwork4) || first.guestNetwork6.Overlaps(first.uplinkNetwork6) {
		t.Fatal("guest and namespace uplink networks overlap")
	}
	if !first.guestNetwork4.Contains(first.guestAddress4.Addr()) || !first.guestNetwork6.Contains(first.guestAddress6.Addr()) {
		t.Fatal("guest address escaped its static subnet")
	}
}

func TestRuleBuffersCanBeDestroyedInPlace(t *testing.T) {
	policy, err := collectPolicy([]endpointTuple{endpointTupleFor(netip.MustParseAddr("1.1.1.1"), 51820)})
	if err != nil {
		t.Fatal(err)
	}
	rules := hostRules(candidateFor(testSessionID, 0), policy)
	if !bytes.Contains(rules, []byte("1.1.1.1")) {
		t.Fatal("fixture endpoint missing from rules")
	}
	clear(rules)
	if bytes.Contains(rules, []byte("1.1.1.1")) {
		t.Fatal("rule buffer was not cleared")
	}
}
