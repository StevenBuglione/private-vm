package network

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
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
		if strings.Contains(namespace, forbidden) || strings.Contains(host, forbidden) {
			t.Fatalf("policy contains broad or bootstrap bypass %q", forbidden)
		}
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
