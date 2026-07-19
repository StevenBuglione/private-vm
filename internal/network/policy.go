package network

import (
	"bytes"
	"net/netip"
	"sort"
	"strconv"
)

func collectPolicy(endpoints []endpointTuple) (endpointPolicy, error) {
	if len(endpoints) == 0 || len(endpoints) > maximumEndpointTuples {
		return endpointPolicy{}, invalidRequest()
	}
	seen := make(map[endpointTuple]struct{}, len(endpoints))
	defer clear(seen)
	policy := endpointPolicy{}
	for _, endpoint := range endpoints {
		if !endpoint.address.IsValid() || endpoint.address.Zone() != "" || endpoint.address.Is4In6() ||
			!endpoint.address.IsGlobalUnicast() || endpoint.port == 0 {
			policy.destroy()
			return endpointPolicy{}, invalidRequest()
		}
		if _, duplicate := seen[endpoint]; duplicate {
			continue
		}
		seen[endpoint] = struct{}{}
		if endpoint.address.Is4() {
			policy.v4 = append(policy.v4, endpoint)
		} else {
			policy.v6 = append(policy.v6, endpoint)
		}
	}
	sort.Slice(policy.v4, func(i, j int) bool { return tupleLess(policy.v4[i], policy.v4[j]) })
	sort.Slice(policy.v6, func(i, j int) bool { return tupleLess(policy.v6[i], policy.v6[j]) })
	return policy, nil
}

func (policy *endpointPolicy) destroy() {
	if policy == nil {
		return
	}
	clear(policy.v4)
	clear(policy.v6)
	*policy = endpointPolicy{}
}

func tupleLess(left, right endpointTuple) bool {
	if comparison := left.address.Compare(right.address); comparison != 0 {
		return comparison < 0
	}
	return left.port < right.port
}

func namespaceRules(spec topologySpec, policy endpointPolicy) []byte {
	var rules bytes.Buffer
	rules.Grow(4096)
	writeLine(&rules, "table inet ", spec.namespaceTable, " {")
	writeEndpointSets(&rules, policy)
	writeLine(&rules, " chain input {")
	writeLine(&rules, "  type filter hook input priority filter; policy drop;")
	writeLine(&rules, "  iifname { \"", spec.tap, "\", \"", spec.namespaceVeth, "\" } ip6 nexthdr icmpv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept")
	writeLine(&rules, " }")
	writeLine(&rules, " chain output {")
	writeLine(&rules, "  type filter hook output priority filter; policy drop;")
	writeLine(&rules, "  oifname { \"", spec.tap, "\", \"", spec.namespaceVeth, "\" } ip6 nexthdr icmpv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept")
	writeLine(&rules, " }")
	writeLine(&rules, " chain forward {")
	writeLine(&rules, "  type filter hook forward priority filter; policy drop;")
	writeLine(&rules, "  iifname \"", spec.namespaceVeth, "\" oifname \"", spec.tap, "\" ip daddr ", spec.guestAddress4.Addr().String(), " ct state { established, related } accept")
	writeLine(&rules, "  iifname \"", spec.namespaceVeth, "\" oifname \"", spec.tap, "\" ip6 daddr ", spec.guestAddress6.Addr().String(), " ct state { established, related } accept")
	writeEndpointAcceptRules(&rules, spec, policy)
	writeLine(&rules, " }")
	writeLine(&rules, "}")
	return rules.Bytes()
}

func hostRules(spec topologySpec, policy endpointPolicy) []byte {
	var rules bytes.Buffer
	rules.Grow(4096)
	writeLine(&rules, "table inet ", spec.hostTable, " {")
	writeEndpointSets(&rules, policy)
	writeLine(&rules, " chain forward {")
	writeLine(&rules, "  type filter hook forward priority filter; policy accept;")
	writeLine(&rules, "  oifname \"", spec.hostVeth, "\" ip daddr ", spec.guestAddress4.Addr().String(), " ct state { established, related } accept")
	writeLine(&rules, "  oifname \"", spec.hostVeth, "\" ip6 daddr ", spec.guestAddress6.Addr().String(), " ct state { established, related } accept")
	writeHostEndpointAcceptRules(&rules, spec, policy)
	writeLine(&rules, "  iifname \"", spec.hostVeth, "\" drop")
	writeLine(&rules, "  oifname \"", spec.hostVeth, "\" drop")
	writeLine(&rules, " }")
	writeLine(&rules, " chain postrouting {")
	writeLine(&rules, "  type nat hook postrouting priority srcnat; policy accept;")
	writeMasqueradeRules(&rules, spec, policy)
	writeLine(&rules, " }")
	writeLine(&rules, "}")
	return rules.Bytes()
}

func deleteTableRules(table string) []byte {
	return []byte("delete table inet " + table + "\n")
}

func writeEndpointSets(destination *bytes.Buffer, policy endpointPolicy) {
	if len(policy.v4) > 0 {
		writeEndpointSet(destination, "proton4", "ipv4_addr", policy.v4)
	}
	if len(policy.v6) > 0 {
		writeEndpointSet(destination, "proton6", "ipv6_addr", policy.v6)
	}
}

func writeEndpointSet(destination *bytes.Buffer, name, addressType string, values []endpointTuple) {
	write(destination, " set ", name, " { type ", addressType, " . inet_service; elements = { ")
	scratch := make([]byte, 0, 64)
	defer clear(scratch)
	for index, value := range values {
		if index > 0 {
			write(destination, ", ")
		}
		scratch = value.address.AppendTo(scratch[:0])
		_, _ = destination.Write(scratch)
		write(destination, " . ")
		scratch = strconv.AppendUint(scratch[:0], uint64(value.port), 10)
		_, _ = destination.Write(scratch)
	}
	writeLine(destination, " } }")
}

func writeEndpointAcceptRules(destination *bytes.Buffer, spec topologySpec, policy endpointPolicy) {
	if len(policy.v4) > 0 {
		writeLine(destination, "  iifname \"", spec.tap, "\" oifname \"", spec.namespaceVeth, "\" ip saddr ", spec.guestAddress4.Addr().String(), " ip daddr . udp dport @proton4 accept")
	}
	if len(policy.v6) > 0 {
		writeLine(destination, "  iifname \"", spec.tap, "\" oifname \"", spec.namespaceVeth, "\" ip6 saddr ", spec.guestAddress6.Addr().String(), " ip6 daddr . udp dport @proton6 accept")
	}
}

func writeHostEndpointAcceptRules(destination *bytes.Buffer, spec topologySpec, policy endpointPolicy) {
	if len(policy.v4) > 0 {
		writeLine(destination, "  iifname \"", spec.hostVeth, "\" ip saddr ", spec.guestAddress4.Addr().String(), " ip daddr . udp dport @proton4 accept")
	}
	if len(policy.v6) > 0 {
		writeLine(destination, "  iifname \"", spec.hostVeth, "\" ip6 saddr ", spec.guestAddress6.Addr().String(), " ip6 daddr . udp dport @proton6 accept")
	}
}

func writeMasqueradeRules(destination *bytes.Buffer, spec topologySpec, policy endpointPolicy) {
	if len(policy.v4) > 0 {
		writeLine(destination, "  iifname \"", spec.hostVeth, "\" ip saddr ", spec.guestAddress4.Addr().String(), " ip daddr . udp dport @proton4 masquerade")
	}
	if len(policy.v6) > 0 {
		writeLine(destination, "  iifname \"", spec.hostVeth, "\" ip6 saddr ", spec.guestAddress6.Addr().String(), " ip6 daddr . udp dport @proton6 masquerade")
	}
}

func write(destination *bytes.Buffer, values ...string) {
	for _, value := range values {
		_, _ = destination.WriteString(value)
	}
}

func writeLine(destination *bytes.Buffer, values ...string) {
	write(destination, values...)
	_ = destination.WriteByte('\n')
}

func endpointTupleFor(address netip.Addr, port uint16) endpointTuple {
	return endpointTuple{address: address, port: port}
}
