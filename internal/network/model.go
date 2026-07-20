package network

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strconv"
)

const (
	maximumAllocationAttempts = 64
	maximumEndpointTuples     = 16
	interfaceNameLimit        = 15
)

type topologySpec struct {
	namespace      string
	hostVeth       string
	namespaceVeth  string
	tap            string
	namespaceTable string
	hostTable      string

	guestNetwork4    netip.Prefix
	guestGateway4    netip.Prefix
	guestAddress4    netip.Prefix
	uplinkNetwork4   netip.Prefix
	hostUplink4      netip.Prefix
	namespaceUplink4 netip.Prefix

	guestNetwork6    netip.Prefix
	guestGateway6    netip.Prefix
	guestAddress6    netip.Prefix
	uplinkNetwork6   netip.Prefix
	hostUplink6      netip.Prefix
	namespaceUplink6 netip.Prefix

	slot uint16
}

type endpointTuple struct {
	address netip.Addr
	port    uint16
}

type endpointPolicy struct {
	v4 []endpointTuple
	v6 []endpointTuple
}

// Inspection is the complete safe network status. Interface names, addresses,
// endpoint values, ports and profile associations are intentionally absent.
type Inspection struct {
	SchemaVersion     int  `json:"schema_version"`
	Ready             bool `json:"ready"`
	IPv4EndpointCount int  `json:"ipv4_endpoint_count"`
	IPv6EndpointCount int  `json:"ipv6_endpoint_count"`
	TAPReady          bool `json:"tap_ready"`
}

// PolicyAudit is the complete safe result of reading the live nftables policy.
// Exact object names, counters, addresses and raw command output stay inside the
// network owner and cannot enter orchestration state.
type PolicyAudit struct {
	NamespacePolicyPresent bool
	HostPolicyPresent      bool
	ForbiddenEgressZero    bool
}

func candidateFor(sessionID string, attempt uint8) topologySpec {
	digest := sha256.Sum256([]byte(sessionID + ":" + strconv.FormatUint(uint64(attempt), 10)))
	suffix := hex.EncodeToString(digest[:5])
	slot := binary.BigEndian.Uint16(digest[5:7])

	v4Base := uint32(0x0af00000) + uint32(slot)*8 // 10.240.0.0/13, two /30s per slot.
	guestBase4 := address4(v4Base)
	uplinkBase4 := address4(v4Base + 4)

	var v6Base [16]byte
	v6Base[0], v6Base[1], v6Base[2], v6Base[3] = 0xfd, 0x70, 0x76, 0x6d
	binary.BigEndian.PutUint16(v6Base[4:6], slot)
	guestBase6 := netip.AddrFrom16(v6Base)
	v6Base[15] = 4
	uplinkBase6 := netip.AddrFrom16(v6Base)

	return topologySpec{
		namespace: "pvmn-" + suffix, hostVeth: "pvh" + suffix,
		namespaceVeth: "pvn" + suffix, tap: "pvt" + suffix,
		namespaceTable: "pvm_" + suffix, hostTable: "pvmh_" + suffix,
		guestNetwork4:    netip.PrefixFrom(guestBase4, 30),
		guestGateway4:    netip.PrefixFrom(guestBase4.Next(), 30),
		guestAddress4:    netip.PrefixFrom(guestBase4.Next().Next(), 30),
		uplinkNetwork4:   netip.PrefixFrom(uplinkBase4, 30),
		hostUplink4:      netip.PrefixFrom(uplinkBase4.Next(), 30),
		namespaceUplink4: netip.PrefixFrom(uplinkBase4.Next().Next(), 30),
		guestNetwork6:    netip.PrefixFrom(guestBase6, 126),
		guestGateway6:    netip.PrefixFrom(guestBase6.Next(), 126),
		guestAddress6:    netip.PrefixFrom(guestBase6.Next().Next(), 126),
		uplinkNetwork6:   netip.PrefixFrom(uplinkBase6, 126),
		hostUplink6:      netip.PrefixFrom(uplinkBase6.Next(), 126),
		namespaceUplink6: netip.PrefixFrom(uplinkBase6.Next().Next(), 126),
		slot:             slot,
	}
}

func address4(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}
