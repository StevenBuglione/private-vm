package network

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

type nftAuditDocument struct {
	Nftables []json.RawMessage `json:"nftables"`
}

type nftAuditMetainfo struct {
	Version           string `json:"version"`
	ReleaseName       string `json:"release_name"`
	JSONSchemaVersion int    `json:"json_schema_version"`
}

type nftAuditTable struct {
	Family  string `json:"family"`
	Name    string `json:"name"`
	Handle  uint64 `json:"handle"`
	Comment string `json:"comment"`
}

type nftAuditChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle uint64 `json:"handle"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Prio   int    `json:"prio"`
	Policy string `json:"policy"`
}

type nftAuditRule struct {
	Family  string            `json:"family"`
	Table   string            `json:"table"`
	Chain   string            `json:"chain"`
	Handle  uint64            `json:"handle"`
	Expr    []json.RawMessage `json:"expr"`
	Comment string            `json:"comment"`
	Index   *uint64           `json:"index,omitempty"`
}

type nftAuditCounter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// parsePolicyAudit consumes one live, bounded `nft -j list table` response.
// The response may contain endpoint values, so every retained RawMessage is
// cleared before return and no parse error includes source text.
func parsePolicyAudit(value []byte, tableName, primaryPolicy string) (bool, error) {
	if len(value) == 0 || tableName == "" || (primaryPolicy != "accept" && primaryPolicy != "drop") {
		return false, ErrCommandFailed
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var document nftAuditDocument
	if err := decoder.Decode(&document); err != nil {
		return false, ErrCommandFailed
	}
	defer func() {
		for _, object := range document.Nftables {
			clear(object)
		}
	}()
	if err := requireJSONEOF(decoder); err != nil || len(document.Nftables) == 0 {
		return false, ErrCommandFailed
	}

	tableCount := 0
	metainfoCount := 0
	primaryCount := 0
	auditChainCount := 0
	sets := make(map[string]bool, 2)
	counters := make(map[string]int, len(auditCounterComments()))
	for _, expected := range auditCounterComments() {
		counters[expected] = 0
	}
	for _, raw := range document.Nftables {
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrapper); err != nil || len(wrapper) != 1 {
			clearRawMap(wrapper)
			return false, ErrCommandFailed
		}
		for kind, payload := range wrapper {
			switch kind {
			case "metainfo":
				var metainfo nftAuditMetainfo
				if err := decodeStrictJSON(payload, &metainfo); err != nil || metainfo.Version == "" ||
					metainfo.ReleaseName == "" || metainfo.JSONSchemaVersion != 1 {
					clearRawMap(wrapper)
					return false, ErrCommandFailed
				}
				metainfoCount++
			case "set":
				name, valid := ownedEndpointSet(payload, tableName)
				if !valid || sets[name] {
					clearRawMap(wrapper)
					return false, ErrCommandFailed
				}
				sets[name] = true
			case "table":
				var table nftAuditTable
				if err := decodeStrictJSON(payload, &table); err != nil || table.Family != "inet" ||
					table.Name != tableName || table.Handle == 0 || table.Comment != policyOwnerComment {
					clearRawMap(wrapper)
					return false, ErrCommandFailed
				}
				tableCount++
			case "chain":
				var chain nftAuditChain
				if err := decodeStrictJSON(payload, &chain); err != nil || chain.Family != "inet" || chain.Table != tableName || chain.Handle == 0 {
					clearRawMap(wrapper)
					return false, ErrCommandFailed
				}
				switch chain.Name {
				case "forward":
					if chain.Type != "filter" || chain.Hook != "forward" || chain.Prio != 0 || chain.Policy != primaryPolicy {
						clearRawMap(wrapper)
						return false, ErrCommandFailed
					}
					primaryCount++
				case policyAuditChain:
					if chain.Type != "filter" || chain.Hook != "forward" || chain.Prio != 1 || chain.Policy != "drop" {
						clearRawMap(wrapper)
						return false, ErrCommandFailed
					}
					auditChainCount++
				}
			case "rule":
				var rule nftAuditRule
				if err := decodeStrictJSON(payload, &rule); err != nil || rule.Handle == 0 {
					clearRawMessages(rule.Expr)
					clearRawMap(wrapper)
					return false, ErrCommandFailed
				}
				valid := auditRuleValid(rule, tableName, counters)
				clearRawMessages(rule.Expr)
				if !valid {
					clearRawMap(wrapper)
					return false, ErrCommandFailed
				}
			default:
				clearRawMap(wrapper)
				return false, ErrCommandFailed
			}
		}
		clearRawMap(wrapper)
	}
	if metainfoCount != 1 || tableCount != 1 || primaryCount != 1 || auditChainCount != 1 || len(sets) == 0 {
		return false, ErrCommandFailed
	}
	for _, count := range counters {
		if count != 1 {
			return false, ErrCommandFailed
		}
	}
	return true, nil
}

func ownedEndpointSet(value []byte, tableName string) (string, bool) {
	var record map[string]json.RawMessage
	if err := json.Unmarshal(value, &record); err != nil {
		clearRawMap(record)
		return "", false
	}
	defer clearRawMap(record)
	var family, table, name string
	var handle uint64
	for field, destination := range map[string]any{
		"family": &family,
		"table":  &table,
		"name":   &name,
		"handle": &handle,
	} {
		raw, exists := record[field]
		if !exists || decodeStrictJSON(raw, destination) != nil {
			return "", false
		}
	}
	if family != "inet" || table != tableName || handle == 0 || (name != "proton4" && name != "proton6") {
		return "", false
	}
	return name, true
}

func auditRuleValid(rule nftAuditRule, tableName string, counters map[string]int) bool {
	if rule.Family != "inet" || rule.Table != tableName {
		return false
	}
	if rule.Chain != policyAuditChain {
		return !strings.HasPrefix(rule.Comment, "private-vm:audit:")
	}
	if rule.Comment == "" {
		// Exact endpoint exemptions carry no counter and are validated by the
		// immutable rule generator plus the current-plan Handle lease.
		return true
	}
	if _, expected := counters[rule.Comment]; !expected {
		return false
	}
	counterCount := 0
	for _, expression := range rule.Expr {
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal(expression, &wrapper); err != nil {
			clearRawMap(wrapper)
			return false
		}
		payload, exists := wrapper["counter"]
		if exists {
			var counter nftAuditCounter
			if err := decodeStrictJSON(payload, &counter); err != nil || counter.Packets != 0 || counter.Bytes != 0 {
				clearRawMap(wrapper)
				return false
			}
			counterCount++
		}
		clearRawMap(wrapper)
	}
	if counterCount != 1 {
		return false
	}
	counters[rule.Comment]++
	return true
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrCommandFailed
	}
	return nil
}

func decodeStrictJSON(value []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrCommandFailed
	}
	return requireJSONEOF(decoder)
}

func clearRawMessages(values []json.RawMessage) {
	for _, value := range values {
		clear(value)
	}
}

func clearRawMap(values map[string]json.RawMessage) {
	for _, value := range values {
		clear(value)
	}
}
