package ink

import (
	"math"
	"net/url"
	"strconv"
	"strings"
)

// isInkEndpointUrl mirrors the reference predicate in src/models/endpoint-url.ts:
// a non-empty string of at most 2048 UTF-8 bytes, no ASCII control or whitespace,
// scheme https (lowercase), a non-empty host, no userinfo, an optional 1..65535
// port, optional path and query, and no fragment.
func isInkEndpointUrl(value string) bool {
	if value == "" || len(value) > 2048 {
		return false
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	if !strings.HasPrefix(value, "https://") {
		return false
	}
	if strings.Contains(value, "#") {
		return false
	}
	authority := value[len("https://"):]
	if i := strings.IndexAny(authority, "/?"); i != -1 {
		authority = authority[:i]
	}
	if authority == "" || strings.Contains(authority, "@") {
		return false
	}
	hostPort := authority
	if strings.HasPrefix(authority, "[") {
		if j := strings.Index(authority, "]"); j != -1 {
			hostPort = authority[j+1:]
		}
	}
	if c := strings.Index(hostPort, ":"); c != -1 {
		port := hostPort[c+1:]
		n, err := strconv.Atoi(port)
		if err != nil || !isAllDigits(port) || n < 1 || n > 65535 {
			return false
		}
	}
	u, err := url.Parse(value)
	if err != nil {
		return false
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func reqBool(m map[string]interface{}, key string) bool {
	_, ok := m[key].(bool)
	return ok
}

func optBool(m map[string]interface{}, key string) bool {
	v, present := m[key]
	if !present {
		return true
	}
	_, ok := v.(bool)
	return ok
}

// optPosInt mirrors z.number().int().positive().optional(): absent is ok; a
// present value must be an integer-valued float in [1, 2^53-1].
func optPosInt(m map[string]interface{}, key string) bool {
	v, present := m[key]
	if !present {
		return true
	}
	f, ok := v.(float64)
	return ok && f == math.Trunc(f) && f >= 1 && f <= maxSafeInteger
}

func reqEnumArray(m map[string]interface{}, key string, maxLen int, allowed ...string) bool {
	v, present := m[key]
	if !present {
		return false
	}
	arr, ok := v.([]interface{})
	if !ok || len(arr) > maxLen {
		return false
	}
	for _, e := range arr {
		s, ok := e.(string)
		if !ok || !inEnum(s, allowed...) {
			return false
		}
	}
	return true
}

func optEnumArray(m map[string]interface{}, key string, maxLen int, allowed ...string) bool {
	if _, present := m[key]; !present {
		return true
	}
	return reqEnumArray(m, key, maxLen, allowed...)
}

func isStrictInkTimestamp(s string) bool {
	_, ok := ParseInkTimestampMs(s)
	return ok
}

var intentTypes = []string{
	"schedule_meeting", "schedule_meeting_response", "intro_request", "intro_response",
	"opportunity", "opportunity_response", "follow_up", "ask", "ask_response",
	"connection_request", "connection_response", "context_share", "ping", "retract", "multi_party_sync",
}

// validateKeyEntry mirrors KeyEntrySchema (key-entry.ts): not strict (unknown
// keys are allowed), strict-RFC3339 key-window timestamps, no length cap on
// keyId or publicKeyMultibase beyond the prefix.
func validateKeyEntry(m map[string]interface{}) bool {
	if id, ok := m["keyId"].(string); !ok || id == "" {
		return false
	}
	if alg, ok := m["algorithm"].(string); !ok || !inEnum(alg, "Ed25519", "X25519") {
		return false
	}
	if pk, ok := m["publicKeyMultibase"].(string); !ok || !strings.HasPrefix(pk, "z") {
		return false
	}
	if st, ok := m["status"].(string); !ok || !inEnum(st, "active", "retired", "revoked") {
		return false
	}
	if vf, ok := m["validFrom"].(string); !ok || !isStrictInkTimestamp(vf) {
		return false
	}
	for _, key := range []string{"validUntil", "revokedAt"} {
		if v, present := m[key]; present {
			s, ok := v.(string)
			if !ok || !isStrictInkTimestamp(s) {
				return false
			}
		}
	}
	if v, present := m["revokeReason"]; present {
		if _, ok := v.(string); !ok {
			return false
		}
	}
	return true
}

func validateThirdPartyAuditService(m map[string]interface{}) bool {
	ep, ok := m["endpoint"].(string)
	if !ok || !isInkEndpointUrl(ep) {
		return false
	}
	return reqStr(m, "did", 512) && reqStr(m, "publicKey", 256)
}

func validateCapabilities(m map[string]interface{}) bool {
	if !reqEnumArray(m, "intentsAccepted", 32, intentTypes...) || !reqEnumArray(m, "intentsSent", 32, intentTypes...) {
		return false
	}
	if v, present := m["receipts"]; present {
		r, ok := v.(map[string]interface{})
		if !ok || !reqBool(r, "send") || !reqEnumArray(r, "dispositions", 16, "received", "delivered", "acted", "rejected", "expired") {
			return false
		}
	}
	if !optBool(m, "auditExchange") {
		return false
	}
	if v, present := m["thirdPartyAudit"]; present {
		tpa, ok := v.(map[string]interface{})
		if !ok {
			return false
		}
		services, present := tpa["services"]
		if !present {
			return false
		}
		arr, ok := services.([]interface{})
		if !ok || len(arr) > 16 {
			return false
		}
		for _, e := range arr {
			s, ok := e.(map[string]interface{})
			if !ok || !validateThirdPartyAuditService(s) {
				return false
			}
		}
		if sp, ok := tpa["submitPolicy"].(string); !ok || !inEnum(sp, "all", "high_value", "none") {
			return false
		}
	}
	return true
}

func validateCardAvailability(m map[string]interface{}) bool {
	return reqStr(m, "timezone", 64) && optStr(m, "meetingHours", 200) && optStr(m, "responseSla", 200)
}

func validateKeySet(m map[string]interface{}) bool {
	for _, key := range []string{"signing", "encryption"} {
		v, present := m[key]
		if !present {
			return false
		}
		arr, ok := v.([]interface{})
		if !ok || len(arr) > 32 {
			return false
		}
		for _, e := range arr {
			ke, ok := e.(map[string]interface{})
			if !ok || !validateKeyEntry(ke) {
				return false
			}
		}
	}
	return true
}

func validateGovernance(m map[string]interface{}) bool {
	if !optPosInt(m, "maxAcceptedDelegationDepth") {
		return false
	}
	// supportedTransports has no .max() in the schema, so it is unbounded.
	if !optEnumArray(m, "supportedTransports", math.MaxInt32, "ink_http", "ink_ws", "extension_api", "voice", "line_phone", "human_review_queue") {
		return false
	}
	if !optBool(m, "supportsCapabilityGatedDiscovery") {
		return false
	}
	if v, present := m["handshakeBudget"]; present {
		hb, ok := v.(map[string]interface{})
		if !ok || !optPosInt(hb, "maxChallengesPerCorrelation") || !optPosInt(hb, "maxIntentsPerMinute") {
			return false
		}
	}
	return true
}

// ValidateAgentCard validates the canonical .well-known/ink/agent.json document
// against AgentCardSchema (src/models/agent-card.ts). The card and its inner
// objects are not strict (unknown keys are ignored) except the embedded profile
// snapshot, which is strict. Endpoint fields use the pinned INK endpoint URL
// grammar, and key-window timestamps use the strict RFC 3339 profile.
func ValidateAgentCard(m map[string]interface{}) bool {
	if p, ok := m["protocol"].(string); !ok || p != "ink/0.1" {
		return false
	}
	if !reqStr(m, "agentId", 512) || !optStr(m, "ownerDid", 512) || !optStr(m, "ownerHandle", 256) || !optStr(m, "atprotoRecordUri", 2048) {
		return false
	}
	if !reqStr(m, "handle", 256) || !reqStr(m, "displayName", 200) {
		return false
	}
	endpoint, ok := m["endpoint"].(string)
	if !ok || !isInkEndpointUrl(endpoint) {
		return false
	}
	if v, present := m["inboxEndpoint"]; present {
		s, ok := v.(string)
		if !ok || !isInkEndpointUrl(s) {
			return false
		}
		// superRefine: when both are present they must be byte-for-byte equal.
		if s != endpoint {
			return false
		}
	}
	if pk, ok := m["publicKeyMultibase"].(string); !ok || !strings.HasPrefix(pk, "z") || utf16Len(pk) > 128 {
		return false
	}
	if v, present := m["profileSnapshot"]; present {
		ps, ok := v.(map[string]interface{})
		if !ok || !validateProfileSnapshot(ps) {
			return false
		}
	}
	caps, ok := m["capabilities"].(map[string]interface{})
	if !ok || !validateCapabilities(caps) {
		return false
	}
	av, ok := m["availability"].(map[string]interface{})
	if !ok || !validateCardAvailability(av) {
		return false
	}
	if v, present := m["keys"]; present {
		k, ok := v.(map[string]interface{})
		if !ok || !validateKeySet(k) {
			return false
		}
	}
	if !optStr(m, "currentSigningKeyId", 128) || !optStr(m, "currentEncryptionKeyId", 128) {
		return false
	}
	if !optPosInt(m, "keySetVersion") {
		return false
	}
	if !optStrArray(m, "supportedProtocolVersions", 8, 16) {
		return false
	}
	if v, present := m["visibility"]; present {
		s, ok := v.(string)
		if !ok || !inEnum(s, "public", "network_only", "capability_gated", "private") {
			return false
		}
	}
	if v, present := m["governance"]; present {
		g, ok := v.(map[string]interface{})
		if !ok || !validateGovernance(g) {
			return false
		}
	}
	return true
}
