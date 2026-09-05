package ink

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

var (
	endpointRegNameRe = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
	endpointIPv6Re    = regexp.MustCompile(`^[0-9A-Fa-f:.]+$`)
	endpointDigitsRe  = regexp.MustCompile(`^[0-9]+$`)
)

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// validPercentEscapes requires every '%' to be followed by two hex digits.
func validPercentEscapes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) || !isHexByte(s[i+1]) || !isHexByte(s[i+2]) {
				return false
			}
		}
	}
	return true
}

// isInkEndpointUrl mirrors the reference predicate in src/models/endpoint-url.ts.
// The grammar is validated by explicit string rules, NOT a runtime URL parser
// (new URL / net/url disagree on backslashes, percent escapes, percent-encoded
// hosts, and IPv6 zone ids), so both implementations run identical logic: a
// non-empty string of at most 2048 UTF-8 bytes, no ASCII control or whitespace,
// no backslash, well-formed percent escapes, scheme https (lowercase), a host
// (reg-name/IPv4 of [A-Za-z0-9.-] or a bracketed IPv6 of [0-9A-Fa-f:.]), no
// userinfo or percent-encoding in the authority, an optional 1..65535 port, an
// optional path and query, and no fragment.
func isInkEndpointUrl(value string) bool {
	if value == "" || len(value) > 2048 {
		return false
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	if strings.Contains(value, "\\") || !validPercentEscapes(value) {
		return false
	}
	if !strings.HasPrefix(value, "https://") || strings.Contains(value, "#") {
		return false
	}
	authority := value[len("https://"):]
	if i := strings.IndexAny(authority, "/?"); i != -1 {
		authority = authority[:i]
	}
	if authority == "" || strings.Contains(authority, "@") || strings.Contains(authority, "%") {
		return false
	}
	var host, port string
	hasPort := false
	if strings.HasPrefix(authority, "[") {
		end := strings.Index(authority, "]")
		if end == -1 {
			return false
		}
		host = authority[1:end]
		after := authority[end+1:]
		if after != "" {
			if !strings.HasPrefix(after, ":") {
				return false
			}
			port, hasPort = after[1:], true
		}
		if host == "" || !endpointIPv6Re.MatchString(host) {
			return false
		}
	} else {
		colon := strings.Index(authority, ":")
		if colon == -1 {
			host = authority
		} else {
			host, port, hasPort = authority[:colon], authority[colon+1:], true
		}
		if host == "" || !endpointRegNameRe.MatchString(host) {
			return false
		}
	}
	if hasPort {
		if !endpointDigitsRe.MatchString(port) {
			return false
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
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
func validateKeyEntry(m map[string]interface{}, role string) bool {
	if id, ok := m["keyId"].(string); !ok || id == "" {
		return false
	}
	// Identity model §4.1: the roles are disjoint and the multicodec enforces
	// it. A signing entry is Ed25519 under 0xed01 and an encryption entry is
	// X25519 under 0xec01, in the algorithm label AND in the decoded bytes.
	wantAlg := "Ed25519"
	if role == "encryption" {
		wantAlg = "X25519"
	}
	if alg, ok := m["algorithm"].(string); !ok || alg != wantAlg {
		return false
	}
	pk, ok := m["publicKeyMultibase"].(string)
	if !ok || !strings.HasPrefix(pk, "z") {
		return false
	}
	if role == "encryption" {
		if _, err := DecodeEncryptionKeyMultibase(pk); err != nil {
			return false
		}
	} else if _, err := DecodePublicKeyMultibase(pk); err != nil {
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
			if !ok || !validateKeyEntry(ke, key) {
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

// discoveryExposureRank is the exposure lattice for the discovery descriptor
// (#188), most-exposed to least. Discovery `scope` reuses the visibility enum
// and MUST NOT exceed the card's visibility (the hard upper bound).
var discoveryExposureRank = map[string]int{
	"public":           3,
	"network_only":     2,
	"capability_gated": 1,
	"private":          0,
}

// validateDiscovery mirrors DiscoveryDescriptorSchema and the card superRefine
// (src/models/agent-card.ts). The descriptor is opt-in and only ever narrows
// exposure: `enabled` and `scope` are required, `scope` is in the visibility
// enum and may not exceed upperBound (the card's visibility, defaulting to
// public). `tags` are at most 32 non-empty strings of at most 64 UTF-16 units;
// `queryable` is an optional bool; `updatedAt` is an optional strict RFC 3339
// timestamp. Unknown keys are ignored for forward compatibility.
func validateDiscovery(m map[string]interface{}, upperBound string) bool {
	if _, ok := m["enabled"].(bool); !ok {
		return false
	}
	scope, ok := m["scope"].(string)
	if !ok || !inEnum(scope, "public", "network_only", "capability_gated", "private") {
		return false
	}
	if discoveryExposureRank[scope] > discoveryExposureRank[upperBound] {
		return false
	}
	if v, present := m["tags"]; present {
		arr, ok := v.([]interface{})
		if !ok || len(arr) > 32 {
			return false
		}
		for _, e := range arr {
			s, ok := e.(string)
			if !ok || s == "" || utf16Len(s) > 64 {
				return false
			}
		}
	}
	if !optBool(m, "queryable") {
		return false
	}
	if v, present := m["updatedAt"]; present {
		s, ok := v.(string)
		if !ok || !isStrictInkTimestamp(s) {
			return false
		}
	}
	return true
}

// validateCardSignature mirrors CardSignatureSchema (agent-card.ts §3.1): a
// required `keyId` of 1..128 UTF-16 code units and a required `signature` that is
// exactly 86 base64url no-padding characters. Optional and backward-compatible.
func validateCardSignature(m map[string]interface{}) bool {
	kid, ok := m["keyId"].(string)
	if !ok || utf16Len(kid) < 1 || utf16Len(kid) > 128 {
		return false
	}
	sig, ok := m["signature"].(string)
	return ok && signatureRe.MatchString(sig)
}

// validateRotationChainSigningEntry mirrors RotationChainSigningEntrySchema
// (§4.1): a committed `{keyId, publicKeyMultibase, status}` entry with no
// `algorithm` and no key-window timestamps.
func validateRotationChainSigningEntry(m map[string]interface{}) bool {
	kid, ok := m["keyId"].(string)
	if !ok || utf16Len(kid) < 1 || utf16Len(kid) > 128 {
		return false
	}
	pk, ok := m["publicKeyMultibase"].(string)
	if !ok || !strings.HasPrefix(pk, "z") || utf16Len(pk) > 128 {
		return false
	}
	st, ok := m["status"].(string)
	return ok && inEnum(st, "active", "retired", "revoked")
}

// validateRotationLink mirrors RotationChainLinkSchema (§4.1): a positive integer
// `keySetVersion`, a `signing` set of 1..32 keyId-unique entries, a `prevKeyId`
// of 1..128 code units and an 86-char base64url `signature`.
func validateRotationLink(m map[string]interface{}) bool {
	kv, present := m["keySetVersion"]
	f, ok := kv.(float64)
	if !present || !ok || f != math.Trunc(f) || f < 1 || f > maxSafeInteger {
		return false
	}
	signing, ok := m["signing"].([]interface{})
	if !ok || len(signing) < 1 || len(signing) > 32 {
		return false
	}
	seen := make(map[string]bool, len(signing))
	for _, e := range signing {
		em, ok := e.(map[string]interface{})
		if !ok || !validateRotationChainSigningEntry(em) {
			return false
		}
		kid := em["keyId"].(string)
		if seen[kid] {
			return false
		}
		seen[kid] = true
	}
	prev, ok := m["prevKeyId"].(string)
	if !ok || utf16Len(prev) < 1 || utf16Len(prev) > 128 {
		return false
	}
	sig, ok := m["signature"].(string)
	return ok && signatureRe.MatchString(sig)
}

// validateRotationChain mirrors RotationChainSchema (§4.1): an array of at most
// 32 links, each validated by validateRotationLink.
func validateRotationChain(v interface{}) bool {
	arr, ok := v.([]interface{})
	if !ok || len(arr) > 32 {
		return false
	}
	for _, e := range arr {
		link, ok := e.(map[string]interface{})
		if !ok || !validateRotationLink(link) {
			return false
		}
	}
	return true
}

// ValidateAgentCard validates the Agent Card document served at the versioned
// discovery path /ink/v1/<agentId>/agent.json (specs/ink-agent-card-discovery-fetch.md)
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
	// An absent visibility is the public upper bound: the card is itself
	// publicly fetchable, so a discovery descriptor may expose up to public.
	visibility := "public"
	if v, present := m["visibility"]; present {
		s, ok := v.(string)
		if !ok || !inEnum(s, "public", "network_only", "capability_gated", "private") {
			return false
		}
		visibility = s
	}
	if v, present := m["discovery"]; present {
		d, ok := v.(map[string]interface{})
		if !ok || !validateDiscovery(d, visibility) {
			return false
		}
	}
	if v, present := m["governance"]; present {
		g, ok := v.(map[string]interface{})
		if !ok || !validateGovernance(g) {
			return false
		}
	}
	// Self-authenticating Agent Card members (ink-agent-card-signature.md, Phase
	// A). All three are OPTIONAL and backward-compatible; a card without them
	// validates exactly as before.
	if v, present := m["cardSignature"]; present {
		cs, ok := v.(map[string]interface{})
		if !ok || !validateCardSignature(cs) {
			return false
		}
	}
	if v, present := m["rotationChain"]; present {
		if !validateRotationChain(v) {
			return false
		}
	}
	if v, present := m["updatedAt"]; present {
		s, ok := v.(string)
		if !ok || !isStrictInkTimestamp(s) {
			return false
		}
	}
	// Evidence members (ink-attestation.md, activated with the evidence
	// capability). Both OPTIONAL and backward-compatible; validation is
	// shape-only, and a stale but well-formed attestation stays card-valid.
	if v, present := m["attestations"]; present {
		if !validateCardAttestations(v) {
			return false
		}
	}
	if v, present := m["evidencePolicy"]; present {
		if !validateEvidencePolicy(v) {
			return false
		}
	}
	return true
}

// maxParseKeys caps the number of signing-key entries ExtractCandidateKeys
// decodes from an Agent Card, mirroring the reference MAX_PARSE_KEYS. Base58
// decode on a poisoned card with thousands of entries would otherwise burn
// CPU even though only the first maxCandidateKeys are ever tried at
// verification time.
const maxParseKeys = 20

// acceptWindowField mirrors the reference extractCandidateKeys `accept`
// closure: an absent field is fine (returns the zero OptionalTimestamp and
// ok=true); a present field that is not a well-formed strict RFC 3339
// timestamp string is suspicious enough that the WHOLE entry is skipped
// (ok=false), not just the field, so a card can't "blank out" an expiry.
func acceptWindowField(entry map[string]interface{}, key string) (OptionalTimestamp, bool) {
	v, present := entry[key]
	if !present {
		return OptionalTimestamp{}, true
	}
	s, ok := v.(string)
	if !ok || !isStrictInkTimestamp(s) {
		return OptionalTimestamp{}, false
	}
	return Timestamp(s), true
}

// ExtractCandidateKeys extracts candidate signing keys from an Agent Card,
// mirroring the reference extractCandidateKeys (src/discovery/agent-card.ts)
// exactly.
//
// Authority rule: presence of keys.signing (even when empty) is
// authoritative. Callers MUST treat the returned set as the complete list of
// acceptable signers, including the empty set, which means "key set
// published, no usable keys" and forbids any legacy bootstrap fallback.
//
//   - keys.signing absent  -> fall back to legacy publicKeyMultibase
//   - keys.signing: []     -> return [] (authoritative empty)
//   - keys.signing: [k..]  -> parse each entry independently; malformed
//     entries are skipped so a single bad entry cannot collapse the whole
//     set to "legacy" and let a rotated-away bootstrap key pass.
//
// Unlike the reference, which is typed over an already validated card, this
// function accepts the raw decoded map, so each entry must also satisfy the
// key-entry schema (keyId, algorithm Ed25519, status, strict validFrom) to be
// returned.
func ExtractCandidateKeys(card map[string]interface{}) []CandidateKey {
	out := []CandidateKey{}
	if card == nil {
		return out
	}

	// card.keys?.signing: a missing `keys` object, or a `keys` that is not
	// an object with no `signing` member reads as "signing absent", matching
	// the reference. A `keys` member that is present but not an object is a
	// malformed card, not a legacy one, and returns an authoritative empty set.
	var signingVal interface{}
	signingPresent := false
	if keysVal, ok := card["keys"]; ok {
		keysObj, isObj := keysVal.(map[string]interface{})
		if !isObj {
			// Present but not an object is not absent. Falling through would
			// treat the card as legacy and hand back the top-level key as
			// active, ignoring what the set said about rotation or revocation.
			return out
		}
		signingVal, signingPresent = keysObj["signing"]
	}

	if signingPresent {
		// Runtime type guard: a malformed card where `signing` is an
		// object/string would otherwise be untyped in Go too: present but
		// not a JSON array reads as authoritative empty.
		arr, ok := signingVal.([]interface{})
		if !ok {
			return out
		}
		limited := arr
		if len(limited) > maxParseKeys {
			limited = limited[:maxParseKeys]
		}
		for _, rawEntry := range limited {
			entry, ok := rawEntry.(map[string]interface{})
			if !ok {
				continue
			}
			// The reference extractor receives a card that already passed
			// AgentCardSchema, so every entry it sees satisfies KeyEntrySchema.
			// This function takes the raw decoded map, so it applies the same
			// entry schema itself: an entry missing a required field (for
			// example validFrom, which would otherwise read as an unbounded
			// window) is skipped, never admitted.
			if !validateKeyEntry(entry, "signing") {
				continue
			}
			keyID, ok := entry["keyId"].(string)
			if !ok {
				continue
			}
			pkmb, ok := entry["publicKeyMultibase"].(string)
			if !ok {
				continue
			}
			status, ok := entry["status"].(string)
			if !ok || !inEnum(status, "active", "retired", "revoked") {
				continue
			}
			validFrom, ok := acceptWindowField(entry, "validFrom")
			if !ok {
				continue
			}
			validUntil, ok := acceptWindowField(entry, "validUntil")
			if !ok {
				continue
			}
			revokedAt, ok := acceptWindowField(entry, "revokedAt")
			if !ok {
				continue
			}
			pub, err := DecodePublicKeyMultibase(pkmb)
			if err != nil {
				// Skip malformed entry; do not collapse the whole set to legacy.
				continue
			}
			out = append(out, CandidateKey{
				KeyID:      keyID,
				PublicKey:  pub,
				Status:     status,
				ValidFrom:  validFrom,
				ValidUntil: validUntil,
				RevokedAt:  revokedAt,
			})
		}
		return out
	}

	// Legacy card (no keys.signing block at all): single key. A malformed
	// legacy publicKeyMultibase returns [] rather than a decode error,
	// because the card itself was observed and [] is the correct "no usable
	// keys" signal; callers must not fall back to bootstrap.
	pkmb, ok := card["publicKeyMultibase"].(string)
	if !ok {
		return out
	}
	pub, err := DecodePublicKeyMultibase(pkmb)
	if err != nil {
		return out
	}
	return append(out, CandidateKey{KeyID: "legacy", PublicKey: pub, Status: "active"})
}
