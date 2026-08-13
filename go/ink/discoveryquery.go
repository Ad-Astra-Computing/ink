package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"unicode/utf8"
)

// discoveryQueryTopLevelKeys is the exact set of members a discovery query
// envelope may carry. All are required; any missing or extra key rejects.
var discoveryQueryTopLevelKeys = map[string]bool{
	"protocol": true, "type": true, "from": true, "to": true,
	"nonce": true, "timestamp": true, "query": true, "signature": true,
}

// discoveryQueryInnerKeys is the exact set of members the query object may
// carry. Every one is optional, but an unknown key rejects.
var discoveryQueryInnerKeys = map[string]bool{"tags": true, "scope": true, "limit": true}

// MaxDiscoveryQueryBodyBytes is the byte-length ceiling on a raw discovery query
// envelope before it is parsed, following the MaxGrantBodyBytes precedent: an
// oversized blob is rejected by a len check before json.Unmarshal runs. The
// reference verifyDiscoveryQueryEnvelope in src/models/discovery-query.ts takes
// an already-decoded object and applies the isWithinBounds structural walk, so
// this Go byte cap is the decode-layer edge the TypeScript side never sees; the
// structural walk below is the actual parity with the reference.
//
// The value is derived from the schema bounds, counted at the wire escape-
// expansion worst case rather than the UTF-8 encoded length. A well-formed
// envelope carries a from, a to (512 UTF-16 code units each), a nonce (256), a
// timestamp, a scope literal, a signature (86 chars), a protocol and a type
// literal, and a query with up to 32 tags of up to 64 code units each. Tags
// dominate at 32*64 = 2048 code units; from, to and nonce add ~1280 more, for
// about 3,300 schema-bounded code units. The envelope on the wire is not
// canonical JSON, so a sender may escape any character: an ASCII code unit is 1
// UTF-8 byte but 6 raw bytes as \uXXXX, and the signature verifies against the
// re-canonicalized envelope, not the raw bytes. At 6 raw bytes per escaped
// character plus a small constant of JSON structural overhead, a maximal envelope
// is roughly 20 KiB of wire bytes. Rounding to a flat 64 KiB (the same figure the
// grant schema, which is comparably small, rounds to) leaves headroom for a valid
// escaped envelope while rejecting a blob orders of magnitude past the schema
// before the decoder touches it.
const MaxDiscoveryQueryBodyBytes = 64 * 1024

// MaxDiscoveryQueryAgeMs is the maximum age of a discovery query at the
// verifying directory's clock, mirroring the reference
// MAX_DISCOVERY_QUERY_AGE_MS. It is the INK message freshness window
// (ink-protocol.md §3.5): a query is a single signed request, not a credential
// with its own window, so it ages by the same rule every other INK message does.
const MaxDiscoveryQueryAgeMs = 5 * 60 * 1000

// MaxDiscoveryQuerySkewMs is how far ahead of the verifying directory's clock a
// query timestamp may sit, mirroring the reference MAX_DISCOVERY_QUERY_SKEW_MS:
// the same 30 second skew allowance INK grants any signed message.
const MaxDiscoveryQuerySkewMs = 30 * 1000

// DiscoveryQueryReason is the stable discriminator a caller uses to map a
// rejection to its own response. It mirrors the TypeScript
// DiscoveryQueryReason. An empty reason accompanies an accept.
type DiscoveryQueryReason string

const (
	DiscoveryQueryReasonSchema      DiscoveryQueryReason = "schema"
	DiscoveryQueryReasonSignature   DiscoveryQueryReason = "signature"
	DiscoveryQueryReasonAudience    DiscoveryQueryReason = "audience"
	DiscoveryQueryReasonExpired     DiscoveryQueryReason = "expired"
	DiscoveryQueryReasonNotYetValid DiscoveryQueryReason = "not_yet_valid"
	DiscoveryQueryReasonReplay      DiscoveryQueryReason = "replay"
)

// DiscoveryQueryKey identifies a query for replay. The key is the pair of the
// signed From and the requester-chosen Nonce. A nonce is chosen by the
// requester, so two requesters can pick the same string; keying on the pair
// keeps one requester's nonces from burning another's.
type DiscoveryQueryKey struct {
	From  string
	Nonce string
}

// DiscoveryQueryContext is everything a verifier needs beyond the requester key.
//
// Audience is the directory's own identity: the signed to must equal it exactly.
// A directory that answers to several spellings of itself (an origin, a bare
// host, a did:web) lists all of them and the signed to must equal one.
// Comparison is exact: this package never lowercases, never strips a trailing
// slash and never derives one spelling from another, so a directory that accepts
// a spelling states it. An empty Audience is a verifier input error and fails
// closed as schema rather than admitting every audience.
//
// Now is the verifier clock, a strict INK timestamp. A query is fresh within
// [Now - MaxDiscoveryQueryAgeMs, Now + MaxDiscoveryQuerySkewMs], both bounds
// inclusive.
//
// SeenNonces is the replay seam, the same shape the grant verifier's SeenGrants
// hook takes: the (from, nonce) pairs this directory has already accepted. It is
// optional and defaults to "not seen", so a directory that omits it is stating
// that it enforces replay somewhere else; the verifier makes no replay decision
// it was given no state for. A directory MUST record an accepted pair atomically
// with acceptance (check-and-insert under one guard) so two concurrent
// presentations of one nonce cannot both be accepted; this verifier reads the
// seam but never records into it.
type DiscoveryQueryContext struct {
	Audience   []string
	Now        string
	SeenNonces []DiscoveryQueryKey
}

// VerifyDiscoveryQueryEnvelope verifies a requester-signed discovery query
// envelope against the requester's public key and a verification context. It
// mirrors the TypeScript verifyDiscoveryQueryEnvelope byte for byte: strict
// schema validation, then a body signature over "tulpa/sign\n" + JCS(envelope
// without the signature field), verified with RFC 8032 strict Ed25519
// (small-order and non-canonical keys rejected, matching @noble/ed25519
// zip215:false), then the audience, freshness and replay checks in the same
// order. It fails closed and returns a typed reason on the first failure.
//
// The envelope signs to, nonce and timestamp, so this verifier consumes all
// three rather than leaving a caller to rediscover that it must. The signature
// is checked before any context decision, so a rejection never reveals whether
// the audience or the window would have passed.
//
// The envelope is parsed once into a generic object, exactly as a JSON.parse
// based verifier sees it: duplicate members collapse to the last value and a
// JSON null is a present null (not an absent field). The same object is both
// validated and canonicalized, so the validated bytes and the signed bytes can
// never disagree.
func VerifyDiscoveryQueryEnvelope(raw []byte, requesterPublicKey []byte, ctx DiscoveryQueryContext) (bool, DiscoveryQueryReason) {
	// Byte cap before the decoder runs: a body past the schema-derived ceiling is
	// rejected outright, so a pathological blob is never unmarshaled. See the
	// MaxDiscoveryQueryBodyBytes derivation.
	if len(raw) > MaxDiscoveryQueryBodyBytes {
		return false, DiscoveryQueryReasonSchema
	}
	// The envelope is a signed artifact: encoding/json rewrites invalid UTF-8 or
	// a lone surrogate to U+FFFD, so a body that is not byte-identical to the
	// signed one could canonicalize to the signed bytes. Reject both up front.
	if !utf8.Valid(raw) || ContainsLoneSurrogateEscape(raw) {
		return false, DiscoveryQueryReasonSchema
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false, DiscoveryQueryReasonSchema
	}
	// Post-parse structural bounds walk. This is parity with the reference: the
	// TypeScript verifyDiscoveryQueryEnvelope runs isWithinBounds on the decoded
	// object before schema validation, so both implementations reject the same
	// over-deep or over-wide envelope before any signature work.
	if !withinBodyBounds(obj) {
		return false, DiscoveryQueryReasonSchema
	}
	signature, ok := validateDiscoveryQueryEnvelope(obj)
	if !ok {
		return false, DiscoveryQueryReasonSchema
	}
	// Ed25519 body signatures are 86 base64url characters, no padding.
	if !signatureRe.MatchString(signature) {
		return false, DiscoveryQueryReasonSchema
	}
	if len(requesterPublicKey) != ed25519.PublicKeySize || !isStrongEd25519PublicKey(requesterPublicKey) {
		return false, DiscoveryQueryReasonSignature
	}
	unsigned := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		if k != "signature" {
			unsigned[k] = v
		}
	}
	canonical, err := canonicalizeJSON(unsigned)
	if err != nil {
		return false, DiscoveryQueryReasonSchema
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false, DiscoveryQueryReasonSchema
	}
	if !ed25519.Verify(ed25519.PublicKey(requesterPublicKey), []byte("tulpa/sign\n"+canonical), sig) {
		return false, DiscoveryQueryReasonSignature
	}

	// Confused-deputy defense: a query addressed to one directory must not be
	// relayed to another. The signed to must equal one of this directory's own
	// identifiers, compared exactly. An empty set is a verifier input error.
	if len(ctx.Audience) == 0 {
		return false, DiscoveryQueryReasonSchema
	}
	to, _ := obj["to"].(string)
	matched := false
	for _, audience := range ctx.Audience {
		if audience == "" {
			return false, DiscoveryQueryReasonSchema
		}
		if audience == to {
			matched = true
		}
	}
	if !matched {
		return false, DiscoveryQueryReasonAudience
	}

	// Freshness. The verifier clock must itself be a strict INK timestamp; a
	// caller that supplies a malformed clock fails closed as a verifier input
	// error. Both bounds are inclusive.
	timestamp, _ := obj["timestamp"].(string)
	sent, okSent := ParseInkTimestampMs(timestamp)
	now, okNow := ParseInkTimestampMs(ctx.Now)
	if !okSent || !okNow {
		return false, DiscoveryQueryReasonSchema
	}
	drift := sent - now
	if drift > MaxDiscoveryQuerySkewMs {
		return false, DiscoveryQueryReasonNotYetValid
	}
	if -drift > MaxDiscoveryQueryAgeMs {
		return false, DiscoveryQueryReasonExpired
	}

	// Replay: a (from, nonce) pair already seen at this directory is a replay.
	// The seen set is receiver state, not part of the envelope.
	from, _ := obj["from"].(string)
	nonce, _ := obj["nonce"].(string)
	key := DiscoveryQueryKey{From: from, Nonce: nonce}
	for _, seen := range ctx.SeenNonces {
		if seen == key {
			return false, DiscoveryQueryReasonReplay
		}
	}

	return true, ""
}

// validateDiscoveryQueryEnvelope validates the parsed envelope object against
// the discovery query schema and returns the signature string on success. It
// rejects a missing or extra member, a wrong-typed or out-of-bound field, an
// explicit null on any field (the reference schema accepts absent, not null),
// and an invalid timestamp. String bounds are counted in UTF-16 code units to
// match the reference (zod .min/.max on strings).
func validateDiscoveryQueryEnvelope(obj map[string]interface{}) (string, bool) {
	for k := range obj {
		if !discoveryQueryTopLevelKeys[k] {
			return "", false
		}
	}
	for k := range discoveryQueryTopLevelKeys {
		if _, present := obj[k]; !present {
			return "", false
		}
	}
	if protocol, ok := obj["protocol"].(string); !ok || protocol != "ink/0.1" {
		return "", false
	}
	if t, ok := obj["type"].(string); !ok || (t != "network.tulpa.discovery_query" && t != "network.ink.discovery_query") {
		return "", false
	}
	if !boundedString(obj["from"], 1, 512) || !boundedString(obj["to"], 1, 512) || !boundedString(obj["nonce"], 16, 256) {
		return "", false
	}
	ts, ok := obj["timestamp"].(string)
	if !ok {
		return "", false
	}
	if _, ok := ParseInkTimestampMs(ts); !ok {
		return "", false
	}
	if !validateDiscoveryQueryBody(obj["query"]) {
		return "", false
	}
	signature, ok := obj["signature"].(string)
	if !ok || signature == "" {
		return "", false
	}
	return signature, true
}

func validateDiscoveryQueryBody(v interface{}) bool {
	query, ok := v.(map[string]interface{})
	if !ok {
		return false
	}
	for k := range query {
		if !discoveryQueryInnerKeys[k] {
			return false
		}
	}
	if raw, present := query["tags"]; present {
		tags, ok := raw.([]interface{})
		if !ok || len(tags) < 1 || len(tags) > 32 {
			return false
		}
		for _, t := range tags {
			if !boundedString(t, 1, 64) {
				return false
			}
		}
	}
	if raw, present := query["scope"]; present {
		scope, ok := raw.(string)
		if !ok {
			return false
		}
		switch scope {
		case "public", "network_only", "capability_gated", "private":
		default:
			return false
		}
	}
	if raw, present := query["limit"]; present {
		limit, ok := raw.(float64)
		if !ok || limit != math.Trunc(limit) || limit < 1 || limit > 100 {
			return false
		}
	}
	return true
}

// boundedString reports whether v is a string whose UTF-16 code-unit length is
// within [min, max]. A non-string (including a JSON null decoded to nil) fails.
func boundedString(v interface{}, min, max int) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	n := utf16Len(s)
	return n >= min && n <= max
}
