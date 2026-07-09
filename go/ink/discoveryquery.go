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

// VerifyDiscoveryQueryEnvelope verifies a requester-signed discovery query
// envelope against the requester's public key. It mirrors the TypeScript
// verifyDiscoveryQueryEnvelope byte for byte: strict schema validation, then a
// body signature over "tulpa/sign\n" + JCS(envelope without the signature
// field), verified with RFC 8032 strict Ed25519 (small-order and non-canonical
// keys rejected, matching @noble/ed25519 zip215:false).
//
// The envelope is parsed once into a generic object, exactly as a JSON.parse
// based verifier sees it: duplicate members collapse to the last value and a
// JSON null is a present null (not an absent field). The same object is both
// validated and canonicalized, so the validated bytes and the signed bytes can
// never disagree.
func VerifyDiscoveryQueryEnvelope(raw []byte, requesterPublicKey []byte) bool {
	// The envelope is a signed artifact: encoding/json rewrites invalid UTF-8 or
	// a lone surrogate to U+FFFD, so a body that is not byte-identical to the
	// signed one could canonicalize to the signed bytes. Reject both up front.
	if !utf8.Valid(raw) || ContainsLoneSurrogateEscape(raw) {
		return false
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false
	}
	signature, ok := validateDiscoveryQueryEnvelope(obj)
	if !ok {
		return false
	}
	// Ed25519 body signatures are 86 base64url characters, no padding.
	if !signatureRe.MatchString(signature) {
		return false
	}
	if len(requesterPublicKey) != ed25519.PublicKeySize || !isStrongEd25519PublicKey(requesterPublicKey) {
		return false
	}
	unsigned := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		if k != "signature" {
			unsigned[k] = v
		}
	}
	canonical, err := canonicalizeJSON(unsigned)
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(requesterPublicKey), []byte("tulpa/sign\n"+canonical), sig)
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
