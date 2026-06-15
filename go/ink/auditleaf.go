package ink

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
)

// Pre-canonicalize bounds mirror the reference (src/crypto/ink.ts). They are
// well above any realistic INK audit event but bail fast on an adversarial one,
// and, just as important, they draw the SAME accept/reject line in both
// implementations: without them a Go witness could commit a Merkle leaf for an
// oversized or deeply nested event that the reference refuses to hash, a
// consensus split. The char counter is in UTF-16 code units to match the
// reference's String.length, and the canonical byte cap is checked after
// canonicalization on the UTF-8 output, exactly as the reference does.
const (
	maxPrecheckNodes      = 10000
	maxPrecheckDepth      = 32
	maxPrecheckChars      = 1200000
	maxCanonicalBodyBytes = 1048576
)

// isWithinCanonicalizeBounds is a cheap depth, node, and char walk run before
// canonicalization. It returns false for a value that exceeds the bounds rather
// than letting the recursive canonicalizer do its sort and serialize on it
// first. It is non-throwing; the caller decides what false means. A number that
// is not a JCS-safe integer is rejected here too, matching the reference, so the
// walk bails before canonicalizeNumber would on the same value.
func isWithinCanonicalizeBounds(value interface{}) bool {
	nodes := 0
	chars := 0
	var walk func(v interface{}, depth int) bool
	walk = func(v interface{}, depth int) bool {
		if depth > maxPrecheckDepth {
			return false
		}
		nodes++
		if nodes > maxPrecheckNodes {
			return false
		}
		switch x := v.(type) {
		case map[string]interface{}:
			for k, val := range x {
				nodes++
				if nodes > maxPrecheckNodes {
					return false
				}
				chars += utf16Len(k)
				if chars > maxPrecheckChars {
					return false
				}
				if !walk(val, depth+1) {
					return false
				}
			}
			return true
		case []interface{}:
			for _, item := range x {
				if !walk(item, depth+1) {
					return false
				}
			}
			return true
		case string:
			chars += utf16Len(x)
			return chars <= maxPrecheckChars
		case float64:
			return !(math.IsInf(x, 0) || math.IsNaN(x) ||
				x != math.Trunc(x) ||
				math.Abs(x) > maxSafeInteger ||
				(x == 0 && math.Signbit(x)))
		default:
			return true
		}
	}
	return walk(value, 0)
}

// ComputeAuditMerkleLeafHash computes the RFC 6962 Merkle leaf hash for an INK
// audit event:
//
//	SHA-256(0x00 || JCS(event-without-agentSignature))
//
// returned as lowercase hex. This is the value a witness commits to its
// transparency log (INK Auditability §7.3) and the value an inclusion proof
// walks up from. It strips agentSignature before canonicalizing, so the leaf a
// witness logs does not change when the agent signature is attached, and it
// carries the 0x00 leaf-domain prefix that separates a leaf from an internal
// node, which is hashed SHA-256(0x01 || left || right).
//
// The event must be a JSON object within the canonicalization bounds whose
// values satisfy INK's signed-body profile; a value that cannot be canonicalized
// (an unsafe-integer number) or that exceeds the depth, node, or size bounds
// makes ok false rather than producing divergent bytes or burning CPU. ok is
// also false for any input that is not a JSON object. A receiver MUST parse the
// raw body through ParseSignedBody first, so a lone UTF-16 surrogate is rejected
// before it reaches this function; ComputeAuditMerkleLeafHash takes the parsed
// value and cannot recover a surrogate that decoding has already dropped.
func ComputeAuditMerkleLeafHash(event interface{}) (string, bool) {
	obj, ok := event.(map[string]interface{})
	if !ok {
		return "", false
	}
	filtered := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		if k == "agentSignature" {
			continue
		}
		filtered[k] = v
	}
	if !isWithinCanonicalizeBounds(filtered) {
		return "", false
	}
	canonical, err := canonicalizeJSON(filtered)
	if err != nil {
		return "", false
	}
	if len(canonical) > maxCanonicalBodyBytes {
		return "", false
	}
	prefixed := make([]byte, 0, len(canonical)+1)
	prefixed = append(prefixed, 0x00)
	prefixed = append(prefixed, canonical...)
	sum := sha256.Sum256(prefixed)
	return hex.EncodeToString(sum[:]), true
}
