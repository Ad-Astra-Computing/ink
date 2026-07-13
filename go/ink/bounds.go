package ink

import "math"

// Pre-parse and post-parse complexity bounds for signed bodies, mirroring the
// reference isWithinBounds walk in src/crypto/sign.ts. The reference bails before
// the recursive sort-and-serialize inside canonicalize, so an attacker who sends
// a structurally valid but pathological body cannot burn CPU or memory in the
// verify path. Go's json.Unmarshal reads the whole body into a generic map with
// no such cap, so a Go verifier that unmarshals raw bytes with no ceiling would
// accept inputs the reference rejects, which breaks the "both implementations
// reject the same inputs" contract.
//
// The bounds are two layers. MaxGrantBodyBytes is a byte-length cap applied to
// the raw bytes before json.Unmarshal runs at all, so an oversized blob is never
// handed to the decoder. maxGrantNodes/maxGrantDepth/maxGrantChars are a walk over
// the decoded value that mirrors the reference node, depth, and character budgets.
//
// The gap is shared: discoveryquery.go, receipt.go, agentcardfetch.go,
// encryption.go, and multikey.go also json.Unmarshal a body with no structural
// cap, so this helper is written to be reusable across them. This change wires it
// only into the authorization-grant path; extending the other verifiers is left
// as a follow-up so each carries its own byte-cap constant and test.
const (
	// The node, depth, and character caps are the reference values from
	// src/crypto/sign.ts, kept in sync so a peer cannot pick the softer path.
	maxGrantNodes = 10000
	maxGrantDepth = 32
	maxGrantChars = 1200000
)

// MaxGrantBodyBytes is the byte-length ceiling on a raw grant body before it is
// parsed. It pins the spec's Byte bound rule: a grant presented as raw bytes must
// be rejected as schema when longer than 65536 bytes, before decoding. This Go
// API receives bytes, so VerifyAuthorizationGrant enforces the bound itself; the
// reference verifier takes an already-decoded object and instead applies the
// structural bounds, so the TypeScript counterpart MAX_GRANT_BODY_BYTES is the
// contract for whatever layer received its bytes. The two constants are kept in
// step so parity is recorded.
//
// The value is derived from the schema bounds rather than the generic character
// budget: a grant carries eleven members whose maximum sizes are pinned by the
// schema (issuer, subject, and audience at 512 UTF-16 code units each, a grantId
// at 256, a scope array of up to 64 entries of up to 128 code units, an 86-char
// signature, two timestamps, a protocol and a type literal, and a boolean). The
// largest a well-formed grant can be is on the order of 12 KiB of UTF-8; a code
// unit can encode to at most three UTF-8 bytes for a body member, and JSON
// structural overhead (quotes, commas, member names) is a small constant on top.
// Rounding that worst case up to a flat 64 KiB leaves generous headroom for a
// valid grant while rejecting a blob orders of magnitude past anything the schema
// admits, before the decoder ever touches it. The cap is deliberately far below
// the reference character budget because the grant schema is far smaller than a
// general INK message.
const MaxGrantBodyBytes = 64 * 1024

// withinGrantBounds walks a decoded JSON value and reports whether it stays
// within the node, depth, and character budgets. It mirrors isWithinBounds in
// src/crypto/sign.ts: every object and array member is a node, a member name
// counts toward both the node and character budgets, and a string value counts
// its length in UTF-16 code units toward the character budget. A value that
// exceeds any budget returns false, so the caller rejects it as schema before any
// signature or canonicalization work.
func withinGrantBounds(v interface{}) bool {
	nodes := 0
	chars := 0
	var walk func(v interface{}, depth int) bool
	walk = func(v interface{}, depth int) bool {
		if depth > maxGrantDepth {
			return false
		}
		nodes++
		if nodes > maxGrantNodes {
			return false
		}
		switch x := v.(type) {
		case map[string]interface{}:
			for key, val := range x {
				nodes++
				if nodes > maxGrantNodes {
					return false
				}
				chars += utf16Len(key)
				if chars > maxGrantChars {
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
			return chars <= maxGrantChars
		case float64:
			// Number parity with the reference isWithinBounds in src/crypto/sign.ts,
			// which rejects a number that is not JCS-safe during the walk. A number is
			// JCS-safe only if it is a safe integer that is not negative zero
			// (Number.isSafeInteger(n) && !Object.is(n, -0)): every conforming
			// canonicalizer then serializes it to identical bytes. So reject a
			// non-finite value, a value with a fractional part, a magnitude past the
			// safe-integer range, and negative zero (which would serialize as 0 and
			// lose its sign). Enforcing it here, not only later at canonicalization,
			// keeps the bounds walk rejecting the same inputs the reference does.
			return !(math.IsInf(x, 0) || math.IsNaN(x) ||
				x != math.Trunc(x) ||
				math.Abs(x) > maxSafeInteger ||
				(x == 0 && math.Signbit(x)))
		default:
			// Booleans and null carry no character budget of their own, matching the
			// reference, which counts only string lengths and member names.
			return true
		}
	}
	return walk(v, 0)
}
