package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"unicode/utf8"
)

// The producing half of the INK body signature (Protocol §3.6): the `signature`
// member an intent envelope, a receipt or any other signed INK object carries in
// its own body, as distinct from the §3.3 transport signature that SignInkMessage
// and SignInkRequest mint over a request. Both halves already existed on the
// verify side of the artifact-specific paths (authorization grants, chains,
// challenges, discovery queries all check a body signature); this is the generic
// producer, the counterpart of signMessage in src/crypto/sign.ts.
//
// Without it a Go sender could not assemble a schema-valid envelope without
// reimplementing RFC 8785 canonicalization, which is a wire-contract hazard: a
// second implementation reaching the same bytes by its own code is the whole
// point of the corpus, but each sender rolling its own canonicalizer is how
// implementations silently diverge.

// Body-signature domain separators, keyed off the message's signed `protocol`
// member. Only the exact string "ink/0.2" selects the neutral domain; every other
// value, including a missing `protocol`, keeps the legacy one, so every signature
// ever produced still verifies. Because `protocol` is inside the signed bytes,
// relabelling a message after signing selects a different domain at the verifier
// and fails. Mirrors bodySignatureDomain in src/crypto/sign.ts.
const (
	legacyBodySignDomain = "tulpa/sign\n"
	v02BodySignDomain    = "ink/sign\n"
)

func bodySignatureDomain(unsigned map[string]any) string {
	if p, ok := unsigned["protocol"].(string); ok && p == "ink/0.2" {
		return v02BodySignDomain
	}
	return legacyBodySignDomain
}

// JCSCanonicalize returns the RFC 8785 (JCS) canonical serialization of a JSON
// value: object members sorted by UTF-16 code unit, no insignificant whitespace,
// minimal string escaping, and numbers under INK's safe-integer profile. It is
// the exported seam a sender needs to build signed bytes, mirroring the
// reference's exported jcsCanonicalize (src/crypto/ink.ts).
//
// It applies the same three guards the reference applies, so both
// implementations refuse the same inputs before spending the recursive
// sort-and-serialize:
//
//   - the node, depth and character budgets of withinBodyBounds, which also
//     rejects a number outside the safe-integer profile and any in-memory Go
//     value that is not a JSON value;
//   - portable strings: every member name and string value must be valid UTF-8.
//     This is the Go analogue of the reference's unpaired-surrogate reject, since
//     a lone surrogate survives in a JavaScript string but reaches Go only as
//     invalid UTF-8, and either would canonicalize to bytes the other side does
//     not reproduce;
//   - a cap on the canonical output, measured in UTF-16 code units to match the
//     reference's String.length check.
//
// Accepted values are the JSON value set (nil, bool, string, float64, []any,
// map[string]any) plus native Go integer types within the safe-integer range,
// which canonicalize identically to their float64 form.
func JCSCanonicalize(v any) (string, error) {
	if !withinBodyBounds(v) {
		return "", errors.New("ink: input exceeds maximum allowed complexity")
	}
	if !hasPortableStrings(v) {
		return "", errors.New("ink: input contains a non-portable string")
	}
	// The escaped-member-name rule is enforced inside canonicalizeJSON's key
	// loop, so it covers this and every other canonicalization path rather than
	// only the ones that remember to ask.
	canonical, err := canonicalizeJSON(v)
	if err != nil {
		return "", err
	}
	if utf16Len(canonical) > maxCanonicalBodyBytes {
		return "", errors.New("ink: canonical output exceeds maximum allowed size")
	}
	return canonical, nil
}

// SignInkBody signs an INK object's own body and returns the base64url
// (unpadded) Ed25519 signature to attach as its `signature` member: exactly 86
// characters [A-Za-z0-9_-]. It is the producing counterpart of the body-signature
// checks the artifact verifiers run, and a byte-faithful port of signMessage in
// src/crypto/sign.ts:
//
//  1. drop any existing `signature` member (the caller's map is not mutated);
//  2. canonicalize the rest with JCSCanonicalize;
//  3. sign the UTF-8 bytes of the version-keyed domain prefix followed by the
//     canonical form.
//
// It errors on a private key of the wrong size, a nil body, or any input
// JCSCanonicalize refuses, so the signer cannot mint a signature over bytes the
// reference producer would not have emitted.
//
// This is the low-level primitive: it signs the exact body it is given and does
// no schema validation, exactly as the reference does. A caller assembling an
// intent envelope is responsible for the envelope shape; the schema layer, not
// this function, decides which `protocol` values are in spec.
func SignInkBody(body map[string]any, privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("ink: private key must be an ed25519 private key")
	}
	if body == nil {
		return "", errors.New("ink: body must be a non-nil object")
	}
	unsigned := make(map[string]any, len(body))
	for k, v := range body {
		if k == "signature" {
			continue
		}
		unsigned[k] = v
	}
	canonical, err := JCSCanonicalize(unsigned)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(privateKey, []byte(bodySignatureDomain(unsigned)+canonical))
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// There is deliberately no exported VerifyInkBody, and this note records the one
// condition that changes that, so the omission stays a decision rather than an
// oversight.
//
// The asymmetry today: this package exports the generic producer but no generic
// verifier. Every body signature it checks belongs to a specific artifact, and
// each of those verifiers (authorizationgrant.go, authorizationchain.go,
// authorizationchallenge.go, discoveryquery.go) inlines the legacy domain
// literal against its own already-schema-validated body, because the artifact,
// not a generic helper, is what decides which key is authoritative and which
// members are stripped before canonicalization. bodySignatureDomain is
// unexported with them, so an outside consumer cannot assemble a generic
// verifier out of exported pieces either: it would have to re-derive the
// version-keyed domain rule, which is exactly the silent-divergence hazard
// SignInkBody exists to remove on the producing side.
//
// That is tolerable only while no Go component consumes generic envelopes. The
// Go surfaces that exist are producers (senders, the interop-lab driver) and
// artifact verifiers, and the generic envelopes this project verifies are
// verified by the TypeScript reference, which exports both halves.
//
// The trigger: the first Go receiver of generic INK envelopes, meaning any
// component that must check the `signature` member of a body whose shape this
// package has no artifact verifier for. A witness inbox, an inbound-message
// server or a third-party receiver built on this library all qualify. At that
// point export VerifyInkBody as the mirror of SignInkBody, taking a parsed body
// and a public key, stripping `signature`, canonicalizing with JCSCanonicalize
// and verifying under bodySignatureDomain of the unsigned body, with the strict
// Ed25519 public-key check the rest of this package applies; then move the four
// artifact verifiers onto it so one implementation of the domain rule serves
// every caller. Adding it before then would ship an exported surface with no
// in-tree caller and no vector pinning its rejection edges, which is how an
// exported function drifts away from the one everything else uses.

// hasPortableStrings reports whether every member name and string value in a
// decoded or in-memory JSON value is valid UTF-8. Invalid UTF-8 would be rewritten
// to U+FFFD by encoding/json and canonicalize to bytes another implementation
// does not reproduce, so it is refused before any signing work. Non-string values
// are not inspected here; withinBodyBounds already rejects any type that is not a
// JSON value. The depth is bounded by the caller's bounds walk.
func hasPortableStrings(v any) bool {
	switch x := v.(type) {
	case string:
		return utf8.ValidString(x)
	case []any:
		for _, e := range x {
			if !hasPortableStrings(e) {
				return false
			}
		}
		return true
	case map[string]any:
		for k, val := range x {
			if !utf8.ValidString(k) || !hasPortableStrings(val) {
				return false
			}
		}
		return true
	default:
		return true
	}
}
