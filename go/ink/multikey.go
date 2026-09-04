package ink

import (
	"crypto/ed25519"
	"encoding/json"
)

const maxCandidateKeys = 20

// maxTimestampTokenBytes caps the raw JSON token an OptionalTimestamp will decode.
// The well-formed check (windowBoundMs -> ParseInkTimestampMs) bounds a bound's
// decoded length only by maxTimestampLength (64 characters); the strict RFC 3339
// grammar admits unbounded fractional digits, so the longest string it can accept
// is 64 characters (for example a full date-time with an offset and 38 fractional
// digits). A JSON string may write each of those characters as a six-byte \uXXXX
// escape, so the worst-case raw token for a still-valid timestamp is 64*6 + 2
// quotes = 386 bytes. 512 sits above that worst case, so this cap rejects only
// tokens that cannot decode to any valid RFC 3339 bound; a rejected token is
// recorded as present but not well-formed, which fails closed under the window
// rule without decoding the oversized string.
const maxTimestampTokenBytes = 512

// OptionalTimestamp is a key-window field (validFrom, validUntil, revokedAt)
// that distinguishes absent from present. Presence is semantic: a present field
// constrains the key even when its value is empty, null, or not a string. The
// zero value is the absent field; a programmatic caller sets a value with
// Timestamp.
//
// Because encoding/json does not call UnmarshalJSON for an absent field, an
// OptionalTimestamp cannot clear stale presence on a reused destination. Decode
// each key entry into a fresh value (the normal pattern) so an absent field is
// read as absent rather than carrying over a previous decode.
type OptionalTimestamp struct {
	// Present is true when the field appeared in the key entry at all.
	Present bool
	// Value is the string value, meaningful only when WellFormed.
	Value string
	// WellFormed is true when the present field was a JSON string (not null,
	// a number, an object, or any other non-string).
	WellFormed bool
}

// Timestamp builds a present, well-formed window value for a programmatic
// caller. An unset (absent) field is the zero OptionalTimestamp.
func Timestamp(value string) OptionalTimestamp {
	return OptionalTimestamp{Present: true, Value: value, WellFormed: true}
}

// UnmarshalJSON records presence and well-formedness. A field that does not
// appear leaves the zero value (absent); a present null or non-string is
// present-but-not-well-formed, which fails closed under the window rule. The
// error is swallowed so a malformed window value does not fail the whole parse;
// the verifier treats it as an unusable key.
func (o *OptionalTimestamp) UnmarshalJSON(b []byte) error {
	// Reset fully: encoding/json reuses the destination when decoding into an
	// existing slice element or pointer, so stale Value/WellFormed from a
	// previous decode must not survive a later null or non-string.
	*o = OptionalTimestamp{Present: true}
	if string(b) == "null" {
		return nil
	}
	// A token past the cap cannot be a valid short RFC 3339 timestamp; leave it
	// present but not well-formed rather than decode an oversized string.
	if len(b) > maxTimestampTokenBytes {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return nil
	}
	o.Value = s
	o.WellFormed = true
	return nil
}

// CandidateKey is one key a signature may verify against, with its rotation
// status and optional validity window.
type CandidateKey struct {
	KeyID      string
	PublicKey  []byte
	Status     string            // active | retired | revoked
	ValidFrom  OptionalTimestamp // optional window lower bound
	ValidUntil OptionalTimestamp // optional window upper bound
	RevokedAt  OptionalTimestamp // if present at all, the key is unusable
}

// MultiKeyResult reports which key, if any, verified the signature.
type MultiKeyResult struct {
	Verified  bool
	KeyID     string
	KeyStatus string
}

// keyValidAtTime applies the validity window. Presence is semantic: a present
// revokedAt of any value marks the key unusable; a present validFrom/validUntil
// that is not a strict RFC 3339 timestamp (empty, null, non-string, or lenient)
// fails closed. An absent field is unconstrained. The bound timestamps use the
// strict grammar shared across implementations.
func keyValidAtTime(k CandidateKey, msgMs int64) bool {
	if k.RevokedAt.Present {
		return false
	}
	if k.ValidFrom.Present {
		vf, ok := windowBoundMs(k.ValidFrom)
		if !ok || msgMs < vf {
			return false
		}
	}
	if k.ValidUntil.Present {
		vu, ok := windowBoundMs(k.ValidUntil)
		if !ok || msgMs > vu {
			return false
		}
	}
	return true
}

// windowBoundMs returns the bound in milliseconds, or false when the present
// field is not a well-formed strict RFC 3339 timestamp.
func windowBoundMs(o OptionalTimestamp) (int64, bool) {
	if !o.WellFormed {
		return 0, false
	}
	return ParseInkTimestampMs(o.Value)
}

// VerifyDetachedSignatureWithKeys verifies a detached artifact signature
// against a candidate key set under the rotation authority rule: a keyId
// hint is tried first if it names an in-window active or retired key, then
// active keys, then retired; revoked keys and keys outside their validity
// window are always skipped. This is the artifact-agnostic policy primitive
// behind every per-artifact WithKeys verifier in this package: verifyWithKey
// closes over the specific artifact and signature and answers only "does
// this raw public key verify it". VerifyInkSignatureWithKeys and every
// per-artifact WithKeys verifier delegate here so the ordering/window policy
// lives in exactly one place.
func VerifyDetachedSignatureWithKeys(verifyWithKey func(pub []byte) bool, keys []CandidateKey, artifactMs int64, hintKeyID string) MultiKeyResult {
	if len(keys) == 0 {
		return MultiKeyResult{}
	}
	if len(keys) > maxCandidateKeys {
		keys = keys[:maxCandidateKeys]
	}

	if hintKeyID != "" {
		for _, k := range keys {
			if k.KeyID != hintKeyID || (k.Status != "active" && k.Status != "retired") {
				continue
			}
			if keyValidAtTime(k, artifactMs) && verifyWithKey(k.PublicKey) {
				return MultiKeyResult{Verified: true, KeyID: k.KeyID, KeyStatus: k.Status}
			}
			break
		}
	}

	for _, status := range []string{"active", "retired"} {
		for _, k := range keys {
			if k.Status != status || !keyValidAtTime(k, artifactMs) {
				continue
			}
			if hintKeyID != "" && k.KeyID == hintKeyID {
				continue
			}
			if verifyWithKey(k.PublicKey) {
				return MultiKeyResult{Verified: true, KeyID: k.KeyID, KeyStatus: k.Status}
			}
		}
	}
	return MultiKeyResult{}
}

// signerStrategy decides which key or keys an artifact verifier core tries
// once it has assembled the signed bytes and decoded the signature. The
// single-key verifiers and their WithKeys siblings share one core per
// artifact and differ only in the strategy, so the structural checks cannot
// drift between the two paths.
type signerStrategy struct {
	// needsClock is true for the rotation-aware strategy, which cannot judge
	// a key's validity window without the artifact's own clock and must fail
	// closed when the artifact carries none.
	needsClock bool
	// keyOK reports whether the fixed key is usable at all. The single-key
	// verifiers check this before the signature stage; the rotation-aware
	// strategy checks each candidate as it is tried and always reports true.
	keyOK func() bool
	// verify runs the signature check. verifyWithKey checks the signature
	// under one raw public key; artifactMs is the artifact clock, meaningful
	// only when the core established one.
	verify func(verifyWithKey func(pub []byte) bool, artifactMs int64) MultiKeyResult
}

func strongEd25519Key(pub []byte) bool {
	return len(pub) == ed25519.PublicKeySize && isStrongEd25519PublicKey(pub)
}

// fixedKey is the single-key strategy: one caller-supplied public key, no
// rotation policy, no key attribution in the result.
func fixedKey(pub []byte) signerStrategy {
	return signerStrategy{
		keyOK: func() bool { return strongEd25519Key(pub) },
		verify: func(verifyWithKey func([]byte) bool, _ int64) MultiKeyResult {
			if !strongEd25519Key(pub) {
				return MultiKeyResult{}
			}
			return MultiKeyResult{Verified: verifyWithKey(pub)}
		},
	}
}

// candidateKeys is the rotation-aware strategy over
// VerifyDetachedSignatureWithKeys.
func candidateKeys(keys []CandidateKey, hintKeyID string) signerStrategy {
	return signerStrategy{
		needsClock: true,
		keyOK:      func() bool { return true },
		verify: func(verifyWithKey func([]byte) bool, artifactMs int64) MultiKeyResult {
			return VerifyDetachedSignatureWithKeys(
				func(pub []byte) bool { return strongEd25519Key(pub) && verifyWithKey(pub) },
				keys,
				artifactMs,
				hintKeyID,
			)
		},
	}
}

// VerifyInkSignatureWithKeys verifies a signature against a candidate key set
// under the rotation authority rule: a keyId hint is tried first if it names an
// in-window active or retired key, then active keys, then retired; revoked keys
// and keys outside their validity window are always skipped. Thin wrapper over
// VerifyDetachedSignatureWithKeys: parses in.Timestamp into the artifact clock
// and closes over VerifyInkSignature for the cryptographic check.
func VerifyInkSignatureWithKeys(in InkSignInput, signature string, keys []CandidateKey, hintKeyID string) MultiKeyResult {
	if !signatureRe.MatchString(signature) {
		return MultiKeyResult{}
	}
	msgMs, ok := ParseInkTimestampMs(in.Timestamp)
	if !ok {
		return MultiKeyResult{}
	}
	return VerifyDetachedSignatureWithKeys(
		func(pub []byte) bool { return VerifyInkSignature(in, signature, pub) },
		keys,
		msgMs,
		hintKeyID,
	)
}

// LiveAuthResult reports a live transport authentication decision, with the
// protocol error code on a rejection.
type LiveAuthResult struct {
	Verified  bool
	KeyID     string
	KeyStatus string
	Error     string
}

// VerifyInkSignatureForLiveAuth applies the retired-key default of Protocol
// §3.3 on top of the multi-key primitive. The primitive answers a HISTORICAL
// question: which entry in the published key set signed this artifact, with a
// retired entry inside its validity window still counting. Live transport
// authentication asks a narrower question, whether the entry that verified may
// authenticate a request arriving NOW, and a retired entry is by construction a
// key the identity has already replaced.
//
// A signature that only a retired entry verified is therefore rejected with
// retired_key_for_live_auth unless the receiver has explicitly opted into a
// bounded rotation grace window via allowRetiredKey. A receiver that opts in
// MUST bound the window; an unbounded one restores every retired key as a live
// credential for the life of the identity, which is what the default prevents.
// This mirrors the requireActiveKey gate inside verifyInkAuth in the TypeScript
// reference (src/middleware/ink-auth.ts), and is pinned by the liveAuth cases
// of the key-rotation conformance category.
//
// A rejection carries no key attribution, so a caller cannot log a key as
// having authenticated a request it did not.
func VerifyInkSignatureForLiveAuth(in InkSignInput, signature string, keys []CandidateKey, hintKeyID string, allowRetiredKey bool) LiveAuthResult {
	r := VerifyInkSignatureWithKeys(in, signature, keys, hintKeyID)
	if !r.Verified {
		return LiveAuthResult{Error: "signature_verification_failed"}
	}
	if !allowRetiredKey && r.KeyStatus == "retired" {
		return LiveAuthResult{Error: "retired_key_for_live_auth"}
	}
	return LiveAuthResult{Verified: true, KeyID: r.KeyID, KeyStatus: r.KeyStatus}
}
