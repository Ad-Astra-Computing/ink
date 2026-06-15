package ink

import "encoding/json"

const maxCandidateKeys = 20

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

// VerifyInkSignatureWithKeys verifies a signature against a candidate key set
// under the rotation authority rule: a keyId hint is tried first if it names an
// in-window active or retired key, then active keys, then retired; revoked keys
// and keys outside their validity window are always skipped.
func VerifyInkSignatureWithKeys(in InkSignInput, signature string, keys []CandidateKey, hintKeyID string) MultiKeyResult {
	if len(keys) == 0 || !signatureRe.MatchString(signature) {
		return MultiKeyResult{}
	}
	msgMs, ok := ParseInkTimestampMs(in.Timestamp)
	if !ok {
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
			if keyValidAtTime(k, msgMs) && VerifyInkSignature(in, signature, k.PublicKey) {
				return MultiKeyResult{Verified: true, KeyID: k.KeyID, KeyStatus: k.Status}
			}
			break
		}
	}

	for _, status := range []string{"active", "retired"} {
		for _, k := range keys {
			if k.Status != status || !keyValidAtTime(k, msgMs) {
				continue
			}
			if hintKeyID != "" && k.KeyID == hintKeyID {
				continue
			}
			if VerifyInkSignature(in, signature, k.PublicKey) {
				return MultiKeyResult{Verified: true, KeyID: k.KeyID, KeyStatus: k.Status}
			}
		}
	}
	return MultiKeyResult{}
}
