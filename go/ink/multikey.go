package ink

import "time"

const maxCandidateKeys = 20

// CandidateKey is one key a signature may verify against, with its rotation
// status and optional validity window.
type CandidateKey struct {
	KeyID      string
	PublicKey  []byte
	Status     string // active | retired | revoked
	ValidFrom  string // optional ISO 8601
	ValidUntil string // optional ISO 8601
	RevokedAt  string // optional ISO 8601; if present at all, the key is skipped
}

// MultiKeyResult reports which key, if any, verified the signature.
type MultiKeyResult struct {
	Verified  bool
	KeyID     string
	KeyStatus string
}

// keyValidAtTime applies the validity window. A present revokedAt skips the key
// regardless of value; validFrom/validUntil must bracket the message time
// inclusively, and a present-but-unparseable bound fails closed. Presence here
// is "non-empty string"; the reference treats any value other than undefined as
// present, so an explicit empty-string field (which the vectors never set)
// would be the one place this could differ.
func keyValidAtTime(k CandidateKey, msgTime time.Time) bool {
	if k.RevokedAt != "" {
		return false
	}
	if k.ValidFrom != "" {
		vf, err := time.Parse(time.RFC3339Nano, k.ValidFrom)
		if err != nil || msgTime.Before(vf) {
			return false
		}
	}
	if k.ValidUntil != "" {
		vu, err := time.Parse(time.RFC3339Nano, k.ValidUntil)
		if err != nil || msgTime.After(vu) {
			return false
		}
	}
	return true
}

// VerifyInkSignatureWithKeys verifies a signature against a candidate key set
// under the rotation authority rule: a keyId hint is tried first if it names an
// in-window active or retired key, then active keys, then retired; revoked keys
// and keys outside their validity window are always skipped.
func VerifyInkSignatureWithKeys(in InkSignInput, signature string, keys []CandidateKey, hintKeyID string) MultiKeyResult {
	if len(keys) == 0 || !signatureRe.MatchString(signature) {
		return MultiKeyResult{}
	}
	if n := utf16Len(in.Timestamp); n == 0 || n > 64 {
		return MultiKeyResult{}
	}
	msgTime, err := time.Parse(time.RFC3339Nano, in.Timestamp)
	if err != nil {
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
			if keyValidAtTime(k, msgTime) && VerifyInkSignature(in, signature, k.PublicKey) {
				return MultiKeyResult{Verified: true, KeyID: k.KeyID, KeyStatus: k.Status}
			}
			break
		}
	}

	for _, status := range []string{"active", "retired"} {
		for _, k := range keys {
			if k.Status != status || !keyValidAtTime(k, msgTime) {
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
