package ink

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

// keyValidAtTime applies the validity window, all timestamps parsed with the
// strict RFC 3339 / millisecond grammar shared across implementations. A
// non-empty revokedAt skips the key; validFrom/validUntil must bracket the
// message time inclusively, and a present-but-malformed or lenient bound fails
// closed. (The empty-string vs absent revokedAt distinction is tracked
// separately; this window check only parses the bound timestamps.)
func keyValidAtTime(k CandidateKey, msgMs int64) bool {
	if k.RevokedAt != "" {
		return false
	}
	if k.ValidFrom != "" {
		vf, ok := ParseInkTimestampMs(k.ValidFrom)
		if !ok || msgMs < vf {
			return false
		}
	}
	if k.ValidUntil != "" {
		vu, ok := ParseInkTimestampMs(k.ValidUntil)
		if !ok || msgMs > vu {
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
