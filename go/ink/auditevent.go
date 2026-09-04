package ink

import (
	"crypto/ed25519"
	"encoding/base64"
)

// VerifyAuditEventSignature verifies an audit event's agentSignature: a
// base64url Ed25519 signature over "ink/audit-event\n" + JCS(event without its
// agentSignature). It returns false (never panics) for a malformed signature, an
// out-of-bounds event, or a weak key. This is the per-event provenance check a
// witness response verifier runs on every event, because Merkle inclusion alone
// does not prove an agent produced the event (INK Auditability §7.5).
func VerifyAuditEventSignature(event map[string]interface{}, publicKey []byte) bool {
	return verifyAuditEventSignatureWith(event, fixedKey(publicKey)).Verified
}

// VerifyAuditEventSignatureWithKeys verifies an audit event's agentSignature
// against a rotation-aware candidate key set (spec §6.2/§12.1: historical
// audit events verify against a retired key still inside its validity
// window; a revoked key never verifies, even for events predating its
// revocation).
//
// The artifact clock is the event's own "timestamp" field, parsed with the
// shared strict RFC 3339 grammar; a missing, non-string, or unparseable
// timestamp fails closed. When hintKeyID is empty, the event's own
// "signingKeyId" (when present and a string) is used as the hint.
func VerifyAuditEventSignatureWithKeys(event map[string]interface{}, keys []CandidateKey, hintKeyID string) MultiKeyResult {
	if hintKeyID == "" {
		if sk, ok := event["signingKeyId"].(string); ok {
			hintKeyID = sk
		}
	}
	return verifyAuditEventSignatureWith(event, candidateKeys(keys, hintKeyID))
}

func verifyAuditEventSignatureWith(event map[string]interface{}, s signerStrategy) MultiKeyResult {
	sig, ok := event["agentSignature"].(string)
	if !ok || !signatureRe.MatchString(sig) {
		return MultiKeyResult{}
	}
	var artifactMs int64
	if s.needsClock {
		ts, ok := event["timestamp"].(string)
		if !ok {
			return MultiKeyResult{}
		}
		artifactMs, ok = ParseInkTimestampMs(ts)
		if !ok {
			return MultiKeyResult{}
		}
	}
	filtered := make(map[string]interface{}, len(event))
	for k, v := range event {
		if k == "agentSignature" {
			continue
		}
		filtered[k] = v
	}
	if !isWithinCanonicalizeBounds(filtered) {
		return MultiKeyResult{}
	}
	canonical, err := canonicalizeJSON(filtered)
	if err != nil {
		return MultiKeyResult{}
	}
	prefixed := "ink/audit-event\n" + canonical
	if len(prefixed) > maxCanonicalBodyBytes {
		return MultiKeyResult{}
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return MultiKeyResult{}
	}
	return s.verify(func(pub []byte) bool {
		return ed25519.Verify(ed25519.PublicKey(pub), []byte(prefixed), sigBytes)
	}, artifactMs)
}
