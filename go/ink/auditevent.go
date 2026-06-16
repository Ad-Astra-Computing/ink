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
	sig, ok := event["agentSignature"].(string)
	if !ok || !signatureRe.MatchString(sig) {
		return false
	}
	filtered := make(map[string]interface{}, len(event))
	for k, v := range event {
		if k == "agentSignature" {
			continue
		}
		filtered[k] = v
	}
	if !isWithinCanonicalizeBounds(filtered) {
		return false
	}
	canonical, err := canonicalizeJSON(filtered)
	if err != nil {
		return false
	}
	prefixed := "ink/audit-event\n" + canonical
	if len(prefixed) > maxCanonicalBodyBytes {
		return false
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	if len(publicKey) != ed25519.PublicKeySize || !isStrongEd25519PublicKey(publicKey) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), []byte(prefixed), sigBytes)
}
