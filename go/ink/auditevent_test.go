package ink

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func signAuditEvent(t *testing.T, priv ed25519.PrivateKey, event map[string]interface{}) string {
	t.Helper()
	filtered := map[string]interface{}{}
	for k, v := range event {
		if k != "agentSignature" {
			filtered[k] = v
		}
	}
	canonical, err := canonicalizeJSON(filtered)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, []byte("ink/audit-event\n"+canonical))
	return base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyAuditEventSignature(t *testing.T) {
	seed := sha256.Sum256([]byte("go-audit-event-test"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	event := map[string]interface{}{"id": "evt-1", "type": "connection_request", "seq": float64(3)}
	event["agentSignature"] = signAuditEvent(t, priv, event)

	if !VerifyAuditEventSignature(event, pub) {
		t.Error("valid agentSignature rejected")
	}

	// Tampering a signed field breaks it.
	tampered := map[string]interface{}{}
	for k, v := range event {
		tampered[k] = v
	}
	tampered["seq"] = float64(4)
	if VerifyAuditEventSignature(tampered, pub) {
		t.Error("tampered event accepted")
	}

	// Wrong key.
	otherSeed := sha256.Sum256([]byte("other"))
	otherPub := ed25519.NewKeyFromSeed(otherSeed[:]).Public().(ed25519.PublicKey)
	if VerifyAuditEventSignature(event, otherPub) {
		t.Error("wrong key accepted")
	}

	// Missing / malformed signature.
	noSig := map[string]interface{}{"id": "evt-1"}
	if VerifyAuditEventSignature(noSig, pub) {
		t.Error("missing agentSignature accepted")
	}
	badSig := map[string]interface{}{"id": "evt-1", "agentSignature": "AAAA"}
	if VerifyAuditEventSignature(badSig, pub) {
		t.Error("malformed agentSignature accepted")
	}
}
