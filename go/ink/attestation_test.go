package ink

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// VerifyAttestation has its own ed25519.Verify call site, so this pins that
// it too rejects a small-order issuer key at the shared signerStrategy gate
// (keyOK / verify -> strongEd25519Key), not just the base VerifyInkSignature.
func TestVerifyAttestationRejectsSmallOrderIssuerKey(t *testing.T) {
	identity := make([]byte, 32)
	identity[0] = 0x01
	basepoint, _ := hex.DecodeString("5866666666666666666666666666666666666666666666666666666666666666")
	scalarOne := make([]byte, 32)
	scalarOne[0] = 0x01
	forgedSig := make([]byte, 0, 64)
	forgedSig = append(forgedSig, basepoint...)
	forgedSig = append(forgedSig, scalarOne...)
	sigB64 := base64.RawURLEncoding.EncodeToString(forgedSig)

	attestation := map[string]interface{}{
		"protocol":      "ink/0.1",
		"type":          "network.ink.attestation",
		"issuer":        "ink:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX",
		"subject":       "did:web:subject.example",
		"claimType":     "example.owner.verified_human",
		"claim":         map[string]interface{}{"method": "in_person"},
		"attestationId": "conformance-att-000000001",
		"issuedAt":      "2026-08-01T00:00:00.000Z",
		"expiresAt":     "2027-08-01T00:00:00.000Z",
		"signature":     sigB64,
	}
	raw, err := json.Marshal(attestation)
	if err != nil {
		t.Fatalf("marshal attestation: %v", err)
	}

	if ok, reason := VerifyAttestation(raw, identity, "2026-09-01T00:00:00.000Z"); ok || reason != AttestationReasonSignature {
		t.Errorf("VerifyAttestation accepted a small-order-A (identity) universal forgery: ok=%v reason=%s", ok, reason)
	}

	keys := []CandidateKey{{PublicKey: identity, Status: "active"}}
	if r := VerifyAttestationWithKeys(raw, keys, "2026-09-01T00:00:00.000Z", ""); r.OK {
		t.Errorf("VerifyAttestationWithKeys accepted a small-order-A (identity) universal forgery")
	}
}
