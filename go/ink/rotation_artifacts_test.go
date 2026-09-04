package ink

// Rotation-aware non-transport artifact verification (spec §6.2/§6.3/§12).
//
// Mirrors test/rotation-aware-artifacts.test.ts: every artifact verifier
// historically took a single raw Ed25519 key, so a retired key inside its
// validity window could not verify historical artifacts, and a revoked key
// could not be reliably excluded. These tests pin the rotation-aware
// "...WithKeys" siblings across every Go non-transport artifact verifier that
// has one: audit events, inclusion receipts, checkpoints, and attestations.
//
// Go/TS parity gap: the TS suite also covers verifyReceiptWithKeys, the
// rotation-aware form of src/ink/receipts.ts's message-disposition receipt
// (network.tulpa.receipt, verified via signMessage/verifyMessage over the
// whole object). Go has no equivalent of that disposition-receipt verifier at
// all (only VerifyInclusionReceipt/VerifyInclusionReceiptWithKeys, the
// witness Merkle receipt, which TS covers separately), so that describe
// block is intentionally not mirrored here.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// ── Audit event ──

func rotSignedAuditEvent(t *testing.T, priv ed25519.PrivateKey, timestamp string, extra map[string]interface{}) map[string]interface{} {
	t.Helper()
	event := map[string]interface{}{
		"id":        "01JBTEST00000001",
		"type":      "message.sent",
		"agentId":   "tulpa:zAgent",
		"timestamp": timestamp,
	}
	for k, v := range extra {
		event[k] = v
	}
	event["agentSignature"] = signAuditEvent(t, priv, event)
	return event
}

func TestVerifyAuditEventSignatureWithKeysRotation(t *testing.T) {
	t.Run("verifies with the active key", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-06-01T00:00:00.000Z", nil)
		keys := []CandidateKey{{KeyID: "k1", PublicKey: pub, Status: "active"}}
		result := VerifyAuditEventSignatureWithKeys(event, keys, "")
		if !result.Verified || result.KeyID != "k1" {
			t.Errorf("got %+v, want verified k1", result)
		}
		if result.KeyStatus == "retired" {
			t.Error("active key reported as retired")
		}
	})

	t.Run("verifies with a retired key inside its window", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-03-01T00:00:00.000Z", nil)
		keys := []CandidateKey{{
			KeyID: "k-old", PublicKey: pub, Status: "retired",
			ValidFrom:  Timestamp("2026-01-01T00:00:00Z"),
			ValidUntil: Timestamp("2026-04-01T00:00:00Z"),
		}}
		result := VerifyAuditEventSignatureWithKeys(event, keys, "")
		if !result.Verified || result.KeyStatus != "retired" {
			t.Errorf("got %+v, want verified via retired key", result)
		}
	})

	t.Run("rejects a retired key outside its window", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-05-01T00:00:00.000Z", nil)
		keys := []CandidateKey{{
			KeyID: "k-old", PublicKey: pub, Status: "retired",
			ValidFrom:  Timestamp("2026-01-01T00:00:00Z"),
			ValidUntil: Timestamp("2026-04-01T00:00:00Z"),
		}}
		if result := VerifyAuditEventSignatureWithKeys(event, keys, ""); result.Verified {
			t.Errorf("out-of-window retired key accepted: %+v", result)
		}
	})

	t.Run("never verifies with a revoked key, even for events predating revokedAt", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-01-01T00:00:00.000Z", nil)
		keys := []CandidateKey{{
			KeyID: "k-revoked", PublicKey: pub, Status: "revoked",
			ValidFrom: Timestamp("2025-01-01T00:00:00Z"),
			RevokedAt: Timestamp("2026-06-01T00:00:00Z"),
		}}
		if result := VerifyAuditEventSignatureWithKeys(event, keys, ""); result.Verified {
			t.Errorf("revoked key accepted: %+v", result)
		}
	})

	t.Run("rejects a key whose status is active but which carries a revokedAt field", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-01-01T00:00:00.000Z", nil)
		keys := []CandidateKey{{
			KeyID: "k-mixed", PublicKey: pub, Status: "active",
			RevokedAt: Timestamp("2026-06-01T00:00:00Z"),
		}}
		if result := VerifyAuditEventSignatureWithKeys(event, keys, ""); result.Verified {
			t.Errorf("active key with revokedAt accepted: %+v", result)
		}
	})

	t.Run("fails closed on a malformed window field", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-03-01T00:00:00.000Z", nil)
		keys := []CandidateKey{{
			KeyID: "k-malformed", PublicKey: pub, Status: "retired",
			// Present but not a well-formed string: must fail closed.
			ValidUntil: OptionalTimestamp{Present: true, WellFormed: false},
		}}
		if result := VerifyAuditEventSignatureWithKeys(event, keys, ""); result.Verified {
			t.Errorf("malformed window field accepted: %+v", result)
		}
	})

	t.Run("fails closed when the event timestamp is missing", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-03-01T00:00:00.000Z", nil)
		delete(event, "timestamp")
		keys := []CandidateKey{{KeyID: "k1", PublicKey: pub, Status: "active"}}
		if result := VerifyAuditEventSignatureWithKeys(event, keys, ""); result.Verified {
			t.Errorf("missing timestamp accepted: %+v", result)
		}
	})

	t.Run("fails closed when the event timestamp is malformed", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-03-01T00:00:00.000Z", nil)
		event["timestamp"] = "not-a-timestamp"
		keys := []CandidateKey{{KeyID: "k1", PublicKey: pub, Status: "active"}}
		if result := VerifyAuditEventSignatureWithKeys(event, keys, ""); result.Verified {
			t.Errorf("malformed timestamp accepted: %+v", result)
		}
	})

	t.Run("defaults the hint to event.signingKeyId and takes the fast path", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		otherPub, _, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-06-01T00:00:00.000Z", map[string]interface{}{"signingKeyId": "k1"})
		keys := []CandidateKey{
			{KeyID: "k-other", PublicKey: otherPub, Status: "active"},
			{KeyID: "k1", PublicKey: pub, Status: "active"},
		}
		result := VerifyAuditEventSignatureWithKeys(event, keys, "")
		if !result.Verified || result.KeyID != "k1" {
			t.Errorf("got %+v, want verified k1 via signingKeyId hint", result)
		}
	})

	t.Run("falls through when hintKeyId names the wrong key", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-06-01T00:00:00.000Z", nil)
		keys := []CandidateKey{{KeyID: "k1", PublicKey: pub, Status: "active"}}
		result := VerifyAuditEventSignatureWithKeys(event, keys, "wrong-hint")
		if !result.Verified || result.KeyID != "k1" {
			t.Errorf("got %+v, want verified k1 despite wrong hint", result)
		}
	})

	t.Run("bounds candidate keys at maxCandidateKeys (20)", func(t *testing.T) {
		if maxCandidateKeys != 20 {
			t.Fatalf("maxCandidateKeys = %d, want 20", maxCandidateKeys)
		}
		pub, priv, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-06-01T00:00:00.000Z", nil)
		keys := make([]CandidateKey, 0, 21)
		for i := 0; i < 20; i++ {
			decoyPub, _, _ := ed25519.GenerateKey(nil)
			keys = append(keys, CandidateKey{KeyID: "decoy", PublicKey: decoyPub, Status: "active"})
		}
		// The real key is candidate #21 (index 20), past the 20-key bound.
		keys = append(keys, CandidateKey{KeyID: "real", PublicKey: pub, Status: "active"})
		if result := VerifyAuditEventSignatureWithKeys(event, keys, ""); result.Verified {
			t.Errorf("21st candidate key accepted: %+v", result)
		}
	})

	t.Run("rejects an empty key array", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-06-01T00:00:00.000Z", nil)
		if result := VerifyAuditEventSignatureWithKeys(event, []CandidateKey{}, ""); result.Verified {
			t.Errorf("empty key array accepted: %+v", result)
		}
	})

	t.Run("rejects a nil keys argument", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(nil)
		event := rotSignedAuditEvent(t, priv, "2026-06-01T00:00:00.000Z", nil)
		if result := VerifyAuditEventSignatureWithKeys(event, nil, ""); result.Verified {
			t.Errorf("nil keys accepted: %+v", result)
		}
	})
}

// ── Inclusion receipt ──

const rotReceiptRoot = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func rotSignedInclusionReceipt(t *testing.T, priv ed25519.PrivateKey, timestamp string) InclusionReceipt {
	t.Helper()
	sig := signReceipt(t, priv, "01JBTEST00000001", 0, 1, rotReceiptRoot, timestamp)
	return InclusionReceipt{
		EventID:          "01JBTEST00000001",
		LeafIndex:        0,
		TreeSize:         1,
		RootHash:         rotReceiptRoot,
		InclusionProof:   []string{},
		Timestamp:        timestamp,
		ServiceSignature: sig,
	}
}

func TestVerifyInclusionReceiptWithKeysRotation(t *testing.T) {
	t.Run("verifies with the active witness key", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		receipt := rotSignedInclusionReceipt(t, priv, "2026-05-27T00:00:00.000Z")
		keys := []CandidateKey{{KeyID: "w1", PublicKey: pub, Status: "active"}}
		result := VerifyInclusionReceiptWithKeys(receipt, keys, "", ReceiptVerifyOptions{})
		if !result.Verified || result.KeyID != "w1" {
			t.Errorf("got %+v, want verified w1", result)
		}
	})

	t.Run("verifies with a retired witness key inside its window", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		receipt := rotSignedInclusionReceipt(t, priv, "2026-02-01T00:00:00.000Z")
		keys := []CandidateKey{{
			KeyID: "w-old", PublicKey: pub, Status: "retired",
			ValidFrom:  Timestamp("2026-01-01T00:00:00Z"),
			ValidUntil: Timestamp("2026-03-01T00:00:00Z"),
		}}
		result := VerifyInclusionReceiptWithKeys(receipt, keys, "", ReceiptVerifyOptions{})
		if !result.Verified || result.KeyStatus != "retired" {
			t.Errorf("got %+v, want verified via retired key", result)
		}
	})

	t.Run("rejects a retired witness key outside its window", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		receipt := rotSignedInclusionReceipt(t, priv, "2026-05-01T00:00:00.000Z")
		keys := []CandidateKey{{
			KeyID: "w-old", PublicKey: pub, Status: "retired",
			ValidFrom:  Timestamp("2026-01-01T00:00:00Z"),
			ValidUntil: Timestamp("2026-03-01T00:00:00Z"),
		}}
		if result := VerifyInclusionReceiptWithKeys(receipt, keys, "", ReceiptVerifyOptions{}); result.Verified {
			t.Errorf("out-of-window retired key accepted: %+v", result)
		}
	})

	t.Run("never verifies with a revoked witness key, even predating revokedAt", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		receipt := rotSignedInclusionReceipt(t, priv, "2026-01-01T00:00:00.000Z")
		keys := []CandidateKey{{
			KeyID: "w-revoked", PublicKey: pub, Status: "revoked",
			RevokedAt: Timestamp("2026-06-01T00:00:00Z"),
		}}
		if result := VerifyInclusionReceiptWithKeys(receipt, keys, "", ReceiptVerifyOptions{}); result.Verified {
			t.Errorf("revoked key accepted: %+v", result)
		}
	})

	t.Run("fails closed on a malformed window field", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		receipt := rotSignedInclusionReceipt(t, priv, "2026-02-01T00:00:00.000Z")
		keys := []CandidateKey{{
			KeyID: "w1", PublicKey: pub, Status: "retired",
			ValidUntil: OptionalTimestamp{Present: true, WellFormed: false},
		}}
		if result := VerifyInclusionReceiptWithKeys(receipt, keys, "", ReceiptVerifyOptions{}); result.Verified {
			t.Errorf("malformed window field accepted: %+v", result)
		}
	})

	t.Run("fails closed when receipt.timestamp is malformed", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		receipt := rotSignedInclusionReceipt(t, priv, "2026-05-27T00:00:00.000Z")
		receipt.Timestamp = "not-a-timestamp"
		keys := []CandidateKey{{KeyID: "w1", PublicKey: pub, Status: "active"}}
		if result := VerifyInclusionReceiptWithKeys(receipt, keys, "", ReceiptVerifyOptions{}); result.Verified {
			t.Errorf("malformed timestamp accepted: %+v", result)
		}
	})

	t.Run("hint fast path picks the hinted key", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		otherPub, _, _ := ed25519.GenerateKey(nil)
		receipt := rotSignedInclusionReceipt(t, priv, "2026-05-27T00:00:00.000Z")
		keys := []CandidateKey{
			{KeyID: "w-other", PublicKey: otherPub, Status: "active"},
			{KeyID: "w1", PublicKey: pub, Status: "active"},
		}
		result := VerifyInclusionReceiptWithKeys(receipt, keys, "w1", ReceiptVerifyOptions{})
		if !result.Verified || result.KeyID != "w1" {
			t.Errorf("got %+v, want verified w1 via hint", result)
		}
	})

	t.Run("bounds candidate keys at maxCandidateKeys (20)", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		receipt := rotSignedInclusionReceipt(t, priv, "2026-05-27T00:00:00.000Z")
		keys := make([]CandidateKey, 0, 21)
		for i := 0; i < 20; i++ {
			decoyPub, _, _ := ed25519.GenerateKey(nil)
			keys = append(keys, CandidateKey{KeyID: "decoy", PublicKey: decoyPub, Status: "active"})
		}
		keys = append(keys, CandidateKey{KeyID: "real", PublicKey: pub, Status: "active"})
		if result := VerifyInclusionReceiptWithKeys(receipt, keys, "", ReceiptVerifyOptions{}); result.Verified {
			t.Errorf("21st candidate key accepted: %+v", result)
		}
	})

	t.Run("rejects empty keys array", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(nil)
		receipt := rotSignedInclusionReceipt(t, priv, "2026-05-27T00:00:00.000Z")
		if result := VerifyInclusionReceiptWithKeys(receipt, []CandidateKey{}, "", ReceiptVerifyOptions{}); result.Verified {
			t.Errorf("empty key array accepted: %+v", result)
		}
	})
}

// ── Checkpoint ──

const (
	rotCheckpointOrigin = "witness.example"
	rotCheckpointRoot   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// rotArtifactMs is a fixed reference clock (2026-06-01T00:00:00.000Z) used as
// the caller-supplied artifactMs for checkpoint verification, mirroring the
// TS test's ARTIFACT_MS = Date.parse(...).
const rotArtifactMs int64 = 1780358400000

func TestVerifyCheckpointWithKeysRotation(t *testing.T) {
	t.Run("verifies with the active key and preserves origin matching", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		signed, err := SignCheckpoint(rotCheckpointOrigin, 42, rotCheckpointRoot, priv)
		if err != nil {
			t.Fatalf("SignCheckpoint: %v", err)
		}
		keys := []CandidateKey{{KeyID: "w1", PublicKey: pub, Status: "active"}}
		data, result := VerifyCheckpointWithKeys(signed, keys, rotCheckpointOrigin, rotArtifactMs, "")
		if !result.Verified {
			t.Fatalf("got %+v, want verified", result)
		}
		if data.Origin != rotCheckpointOrigin || data.TreeSize != 42 || result.KeyID != "w1" {
			t.Errorf("data=%+v result=%+v", data, result)
		}
	})

	t.Run("rejects when the origin does not match, regardless of key set", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		signed, _ := SignCheckpoint(rotCheckpointOrigin, 42, rotCheckpointRoot, priv)
		keys := []CandidateKey{{KeyID: "w1", PublicKey: pub, Status: "active"}}
		if _, result := VerifyCheckpointWithKeys(signed, keys, "other.example", rotArtifactMs, ""); result.Verified {
			t.Errorf("wrong-origin checkpoint accepted: %+v", result)
		}
	})

	t.Run("verifies with a retired key inside its window", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		signed, _ := SignCheckpoint(rotCheckpointOrigin, 42, rotCheckpointRoot, priv)
		keys := []CandidateKey{{
			KeyID: "w-old", PublicKey: pub, Status: "retired",
			ValidFrom:  Timestamp("2026-01-01T00:00:00Z"),
			ValidUntil: Timestamp("2026-07-01T00:00:00Z"),
		}}
		_, result := VerifyCheckpointWithKeys(signed, keys, rotCheckpointOrigin, rotArtifactMs, "")
		if !result.Verified || result.KeyStatus != "retired" {
			t.Errorf("got %+v, want verified via retired key", result)
		}
	})

	t.Run("rejects a retired key outside its window", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		signed, _ := SignCheckpoint(rotCheckpointOrigin, 42, rotCheckpointRoot, priv)
		keys := []CandidateKey{{
			KeyID: "w-old", PublicKey: pub, Status: "retired",
			ValidFrom:  Timestamp("2026-01-01T00:00:00Z"),
			ValidUntil: Timestamp("2026-02-01T00:00:00Z"),
		}}
		if _, result := VerifyCheckpointWithKeys(signed, keys, rotCheckpointOrigin, rotArtifactMs, ""); result.Verified {
			t.Errorf("out-of-window retired key accepted: %+v", result)
		}
	})

	t.Run("never verifies with a revoked key, even for an artifact clock predating revokedAt", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		signed, _ := SignCheckpoint(rotCheckpointOrigin, 42, rotCheckpointRoot, priv)
		keys := []CandidateKey{{
			KeyID: "w-revoked", PublicKey: pub, Status: "revoked",
			RevokedAt: Timestamp("2026-12-01T00:00:00Z"),
		}}
		if _, result := VerifyCheckpointWithKeys(signed, keys, rotCheckpointOrigin, rotArtifactMs, ""); result.Verified {
			t.Errorf("revoked key accepted: %+v", result)
		}
	})

	// Note: the TS suite also pins "fails closed on a non-finite artifactMs"
	// (Number.NaN). Go's artifactMs is a typed int64 with no non-finite state,
	// so that case has no Go analog and is intentionally omitted.

	t.Run("hint fast path picks the hinted key", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		otherPub, _, _ := ed25519.GenerateKey(nil)
		signed, _ := SignCheckpoint(rotCheckpointOrigin, 42, rotCheckpointRoot, priv)
		keys := []CandidateKey{
			{KeyID: "w-other", PublicKey: otherPub, Status: "active"},
			{KeyID: "w1", PublicKey: pub, Status: "active"},
		}
		_, result := VerifyCheckpointWithKeys(signed, keys, rotCheckpointOrigin, rotArtifactMs, "w1")
		if !result.Verified || result.KeyID != "w1" {
			t.Errorf("got %+v, want verified w1 via hint", result)
		}
	})

	t.Run("rejects empty key array", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(nil)
		signed, _ := SignCheckpoint(rotCheckpointOrigin, 42, rotCheckpointRoot, priv)
		if _, result := VerifyCheckpointWithKeys(signed, []CandidateKey{}, rotCheckpointOrigin, rotArtifactMs, ""); result.Verified {
			t.Errorf("empty key array accepted: %+v", result)
		}
	})
}

// ── Attestation ──

// rotMakeAttestation builds and signs a raw attestation body, mirroring the
// TS test's makeAttestation via buildAttestation.
func rotMakeAttestation(t *testing.T, priv ed25519.PrivateKey, issuedAt, expiresAt string) []byte {
	t.Helper()
	unsigned := map[string]interface{}{
		"protocol":      "ink/0.1",
		"type":          "network.ink.attestation",
		"issuer":        "tulpa:zIssuer",
		"subject":       "tulpa:zSubject",
		"claimType":     "trust.verified",
		"claim":         map[string]interface{}{},
		"attestationId": "attn-0000000000000001",
		"issuedAt":      issuedAt,
		"expiresAt":     expiresAt,
	}
	canonical, err := canonicalizeJSON(unsigned)
	if err != nil {
		t.Fatalf("canonicalize attestation: %v", err)
	}
	sig := ed25519.Sign(priv, []byte("tulpa/sign\n"+canonical))
	signed := make(map[string]interface{}, len(unsigned)+1)
	for k, v := range unsigned {
		signed[k] = v
	}
	signed["signature"] = base64.RawURLEncoding.EncodeToString(sig)
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal attestation: %v", err)
	}
	return raw
}

func TestVerifyAttestationWithKeysRotation(t *testing.T) {
	const now = "2026-06-15T00:00:00Z"

	t.Run("verifies with the active issuer key", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		raw := rotMakeAttestation(t, priv, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z")
		keys := []CandidateKey{{KeyID: "i1", PublicKey: pub, Status: "active"}}
		result := VerifyAttestationWithKeys(raw, keys, now, "")
		if !result.OK {
			t.Errorf("got %+v, want ok", result)
		}
	})

	t.Run("verifies with a retired issuer key inside its window", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		raw := rotMakeAttestation(t, priv, "2026-02-01T00:00:00Z", "2026-12-01T00:00:00Z")
		keys := []CandidateKey{{
			KeyID: "i-old", PublicKey: pub, Status: "retired",
			ValidFrom:  Timestamp("2026-01-01T00:00:00Z"),
			ValidUntil: Timestamp("2026-03-01T00:00:00Z"),
		}}
		result := VerifyAttestationWithKeys(raw, keys, now, "")
		if !result.OK || result.Key.KeyStatus != "retired" {
			t.Errorf("got %+v, want ok via retired key", result)
		}
	})

	t.Run("rejects a retired issuer key outside its window", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		raw := rotMakeAttestation(t, priv, "2026-05-01T00:00:00Z", "2026-12-01T00:00:00Z")
		keys := []CandidateKey{{
			KeyID: "i-old", PublicKey: pub, Status: "retired",
			ValidFrom:  Timestamp("2026-01-01T00:00:00Z"),
			ValidUntil: Timestamp("2026-03-01T00:00:00Z"),
		}}
		if result := VerifyAttestationWithKeys(raw, keys, now, ""); result.OK {
			t.Errorf("out-of-window retired key accepted: %+v", result)
		}
	})

	t.Run("never verifies with a revoked issuer key, even for issuedAt predating revokedAt", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		raw := rotMakeAttestation(t, priv, "2026-01-01T00:00:00Z", "2026-12-01T00:00:00Z")
		keys := []CandidateKey{{
			KeyID: "i-revoked", PublicKey: pub, Status: "revoked",
			RevokedAt: Timestamp("2026-12-31T00:00:00Z"),
		}}
		result := VerifyAttestationWithKeys(raw, keys, now, "")
		if result.OK {
			t.Errorf("revoked key accepted: %+v", result)
		}
		if result.Reason != AttestationReasonSignature {
			t.Errorf("reason = %q, want %q", result.Reason, AttestationReasonSignature)
		}
	})

	t.Run("rejects a key that is active but carries a revokedAt field", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		raw := rotMakeAttestation(t, priv, "2026-01-01T00:00:00Z", "2026-12-01T00:00:00Z")
		keys := []CandidateKey{{
			KeyID: "i-mixed", PublicKey: pub, Status: "active",
			RevokedAt: Timestamp("2026-12-31T00:00:00Z"),
		}}
		if result := VerifyAttestationWithKeys(raw, keys, now, ""); result.OK {
			t.Errorf("active key with revokedAt accepted: %+v", result)
		}
	})

	t.Run("fails closed on a malformed window field", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		raw := rotMakeAttestation(t, priv, "2026-02-01T00:00:00Z", "2026-12-01T00:00:00Z")
		keys := []CandidateKey{{
			KeyID: "i1", PublicKey: pub, Status: "retired",
			ValidFrom: OptionalTimestamp{Present: true, WellFormed: false},
		}}
		if result := VerifyAttestationWithKeys(raw, keys, now, ""); result.OK {
			t.Errorf("malformed window field accepted: %+v", result)
		}
	})

	t.Run("hint fast path picks the hinted key", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		otherPub, _, _ := ed25519.GenerateKey(nil)
		raw := rotMakeAttestation(t, priv, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z")
		keys := []CandidateKey{
			{KeyID: "i-other", PublicKey: otherPub, Status: "active"},
			{KeyID: "i1", PublicKey: pub, Status: "active"},
		}
		result := VerifyAttestationWithKeys(raw, keys, now, "i1")
		if !result.OK || result.Key.KeyID != "i1" {
			t.Errorf("got %+v, want ok via i1 hint", result)
		}
	})

	t.Run("rejects an empty key array", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(nil)
		raw := rotMakeAttestation(t, priv, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z")
		if result := VerifyAttestationWithKeys(raw, []CandidateKey{}, now, ""); result.OK {
			t.Errorf("empty key array accepted: %+v", result)
		}
	})
}
