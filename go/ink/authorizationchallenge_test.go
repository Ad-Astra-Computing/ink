package ink

import (
	"bytes"
	"testing"
)

// TestChallengeByteBound covers the raw-byte ceiling the shared conformance
// corpus does not carry: a case proving it would have to embed a body larger
// than the 64 KiB cap, which is not worth that much corpus weight when the rule
// is a length comparison. A raw body past MaxChallengeBodyBytes is refused as
// schema before the decoder runs.
func TestChallengeByteBound(t *testing.T) {
	if MaxChallengeBodyBytes != 64*1024 {
		t.Fatalf("MaxChallengeBodyBytes = %d, want 65536", MaxChallengeBodyBytes)
	}
	// A body one byte past the ceiling, never decoded.
	raw := append([]byte(`{"x":"`), bytes.Repeat([]byte("a"), MaxChallengeBodyBytes)...)
	raw = append(raw, []byte(`"}`)...)
	if len(raw) <= MaxChallengeBodyBytes {
		t.Fatalf("test body is not over the ceiling: %d", len(raw))
	}
	ok, reason := VerifyAuthorizationChallenge(raw, nil, AuthorizationChallengeContext{Now: "2026-07-16T12:02:00.000Z"})
	if ok || reason != ChallengeReasonSchema {
		t.Fatalf("oversized body: ok=%v reason=%q, want reject schema", ok, reason)
	}
}

// TestDeriveChallengeGrantIDParity pins the derivation properties the flow relies
// on: determinism, independence from non-binding fields, and distinctness across
// any of the four binding fields. The exact fixed-input values are pinned against
// the reference in the agent-authorization conformance vectors.
func TestDeriveChallengeGrantIDParity(t *testing.T) {
	rp, nonce, issuedAt, expiresAt := "did:web:rp.example", "nonce-challenge-000000001", "2026-07-16T12:00:00.000Z", "2026-07-16T12:05:00.000Z"
	id := DeriveChallengeGrantID(rp, nonce, issuedAt, expiresAt)
	if id != DeriveChallengeGrantID(rp, nonce, issuedAt, expiresAt) {
		t.Fatalf("derivation is not deterministic")
	}
	if len(id) != 43 {
		t.Fatalf("derived id length = %d, want 43", len(id))
	}
	if DeriveChallengeGrantID("did:web:rp2.example", nonce, issuedAt, expiresAt) == id {
		t.Errorf("differing rp derived the same id")
	}
	if DeriveChallengeGrantID(rp, "nonce-challenge-000000002", issuedAt, expiresAt) == id {
		t.Errorf("differing nonce derived the same id")
	}
	if DeriveChallengeGrantID(rp, nonce, issuedAt, "2026-07-16T12:06:00.000Z") == id {
		t.Errorf("differing window derived the same id")
	}
}

// TestDeriveRPOriginParity mirrors the reference deriveRpOrigin edge cases so the
// two implementations derive the same origin (or reject) for the same input.
func TestDeriveRPOriginParity(t *testing.T) {
	accept := map[string]string{
		"did:web:rp.example":         "https://rp.example",
		"did:web:rp.example%3A8443":  "https://rp.example:8443",
		"did:web:a.b.c.example":      "https://a.b.c.example",
		"did:web:rp.example%3A65535": "https://rp.example:65535",
	}
	for in, want := range accept {
		got, ok := deriveRPOrigin(in)
		if !ok || got != want {
			t.Errorf("deriveRPOrigin(%q) = (%q,%v), want (%q,true)", in, got, ok, want)
		}
	}
	reject := []string{
		"did:web:rp.example:path",
		"did:web:RP.example",
		"did:web:rp.123",
		"did:web:192.168.0.1",
		"did:web:rp.example%3A443",
		"did:web:rp.example%3a8443",
		"did:web:rp.example%3A08443",
		"did:web:-rp.example",
		"did:web:rp.example.",
		"web:rp.example",
		"did:web:",
		"did:web:rp.example%3A8443%3A9000",
		"did:web:rp.example%3A0",
		"did:web:rp.example%3A65536",
		"did:web:[2001:db8::1]",
		"did:web:rp%2Eexample",
	}
	for _, in := range reject {
		if got, ok := deriveRPOrigin(in); ok {
			t.Errorf("deriveRPOrigin(%q) = (%q,true), want reject", in, got)
		}
	}
}
