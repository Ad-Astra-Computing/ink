package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// A small-order public key yields a universal forgery under the cofactorless
// verification equation: for A = identity, [h]A = identity for every h, so
// [S]B = R + [h]A reduces to [S]B = R, which holds for S = 1 and R = [1]B = B
// (the basepoint) regardless of the message. The reference verifier
// (@noble/ed25519 with zip215:false) rejects small-order keys up front, so the
// Go verifier must reject them too or it would accept signatures the reference
// rejects. Go's bare crypto/ed25519.Verify does NOT reject small-order A.
func TestSmallOrderPublicKeyRejected(t *testing.T) {
	identity := make([]byte, 32)
	identity[0] = 0x01
	basepoint, _ := hex.DecodeString("5866666666666666666666666666666666666666666666666666666666666666")
	scalarOne := make([]byte, 32)
	scalarOne[0] = 0x01
	forgedSig := make([]byte, 0, 64)
	forgedSig = append(forgedSig, basepoint...)
	forgedSig = append(forgedSig, scalarOne...)
	sigB64 := base64.RawURLEncoding.EncodeToString(forgedSig)

	in := InkSignInput{
		Method:       "POST",
		Path:         "/ink/v1/x/intent",
		RecipientDid: "tulpa:z",
		Body:         map[string]interface{}{},
		Timestamp:    "2026-06-11T00:00:00.000Z",
	}
	if VerifyInkSignature(in, sigB64, identity) {
		t.Errorf("verifier accepted a small-order-A (identity) universal forgery")
	}
}

// A non-canonical public-key encoding (y >= p) decodes to a valid, non-small-
// order point, so the small-order check alone does not catch it; the reference
// (@noble/ed25519 with zip215:false) requires y < p and rejects it, so the Go
// verifier must reject it too via a canonical re-encode check. This encoding is
// y = p + 3 (the point whose canonical encoding is 0x03..00).
func TestNonCanonicalPublicKeyRejected(t *testing.T) {
	nonCanonical, _ := hex.DecodeString("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	if isStrongEd25519PublicKey(nonCanonical) {
		t.Errorf("accepted a non-canonical (y >= p) public-key encoding")
	}
}

// A newline inside a signed body string is escaped by JCS, so it cannot shift
// the newline-delimited signature base boundaries.
func TestBodyNewlineIsEscaped(t *testing.T) {
	got := canonicalizeString("a\nb\r\tc")
	want := `"a\nb\r\tc"`
	if got != want {
		t.Errorf("canonicalizeString = %q, want %q", got, want)
	}
}

// A CR or LF in a scalar field is rejected outright, so it cannot inject a
// boundary into the signature base.
func TestScalarNewlineRejected(t *testing.T) {
	base := InkSignInput{
		Method:       "POST",
		Path:         "/ink/v1/x/intent",
		RecipientDid: "tulpa:z",
		Body:         map[string]interface{}{},
		Timestamp:    "2026-06-11T00:00:00.000Z",
	}
	for _, mut := range []func(*InkSignInput){
		func(in *InkSignInput) { in.RecipientDid = "tulpa:\nz" },
		func(in *InkSignInput) { in.Path = "/a\r/b" },
		func(in *InkSignInput) { in.Method = "PO\nST" },
		func(in *InkSignInput) { in.Timestamp = "2026\n" },
	} {
		in := base
		mut(&in)
		if _, err := BuildSignatureBase(in); err == nil {
			t.Errorf("expected error for scalar containing a newline: %+v", in)
		}
	}
}

// TestSignatureBaseRejectsOverCapBody pins that BuildSignatureBase rejects a body
// whose canonical output exceeds the post-canonicalize cap, mirroring the
// reference buildSignatureBase in src/crypto/ink.ts: jcsCanonicalize caps
// result.length (UTF-16 code units) at MAX_SIGBASE_BODY_BYTES, and buildSignatureBase
// then caps the TextEncoder-encoded (UTF-8) length at the same constant. A single
// ~1.1M-char string value passes the pre-canonicalize walk (maxBodyChars is
// 1,200,000) yet its canonical form exceeds 1,048,576 code units, so only the
// post-canonicalize cap can reject it. Without the cap a Go verifier would spend
// signature work on a body the TS verifier refuses before verifying.
func TestSignatureBaseRejectsOverCapBody(t *testing.T) {
	b := make([]byte, maxCanonicalBodyBytes+50_000)
	for i := range b {
		b[i] = 'a'
	}
	in := InkSignInput{
		Method:       "POST",
		Path:         "/x",
		RecipientDid: "tulpa:z",
		Body:         map[string]interface{}{"d": string(b)},
		Timestamp:    "2026-06-11T00:00:00.000Z",
	}
	if !withinBodyBounds(in.Body) {
		t.Fatal("fixture body should pass the pre-canonicalize walk so only the post-cap can reject it")
	}
	if _, err := BuildSignatureBase(in); err == nil {
		t.Error("BuildSignatureBase accepted a body whose canonical output exceeds the cap")
	}
}

// TestSignatureBaseRejectsOverComplexBody pins the pre-canonicalize structural
// walk on BuildSignatureBase, mirroring isWithinCanonicalizeBounds in
// src/crypto/ink.ts (buildSignatureBase runs it before jcsCanonicalize). An
// over-deep body is rejected before any canonicalization.
func TestSignatureBaseRejectsOverComplexBody(t *testing.T) {
	// Build a nesting deeper than maxBodyDepth (32).
	var body interface{} = "leaf"
	for i := 0; i < maxBodyDepth+5; i++ {
		body = map[string]interface{}{"n": body}
	}
	in := InkSignInput{
		Method:       "POST",
		Path:         "/x",
		RecipientDid: "tulpa:z",
		Body:         body,
		Timestamp:    "2026-06-11T00:00:00.000Z",
	}
	if _, err := BuildSignatureBase(in); err == nil {
		t.Error("BuildSignatureBase accepted an over-deep body")
	}
}

// TestVerifyInkSignatureRejectsOverCapBody pins that the verify entry point
// inherits the post-canonicalize cap, so a Go receiver rejects an over-cap body
// the same way verifyInkSignature does in the reference.
func TestVerifyInkSignatureRejectsOverCapBody(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	b := make([]byte, maxCanonicalBodyBytes+50_000)
	for i := range b {
		b[i] = 'a'
	}
	in := InkSignInput{
		Method:       "POST",
		Path:         "/x",
		RecipientDid: "tulpa:z",
		Body:         map[string]interface{}{"d": string(b)},
		Timestamp:    "2026-06-11T00:00:00.000Z",
	}
	// An 86-char base64url string is a well-formed-shape signature; the body cap
	// must reject before any Ed25519 work, so verification returns false.
	fakeSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	if VerifyInkSignature(in, fakeSig, pub) {
		t.Error("VerifyInkSignature accepted an over-cap body")
	}
}

// TestSignatureBaseAcceptsUnderCapBody pins that a body under the cap still builds
// a signature base, so the added caps are reject-only.
func TestSignatureBaseAcceptsUnderCapBody(t *testing.T) {
	in := InkSignInput{
		Method:       "POST",
		Path:         "/x",
		RecipientDid: "tulpa:z",
		Body:         map[string]interface{}{"hello": "world"},
		Timestamp:    "2026-06-11T00:00:00.000Z",
	}
	if _, err := BuildSignatureBase(in); err != nil {
		t.Errorf("BuildSignatureBase rejected a small under-cap body: %v", err)
	}
}

// A safe integer in a signed body canonicalizes to a plain decimal; a value
// with a fractional part is not in the safe-integer profile and fails closed
// rather than producing a possibly divergent serialization.
func TestSignedBodyNumberProfile(t *testing.T) {
	base := func(body interface{}) InkSignInput {
		return InkSignInput{
			Method:       "POST",
			Path:         "/x",
			RecipientDid: "tulpa:z",
			Body:         body,
			Timestamp:    "2026-06-11T00:00:00.000Z",
		}
	}
	if _, err := BuildSignatureBase(base(map[string]interface{}{"n": float64(1)})); err != nil {
		t.Errorf("safe integer should be accepted, got error: %v", err)
	}
	if _, err := BuildSignatureBase(base(map[string]interface{}{"n": float64(1.5)})); err == nil {
		t.Errorf("a fractional number should fail closed")
	}
}
