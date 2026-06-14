package ink

import (
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

// Numbers in a signed body are out of scope for v1 and fail closed rather than
// producing a possibly divergent serialization.
func TestNumberInBodyFailsClosed(t *testing.T) {
	in := InkSignInput{
		Method:       "POST",
		Path:         "/x",
		RecipientDid: "tulpa:z",
		Body:         map[string]interface{}{"n": float64(1)},
		Timestamp:    "2026-06-11T00:00:00.000Z",
	}
	if _, err := BuildSignatureBase(in); err == nil {
		t.Errorf("expected error for a number in the signed body")
	}
}
