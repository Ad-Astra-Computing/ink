package ink

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"

	"filippo.io/edwards25519"
)

// InkSignInput is the canonical request shape an INK signature covers.
type InkSignInput struct {
	Method       string
	Path         string
	RecipientDid string
	Body         interface{}
	Timestamp    string
}

var signatureRe = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)

func containsCRLF(s string) bool { return strings.ContainsAny(s, "\r\n") }

// BuildSignatureBase assembles the string an INK signature is computed over:
// the ink/0.1 domain, the request scalars, the JCS-canonical body, and the
// timestamp, newline separated. Scalars are length-capped (in UTF-16 code
// units) and must not contain a CR or LF, matching the reference contract.
func BuildSignatureBase(in InkSignInput) (string, error) {
	scalarOK := func(s string, max int) bool {
		n := utf16Len(s)
		return n > 0 && n <= max
	}
	if !scalarOK(in.Method, 16) {
		return "", errors.New("invalid signature-base method")
	}
	if !scalarOK(in.Path, 2048) {
		return "", errors.New("invalid signature-base path")
	}
	if !scalarOK(in.RecipientDid, 256) {
		return "", errors.New("invalid signature-base recipientDid")
	}
	if !scalarOK(in.Timestamp, 64) {
		return "", errors.New("invalid signature-base timestamp")
	}
	if containsCRLF(in.Method) || containsCRLF(in.Path) || containsCRLF(in.RecipientDid) || containsCRLF(in.Timestamp) {
		return "", errors.New("newline or CR not allowed in a scalar field")
	}
	canonical, err := canonicalizeJSON(in.Body)
	if err != nil {
		return "", err
	}
	return "ink/0.1\n" + in.Method + "\n" + in.Path + "\n" + in.RecipientDid + "\n" + canonical + "\n" + in.Timestamp, nil
}

// VerifyInkSignature verifies a base64url Ed25519 signature over the signature
// base. Verification matches the reference implementation (@noble/ed25519 with
// zip215:false): the public key must be canonically encoded and must not be a
// small-order point, then the RFC 8032 cofactorless equation is checked by
// Go's crypto/ed25519. A malformed signature, an invalid or small-order key, or
// an unbuildable signature base all return false.
func VerifyInkSignature(in InkSignInput, signatureBase64url string, publicKey []byte) bool {
	if !signatureRe.MatchString(signatureBase64url) {
		return false
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if !isStrongEd25519PublicKey(publicKey) {
		return false
	}
	sigBase, err := BuildSignatureBase(in)
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(signatureBase64url)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), []byte(sigBase), sig)
}

// isStrongEd25519PublicKey rejects keys that Go's bare crypto/ed25519.Verify
// would accept but the reference (noble zip215:false) rejects: non-canonically
// encoded points and small-order points. A small-order A makes [h]A constant
// across messages, which lets an attacker forge a signature that verifies for
// any message; noble rejects such keys before any arithmetic, so the Go
// verifier must too. edwards25519.SetBytes accepts non-canonical encodings of
// valid points (e.g. a y-coordinate not reduced mod p), so canonicality is
// enforced by re-encoding and comparing; noble requires y < p. A point is
// small-order iff multiplying it by the cofactor (8) yields the identity.
func isStrongEd25519PublicKey(publicKey []byte) bool {
	a, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return false
	}
	if !bytes.Equal(a.Bytes(), publicKey) {
		return false
	}
	cofactored := new(edwards25519.Point).MultByCofactor(a)
	return cofactored.Equal(edwards25519.NewIdentityPoint()) != 1
}
