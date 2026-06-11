package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
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
// base. Verification is RFC 8032 strict (Go's crypto/ed25519), matching the
// reference implementation's zip215:false. A malformed signature, an invalid
// key length, or an unbuildable signature base all return false.
func VerifyInkSignature(in InkSignInput, signatureBase64url string, publicKey []byte) bool {
	if !signatureRe.MatchString(signatureBase64url) {
		return false
	}
	if len(publicKey) != ed25519.PublicKeySize {
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
