package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"regexp"
)

// The producing half of INK transport auth (§3.3). VerifyInkSignature checks a
// request signature; these functions mint one. The signer and the verifier
// build the signed bytes with the same BuildSignatureBase, so a request signed
// here verifies there byte for byte, and the Authorization header is emitted in
// the exact grammar the reference parser accepts. They mirror signInkMessage and
// buildAuthHeader in src/crypto/ink.ts.

// keyIDRe is the keyId grammar from ink-protocol.md §3.3: [A-Za-z0-9_:.-]{1,128}.
// It matches the parameter the reference Authorization-header parser accepts,
// `^INK-Ed25519 ([A-Za-z0-9_-]{86})(?: keyId=([A-Za-z0-9_:.-]{1,128}))?$`, so a
// header built here round-trips through it.
var keyIDRe = regexp.MustCompile(`^[A-Za-z0-9_:.-]{1,128}$`)

// authHeaderRe is the whole INK-Ed25519 Authorization header grammar from §3.3,
// mirroring the reference parser's regex
// `^INK-Ed25519 ([A-Za-z0-9_-]{86})(?: keyId=([A-Za-z0-9_:.-]{1,128}))?$`. RE2 has
// no backtracking and no `\s` here, so single literal spaces and the anchored,
// bounded groups decide every input identically to the JavaScript RegExp: the
// 86-char base64url signature in group 1 and the optional 1-128 char keyId in
// group 2, with an embedded CR/LF or any trailing data failing the `$` anchor.
var authHeaderRe = regexp.MustCompile(`^INK-Ed25519 ([A-Za-z0-9_-]{86})(?: keyId=([A-Za-z0-9_:.-]{1,128}))?$`)

// InkAuthHeaderParse is the outcome of parsing an INK-Ed25519 Authorization
// header value. On OK the Signature (and optional KeyID) are set; otherwise
// Reason carries the rejection code.
type InkAuthHeaderParse struct {
	OK        bool
	Signature string
	KeyID     string // empty when the header carries no keyId parameter
	Reason    string // "missing_authorization" or "invalid_auth_scheme" when !OK
}

// ParseInkAuthHeader parses an INK-Ed25519 Authorization header value into its
// signature and optional keyId, purely from the §3.3 grammar. It is the parse
// half of transport auth with no key resolution, timestamp, or signature work:
// the grammar the reference parseInkAuthHeader in src/middleware/ink-auth.ts
// must agree with byte for byte, exercised by the authorization-header
// conformance category.
//
// An empty header is "missing_authorization"; any value that does not match the
// grammar (wrong scheme, wrong signature length or alphabet, stray whitespace,
// an embedded CR/LF, an empty or over-long or ill-formed keyId, or trailing
// data) is "invalid_auth_scheme". It never errors.
func ParseInkAuthHeader(header string) InkAuthHeaderParse {
	if len(header) == 0 {
		return InkAuthHeaderParse{OK: false, Reason: "missing_authorization"}
	}
	// A fast-path length cap before the regex: any header this long cannot match
	// the bounded grammar anyway, so it rejects as invalid_auth_scheme, the same
	// verdict the regex would give.
	if len(header) > 512 {
		return InkAuthHeaderParse{OK: false, Reason: "invalid_auth_scheme"}
	}
	m := authHeaderRe.FindStringSubmatch(header)
	if m == nil {
		return InkAuthHeaderParse{OK: false, Reason: "invalid_auth_scheme"}
	}
	return InkAuthHeaderParse{OK: true, Signature: m[1], KeyID: m[2]}
}

// SignInkMessage signs an INK transport request. It builds the §3.3 signature
// base with BuildSignatureBase (the same builder VerifyInkSignature uses, so the
// signer and verifier agree on the signed bytes), signs the UTF-8 base bytes
// with Ed25519, and returns the signature as base64url without padding: exactly
// 86 characters [A-Za-z0-9_-]. It mirrors signInkMessage in src/crypto/ink.ts.
//
// It errors on a private key of the wrong size or an unbuildable base: an empty,
// over-long, or CR/LF-bearing scalar, or an over-complex or over-cap body, all
// rejected by BuildSignatureBase before any signing work.
func SignInkMessage(in InkSignInput, privateKey ed25519.PrivateKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("private key must be an ed25519 private key")
	}
	base, err := BuildSignatureBase(in)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(privateKey, []byte(base))
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// BuildAuthHeader builds the INK Authorization header value per §3.3:
//
//	INK-Ed25519 <base64url(signature)> [keyId=<keyId>]
//
// signatureBase64url MUST be exactly 86 base64url characters (a 64-byte Ed25519
// signature); any other shape is rejected at the builder so a caller gets an
// early error instead of sending a syntactically valid but semantically wrong
// header. keyId is optional: an empty string omits the parameter, and a
// non-empty keyId MUST match [A-Za-z0-9_:.-]{1,128}, which excludes CR/LF and
// spaces so the value cannot inject a header boundary. The result round-trips
// through the reference parser. It mirrors buildAuthHeader in src/crypto/ink.ts.
func BuildAuthHeader(signatureBase64url, keyID string) (string, error) {
	if !signatureRe.MatchString(signatureBase64url) {
		return "", errors.New("signature must be exactly 86 base64url characters (Ed25519)")
	}
	if keyID == "" {
		return "INK-Ed25519 " + signatureBase64url, nil
	}
	if !keyIDRe.MatchString(keyID) {
		return "", errors.New("keyId must be 1-128 chars [A-Za-z0-9_:.-]")
	}
	return "INK-Ed25519 " + signatureBase64url + " keyId=" + keyID, nil
}

// SignInkRequest is the one-shot: it signs the request with SignInkMessage and
// wraps the signature in an Authorization header with BuildAuthHeader, returning
// both. keyID is optional (an empty string omits the parameter).
func SignInkRequest(in InkSignInput, privateKey ed25519.PrivateKey, keyID string) (signature, authHeader string, err error) {
	signature, err = SignInkMessage(in, privateKey)
	if err != nil {
		return "", "", err
	}
	authHeader, err = BuildAuthHeader(signature, keyID)
	if err != nil {
		return "", "", err
	}
	return signature, authHeader, nil
}
