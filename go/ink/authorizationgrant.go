package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"unicode/utf8"
)

// authorizationGrantTopLevelKeys is the exact set of members an authorization
// grant may carry. All are required except requireVerifiedOwner, which is
// optional; any unknown key rejects.
var authorizationGrantTopLevelKeys = map[string]bool{
	"protocol": true, "type": true, "issuer": true, "subject": true,
	"audience": true, "scope": true, "grantId": true, "issuedAt": true,
	"expiresAt": true, "requireVerifiedOwner": true, "signature": true,
}

// authorizationGrantRequiredKeys is the subset that must be present. The
// remaining member (requireVerifiedOwner) is optional.
var authorizationGrantRequiredKeys = []string{
	"protocol", "type", "issuer", "subject", "audience",
	"scope", "grantId", "issuedAt", "expiresAt", "signature",
}

const (
	grantIDMin    = 16
	grantIDMax    = 256
	scopeEntryMax = 128
	scopeMax      = 64
)

// AuthorizationGrantReason is the stable discriminator a caller uses to map a
// rejection to its own response. It mirrors the TypeScript
// AuthorizationGrantReason. An empty reason accompanies an accept.
type AuthorizationGrantReason string

const (
	GrantReasonSchema          AuthorizationGrantReason = "schema"
	GrantReasonSignature       AuthorizationGrantReason = "signature"
	GrantReasonAudience        AuthorizationGrantReason = "audience"
	GrantReasonExpired         AuthorizationGrantReason = "expired"
	GrantReasonNotYetValid     AuthorizationGrantReason = "not_yet_valid"
	GrantReasonReplay          AuthorizationGrantReason = "replay"
	GrantReasonRevoked         AuthorizationGrantReason = "revoked"
	GrantReasonOwnerUnverified AuthorizationGrantReason = "owner_unverified"
)

// AuthorizationGrantContext is everything a verifier needs beyond the issuer
// key. Audience is the checking service's own identity, compared against the
// signed audience to reject a confused-deputy replay. Now is the verifier clock,
// a strict INK timestamp. SeenGrantIDs and IsRevoked are the replay and
// revocation receiver-policy hooks. VerifiedOwnerStatus is the owner-verification
// composition hook, consulted only when the grant requires it; an empty string
// means no status was supplied (treated as unverified).
type AuthorizationGrantContext struct {
	Audience            string
	Now                 string
	SeenGrantIDs        []string
	IsRevoked           func(grantID string) bool
	VerifiedOwnerStatus string
}

// VerifyAuthorizationGrant verifies a scoped authorization grant against the
// issuer public key and a verification context. It mirrors the TypeScript
// verifyAuthorizationGrant byte for byte: strict schema validation, then a body
// signature over "tulpa/sign\n" + JCS(grant without the signature field),
// verified with RFC 8032 strict Ed25519, then the audience, window, replay,
// revocation, and owner-verification checks in the same order. It fails closed
// and returns a typed reason on the first failure.
//
// The grant is parsed once into a generic object, exactly as a JSON.parse based
// verifier sees it, so the validated bytes and the signed bytes cannot disagree.
func VerifyAuthorizationGrant(raw []byte, issuerPublicKey []byte, ctx AuthorizationGrantContext) (bool, AuthorizationGrantReason) {
	// The grant is a signed artifact: encoding/json rewrites invalid UTF-8 or a
	// lone surrogate to U+FFFD, so reject both before parsing.
	if !utf8.Valid(raw) || ContainsLoneSurrogateEscape(raw) {
		return false, GrantReasonSchema
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false, GrantReasonSchema
	}
	signature, ok := validateAuthorizationGrant(obj)
	if !ok {
		return false, GrantReasonSchema
	}
	if !signatureRe.MatchString(signature) {
		return false, GrantReasonSchema
	}
	if len(issuerPublicKey) != ed25519.PublicKeySize || !isStrongEd25519PublicKey(issuerPublicKey) {
		return false, GrantReasonSignature
	}
	unsigned := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		if k != "signature" {
			unsigned[k] = v
		}
	}
	canonical, err := canonicalizeJSON(unsigned)
	if err != nil {
		return false, GrantReasonSchema
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false, GrantReasonSchema
	}
	if !ed25519.Verify(ed25519.PublicKey(issuerPublicKey), []byte("tulpa/sign\n"+canonical), sig) {
		return false, GrantReasonSignature
	}

	// Confused-deputy defense: a grant minted for one service must not verify at
	// another. The signed audience must equal the checking service's identity.
	audience, _ := obj["audience"].(string)
	if audience != ctx.Audience {
		return false, GrantReasonAudience
	}

	// Validity window. The verifier clock must be a strict INK timestamp; a
	// malformed clock fails closed. Lower bound inclusive, upper bound exclusive.
	now, okNow := ParseInkTimestampMs(ctx.Now)
	if !okNow {
		return false, GrantReasonExpired
	}
	issuedAt, _ := obj["issuedAt"].(string)
	expiresAt, _ := obj["expiresAt"].(string)
	start, okStart := ParseInkTimestampMs(issuedAt)
	end, okEnd := ParseInkTimestampMs(expiresAt)
	if !okStart || !okEnd {
		return false, GrantReasonSchema
	}
	if now < start {
		return false, GrantReasonNotYetValid
	}
	if now >= end {
		return false, GrantReasonExpired
	}

	grantID, _ := obj["grantId"].(string)

	// Replay: a grantId already seen at this receiver is a replay.
	for _, seen := range ctx.SeenGrantIDs {
		if seen == grantID {
			return false, GrantReasonReplay
		}
	}

	// Revocation: the receiver's denylist predicate.
	if ctx.IsRevoked != nil && ctx.IsRevoked(grantID) {
		return false, GrantReasonRevoked
	}

	// Owner-verification composition hook, consulted only when the grant asks for
	// it. Absent status is unverified.
	if req, present := obj["requireVerifiedOwner"]; present {
		if b, isBool := req.(bool); isBool && b {
			if ctx.VerifiedOwnerStatus != "verified" {
				return false, GrantReasonOwnerUnverified
			}
		}
	}

	return true, ""
}

// validateAuthorizationGrant validates the parsed grant object against the
// schema and returns the signature string on success. It rejects a missing
// required member, an extra member, a wrong-typed or out-of-bound field, an
// explicit null on any field, an invalid timestamp, an inverted validity window,
// and a malformed scope. String bounds are counted in UTF-16 code units to match
// the reference. requireVerifiedOwner, when present, must be a boolean.
func validateAuthorizationGrant(obj map[string]interface{}) (string, bool) {
	for k := range obj {
		if !authorizationGrantTopLevelKeys[k] {
			return "", false
		}
	}
	for _, k := range authorizationGrantRequiredKeys {
		if _, present := obj[k]; !present {
			return "", false
		}
	}
	if protocol, ok := obj["protocol"].(string); !ok || protocol != "ink/0.1" {
		return "", false
	}
	if t, ok := obj["type"].(string); !ok || (t != "network.tulpa.authorization_grant" && t != "network.ink.authorization_grant") {
		return "", false
	}
	if !boundedString(obj["issuer"], 1, 512) || !boundedString(obj["subject"], 1, 512) || !boundedString(obj["audience"], 1, 512) {
		return "", false
	}
	if !boundedString(obj["grantId"], grantIDMin, grantIDMax) {
		return "", false
	}
	issuedAt, ok := obj["issuedAt"].(string)
	if !ok {
		return "", false
	}
	start, okStart := ParseInkTimestampMs(issuedAt)
	if !okStart {
		return "", false
	}
	expiresAt, ok := obj["expiresAt"].(string)
	if !ok {
		return "", false
	}
	end, okEnd := ParseInkTimestampMs(expiresAt)
	if !okEnd {
		return "", false
	}
	// The window must be strictly positive: a zero or negative window is a
	// malformed grant, matching the reference refine.
	if end <= start {
		return "", false
	}
	if !validateAuthorizationGrantScope(obj["scope"]) {
		return "", false
	}
	if req, present := obj["requireVerifiedOwner"]; present {
		if _, isBool := req.(bool); !isBool {
			return "", false
		}
	}
	signature, ok := obj["signature"].(string)
	if !ok || signature == "" {
		return "", false
	}
	return signature, true
}

// validateAuthorizationGrantScope reports whether v is a non-empty array of 1 to
// scopeMax distinct strings, each 1 to scopeEntryMax UTF-16 code units.
// Distinctness matches the reference refine so two implementations count the
// same set.
func validateAuthorizationGrantScope(v interface{}) bool {
	scope, ok := v.([]interface{})
	if !ok || len(scope) < 1 || len(scope) > scopeMax {
		return false
	}
	seen := make(map[string]bool, len(scope))
	for _, entry := range scope {
		s, ok := entry.(string)
		if !ok {
			return false
		}
		if !boundedString(s, 1, scopeEntryMax) {
			return false
		}
		if seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
