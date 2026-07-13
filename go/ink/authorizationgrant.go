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

// MaxGrantLifetimeMs is the maximum grant lifetime in milliseconds. The validity
// window (expiresAt minus issuedAt) must not exceed it. It mirrors the reference
// MAX_GRANT_LIFETIME_MS: ten minutes, the login/bootstrap ceiling. A grant whose
// window is longer is out of profile and rejects structurally, independent of the
// verifier clock. A verifier caller may tighten this per check but never loosen
// it.
const MaxGrantLifetimeMs = 10 * 60 * 1000

// AuthorizationGrantReason is the stable discriminator a caller uses to map a
// rejection to its own response. It mirrors the TypeScript
// AuthorizationGrantReason. An empty reason accompanies an accept.
type AuthorizationGrantReason string

const (
	GrantReasonSchema          AuthorizationGrantReason = "schema"
	GrantReasonSignature       AuthorizationGrantReason = "signature"
	GrantReasonAudience        AuthorizationGrantReason = "audience"
	GrantReasonSubject         AuthorizationGrantReason = "subject"
	GrantReasonExpired         AuthorizationGrantReason = "expired"
	GrantReasonNotYetValid     AuthorizationGrantReason = "not_yet_valid"
	GrantReasonReplay          AuthorizationGrantReason = "replay"
	GrantReasonRevoked         AuthorizationGrantReason = "revoked"
	GrantReasonOwnerUnverified AuthorizationGrantReason = "owner_unverified"
)

// GrantKey identifies a grant for replay and revocation. Both keys are the pair
// of the signed Issuer and the issuer-chosen GrantID. GrantID is chosen by the
// issuer, so two issuers can pick the same string; keying on the pair keeps one
// issuer's seen or revoked ids from colliding with another's.
type GrantKey struct {
	Issuer  string
	GrantID string
}

// AuthorizationGrantContext is everything a verifier needs beyond the issuer
// key. Audience is the checking service's own identity, compared against the
// signed audience to reject a confused-deputy replay. Now is the verifier clock,
// a strict INK timestamp. Presenter is the authenticated identity of the
// principal presenting the grant, as the transport established it (for INK, the
// signed envelope sender); when it is non-empty it must equal the signed subject,
// so a stolen grant is not presentable by another principal inside its window. An
// empty Presenter skips the binding check and leaves the grant a bearer artifact
// the audience must bind out of band. SeenGrants and IsRevoked are the replay and
// revocation receiver-policy hooks, both keyed by the (issuer, grantId) pair.
// SeenGrants only reports what a prior acceptance recorded: a service MUST record
// the accepted (issuer, grantId) pair atomically with acceptance (check-and-insert
// under one guard) so two concurrent presentations of the same pair cannot both
// be accepted; this verifier reads the set but does not record into it.
// VerifiedOwnerStatus is the owner-verification composition hook, consulted only
// when the grant requires it; an empty string means no status was supplied
// (treated as unverified). MaxLifetimeMs optionally tightens the maximum grant
// lifetime for this check; a zero value means "use the profile default" (a Go
// zero-value integer is indistinguishable from an unset one), a NEGATIVE value is
// a verifier input error that fails closed as schema, and any positive value is
// clamped to at most MaxGrantLifetimeMs so a caller can only shorten the ceiling,
// never raise it. The Go type is an integer, so it cannot carry the NaN or
// Infinity the reference guards against: the reference rejects a maxLifetimeMs
// that is not a finite number greater than zero as schema, and this integer field
// expresses the same rule by construction, treating only zero as unset.
type AuthorizationGrantContext struct {
	Audience            string
	Now                 string
	Presenter           string
	SeenGrants          []GrantKey
	IsRevoked           func(key GrantKey) bool
	VerifiedOwnerStatus string
	MaxLifetimeMs       int64
}

// VerifyAuthorizationGrant verifies a scoped authorization grant against the
// issuer public key and a verification context. It mirrors the TypeScript
// verifyAuthorizationGrant byte for byte: a complexity bound, strict schema
// validation, then a body signature over "tulpa/sign\n" + JCS(grant without the
// signature field), verified with RFC 8032 strict Ed25519, then the audience,
// presentation-binding, window, replay, revocation, and owner-verification checks
// in the same order. It fails closed and returns a typed reason on the first
// failure.
//
// The grant is parsed once into a generic object, exactly as a JSON.parse based
// verifier sees it, so the validated bytes and the signed bytes cannot disagree.
func VerifyAuthorizationGrant(raw []byte, issuerPublicKey []byte, ctx AuthorizationGrantContext) (bool, AuthorizationGrantReason) {
	// Byte cap before anything touches the decoder: a body past the schema-derived
	// ceiling is rejected outright, so a pathological blob is never unmarshaled.
	// The reference bails inside its pre-canonicalize bounds walk; this is the same
	// stance at the byte boundary. See bounds.go for the derivation.
	if len(raw) > MaxGrantBodyBytes {
		return false, GrantReasonSchema
	}
	// The grant is a signed artifact: encoding/json rewrites invalid UTF-8 or a
	// lone surrogate to U+FFFD, so reject both before parsing.
	if !utf8.Valid(raw) || ContainsLoneSurrogateEscape(raw) {
		return false, GrantReasonSchema
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false, GrantReasonSchema
	}
	// Post-parse structural bounds walk, mirroring the reference node, depth, and
	// character budgets so both implementations reject the same over-deep or
	// over-wide object. This runs before schema validation walks the fields, so a
	// pathological structure short circuits here rather than deep inside field
	// checks or canonicalization.
	if !withinBodyBounds(obj) {
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

	// Presentation binding. When the caller authenticated the presenting principal
	// it supplies Presenter here, which must equal the signed subject, so a stolen
	// grant is not presentable by another principal inside its window. An empty
	// Presenter skips the check and leaves the grant a bearer artifact the audience
	// binds out of band. This runs after the audience check and before the window
	// checks, so a stolen grant rejects on the binding rather than on its clock.
	if ctx.Presenter != "" {
		subject, _ := obj["subject"].(string)
		if ctx.Presenter != subject {
			return false, GrantReasonSubject
		}
	}

	issuedAt, _ := obj["issuedAt"].(string)
	expiresAt, _ := obj["expiresAt"].(string)
	start, okStart := ParseInkTimestampMs(issuedAt)
	end, okEnd := ParseInkTimestampMs(expiresAt)
	if !okStart || !okEnd {
		return false, GrantReasonSchema
	}

	// Caller-tightened lifetime. The schema already enforced the profile ceiling
	// before the signature; here a caller may shorten it further for this check.
	// The value is clamped so it can only tighten, never loosen, and is checked
	// after the signature so the policy value is not observable on an
	// unauthenticated grant. A window past the tightened cap rejects as schema.
	//
	// A zero MaxLifetimeMs means unset: use the profile default, no tightening,
	// since a Go zero-value integer is indistinguishable from an unset one. A
	// NEGATIVE value is a verifier input error, not "use default": a negative cap
	// admits no window at all, so it fails closed as schema, mirroring the
	// reference, which rejects a maxLifetimeMs that is not a finite number greater
	// than zero (the non-finite case is TS-only, since this integer field cannot
	// express NaN or Infinity).
	if ctx.MaxLifetimeMs < 0 {
		return false, GrantReasonSchema
	}
	if ctx.MaxLifetimeMs > 0 {
		cap := ctx.MaxLifetimeMs
		if cap > MaxGrantLifetimeMs {
			cap = MaxGrantLifetimeMs
		}
		if end-start > cap {
			return false, GrantReasonSchema
		}
	}

	// Validity window. The verifier clock must be a strict INK timestamp; a
	// malformed clock is a verifier input error and fails closed as schema, not a
	// window verdict the verifier never computed. Lower bound inclusive, upper
	// bound exclusive.
	now, okNow := ParseInkTimestampMs(ctx.Now)
	if !okNow {
		return false, GrantReasonSchema
	}
	if now < start {
		return false, GrantReasonNotYetValid
	}
	if now >= end {
		return false, GrantReasonExpired
	}

	issuer, _ := obj["issuer"].(string)
	grantID, _ := obj["grantId"].(string)
	key := GrantKey{Issuer: issuer, GrantID: grantID}

	// Replay: an (issuer, grantId) pair already seen at this receiver is a replay.
	// Keying on the pair keeps one issuer's ids from colliding with another's.
	for _, seen := range ctx.SeenGrants {
		if seen.Issuer == issuer && seen.GrantID == grantID {
			return false, GrantReasonReplay
		}
	}

	// Revocation: the receiver's denylist predicate, keyed by the same pair.
	if ctx.IsRevoked != nil && ctx.IsRevoked(key) {
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
	// The window must be strictly positive and no longer than the maximum grant
	// lifetime: a zero or negative window is malformed, and an over-long window is
	// out of profile. Both match the reference refine.
	if end <= start || end-start > MaxGrantLifetimeMs {
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
