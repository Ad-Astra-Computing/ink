package ink

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
)

// The "INK Agent Authorization" sign-in challenge, the one artifact the flow
// profile adds on top of the authorization grant (specs/ink-agent-authorization.md).
// A relying party signs a challenge to request sign-in; the user's agent verifies
// it against an active RP signing key before minting the grant that answers it.
// This mirrors the TypeScript verifyAuthorizationChallenge byte for byte: a byte
// cap, strict schema validation with the parser-independent rp and redirectUri
// rules, then a body signature over "tulpa/sign\n" + JCS(challenge without the
// signature field) verified against an active in-window key with RFC 8032 strict
// Ed25519, then the validity window. It fails closed and returns a typed reason.

// authorizationChallengeTopLevelKeys is the exact set of members a challenge may
// carry. All are required; any unknown key rejects.
var authorizationChallengeTopLevelKeys = map[string]bool{
	"protocol": true, "type": true, "rp": true, "nonce": true,
	"requestedScope": true, "redirectUri": true, "issuedAt": true,
	"expiresAt": true, "signature": true,
}

var authorizationChallengeRequiredKeys = []string{
	"protocol", "type", "rp", "nonce", "requestedScope",
	"redirectUri", "issuedAt", "expiresAt", "signature",
}

const (
	challengeRPMax         = 512
	challengeNonceMin      = 16
	challengeNonceMax      = 256
	challengeScopeEntryMax = 128
	challengeScopeMax      = 64
	challengeRedirectMax   = 2048
)

// MaxChallengeLifetimeMs is the maximum challenge lifetime in milliseconds. It
// mirrors the reference MAX_CHALLENGE_LIFETIME_MS: ten minutes, the same
// login/bootstrap ceiling the grant applies. A challenge whose window is longer
// is out of profile and rejects structurally, independent of the verifier clock.
const MaxChallengeLifetimeMs = 10 * 60 * 1000

// MaxChallengeBodyBytes is the byte-length ceiling on a raw challenge body before
// it is parsed. It pins the spec's Byte bound rule: a challenge presented as raw
// bytes must be rejected as schema when longer than 65536 bytes, before decoding.
// Both implementations receive bytes and enforce the bound themselves, and the
// TypeScript counterpart MAX_CHALLENGE_BODY_BYTES carries the same value.
const MaxChallengeBodyBytes = 64 * 1024

// challengeIDDomain is the domain string the derived grantId digest covers,
// followed by a newline and the JCS of the four binding fields.
const challengeIDDomain = "ink/challenge-id"

// identityAssertScope is the token every requestedScope must include and every
// identity assertion must carry.
const identityAssertScope = "identity.assert"

// challengeScopeRegistry is the profile's closed scope registry. Every
// requestedScope entry must be one of these tokens.
var challengeScopeRegistry = map[string]bool{
	"identity.assert": true, "profile.read": true, "agent.message.send": true,
}

var (
	challengeLabelRe    = regexp.MustCompile(`^[a-z0-9-]+$`)
	challengeAllDigitRe = regexp.MustCompile(`^[0-9]+$`)
	challengeRPPortRe   = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
)

// AuthorizationChallengeReason is the stable discriminator mirroring the
// TypeScript AuthorizationChallengeReason. An empty reason accompanies an accept.
type AuthorizationChallengeReason string

const (
	ChallengeReasonSchema      AuthorizationChallengeReason = "schema"
	ChallengeReasonSignature   AuthorizationChallengeReason = "signature"
	ChallengeReasonNotYetValid AuthorizationChallengeReason = "not_yet_valid"
	ChallengeReasonExpired     AuthorizationChallengeReason = "expired"
)

// AuthorizationChallengeContext is everything the verifier needs beyond the
// candidate key set. Now is the verifier clock, a strict INK timestamp, consulted
// both for the key validity window in the signature step and for the challenge
// validity window, never at the RP-chosen issuedAt. A malformed Now fails closed
// as schema wherever it is consulted.
type AuthorizationChallengeContext struct {
	Now string
}

// deriveRPOrigin derives the RP origin from a bare-host did:web identifier by
// explicit string rules, never a URL parser. It returns the origin and true, or
// false when rp is not a bare-host did:web under the profile grammar. It mirrors
// the reference deriveRpOrigin.
func deriveRPOrigin(rp string) (string, bool) {
	const prefix = "did:web:"
	if !strings.HasPrefix(rp, prefix) {
		return "", false
	}
	rest := rp[len(prefix):]
	if rest == "" {
		return "", false
	}
	host := rest
	port := ""
	hasPort := false
	if idx := strings.Index(rest, "%3A"); idx >= 0 {
		host = rest[:idx]
		port = rest[idx+3:]
		hasPort = true
		// Exactly one port marker: a second %3A is malformed.
		if strings.Contains(port, "%3A") {
			return "", false
		}
	}
	// The host carries no percent-encoding: an A-label host is already ASCII, and
	// a leftover % (for example a lowercase %3a the uppercase marker missed) is
	// malformed rather than a port separator.
	if strings.Contains(host, "%") {
		return "", false
	}
	if !isBareHost(host) {
		return "", false
	}
	if hasPort && !isRPPort(port) {
		return "", false
	}
	origin := "https://" + host
	if hasPort {
		origin += ":" + port
	}
	return origin, true
}

// isBareHost reports whether host is one or more dot-separated LDH labels, each 1
// to 63 characters of lowercase a-z, digits, and hyphens, not starting or ending
// with a hyphen, with no empty label, and a final label that is not all-numeric.
func isBareHost(host string) bool {
	if host == "" {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		if !challengeLabelRe.MatchString(label) {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	last := labels[len(labels)-1]
	return !challengeAllDigitRe.MatchString(last)
}

// isRPPort reports whether port is a decimal 1 to 65535 with no leading zeros and
// is not the default 443 (whose derived origin would collide with the default).
func isRPPort(port string) bool {
	if !challengeRPPortRe.MatchString(port) {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || n == 443 {
		return false
	}
	return true
}

// isChallengeRedirect reports whether redirectURI is admissible for a challenge
// whose RP origin is origin, by explicit string rules with no URL parsing: it
// must be the derived origin followed immediately by / and an optional path and
// query under a literal prefix match, and must not contain #, \, any ASCII
// control character (U+0000-U+001F, U+007F) or ASCII whitespace (not trimmed).
func isChallengeRedirect(redirectURI, origin string) bool {
	for _, r := range redirectURI {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	if strings.ContainsAny(redirectURI, "#\\") {
		return false
	}
	return strings.HasPrefix(redirectURI, origin+"/")
}

// VerifyAuthorizationChallenge verifies a sign-in challenge against the RP card's
// candidate signing keys and a verification context. It fails closed and returns
// a typed reason on the first failure.
//
// Check order (each returns its own reason):
//  1. structural schema + byte safety + rp/redirect/scope/window rules -> schema
//  2. RP signature against an active, in-window signing key            -> signature
//  3. validity window                                                  -> not_yet_valid | expired
func VerifyAuthorizationChallenge(raw []byte, keys []CandidateKey, ctx AuthorizationChallengeContext) (bool, AuthorizationChallengeReason) {
	// Byte cap before the decoder: a body past the schema-derived ceiling is
	// refused without unmarshaling, the same stance the grant takes.
	if len(raw) > MaxChallengeBodyBytes {
		return false, ChallengeReasonSchema
	}
	// The artifact is signed over its raw bytes, so every text-level rule of
	// ink-signed-string-safety.md runs before parsing. Routed through the
	// shared parser so a new rule cannot reach some verifiers and not others.
	obj, okParse := ParseSignedObject(raw)
	if !okParse {
		return false, ChallengeReasonSchema
	}
	if !withinBodyBounds(obj) {
		return false, ChallengeReasonSchema
	}
	signature, ok := validateAuthorizationChallenge(obj)
	if !ok {
		return false, ChallengeReasonSchema
	}
	if !signatureRe.MatchString(signature) {
		return false, ChallengeReasonSchema
	}
	// The verifier clock feeds both the key window in the signature step and the
	// validity window below. A malformed clock is a verifier input error and fails
	// closed as schema.
	nowMs, okNow := ParseInkTimestampMs(ctx.Now)
	if !okNow {
		return false, ChallengeReasonSchema
	}
	// Signature before the window, so a rejection never leaks whether the window
	// would have passed.
	if !verifyChallengeSignature(obj, signature, keys, nowMs) {
		return false, ChallengeReasonSignature
	}
	issuedAt, _ := obj["issuedAt"].(string)
	expiresAt, _ := obj["expiresAt"].(string)
	start, okStart := ParseInkTimestampMs(issuedAt)
	end, okEnd := ParseInkTimestampMs(expiresAt)
	if !okStart || !okEnd {
		return false, ChallengeReasonSchema
	}
	if nowMs < start {
		return false, ChallengeReasonNotYetValid
	}
	if nowMs >= end {
		return false, ChallengeReasonExpired
	}
	return true, ""
}

// verifyChallengeSignature verifies the challenge body signature against an active
// signing key of the RP card, evaluated at the verifier clock. Only active keys
// are tried: a live challenge is never historical, so a retired key must not
// verify one, and a revoked key never verifies. The window is evaluated at now,
// not the RP-chosen issuedAt. A card that yields no usable active key fails.
func verifyChallengeSignature(obj map[string]interface{}, signature string, keys []CandidateKey, nowMs int64) bool {
	unsigned := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		if k != "signature" {
			unsigned[k] = v
		}
	}
	canonical, err := canonicalizeJSON(unsigned)
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg := []byte("tulpa/sign\n" + canonical)
	if len(keys) > maxCandidateKeys {
		keys = keys[:maxCandidateKeys]
	}
	for _, k := range keys {
		if k.Status != "active" || !keyValidAtTime(k, nowMs) {
			continue
		}
		if len(k.PublicKey) != ed25519.PublicKeySize || !isStrongEd25519PublicKey(k.PublicKey) {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(k.PublicKey), msg, sig) {
			return true
		}
	}
	return false
}

// validateAuthorizationChallenge validates the parsed challenge object against the
// schema and returns the signature string on success. It rejects a missing
// required member, an extra member, a wrong-typed or out-of-bound field, an
// explicit null, an invalid timestamp, an inverted or over-long window, a
// non-bare-host rp, an out-of-profile redirectUri, and a malformed requestedScope.
// String bounds are counted in UTF-16 code units to match the reference.
func validateAuthorizationChallenge(obj map[string]interface{}) (string, bool) {
	for k := range obj {
		if !authorizationChallengeTopLevelKeys[k] {
			return "", false
		}
	}
	for _, k := range authorizationChallengeRequiredKeys {
		if _, present := obj[k]; !present {
			return "", false
		}
	}
	if protocol, ok := obj["protocol"].(string); !ok || protocol != "ink/0.1" {
		return "", false
	}
	// A single spelling: the challenge is a new type with no legacy dual-accept.
	if t, ok := obj["type"].(string); !ok || t != "network.ink.authorization_challenge" {
		return "", false
	}
	rp, ok := obj["rp"].(string)
	if !ok || !boundedString(rp, 1, challengeRPMax) {
		return "", false
	}
	origin, okOrigin := deriveRPOrigin(rp)
	if !okOrigin {
		return "", false
	}
	if !boundedString(obj["nonce"], challengeNonceMin, challengeNonceMax) {
		return "", false
	}
	redirectURI, ok := obj["redirectUri"].(string)
	if !ok || !boundedString(redirectURI, 1, challengeRedirectMax) {
		return "", false
	}
	if !isChallengeRedirect(redirectURI, origin) {
		return "", false
	}
	if !validateRequestedScope(obj["requestedScope"]) {
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
	// The window must be strictly positive and no longer than the maximum
	// challenge lifetime.
	if end <= start || end-start > MaxChallengeLifetimeMs {
		return "", false
	}
	signature, ok := obj["signature"].(string)
	if !ok || signature == "" {
		return "", false
	}
	return signature, true
}

// validateRequestedScope reports whether v is a non-empty array of 1 to 64
// distinct registry tokens, each 1 to 128 UTF-16 code units, that includes
// identity.assert. An entry outside the registry is malformed on the request side.
func validateRequestedScope(v interface{}) bool {
	scope, ok := v.([]interface{})
	if !ok || len(scope) < 1 || len(scope) > challengeScopeMax {
		return false
	}
	seen := make(map[string]bool, len(scope))
	hasIdentityAssert := false
	for _, entry := range scope {
		s, ok := entry.(string)
		if !ok {
			return false
		}
		if !boundedString(s, 1, challengeScopeEntryMax) {
			return false
		}
		if !challengeScopeRegistry[s] {
			return false
		}
		if seen[s] {
			return false
		}
		seen[s] = true
		if s == identityAssertScope {
			hasIdentityAssert = true
		}
	}
	return hasIdentityAssert
}

// DeriveChallengeGrantID derives the identity assertion's grantId from a verified
// challenge's four binding fields. It is the base64url encoding without padding of
// the SHA-256 digest of the domain string "ink/challenge-id", a newline, then the
// JCS canonicalization of the object with exactly rp, nonce, issuedAt, and
// expiresAt. It mirrors the reference deriveChallengeGrantId: NOT the raw nonce,
// so two RPs sharing a nonce or one RP reusing one in a fresh window cannot
// collide, and challenges differing in any binding field derive distinct ids.
func DeriveChallengeGrantID(rp, nonce, issuedAt, expiresAt string) string {
	binding := map[string]interface{}{
		"rp":        rp,
		"nonce":     nonce,
		"issuedAt":  issuedAt,
		"expiresAt": expiresAt,
	}
	canonical, err := canonicalizeJSON(binding)
	if err != nil {
		return ""
	}
	h := sha256.Sum256([]byte(challengeIDDomain + "\n" + canonical))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
