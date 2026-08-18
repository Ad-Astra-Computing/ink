package ink

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
)

// A linear authorization chain: 2 to 4 delegation links, each the grant field
// model with a network.ink.delegation_link type and a parent hash, each hop
// narrowing the last. The chain is the post-1.0 delegation extension on top of the
// authorization-grant primitive (specs/ink-authorization-chain.md). This mirrors
// the TypeScript verifyAuthorizationChain byte for byte: a byte cap, strict schema
// validation on signed bytes, then continuity (issuer-subject seam and parent
// hash) and monotonic attenuation, then per-link body signatures over
// "tulpa/sign\n" + JCS(link without the signature field) against active issuer
// keys, then the audience, presentation-binding, window, replay, revocation, and
// owner-verification context checks. It fails closed and returns a typed reason on
// the first failure.

// chainWrapperKeys is the exact set of members a presentation wrapper may carry.
// The wrapper is unsigned and carries no signature of its own.
var chainWrapperKeys = map[string]bool{
	"protocol": true, "type": true, "links": true,
}

// delegationLinkTopLevelKeys is the exact set of members a delegation link may
// carry. All are required except requireVerifiedOwner (optional) and parent
// (present on non-root links, absent on the root, enforced by position).
var delegationLinkTopLevelKeys = map[string]bool{
	"protocol": true, "type": true, "issuer": true, "subject": true,
	"audience": true, "scope": true, "grantId": true, "issuedAt": true,
	"expiresAt": true, "requireVerifiedOwner": true, "parent": true, "signature": true,
}

// delegationLinkRequiredKeys is the subset that must be present on every link.
// requireVerifiedOwner is optional and parent is position-dependent, so neither is
// listed here.
var delegationLinkRequiredKeys = []string{
	"protocol", "type", "issuer", "subject", "audience",
	"scope", "grantId", "issuedAt", "expiresAt", "signature",
}

const (
	minChainLinks = 2
	maxChainLinks = 4

	// Lifetime ceilings by link position, checked structurally in pass 1 on the
	// signed issuedAt and expiresAt, clock-independent. An intermediate link only
	// authorizes further delegation within a day-scale window; the final link is the
	// credential exercised at the audience and carries the tight bootstrap ceiling.
	intermediateLinkMaxLifetimeMs = 24 * 60 * 60 * 1000
	finalLinkMaxLifetimeMs        = 10 * 60 * 1000
)

// MaxChainBodyBytes is the byte-length ceiling on a raw chain body before it is
// parsed. It pins the spec's Raw byte cap rule: a chain presented as raw bytes must
// be rejected as schema when longer than 65536 bytes, before decoding. Both
// implementations receive bytes and enforce the bound themselves, and the
// TypeScript counterpart MAX_CHAIN_BODY_BYTES carries the same value.
const MaxChainBodyBytes = 64 * 1024

// delegationLinkType is the single spelling a delegation link carries; there is no
// legacy dual-accept alias, and a grant type is never accepted as a chain link.
const delegationLinkType = "network.ink.delegation_link"

// authorizationChainType is the single spelling of the presentation wrapper.
const authorizationChainType = "network.ink.authorization_chain"

// parentHashDomain is the domain string the parent digest covers, followed by a
// single newline and the JCS of the full parent link including its signature.
const parentHashDomain = "ink/delegation-link"

// delegationExtendScope is the reserved delegability token: its presence in a
// link's scope authorizes exactly one further re-delegation below it.
const delegationExtendScope = "delegation.extend"

// parentHashRe is the shape of a parent digest: 43 base64url characters, the
// encoding of a 32-byte SHA-256 digest without padding.
var parentHashRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// AuthorizationChainReason is the stable discriminator mirroring the TypeScript
// AuthorizationChainReason. The set is exactly eleven reasons: nine reused verbatim
// from the grant, plus chain and attenuation. An empty reason accompanies an accept.
type AuthorizationChainReason string

const (
	ChainReasonSchema          AuthorizationChainReason = "schema"
	ChainReasonChain           AuthorizationChainReason = "chain"
	ChainReasonAttenuation     AuthorizationChainReason = "attenuation"
	ChainReasonSignature       AuthorizationChainReason = "signature"
	ChainReasonAudience        AuthorizationChainReason = "audience"
	ChainReasonSubject         AuthorizationChainReason = "subject"
	ChainReasonNotYetValid     AuthorizationChainReason = "not_yet_valid"
	ChainReasonExpired         AuthorizationChainReason = "expired"
	ChainReasonReplay          AuthorizationChainReason = "replay"
	ChainReasonRevoked         AuthorizationChainReason = "revoked"
	ChainReasonOwnerUnverified AuthorizationChainReason = "owner_unverified"
)

// ChainIssuerKey is a resolved signing key for one link's issuer, the output of
// the Agent Card machinery pass 2 runs per issuer. Only an active key verifies a
// link, so a retired or a revoked key never does; a verifier that cannot resolve an
// issuer to a usable active key supplies a non-active entry and the link rejects as
// signature.
type ChainIssuerKey struct {
	PublicKey []byte
	Status    string // active | retired | revoked
}

// AuthorizationChainContext is everything the verifier needs beyond the per-link
// issuer keys. Audience is the verifying service, compared against every link's
// signed audience. Now is the verifier clock, a strict INK timestamp; a malformed
// Now fails closed as schema wherever it is consulted. IssuerKeys resolves each
// link's issuer to a signing key, aligned root-first to the links. Presenter is the
// authenticated presenting principal; when non-empty it must equal the FINAL link's
// subject, and an empty Presenter skips the binding. SeenGrants is the replay seen
// set, READ against the final link's (issuer, grantId) pair only; this verifier
// never records. IsRevoked is the revocation predicate, consulted for EVERY link's
// pair. VerifiedOwnerStatus is the owner-verification hook, consulted when any link
// requires it (a conjunction over the chain); an empty string is unverified.
type AuthorizationChainContext struct {
	Audience            string
	Now                 string
	IssuerKeys          []ChainIssuerKey
	Presenter           string
	SeenGrants          []GrantKey
	IsRevoked           func(key GrantKey) bool
	VerifiedOwnerStatus string
}

// parsedChainLink holds a validated link's fields plus the raw decoded object, so
// the parent hash is computed over the exact presented bytes.
type parsedChainLink struct {
	raw       map[string]interface{}
	issuer    string
	subject   string
	audience  string
	grantID   string
	signature string
	parent    string
	hasParent bool
	scope     []string
	scopeSet  map[string]bool
	reqOwner  bool
	startMs   int64
	endMs     int64
}

// VerifyAuthorizationChain verifies a presented authorization chain against a
// verification context. It fails closed and returns a typed reason on the first
// failure, in the same three-pass order as the reference: pass 1 structure
// (schema, then chain continuity, then attenuation) on the signed bytes, pass 2
// per-link signatures root to head, then pass 3 context.
func VerifyAuthorizationChain(raw []byte, ctx AuthorizationChainContext) (bool, AuthorizationChainReason) {
	// Byte cap before the decoder touches the bytes.
	if len(raw) > MaxChainBodyBytes {
		return false, ChainReasonSchema
	}
	// The artifact is signed over its raw bytes, so every text-level rule of
	// ink-signed-string-safety.md runs before parsing. Routed through the
	// shared parser so a new rule cannot reach some verifiers and not others.
	obj, okParse := ParseSignedObject(raw)
	if !okParse {
		return false, ChainReasonSchema
	}
	if !withinBodyBounds(obj) {
		return false, ChainReasonSchema
	}

	// ── Pass 1a: wrapper and per-link schema ──
	for k := range obj {
		if !chainWrapperKeys[k] {
			return false, ChainReasonSchema
		}
	}
	for _, k := range []string{"protocol", "type", "links"} {
		if _, present := obj[k]; !present {
			return false, ChainReasonSchema
		}
	}
	if protocol, ok := obj["protocol"].(string); !ok || protocol != "ink/0.1" {
		return false, ChainReasonSchema
	}
	if t, ok := obj["type"].(string); !ok || t != authorizationChainType {
		return false, ChainReasonSchema
	}
	rawLinks, ok := obj["links"].([]interface{})
	if !ok || len(rawLinks) < minChainLinks || len(rawLinks) > maxChainLinks {
		return false, ChainReasonSchema
	}
	n := len(rawLinks)
	links := make([]parsedChainLink, 0, n)
	for _, rl := range rawLinks {
		linkObj, ok := rl.(map[string]interface{})
		if !ok {
			return false, ChainReasonSchema
		}
		parsed, ok := validateDelegationLink(linkObj)
		if !ok {
			return false, ChainReasonSchema
		}
		links = append(links, parsed)
	}

	// Per-position schema rules: the root carries no parent and every non-root link
	// carries one, and each link's lifetime is within its position ceiling.
	for i := 0; i < n; i++ {
		isRoot := i == 0
		isFinal := i == n-1
		if isRoot && links[i].hasParent {
			return false, ChainReasonSchema
		}
		if !isRoot && !links[i].hasParent {
			return false, ChainReasonSchema
		}
		ceiling := int64(intermediateLinkMaxLifetimeMs)
		if isFinal {
			ceiling = finalLinkMaxLifetimeMs
		}
		if links[i].endMs-links[i].startMs > ceiling {
			return false, ChainReasonSchema
		}
	}

	// ── Pass 1b: continuity (issuer-subject seam and parent hash) ──
	for i := 1; i < n; i++ {
		if links[i].issuer != links[i-1].subject {
			return false, ChainReasonChain
		}
		expected, ok := deriveChainParentHash(links[i-1].raw)
		if !ok || links[i].parent != expected {
			return false, ChainReasonChain
		}
	}

	// ── Pass 1c: attenuation (scope subset, window nesting, delegability) ──
	for i := 1; i < n; i++ {
		parent := links[i-1]
		child := links[i]
		for _, token := range child.scope {
			if !parent.scopeSet[token] {
				return false, ChainReasonAttenuation
			}
		}
		if !(parent.startMs <= child.startMs && child.endMs <= parent.endMs) {
			return false, ChainReasonAttenuation
		}
		if !parent.scopeSet[delegationExtendScope] {
			return false, ChainReasonAttenuation
		}
	}

	// ── Pass 2: signatures, root to head ──
	// The verifier clock is consulted here first (key activity), so a malformed
	// clock fails closed as schema before any signature check, not as signature.
	nowMs, okNow := ParseInkTimestampMs(ctx.Now)
	if !okNow {
		return false, ChainReasonSchema
	}
	for i := 0; i < n; i++ {
		if i >= len(ctx.IssuerKeys) {
			return false, ChainReasonSignature
		}
		if !verifyChainLinkSignature(links[i].raw, links[i].signature, ctx.IssuerKeys[i]) {
			return false, ChainReasonSignature
		}
	}

	// ── Pass 3: context ──
	// Audience across every link (confused-deputy defense).
	for i := 0; i < n; i++ {
		if links[i].audience != ctx.Audience {
			return false, ChainReasonAudience
		}
	}

	// Presentation binding: a supplied presenter must equal the final link's
	// subject. An empty presenter skips the binding.
	final := links[n-1]
	if ctx.Presenter != "" && ctx.Presenter != final.subject {
		return false, ChainReasonSubject
	}

	// Validity window: now in [issuedAt, expiresAt) for every link.
	for i := 0; i < n; i++ {
		if nowMs < links[i].startMs {
			return false, ChainReasonNotYetValid
		}
		if nowMs >= links[i].endMs {
			return false, ChainReasonExpired
		}
	}

	// Replay: READ the seen set on the final link only. Intermediate links are not
	// replay-checked. The verifier never records.
	for _, seen := range ctx.SeenGrants {
		if seen.Issuer == final.issuer && seen.GrantID == final.grantID {
			return false, ChainReasonReplay
		}
	}

	// Revocation: every link's (issuer, grantId) pair. A revoked pair anywhere in
	// the chain rejects the whole chain.
	if ctx.IsRevoked != nil {
		for i := 0; i < n; i++ {
			if ctx.IsRevoked(GrantKey{Issuer: links[i].issuer, GrantID: links[i].grantID}) {
				return false, ChainReasonRevoked
			}
		}
	}

	// Owner verification is a conjunction: if any link requires a verified owner the
	// whole chain does, and the supplied status must be verified. Absent is unverified.
	requiresOwner := false
	for i := 0; i < n; i++ {
		if links[i].reqOwner {
			requiresOwner = true
			break
		}
	}
	if requiresOwner && ctx.VerifiedOwnerStatus != "verified" {
		return false, ChainReasonOwnerUnverified
	}

	return true, ""
}

// validateDelegationLink validates a single link object against the delegation-link
// schema and returns its parsed fields on success. It rejects a missing required
// member, an extra member, a wrong-typed or out-of-bound field, an explicit null on
// any field, an invalid timestamp, a non-positive window, a malformed scope, and a
// malformed parent or signature shape. The parent, when present, must be 43
// base64url characters; its presence-by-position is enforced by the caller because
// it depends on the link's index. The per-position lifetime ceiling is likewise the
// caller's, since it depends on whether the link is the final one.
func validateDelegationLink(obj map[string]interface{}) (parsedChainLink, bool) {
	var p parsedChainLink
	p.raw = obj
	for k := range obj {
		if !delegationLinkTopLevelKeys[k] {
			return p, false
		}
	}
	for _, k := range delegationLinkRequiredKeys {
		if _, present := obj[k]; !present {
			return p, false
		}
	}
	if protocol, ok := obj["protocol"].(string); !ok || protocol != "ink/0.1" {
		return p, false
	}
	if t, ok := obj["type"].(string); !ok || t != delegationLinkType {
		return p, false
	}
	issuer, ok := obj["issuer"].(string)
	if !ok || !boundedString(issuer, 1, 512) {
		return p, false
	}
	subject, ok := obj["subject"].(string)
	if !ok || !boundedString(subject, 1, 512) {
		return p, false
	}
	audience, ok := obj["audience"].(string)
	if !ok || !boundedString(audience, 1, 512) {
		return p, false
	}
	grantID, ok := obj["grantId"].(string)
	if !ok || !boundedString(grantID, grantIDMin, grantIDMax) {
		return p, false
	}
	scope, scopeSet, ok := validateDelegationScope(obj["scope"])
	if !ok {
		return p, false
	}
	issuedAt, ok := obj["issuedAt"].(string)
	if !ok {
		return p, false
	}
	start, okStart := ParseInkTimestampMs(issuedAt)
	if !okStart {
		return p, false
	}
	expiresAt, ok := obj["expiresAt"].(string)
	if !ok {
		return p, false
	}
	end, okEnd := ParseInkTimestampMs(expiresAt)
	if !okEnd {
		return p, false
	}
	// The window must be strictly positive; the position-dependent lifetime ceiling
	// is enforced by the caller.
	if end <= start {
		return p, false
	}
	if req, present := obj["requireVerifiedOwner"]; present {
		b, isBool := req.(bool)
		if !isBool {
			return p, false
		}
		p.reqOwner = b
	}
	if pv, present := obj["parent"]; present {
		ps, isStr := pv.(string)
		if !isStr || !parentHashRe.MatchString(ps) {
			return p, false
		}
		p.parent = ps
		p.hasParent = true
	}
	signature, ok := obj["signature"].(string)
	if !ok || !signatureRe.MatchString(signature) {
		return p, false
	}
	p.issuer = issuer
	p.subject = subject
	p.audience = audience
	p.grantID = grantID
	p.signature = signature
	p.scope = scope
	p.scopeSet = scopeSet
	p.startMs = start
	p.endMs = end
	return p, true
}

// validateDelegationScope reports whether v is a non-empty array of 1 to 64
// distinct strings, each 1 to 128 UTF-16 code units, and returns the tokens and
// their set. Distinctness matches the reference so two implementations count the
// same set.
func validateDelegationScope(v interface{}) ([]string, map[string]bool, bool) {
	arr, ok := v.([]interface{})
	if !ok || len(arr) < 1 || len(arr) > scopeMax {
		return nil, nil, false
	}
	tokens := make([]string, 0, len(arr))
	set := make(map[string]bool, len(arr))
	for _, entry := range arr {
		s, ok := entry.(string)
		if !ok || !boundedString(s, 1, scopeEntryMax) {
			return nil, nil, false
		}
		if set[s] {
			return nil, nil, false
		}
		set[s] = true
		tokens = append(tokens, s)
	}
	return tokens, set, true
}

// deriveChainParentHash computes the base64url-no-padding SHA-256 digest of the
// domain string "ink/delegation-link", a newline, and the JCS canonicalization of
// the full parent link INCLUDING its signature. It mirrors the reference
// deriveDelegationParentHash.
func deriveChainParentHash(parentObj map[string]interface{}) (string, bool) {
	canonical, err := canonicalizeJSON(parentObj)
	if err != nil {
		return "", false
	}
	h := sha256.Sum256([]byte(parentHashDomain + "\n" + canonical))
	return base64.RawURLEncoding.EncodeToString(h[:]), true
}

// verifyChainLinkSignature verifies a link's body signature against its resolved
// issuer key. Only an active key verifies: a retired or a revoked key never does,
// the chain's fast revocation lever for a compromised delegate. The signed bytes
// are "tulpa/sign\n" + JCS(link without the signature field), matching the grant.
func verifyChainLinkSignature(linkObj map[string]interface{}, signature string, key ChainIssuerKey) bool {
	if key.Status != "active" {
		return false
	}
	if len(key.PublicKey) != ed25519.PublicKeySize || !isStrongEd25519PublicKey(key.PublicKey) {
		return false
	}
	unsigned := make(map[string]interface{}, len(linkObj))
	for k, v := range linkObj {
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
	return ed25519.Verify(ed25519.PublicKey(key.PublicKey), []byte("tulpa/sign\n"+canonical), sig)
}
