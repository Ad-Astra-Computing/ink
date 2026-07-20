package ink

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"math"
	"strings"
)

// Self-authenticating Agent Card verifier (ink-agent-card-signature.md §5).
//
// This is an independent Go verifier at behavioral parity with the TypeScript
// reference in src/crypto/agent-card-signature.ts: it makes byte-for-byte the
// same accept/reject decisions with matching reason semantics on the same input.
// It reuses the repo's single crypto stack — JCS (Protocol §3.2, canonicalizeJSON),
// base64url no-padding (§3.3) and strict RFC 8032 Ed25519 via the same
// isStrongEd25519PublicKey gate the transport verifier uses — and introduces no
// second crypto path.
//
// VerifyAgentCardSignature is a PURE function of its inputs: the caller supplies
// any cached prior card and any resolved DID-document keys. The library never
// fetches and never manages a ratchet store; the typed result and its audit
// events are the only seam a consumer acts on. The card is a decoded
// map[string]interface{}, the same shape ValidateAgentCard consumes, so
// canonicalization covers every field.

const (
	// cardSignatureDomain is the domain-separation prefix for the card proof
	// (§3.2). Not version-keyed.
	cardSignatureDomain = "ink/agent-card\n"
	// cardRotationDomain is the domain-separation prefix for a rotation-chain
	// link (§4.1).
	cardRotationDomain = "ink/card-rotation\n"
	// legacyBootstrapKeyID is the literal keyId a legacy single-key card MUST use
	// (§3.3).
	legacyBootstrapKeyID = "bootstrap"
	// maxRotationChainLinks caps a rotation chain; a longer chain is rejected
	// (§4.1).
	maxRotationChainLinks = 32
)

type cardPrincipalKind int

const (
	kindKeyDerived cardPrincipalKind = iota
	kindDidWeb
	kindOther
)

// VerifyAgentCardSignature verifies a fetched Agent Card under §5 steps 2-4
// (proof, rooting, continuity) plus the unsigned-card ratchet of §7. It assumes
// the caller already ran the discovery fetch contract (§5 step 1); as a
// defensive backstop it re-checks that card["agentId"] equals the requested
// agentID.
//
// Pure: no I/O. The result's Authenticated/Rejected/Reason/AuditEvents is the
// whole seam a consumer acts on. It never panics out: a hostile card whose shape
// trips an internal invariant fails closed as invalid_card, and a present
// cardSignature is never demoted to unsigned (§3.4).
func VerifyAgentCardSignature(card map[string]interface{}, agentID string, options CardVerifyOptions) (result CardVerifyResult) {
	defer func() {
		if r := recover(); r != nil {
			result = rejectCard(ReasonInvalidCard)
		}
	}()

	if card == nil || agentID == "" {
		return rejectCard(ReasonInvalidCard)
	}
	// §5 step 1 backstop: identity binding.
	if cid, ok := card["agentId"].(string); !ok || cid != agentID {
		return rejectCard(ReasonIdentityMismatch)
	}

	kind := cardPrincipalKindOf(agentID)
	cachedCard := options.CachedCard

	// Unsigned path: the only cards this spec treats as unsigned are those with
	// no `cardSignature` at all (§3.4). A present-but-null member is not a card
	// signature; a present-but-malformed member fails closed rather than demoting.
	rawSig, present := card["cardSignature"]
	if !present || rawSig == nil {
		return verifyUnsignedCard(kind, cachedCard, options.Profile)
	}
	sigMap, ok := rawSig.(map[string]interface{})
	if !ok {
		return rejectCard(ReasonInvalidCard)
	}
	keyID, _ := sigMap["keyId"].(string)
	signature, _ := sigMap["signature"].(string)

	// §6: when `cardSignature` is present, `keySetVersion` is a MUST. It is the
	// SOLE monotonic quantity the continuity rules compare, so a signed card that
	// omits it would silently skip the version-regression check. The schema keeps
	// it optional for backward-compat with unsigned cards; the enforcement is
	// verifier-side.
	if _, ok := cardNumber(card["keySetVersion"]); !ok {
		return rejectCard(ReasonMissingKeySetVersion)
	}

	// ── §5 step 2: proof ──
	proof := verifyCardProof(card, keyID, signature)
	if !proof.ok {
		return rejectCard(proof.reason)
	}

	// ── §5 step 3: rooting ──
	rooting := rootCardSigner(card, agentID, kind, proof.signerKey, cachedCard, options)
	if rooting.rejected {
		return CardVerifyResult{Authenticated: false, Rejected: true, Reason: rooting.reason, AuditEvents: rooting.auditEvents}
	}

	// ── §5 step 4: continuity and rollback ──
	if cachedCard != nil {
		if rejected, reason := checkCardContinuity(card, cachedCard, proof.signerKey, rooting.verifiedSigners); rejected {
			events := append(append([]string{}, rooting.auditEvents...), "card.continuity_violation")
			return CardVerifyResult{Authenticated: false, Rejected: true, Reason: reason, AuditEvents: events}
		}
	}

	// ── §5 step 5: adopt ──
	return CardVerifyResult{Authenticated: true, Rejected: false, Reason: ReasonSignedAuthenticated, AuditEvents: rooting.auditEvents}
}

// verifyUnsignedCard handles the §7 ratchet, §8 first-contact and Phase C 1.0
// unsigned rules.
func verifyUnsignedCard(kind cardPrincipalKind, cachedCard map[string]interface{}, profile string) CardVerifyResult {
	// Signature-stripping ratchet (§7): once a valid authenticated card has been
	// observed for a principal, any subsequent unsigned card is rejected forever.
	// The caller only caches authenticated cards, so a present cachedCard IS that
	// observation. Retain the cached card (the caller keeps it on a reject).
	if cachedCard != nil {
		return rejectCard(ReasonUnsignedAfterAuthenticated)
	}
	// First contact, no prior state.
	if profile == Profile10 {
		// Phase C: an unsigned card is rejected outright. A key-derived id
		// intrinsically carries its signing authority, so it is called out.
		if kind == kindKeyDerived {
			return rejectCard(ReasonUnsignedKeyDerived10)
		}
		return rejectCard(ReasonUnsigned10Profile)
	}
	// Phase A pre-1.0: an unsigned first-contact card still validates (§8).
	return CardVerifyResult{Authenticated: true, Rejected: false, Reason: ReasonUnsignedFirstContactAccept, AuditEvents: nil}
}

// ── §3.3 / §3.4: proof ──

type cardProofResult struct {
	ok        bool
	reason    CardVerifyReason
	signerKey []byte
}

func verifyCardProof(card map[string]interface{}, keyID, signature string) cardProofResult {
	signing, hasSigning := cardSigningEntries(card)
	var signerKey []byte

	if hasSigning {
		// Key-set card (§3.3). Duplicate keyIds would make head-binding and signer
		// resolution ambiguous (§4.1); reject them.
		seen := make(map[string]bool, len(signing))
		for _, e := range signing {
			em, _ := e.(map[string]interface{})
			kid, _ := em["keyId"].(string)
			if seen[kid] {
				return cardProofResult{reason: ReasonDuplicateKeyID}
			}
			seen[kid] = true
		}
		currentID, ok := card["currentSigningKeyId"].(string)
		if !ok || currentID == "" {
			return cardProofResult{reason: ReasonMissingCurrentSigningKeyID}
		}
		entry := findSigningEntry(signing, keyID)
		if entry == nil {
			return cardProofResult{reason: ReasonSignerAbsentFromSigning}
		}
		// A card is a live statement re-signed on every update; a retired or
		// revoked signer contradicts that (§3.3). Active only.
		if status, _ := entry["status"].(string); status != "active" {
			return cardProofResult{reason: ReasonSignerNotActive}
		}
		// The active signer MUST be currentSigningKeyId, unconditionally (§3.3).
		if keyID != currentID {
			return cardProofResult{reason: ReasonSignerNotCurrent}
		}
		mb, _ := entry["publicKeyMultibase"].(string)
		key, err := DecodePublicKeyMultibase(mb)
		if err != nil {
			return cardProofResult{reason: ReasonInvalidKeyEncode}
		}
		signerKey = key
	} else {
		// Legacy single-key card (§3.3): keyId MUST be the literal `bootstrap` and
		// the verifying key is the top-level publicKeyMultibase.
		if keyID != legacyBootstrapKeyID {
			return cardProofResult{reason: ReasonLegacyBootstrapMismatch}
		}
		mb, _ := card["publicKeyMultibase"].(string)
		key, err := DecodePublicKeyMultibase(mb)
		if err != nil {
			return cardProofResult{reason: ReasonInvalidKeyEncode}
		}
		signerKey = key
	}

	if !verifyOverCardDomain(cardSignatureDomain, stripCardKey(card, "cardSignature"), signature, signerKey) {
		// An invalid signature REJECTS outright; never demote to unsigned (§3.4).
		return cardProofResult{reason: ReasonInvalidSignature}
	}
	return cardProofResult{ok: true, signerKey: signerKey}
}

// ── §4: rooting by principal kind ──

type rootCardResult struct {
	rejected    bool
	reason      CardVerifyReason
	auditEvents []string
	// verifiedSigners are the ordered key bytes that ACTUALLY exercised signing
	// authority while the chain was verified: link 1's resolved root (the genesis
	// key, or the DID-document key it verified against) and every later link's
	// verified signer. This is the ONLY basis §6 continuity may bridge through — a
	// key that merely appears in some link's committed `signing` set signed
	// nothing and carries no authority. Empty for a no-chain root (the card signer
	// covers it).
	verifiedSigners [][]byte
}

func rootCardOk(auditEvents []string, verifiedSigners [][]byte) rootCardResult {
	return rootCardResult{rejected: false, reason: ReasonSignedAuthenticated, auditEvents: auditEvents, verifiedSigners: verifiedSigners}
}

func rootCardReject(reason CardVerifyReason, auditEvents []string) rootCardResult {
	return rootCardResult{rejected: true, reason: reason, auditEvents: auditEvents}
}

func rootCardSigner(card map[string]interface{}, agentID string, kind cardPrincipalKind, signerKey []byte, cachedCard map[string]interface{}, options CardVerifyOptions) rootCardResult {
	chain, hasChain := rotationChainLinks(card)

	switch kind {
	case kindKeyDerived:
		genesis, err := extractPublicKeyFromAgentID(agentID)
		if err != nil {
			return rootCardReject(ReasonInvalidCard, nil)
		}
		if hasChain && len(chain) > 0 {
			return rootChainedCard(card, chain, [][]byte{genesis}, ReasonChainLinkInvalidSig)
		}
		// No chain: cardSignature key MUST be byte-equal to the genesis key (§4.1).
		if !bytesEqualCT(signerKey, genesis) {
			return rootCardReject(ReasonGenesisKeyMismatch, nil)
		}
		return rootCardOk(nil, nil)

	case kindDidWeb:
		unavailable, didKeys := normalizeDidResolution(options.DidVerificationKeys)
		if unavailable {
			// Resolver-unavailable rule (§4.2). Cold + 1.0 fails closed; otherwise
			// (pre-1.0 either way, or 1.0 warm) continue under signature-plus-
			// continuity and record that the anchor was not checked.
			if options.Profile == Profile10 && cachedCard == nil {
				return rootCardReject(ReasonDidwebResolverUnavail, nil)
			}
			return rootCardOk([]string{"card.anchor_unverified"}, nil)
		}
		// The cardSignature key MUST be anchored in the DID document (§4.2).
		if !anyBytesEqual(didKeys, signerKey) {
			return rootCardReject(ReasonDidwebSignerNotAnchored, nil)
		}
		if hasChain && len(chain) > 0 {
			// Link 1 re-roots on a DID-document key rather than a genesis key (§4.2).
			return rootChainedCard(card, chain, didKeys, ReasonDidwebSignerNotAnchored)
		}
		return rootCardOk(nil, nil)

	default:
		// Other principal kinds: §4 defines rooting for EXACTLY two principal kinds,
		// key-derived (§4.1) and did:web (§4.2). Anything else has no trust root. A
		// signed card whose proof verified against its own `keys.signing` is
		// otherwise self-asserting: the key set anchors nothing outside the card.
		// Such a card MUST be rejected with a dedicated reason, NOT accepted with no
		// anchor and NOT demoted to unsigned (§3.4).
		return rootCardReject(ReasonUnrootedPrincipal, nil)
	}
}

type committedKey struct {
	keyID  string
	key    []byte
	status string
}

// rootChainedCard walks a rotation chain genesis-to-head and binds the head to
// the card (§4.1 steps 2-3, reused verbatim for did:web §4.2). rootCandidates
// are the keys link 1's signer may be (the embedded genesis key, or the
// DID-document keys).
func rootChainedCard(card map[string]interface{}, chain []interface{}, rootCandidates [][]byte, link1FailureReason CardVerifyReason) rootCardResult {
	if len(chain) > maxRotationChainLinks {
		return rootCardReject(ReasonChainTooLong, nil)
	}

	var prevSet []committedKey
	var prevVersion float64
	// The keys that actually verified a link signature, collected genesis-to-head.
	// §6 continuity bridges through THIS basis, never through committed-set members.
	verifiedSigners := [][]byte{}

	for i, raw := range chain {
		link, ok := raw.(map[string]interface{})
		if !ok {
			return rootCardReject(ReasonInvalidCard, nil)
		}
		signingRaw, ok := link["signing"].([]interface{})
		if !ok {
			return rootCardReject(ReasonInvalidCard, nil)
		}

		// Decode the complete committed signing set at this link.
		committed, err := decodeCommittedSet(signingRaw)
		if err != nil {
			return rootCardReject(ReasonInvalidKeyEncode, nil)
		}
		seen := make(map[string]bool, len(committed))
		for _, e := range committed {
			if seen[e.keyID] {
				return rootCardReject(ReasonChainDuplicateKeyID, nil)
			}
			seen[e.keyID] = true
		}

		version, ok := cardNumber(link["keySetVersion"])
		if !ok {
			return rootCardReject(ReasonInvalidCard, nil)
		}
		// keySetVersion strictly increasing and contiguous across CONSECUTIVE links;
		// the first link may commit any version (§4.1).
		if i > 0 && version != prevVersion+1 {
			return rootCardReject(ReasonChainNoncontiguous, nil)
		}

		// The signed bytes cover exactly {keySetVersion, signing, prevKeyId},
		// mirroring the reference reconstruction of the unsigned link.
		unsignedLink := map[string]interface{}{
			"keySetVersion": link["keySetVersion"],
			"signing":       link["signing"],
			"prevKeyId":     link["prevKeyId"],
		}
		sigStr, _ := link["signature"].(string)

		if i == 0 {
			// Link 1's signer must be a root candidate (§4.1 / §4.2). Its signature
			// verifying under a candidate key IS the byte-equality to that root.
			var rootedKey []byte
			for _, cand := range rootCandidates {
				if verifyOverCardDomain(cardRotationDomain, unsignedLink, sigStr, cand) {
					rootedKey = cand
					break
				}
			}
			if rootedKey == nil {
				return rootCardReject(link1FailureReason, nil)
			}
			verifiedSigners = append(verifiedSigners, rootedKey)
		} else {
			// Link-signer rule (§4.1): the signer named by prevKeyId MUST appear in
			// the prior link's committed set with status active.
			prevKeyID, _ := link["prevKeyId"].(string)
			signerEntry := findCommitted(prevSet, prevKeyID)
			if signerEntry == nil || signerEntry.status != "active" {
				return rootCardReject(ReasonChainLinkSignerNotActive, nil)
			}
			if !verifyOverCardDomain(cardRotationDomain, unsignedLink, sigStr, signerEntry.key) {
				return rootCardReject(ReasonChainLinkInvalidSig, nil)
			}
			// This link's verified signer is the prevKeyId key resolved (and now
			// signature-verified) from the PRIOR link's committed set.
			verifiedSigners = append(verifiedSigners, signerEntry.key)
		}

		prevSet = committed
		prevVersion = version
	}

	// Head-binding (§4.1 step 3). Both must hold.
	// (a) head link keySetVersion EQUALS the card's top-level keySetVersion.
	cardVersion, _ := cardNumber(card["keySetVersion"])
	if cardVersion != prevVersion {
		return rootCardReject(ReasonHeadVersionMismatch, nil)
	}
	// (b) head signing set CORRESPONDS EXACTLY to the card's keys.signing, keyed
	// by keyId, with byte-equal decoded keys (§3.5) and equal status.
	cardSigning, _ := cardSigningEntries(card)
	if len(prevSet) != len(cardSigning) {
		return rootCardReject(ReasonHeadSetMismatch, nil)
	}
	for _, he := range prevSet {
		ce := findSigningEntry(cardSigning, he.keyID)
		if ce == nil {
			return rootCardReject(ReasonHeadSetMismatch, nil)
		}
		mb, _ := ce["publicKeyMultibase"].(string)
		ck, err := DecodePublicKeyMultibase(mb)
		if err != nil {
			return rootCardReject(ReasonInvalidKeyEncode, nil)
		}
		cstatus, _ := ce["status"].(string)
		if !bytesEqualCT(ck, he.key) || cstatus != he.status {
			return rootCardReject(ReasonHeadSetMismatch, nil)
		}
	}

	return rootCardOk(nil, verifiedSigners)
}

// ── §6: continuity and rollback ──

func checkCardContinuity(card, cachedCard map[string]interface{}, cardSignerKey []byte, verifiedSigners [][]byte) (bool, CardVerifyReason) {
	// Reject a new card whose keySetVersion is lower than the cached one (§6).
	cardVer, okCard := cardNumber(card["keySetVersion"])
	cachedVer, okCached := cardNumber(cachedCard["keySetVersion"])
	if okCard && okCached && cardVer < cachedVer {
		return true, ReasonContinuityVersionReg
	}

	// Reject a new card whose signing key is not reachable from the cached card's
	// non-revoked signing set, directly OR through the rotation-chain links that
	// connect the cached set to the new head (§6).
	cachedSigning, _ := cardSigningEntries(cachedCard)
	cachedNonRevoked := [][]byte{}
	for _, e := range cachedSigning {
		em, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		if status, _ := em["status"].(string); status == "revoked" {
			continue
		}
		mb, _ := em["publicKeyMultibase"].(string)
		key, err := DecodePublicKeyMultibase(mb)
		if err != nil {
			// A cached entry that cannot decode contributes no reachable key.
			continue
		}
		cachedNonRevoked = append(cachedNonRevoked, key)
	}
	if len(cachedNonRevoked) == 0 {
		return false, ReasonSignedAuthenticated
	}

	// Reachability bridges ONLY through keys that actually EXERCISED SIGNING
	// AUTHORITY in the already-verified chain, never through committed-set
	// membership. A link's committed `signing` set is attacker-chosen JSON: only a
	// link's SIGNATURE is cryptographically constrained (to a key active in the
	// predecessor link), and listing a public key in a committed set requires no
	// secret. So the verified-signer basis is exactly the genesis / link-1 root and
	// each link's resolved-and-verified signer (rooting.verifiedSigners), plus the
	// card's own cardSignature signer (which subsumes the no-chain direct-hit case).
	// Iterating committed members instead lets an attacker with a leaked, now-revoked
	// historical key STUFF the genuine current key into a forged link's committed set
	// and bridge continuity through a key that signed nothing.
	//
	// This still ACCEPTS an honest agent that rotated twice between two warm fetches:
	// the cached interior key is the verified signer of the link it signed, so it is
	// in the basis. It REJECTS the chain-extension fork and the committed-set-stuffing
	// fork alike.
	basis := append([][]byte{cardSignerKey}, verifiedSigners...)
	for _, signer := range basis {
		if anyBytesEqual(cachedNonRevoked, signer) {
			return false, ReasonSignedAuthenticated
		}
	}
	return true, ReasonContinuityUnreachableKey
}

// ── Low-level primitives ──

// verifyOverCardDomain verifies an Ed25519 signature over domain + JCS(obj) under
// RFC 8032 strict, the single verify primitive both the card proof and every
// rotation link route through. It applies the same canonicalize-bounds and size
// caps the reference jcsCanonicalize enforces, and the same isStrongEd25519PublicKey
// gate the transport verifier uses (zip215:false parity). Returns false, never
// panics, for a malformed signature, an over-cap canonicalization or a bad key.
func verifyOverCardDomain(domain string, obj map[string]interface{}, signature string, publicKey []byte) bool {
	if !signatureRe.MatchString(signature) {
		return false
	}
	if !isWithinCanonicalizeBounds(obj) {
		return false
	}
	canonical, err := canonicalizeJSON(obj)
	if err != nil {
		return false
	}
	if utf16Len(canonical) > maxCanonicalBodyBytes {
		return false
	}
	prefixed := domain + canonical
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	if len(publicKey) != ed25519.PublicKeySize || !isStrongEd25519PublicKey(publicKey) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), []byte(prefixed), sig)
}

// stripCardKey returns a shallow copy of the card map with the named key removed.
func stripCardKey(card map[string]interface{}, key string) map[string]interface{} {
	out := make(map[string]interface{}, len(card))
	for k, v := range card {
		if k == key {
			continue
		}
		out[k] = v
	}
	return out
}

// cardSigningEntries returns card.keys.signing as a raw slice, matching the
// reference `card.keys?.signing`: a missing keys object or a non-array signing
// member yields the legacy (no-signing-set) path.
func cardSigningEntries(card map[string]interface{}) ([]interface{}, bool) {
	keys, ok := card["keys"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	signing, ok := keys["signing"].([]interface{})
	if !ok {
		return nil, false
	}
	return signing, true
}

func rotationChainLinks(card map[string]interface{}) ([]interface{}, bool) {
	chain, ok := card["rotationChain"].([]interface{})
	return chain, ok
}

func findSigningEntry(signing []interface{}, keyID string) map[string]interface{} {
	for _, e := range signing {
		em, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		if kid, _ := em["keyId"].(string); kid == keyID {
			return em
		}
	}
	return nil
}

func findCommitted(set []committedKey, keyID string) *committedKey {
	for i := range set {
		if set[i].keyID == keyID {
			return &set[i]
		}
	}
	return nil
}

// decodeCommittedSet decodes a link's committed signing set. A non-object entry
// or a public key that is not a 0xed01 Ed25519 multibase yields an error, which
// the caller maps to invalid_key_encoding, matching the reference decode-throw.
func decodeCommittedSet(signing []interface{}) ([]committedKey, error) {
	out := make([]committedKey, 0, len(signing))
	for _, e := range signing {
		em, ok := e.(map[string]interface{})
		if !ok {
			return nil, errors.New("rotation link signing entry is not an object")
		}
		mb, _ := em["publicKeyMultibase"].(string)
		key, err := DecodePublicKeyMultibase(mb)
		if err != nil {
			return nil, err
		}
		kid, _ := em["keyId"].(string)
		status, _ := em["status"].(string)
		out = append(out, committedKey{keyID: kid, key: key, status: status})
	}
	return out, nil
}

// cardNumber reads a JSON number that may arrive as float64 (the wire form) or a
// native Go integer (an in-memory caller), returning its float64 value and
// whether it was numeric. A non-finite or non-integer value is not a valid
// keySetVersion, matching the JCS-safe-integer profile the rest of the stack
// enforces.
func cardNumber(v interface{}) (float64, bool) {
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	case int32:
		f = float64(n)
	default:
		return 0, false
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

func cardPrincipalKindOf(agentID string) cardPrincipalKind {
	for _, p := range agentIDKeyPrefixes {
		if strings.HasPrefix(agentID, p) {
			return kindKeyDerived
		}
	}
	if strings.HasPrefix(agentID, "did:web:") {
		return kindDidWeb
	}
	return kindOther
}

// extractPublicKeyFromAgentID decodes the embedded Ed25519 key from a key-derived
// agentId (tulpa:/ink:), mirroring the reference extractPublicKeyFromAgentId.
func extractPublicKeyFromAgentID(agentID string) ([]byte, error) {
	if n := utf16Len(agentID); n == 0 || n > 512 {
		return nil, errors.New("invalid agent ID")
	}
	for _, p := range agentIDKeyPrefixes {
		if strings.HasPrefix(agentID, p) {
			return DecodePublicKeyMultibase(agentID[len(p):])
		}
	}
	return nil, errors.New("invalid agent ID format")
}

// normalizeDidResolution mirrors the reference: a nil pointer or an explicit
// "unavailable" status is unavailable; otherwise the multibase verification keys
// are decoded, skipping any that are not a 0xed01 Ed25519 key.
func normalizeDidResolution(r *DidResolution) (unavailable bool, keys [][]byte) {
	if r == nil || r.Status == DidUnavailable {
		return true, nil
	}
	out := make([][]byte, 0, len(r.VerificationKeys))
	for _, s := range r.VerificationKeys {
		if k, err := DecodePublicKeyMultibase(s); err == nil {
			out = append(out, k)
		}
	}
	return false, out
}

func anyBytesEqual(set [][]byte, target []byte) bool {
	for _, k := range set {
		if bytesEqualCT(k, target) {
			return true
		}
	}
	return false
}

// bytesEqualCT is a length-checked constant-time byte comparison of two keys.
func bytesEqualCT(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func rejectCard(reason CardVerifyReason) CardVerifyResult {
	return CardVerifyResult{Authenticated: false, Rejected: true, Reason: reason, AuditEvents: nil}
}
