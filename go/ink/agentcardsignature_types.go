package ink

// Self-authenticating Agent Card types (ink-agent-card-signature.md, Phase A).
//
// These mirror the OPTIONAL card members the reference schema adds in
// src/models/agent-card.ts: the `cardSignature` proof, the `rotationChain`
// rooting and the informational `updatedAt` timestamp. All are OPTIONAL and
// backward-compatible: a card without them validates exactly as before, and a
// consumer that predates the spec ignores them as unknown top-level fields
// (Protocol §2). A card that carries a `cardSignature` becomes the authoritative
// key set only after the §5 verifier (VerifyAgentCardSignature) accepts it.
//
// The verifier itself operates on a decoded map[string]interface{} card, the
// same shape ValidateAgentCard and the transport verifiers consume, so JCS
// canonicalization covers every card field byte-for-byte. These structs document
// the wire shape and give a caller a typed target to unmarshal into.

// CardSignature is the OPTIONAL self-authenticating card proof (§3.1). `KeyID`
// names the signing key resolved under §3.3; `Signature` is base64url no-padding
// over `ink/agent-card\n` + JCS(card without `cardSignature`).
type CardSignature struct {
	KeyID     string `json:"keyId"`
	Signature string `json:"signature"`
}

// RotationChainSigningEntry is one committed signing-key entry inside a
// rotation-chain link (§4.1). It carries NO `algorithm` (Ed25519 is pinned for
// chain-capable keys) and NO key-window timestamps: a link commits the complete
// `{keyId, publicKeyMultibase, status}` set at its `keySetVersion`.
type RotationChainSigningEntry struct {
	KeyID              string `json:"keyId"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	Status             string `json:"status"`
}

// RotationChainLink is one link of the OPTIONAL rotation chain (§4.1).
// `Signature` covers `ink/card-rotation\n` + JCS(link without `signature`).
// Every `KeyID` within a link's `Signing` set MUST be unique so the head-binding
// correspondence of §4.1 step 3b is unambiguous.
type RotationChainLink struct {
	KeySetVersion int                         `json:"keySetVersion"`
	Signing       []RotationChainSigningEntry `json:"signing"`
	PrevKeyID     string                      `json:"prevKeyId"`
	Signature     string                      `json:"signature"`
}

// CardVerifyReason is the typed decision reason the verifier returns. The string
// values match the reference AgentCardVerifyReason union in
// src/crypto/agent-card-signature.ts one-for-one, so both implementations report
// the same reason on the same input.
type CardVerifyReason string

const (
	// accepts
	ReasonSignedAuthenticated        CardVerifyReason = "signed_authenticated"
	ReasonUnsignedFirstContactAccept CardVerifyReason = "unsigned_first_contact_accepted"
	// unsigned rejects
	ReasonUnsignedAfterAuthenticated CardVerifyReason = "unsigned_after_authenticated"
	ReasonUnsignedKeyDerived10       CardVerifyReason = "unsigned_key_derived_1_0"
	ReasonUnsigned10Profile          CardVerifyReason = "unsigned_1_0_profile"
	// proof rejects (§3.3, §3.4, §6)
	ReasonInvalidSignature           CardVerifyReason = "invalid_signature"
	ReasonSignerNotActive            CardVerifyReason = "signer_not_active"
	ReasonSignerNotCurrent           CardVerifyReason = "signer_not_current"
	ReasonSignerAbsentFromSigning    CardVerifyReason = "signer_absent_from_signing"
	ReasonMissingCurrentSigningKeyID CardVerifyReason = "missing_current_signing_key_id"
	ReasonMissingKeySetVersion       CardVerifyReason = "missing_key_set_version"
	ReasonLegacyBootstrapMismatch    CardVerifyReason = "legacy_bootstrap_mismatch"
	ReasonDuplicateKeyID             CardVerifyReason = "duplicate_key_id"
	// rooting rejects (§4)
	ReasonChainTooLong             CardVerifyReason = "chain_too_long"
	ReasonChainLinkInvalidSig      CardVerifyReason = "chain_link_invalid_signature"
	ReasonChainNoncontiguous       CardVerifyReason = "chain_noncontiguous_version"
	ReasonChainLinkSignerNotActive CardVerifyReason = "chain_link_signer_not_active"
	ReasonChainDuplicateKeyID      CardVerifyReason = "chain_duplicate_key_id"
	ReasonHeadVersionMismatch      CardVerifyReason = "head_version_mismatch"
	ReasonHeadSetMismatch          CardVerifyReason = "head_set_mismatch"
	ReasonGenesisKeyMismatch       CardVerifyReason = "genesis_key_mismatch"
	ReasonUnrootedPrincipal        CardVerifyReason = "unrooted_principal"
	ReasonDidwebSignerNotAnchored  CardVerifyReason = "didweb_signer_not_anchored"
	ReasonDidwebResolverUnavail    CardVerifyReason = "didweb_resolver_unavailable"
	// continuity rejects (§6)
	ReasonContinuityVersionReg     CardVerifyReason = "continuity_version_regression"
	ReasonContinuityUnreachableKey CardVerifyReason = "continuity_unreachable_key"
	// input rejects
	ReasonIdentityMismatch CardVerifyReason = "identity_mismatch"
	ReasonInvalidCard      CardVerifyReason = "invalid_card"
	ReasonInvalidKeyEncode CardVerifyReason = "invalid_key_encoding"
)

// CardVerifyResult is the verifier's typed decision, mirroring the reference
// AgentCardVerifyResult. A normal reject sets Rejected and a Reason; it never
// panics out of the verifier. AuditEvents carries the marks the caller MUST
// record, for example `card.anchor_unverified` or `card.continuity_violation`.
type CardVerifyResult struct {
	Authenticated bool
	Rejected      bool
	Reason        CardVerifyReason
	AuditEvents   []string
}

// DidResolution is a resolved DID document's verification-method keys, or an
// explicit "unavailable" signal (§4.2). It mirrors the reference DidResolution:
// Status is "resolved" or "unavailable"; VerificationKeys are multibase
// public-key strings (the DID-document form). A nil *DidResolution passed to the
// verifier is treated as unavailable.
type DidResolution struct {
	Status           string
	VerificationKeys []string
}

// DID resolution status values.
const (
	DidResolved    = "resolved"
	DidUnavailable = "unavailable"
)

// CardVerifyOptions carries the pure inputs a cold or warm verify needs. It
// mirrors the reference AgentCardVerifyOptions: the library never fetches and
// never manages a ratchet store, so the caller supplies any cached prior card
// and any resolved DID-document keys.
type CardVerifyOptions struct {
	// CachedCard is a cached prior AUTHENTICATED card for the same principal, or
	// nil for a cold verifier. Its presence drives the signature-stripping
	// ratchet (§7) and the continuity and rollback rules (§6). The library trusts
	// it as already-authenticated; validating it was the caller's job.
	CachedCard map[string]interface{}
	// DidVerificationKeys is, for a did:web principal, the resolved DID-document
	// verification keys or an unavailable signal. A nil pointer is treated as
	// unavailable. Ignored for key-derived ids.
	DidVerificationKeys *DidResolution
	// Profile keys the unsigned and resolver-unavailable outcomes: "pre-1.0" or
	// "1.0".
	Profile string
	// EnforcePhaseC is the staged, DEFAULT-OFF Phase C switch (§10).
	//
	// Phase C is the receiver-side half of the card-signature rollout: an
	// unsigned card is rejected outright, and a cold did:web verifier fails
	// closed when the DID document is unreachable. It MUST NOT begin fewer than
	// 90 days after the Phase B ship, so the code lands inert and the switch is
	// flipped later.
	//
	// It is an EXPLICIT tri-state flag, not a version string, and it OVERRIDES
	// Profile in both directions. Left nil, the verifier behaves exactly as it
	// did before the flag existed: Phase C rules apply when and only when the
	// caller passed Profile "1.0". At the flip the nil default becomes true.
	EnforcePhaseC *bool
}

// PhaseCEnforced resolves the staged Phase C switch (§10). The explicit flag
// wins whenever the caller sets it; with the flag nil the pre-flag behaviour
// stands, which is that the "1.0" conformance profile carries the Phase C
// rules. One resolved boolean is threaded through the verifier so the two Phase
// C decision points (the unsigned-card rule and the cold did:web
// resolver-unavailable rule) cannot drift apart.
func (o CardVerifyOptions) PhaseCEnforced() bool {
	if o.EnforcePhaseC != nil {
		return *o.EnforcePhaseC
	}
	return o.Profile == Profile10
}

// Verify profile values.
const (
	ProfilePre10 = "pre-1.0"
	Profile10    = "1.0"
)
