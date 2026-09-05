import * as ed from "@noble/ed25519";
import { base64urlDecode, jcsCanonicalize } from "./ink.js";
import {
  AGENT_ID_KEY_PREFIXES,
  decodePublicKeyMultibase,
  extractPublicKeyFromAgentId,
} from "./keys.js";
import type {
  AgentCard,
  CardSignature,
  RotationChainLink,
} from "../models/agent-card.js";

// ── Self-authenticating Agent Card (ink-agent-card-signature.md) ──
//
// This module is the TypeScript reference for the OPTIONAL `cardSignature`
// card proof and its `rotationChain` rooting. It reuses the repo's single
// crypto stack: JCS (Protocol §3.2, via jcsCanonicalize), base64url no-pad
// (§3.3) and Ed25519 under RFC 8032 strict (zip215:false), exactly as the body
// signer does. It introduces no second crypto path.
//
// The verifier `verifyAgentCardSignature` is a PURE function of its inputs: the
// caller supplies any cached prior card and any resolved DID-document keys. The
// library never fetches, and never manages a ratchet store; the typed result and
// its audit events are the only seam a consumer (tulpa) acts on. That keeps this
// slice vector-friendly, since a conformance vector is a pure input→decision map.

/** Domain-separation prefix for the card proof (§3.2). Not version-keyed. */
export const CARD_SIGNATURE_DOMAIN = "ink/agent-card\n";
/** Domain-separation prefix for a rotation-chain link (§4.1). */
export const CARD_ROTATION_DOMAIN = "ink/card-rotation\n";

/** The literal `keyId` a legacy single-key card MUST use (§3.3). */
const LEGACY_BOOTSTRAP_KEY_ID = "bootstrap";

/** A verifier MUST reject a rotation chain longer than 32 links (§4.1). */
const MAX_ROTATION_CHAIN_LINKS = 32;

const SIGNATURE_RE = /^[A-Za-z0-9_-]{86}$/;

// ── Signing helpers (producer side; also exercised by tests) ──

/**
 * Compute the `cardSignature.signature` for a card. Ed25519 over the UTF-8 bytes
 * of `ink/agent-card\n` + JCS(card with `cardSignature` removed and nothing else
 * stripped) (§3.2). The caller pairs the returned 86-char base64url signature
 * with the signing key's `keyId` to form the `cardSignature` member.
 */
export async function signAgentCard(
  card: Record<string, unknown>,
  privateKey: Uint8Array,
): Promise<string> {
  const { cardSignature: _omit, ...unsigned } = card;
  return signOverDomain(CARD_SIGNATURE_DOMAIN, unsigned, privateKey);
}

/**
 * Compute the `signature` for a rotation-chain link. Ed25519 over the UTF-8
 * bytes of `ink/card-rotation\n` + JCS(link with `signature` removed) (§4.1).
 */
export async function signRotationLink(
  link: Record<string, unknown>,
  privateKey: Uint8Array,
): Promise<string> {
  const { signature: _omit, ...unsigned } = link;
  return signOverDomain(CARD_ROTATION_DOMAIN, unsigned, privateKey);
}

async function signOverDomain(
  domain: string,
  obj: Record<string, unknown>,
  privateKey: Uint8Array,
): Promise<string> {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) {
    throw new Error("privateKey must be a 32-byte Uint8Array");
  }
  const canonical = jcsCanonicalize(obj);
  const bytes = new TextEncoder().encode(domain + canonical);
  const sig = await ed.signAsync(bytes, privateKey);
  return base64urlEncode(sig);
}

// ── Verifier result ──

export type AgentCardVerifyReason =
  // accepts
  | "signed_authenticated"
  | "unsigned_first_contact_accepted"
  // unsigned rejects
  | "unsigned_after_authenticated"
  | "unsigned_key_derived_1_0"
  | "unsigned_1_0_profile"
  // proof rejects (§3.3, §3.4, §6)
  | "invalid_signature"
  | "signer_not_active"
  | "signer_not_current"
  | "signer_absent_from_signing"
  | "missing_current_signing_key_id"
  | "missing_key_set_version"
  | "legacy_bootstrap_mismatch"
  | "duplicate_key_id"
  // rooting rejects (§4)
  | "chain_too_long"
  | "chain_link_invalid_signature"
  | "chain_noncontiguous_version"
  | "chain_link_signer_not_active"
  | "chain_duplicate_key_id"
  | "head_version_mismatch"
  | "head_set_mismatch"
  | "genesis_key_mismatch"
  | "unrooted_principal"
  | "didweb_signer_not_anchored"
  | "didweb_resolver_unavailable"
  // continuity rejects (§6)
  | "continuity_version_regression"
  | "continuity_unreachable_key"
  // input rejects
  | "identity_mismatch"
  | "invalid_card"
  | "invalid_key_encoding";

/**
 * The verifier's typed decision. A normal reject sets `rejected: true` and a
 * `reason`; it does NOT throw (exceptions are reserved for programmer error,
 * and even those are contained and surfaced as `invalid_card`). `auditEvents`
 * carries the marks the caller MUST record, e.g. `card.anchor_unverified` or
 * `card.continuity_violation`.
 */
export interface AgentCardVerifyResult {
  authenticated: boolean;
  rejected: boolean;
  reason: AgentCardVerifyReason;
  auditEvents: string[];
}

/**
 * A resolved DID document's verification-method keys, or an explicit
 * "unreachable" signal. Keys may be supplied as `publicKeyMultibase` strings
 * (the DID-document form) or as raw 32-byte Ed25519 keys. A bare array is
 * shorthand for `{ status: "resolved", verificationKeys: [...] }`.
 */
export type DidResolution =
  | { status: "resolved"; verificationKeys: Array<string | Uint8Array> }
  | { status: "unavailable" }
  | Array<string | Uint8Array>;

export interface AgentCardVerifyOptions {
  /**
   * A cached prior AUTHENTICATED card for the same principal, or null/undefined
   * for a cold verifier. Its presence drives the signature-stripping ratchet
   * (§7) and the continuity and rollback rules (§6). The library trusts it as
   * already-authenticated; validating it was the caller's job when it cached it.
   */
  cachedCard?: AgentCard | null;
  /**
   * For a did:web principal: the resolved DID-document verification keys, or
   * `{ status: "unavailable" }` when the resolver could not be reached. Omitted
   * for a did:web card is treated as unavailable. Ignored for key-derived ids.
   */
  didVerificationKeys?: DidResolution;
  /** Conformance profile keying the unsigned and resolver-unavailable outcomes. */
  profile: "pre-1.0" | "1.0";
  /**
   * Phase C enforcement (§10), staged and DEFAULT-OFF.
   *
   * Phase C is the receiver-side half of the card-signature rollout: an unsigned
   * card is rejected outright, and a cold did:web verifier fails closed when the
   * DID document is unreachable. It MUST NOT begin fewer than 90 days after the
   * Phase B ship, so the code lands inert and the switch is flipped later.
   *
   * This is an EXPLICIT boolean, not a version string, and it OVERRIDES
   * `profile` in both directions. Left undefined, the verifier behaves exactly
   * as it did before the flag existed: Phase C rules apply when and only when
   * the caller passed `profile: "1.0"`. An adopter who does not set it observes
   * byte-identical semantics to the previous release.
   *
   * At the flip this field's default becomes `true`.
   */
  enforcePhaseC?: boolean;
}

/**
 * Resolve the staged Phase C switch (§10). The explicit flag wins whenever the
 * caller sets it; with the flag absent the pre-flag behaviour stands, which is
 * that the `1.0` conformance profile carries the Phase C rules. Threading one
 * resolved boolean through the verifier keeps the two Phase C decision points
 * (the unsigned-card rule and the cold did:web resolver-unavailable rule) from
 * drifting apart.
 */
function phaseCEnforced(options: AgentCardVerifyOptions): boolean {
  return options.enforcePhaseC ?? options.profile === "1.0";
}

// ── Verifier ──

/**
 * Verify a fetched Agent Card under ink-agent-card-signature.md §5.
 *
 * This runs §5 steps 2 through 4 (proof, rooting, continuity) plus the
 * unsigned-card ratchet of §7. It assumes the caller already ran the discovery
 * fetch contract (§5 step 1: status, length, content type, size, JSON, schema,
 * protocol, identity binding); as a defensive backstop it re-checks that
 * `card.agentId` equals the requested `agentId`.
 *
 * Pure: no I/O. The result's `authenticated`/`rejected`/`reason`/`auditEvents`
 * is the whole seam a consumer acts on.
 */
export async function verifyAgentCardSignature(
  card: AgentCard,
  agentId: string,
  options: AgentCardVerifyOptions,
): Promise<AgentCardVerifyResult> {
  try {
    if (card === null || typeof card !== "object" || Array.isArray(card)) {
      return reject("invalid_card");
    }
    if (typeof agentId !== "string" || agentId.length === 0) {
      return reject("invalid_card");
    }
    // A member that is present but not the shape the schema declares is not
    // absent. Reading it as absent selects a weaker path: no key set means the
    // legacy single key, no rotation chain means the genesis root, and either
    // one authenticates a card the set or the chain would have rejected. The
    // verifier is exported, so it fails closed on its own rather than trusting
    // that admission ran.
    const keysMember: unknown = (card as { keys?: unknown }).keys;
    if (keysMember !== undefined) {
      if (keysMember === null || typeof keysMember !== "object" || Array.isArray(keysMember)) {
        return reject("invalid_card");
      }
      const signing: unknown = (keysMember as { signing?: unknown }).signing;
      if (signing !== undefined && !Array.isArray(signing)) return reject("invalid_card");
    }
    // §3.4: the only unsigned card is one carrying no `cardSignature` at all.
    // A present member that is not a signature object must not take the
    // unsigned path, which is the more permissive one on a cold first contact.
    if ("cardSignature" in card) {
      const sig: unknown = (card as { cardSignature?: unknown }).cardSignature;
      if (sig === null || typeof sig !== "object" || Array.isArray(sig)) return reject("invalid_card");
    }
    const chainMember: unknown = (card as { rotationChain?: unknown }).rotationChain;
    if (chainMember !== undefined && !Array.isArray(chainMember)) return reject("invalid_card");

    // §5 step 1 backstop: identity binding.
    if (card.agentId !== agentId) {
      return reject("identity_mismatch");
    }

    const kind = principalKind(agentId);
    const cachedCard = options.cachedCard ?? null;
    const cardSignature = card.cardSignature;
    const phaseC = phaseCEnforced(options);

    // Unsigned path: the only cards this spec treats as unsigned are those with
    // no `cardSignature` at all (§3.4).
    if (!cardSignature) {
      return verifyUnsigned(kind, cachedCard, phaseC);
    }

    // §6: when `cardSignature` is present, `keySetVersion` is a MUST. It is the
    // SOLE monotonic quantity the continuity rules compare, so a signed card that
    // omits it would silently skip the version-regression check. The schema keeps
    // it optional for backward-compat with unsigned cards; the enforcement is
    // verifier-side. (`updatedAt` stays unenforced in Phase A.)
    if (typeof card.keySetVersion !== "number") {
      return reject("missing_key_set_version");
    }

    // ── §5 step 2: proof ──
    const proof = await verifyProof(card, cardSignature);
    if (!proof.ok) {
      return reject(proof.reason);
    }

    // ── §5 step 3: rooting ──
    const rooting = await rootSigner(card, agentId, kind, proof.signerKey, cachedCard, options, phaseC);
    if (rooting.rejected) {
      return { authenticated: false, rejected: true, reason: rooting.reason, auditEvents: rooting.auditEvents };
    }

    // ── §5 step 4: continuity and rollback ──
    if (cachedCard) {
      const continuity = checkContinuity(card, cachedCard, proof.signerKey, rooting.verifiedSigners);
      if (continuity.rejected) {
        return {
          authenticated: false,
          rejected: true,
          reason: continuity.reason,
          auditEvents: [...rooting.auditEvents, "card.continuity_violation"],
        };
      }
    }

    // ── §5 step 5: adopt ──
    return {
      authenticated: true,
      rejected: false,
      reason: "signed_authenticated",
      auditEvents: rooting.auditEvents,
    };
  } catch {
    // A hostile object whose getters/proxy traps throw, or an over-cap
    // canonicalization, fails closed as an invalid card. Never demote to
    // unsigned, never throw out of the verifier.
    return reject("invalid_card");
  }
}

// ── Unsigned-card handling (§7 ratchet, §8 first-contact, Phase C 1.0) ──

function verifyUnsigned(
  kind: PrincipalKind,
  cachedCard: AgentCard | null,
  phaseC: boolean,
): AgentCardVerifyResult {
  // Signature-stripping ratchet (§7): once a valid authenticated card has been
  // observed for a principal, any subsequent unsigned card is rejected forever.
  // The caller only caches authenticated cards, so a present cachedCard IS that
  // observation. Retain the cached card (the caller keeps it on a reject).
  if (cachedCard) {
    return reject("unsigned_after_authenticated");
  }
  // First contact, no prior state.
  if (phaseC) {
    // Phase C: an unsigned card is rejected outright. A key-derived id
    // intrinsically carries its signing authority, so it is called out.
    return reject(kind === "key-derived" ? "unsigned_key_derived_1_0" : "unsigned_1_0_profile");
  }
  // Phase A pre-1.0: an unsigned first-contact card still validates (§8).
  return {
    authenticated: true,
    rejected: false,
    reason: "unsigned_first_contact_accepted",
    auditEvents: [],
  };
}

// ── §3.3 / §3.4: proof ──

type ProofResult =
  | { ok: true; signerKey: Uint8Array; signerKeyId: string }
  | { ok: false; reason: AgentCardVerifyReason };

async function verifyProof(card: AgentCard, cardSignature: CardSignature): Promise<ProofResult> {
  const signing = card.keys?.signing;
  let signerKey: Uint8Array;

  if (signing) {
    // Key-set card (§3.3). Duplicate keyIds would make the head-binding and
    // signer resolution ambiguous (§4.1); reject them.
    const seen = new Set<string>();
    for (const entry of signing) {
      if (seen.has(entry.keyId)) return { ok: false, reason: "duplicate_key_id" };
      seen.add(entry.keyId);
    }
    if (!card.currentSigningKeyId) {
      return { ok: false, reason: "missing_current_signing_key_id" };
    }
    const entry = signing.find((k) => k.keyId === cardSignature.keyId);
    if (!entry) return { ok: false, reason: "signer_absent_from_signing" };
    // A card is a live statement re-signed on every update; a retired or revoked
    // signer contradicts that (§3.3). Active only.
    if (entry.status !== "active") return { ok: false, reason: "signer_not_active" };
    // The active signer MUST be currentSigningKeyId, unconditionally (§3.3).
    if (cardSignature.keyId !== card.currentSigningKeyId) {
      return { ok: false, reason: "signer_not_current" };
    }
    try {
      signerKey = decodePublicKeyMultibase(entry.publicKeyMultibase);
    } catch {
      return { ok: false, reason: "invalid_key_encoding" };
    }
  } else {
    // Legacy single-key card (§3.3): keyId MUST be the literal `bootstrap` and
    // the verifying key is the top-level publicKeyMultibase.
    if (cardSignature.keyId !== LEGACY_BOOTSTRAP_KEY_ID) {
      return { ok: false, reason: "legacy_bootstrap_mismatch" };
    }
    try {
      signerKey = decodePublicKeyMultibase(card.publicKeyMultibase);
    } catch {
      return { ok: false, reason: "invalid_key_encoding" };
    }
  }

  const ok = await verifyOverDomain(CARD_SIGNATURE_DOMAIN, stripCardSignature(card), cardSignature.signature, signerKey);
  if (!ok) {
    // An invalid signature REJECTS outright; never demote to unsigned (§3.4).
    return { ok: false, reason: "invalid_signature" };
  }
  return { ok: true, signerKey, signerKeyId: cardSignature.keyId };
}

// ── §4: rooting by principal kind ──

type PrincipalKind = "key-derived" | "did:web" | "other";

interface RootResult {
  rejected: boolean;
  reason: AgentCardVerifyReason;
  auditEvents: string[];
  // The ordered key bytes that ACTUALLY exercised signing authority while the
  // chain was verified: link 1's resolved root (the genesis key, or the
  // DID-document key it verified against) and every later link's verified
  // signer. This is the ONLY basis §6 continuity may bridge through — a key that
  // merely appears in some link's committed `signing` set signed nothing and
  // carries no authority. Empty for a no-chain root (the card signer covers it).
  verifiedSigners: Uint8Array[];
}

function rootOk(auditEvents: string[] = [], verifiedSigners: Uint8Array[] = []): RootResult {
  return { rejected: false, reason: "signed_authenticated", auditEvents, verifiedSigners };
}
function rootReject(reason: AgentCardVerifyReason, auditEvents: string[] = []): RootResult {
  return { rejected: true, reason, auditEvents, verifiedSigners: [] };
}

async function rootSigner(
  card: AgentCard,
  agentId: string,
  kind: PrincipalKind,
  signerKey: Uint8Array,
  cachedCard: AgentCard | null,
  options: AgentCardVerifyOptions,
  phaseC: boolean,
): Promise<RootResult> {
  const chain = card.rotationChain;

  if (kind === "key-derived") {
    let genesis: Uint8Array;
    try {
      genesis = extractPublicKeyFromAgentId(agentId);
    } catch {
      return rootReject("invalid_card");
    }
    if (chain && chain.length > 0) {
      return await rootChained(card, chain, [genesis], "chain_link_invalid_signature");
    }
    // No chain: cardSignature key MUST be byte-equal to the genesis key (§4.1).
    if (!bytesEqual(signerKey, genesis)) {
      return rootReject("genesis_key_mismatch");
    }
    return rootOk();
  }

  if (kind === "did:web") {
    const resolution = normalizeDidResolution(options.didVerificationKeys);
    if (resolution.status === "unavailable") {
      // Resolver-unavailable rule (§4.2). Cold under Phase C fails closed;
      // otherwise (Phase C not enforced, or enforced but warm) continue under
      // signature-plus-continuity and record that the anchor was not checked.
      if (phaseC && !cachedCard) {
        return rootReject("didweb_resolver_unavailable");
      }
      return rootOk(["card.anchor_unverified"]);
    }
    const didKeys = resolution.keys;
    // The cardSignature key MUST be anchored in the DID document (§4.2).
    if (!didKeys.some((k) => bytesEqual(k, signerKey))) {
      return rootReject("didweb_signer_not_anchored");
    }
    if (chain && chain.length > 0) {
      // Link 1 re-roots on a DID-document key rather than a genesis key (§4.2).
      return await rootChained(card, chain, didKeys, "didweb_signer_not_anchored");
    }
    return rootOk();
  }

  // Other principal kinds: §4 defines rooting for EXACTLY two principal kinds,
  // key-derived (§4.1) and did:web (§4.2). Anything else has no trust root. A
  // signed card whose proof verified against its own `keys.signing` is otherwise
  // self-asserting: the key set anchors nothing outside the card. Such a card
  // MUST be rejected with a dedicated reason, NOT accepted with no anchor and NOT
  // fallen through to the unsigned path (a signed card is never demoted, §3.4).
  return rootReject("unrooted_principal");
}

// Walk a rotation chain genesis-to-head and bind the head to the card (§4.1
// steps 2-3, reused verbatim for did:web §4.2). `rootCandidates` are the keys
// link 1's signer may be (the embedded genesis key, or the DID-document keys).
async function rootChained(
  card: AgentCard,
  chain: RotationChainLink[],
  rootCandidates: Uint8Array[],
  link1FailureReason: AgentCardVerifyReason,
): Promise<RootResult> {
  if (chain.length > MAX_ROTATION_CHAIN_LINKS) {
    return rootReject("chain_too_long");
  }

  let prevSet: Array<{ keyId: string; key: Uint8Array; status: string }> | null = null;
  let prevVersion: number | null = null;
  // The keys that actually verified a link signature, collected genesis-to-head.
  // §6 continuity bridges through THIS basis, never through committed-set members.
  const verifiedSigners: Uint8Array[] = [];

  for (let i = 0; i < chain.length; i++) {
    const link = chain[i]!;

    // Decode the complete committed signing set at this link.
    let committed: Array<{ keyId: string; key: Uint8Array; status: string }>;
    try {
      committed = link.signing.map((e) => ({
        keyId: e.keyId,
        key: decodePublicKeyMultibase(e.publicKeyMultibase),
        status: e.status,
      }));
    } catch {
      return rootReject("invalid_key_encoding");
    }
    const seen = new Set<string>();
    for (const e of committed) {
      if (seen.has(e.keyId)) return rootReject("chain_duplicate_key_id");
      seen.add(e.keyId);
    }

    // keySetVersion strictly increasing and contiguous across CONSECUTIVE links;
    // the first link may commit any version (§4.1).
    if (i > 0 && link.keySetVersion !== (prevVersion as number) + 1) {
      return rootReject("chain_noncontiguous_version");
    }

    // §4.1 preimage: JCS of the WHOLE link with `signature` removed and nothing
    // else stripped, the same house rule §3.2 sets for the card. Reconstructing
    // from a named-field subset would leave any other member uncovered and
    // freely mutable under a still-valid signature, and would silently exclude
    // the `algorithm` member §4.1 reserves for a later additive minor.
    const { signature: _sig, ...unsignedLink } = link as Record<string, unknown>;
    if (i === 0) {
      // Link 1's signer must be a root candidate (§4.1 / §4.2). Its signature
      // verifying under a candidate key IS the byte-equality to that root.
      let rootedKey: Uint8Array | null = null;
      for (const cand of rootCandidates) {
        if (await verifyOverDomain(CARD_ROTATION_DOMAIN, unsignedLink, link.signature, cand)) {
          rootedKey = cand;
          break;
        }
      }
      if (!rootedKey) return rootReject(link1FailureReason);
      // Link 1's verified signer is the root candidate its signature verified
      // against (the genesis key, or the DID-document key for a did:web chain).
      verifiedSigners.push(rootedKey);
    } else {
      // Link-signer rule (§4.1): the signer named by prevKeyId MUST appear in
      // the prior link's committed set with status active.
      const signerEntry = (prevSet as Array<{ keyId: string; key: Uint8Array; status: string }>).find(
        (e) => e.keyId === link.prevKeyId,
      );
      if (!signerEntry || signerEntry.status !== "active") {
        return rootReject("chain_link_signer_not_active");
      }
      const ok = await verifyOverDomain(CARD_ROTATION_DOMAIN, unsignedLink, link.signature, signerEntry.key);
      if (!ok) return rootReject("chain_link_invalid_signature");
      // This link's verified signer is the prevKeyId key resolved (and now
      // signature-verified) from the PRIOR link's committed set.
      verifiedSigners.push(signerEntry.key);
    }

    prevSet = committed;
    prevVersion = link.keySetVersion;
  }

  // Head-binding (§4.1 step 3). Both must hold.
  const headSet = prevSet as Array<{ keyId: string; key: Uint8Array; status: string }>;
  // (a) head link keySetVersion EQUALS the card's top-level keySetVersion.
  if (card.keySetVersion !== prevVersion) {
    return rootReject("head_version_mismatch");
  }
  // (b) head signing set CORRESPONDS EXACTLY to the card's keys.signing, keyed
  // by keyId, with byte-equal decoded keys (§3.5) and equal status.
  const cardSigning = card.keys?.signing ?? [];
  if (headSet.length !== cardSigning.length) {
    return rootReject("head_set_mismatch");
  }
  for (const he of headSet) {
    const ce = cardSigning.find((k) => k.keyId === he.keyId);
    if (!ce) return rootReject("head_set_mismatch");
    let ck: Uint8Array;
    try {
      ck = decodePublicKeyMultibase(ce.publicKeyMultibase);
    } catch {
      return rootReject("invalid_key_encoding");
    }
    if (!bytesEqual(ck, he.key) || ce.status !== he.status) {
      return rootReject("head_set_mismatch");
    }
  }

  return rootOk([], verifiedSigners);
}

// ── §6: continuity and rollback ──

interface ContinuityResult {
  rejected: boolean;
  reason: AgentCardVerifyReason;
}

function checkContinuity(
  card: AgentCard,
  cachedCard: AgentCard,
  cardSignerKey: Uint8Array,
  verifiedSigners: Uint8Array[],
): ContinuityResult {
  // Reject a new card whose keySetVersion is lower than the cached one (§6).
  if (
    typeof card.keySetVersion === "number" &&
    typeof cachedCard.keySetVersion === "number" &&
    card.keySetVersion < cachedCard.keySetVersion
  ) {
    return { rejected: true, reason: "continuity_version_regression" };
  }

  // Reject a new card whose signing key is not reachable from the cached card's
  // non-revoked signing set, directly OR through the rotation-chain links that
  // connect the cached set to the new head (§6).
  const cachedSigning = cachedCard.keys?.signing ?? [];
  const cachedNonRevoked: Uint8Array[] = [];
  for (const entry of cachedSigning) {
    if (entry.status === "revoked") continue;
    try {
      cachedNonRevoked.push(decodePublicKeyMultibase(entry.publicKeyMultibase));
    } catch {
      // A cached entry that cannot decode contributes no reachable key.
    }
  }
  if (cachedNonRevoked.length === 0) {
    return { rejected: false, reason: "signed_authenticated" };
  }

  // Reachability bridges ONLY through keys that actually EXERCISED SIGNING
  // AUTHORITY in the already-verified chain, never through committed-set
  // membership. A link's committed `signing` set is attacker-chosen JSON: only a
  // link's SIGNATURE is cryptographically constrained (to a key active in the
  // predecessor link), and listing a public key in a committed set requires no
  // secret. So the verified-signer basis is exactly the genesis / link-1 root
  // and each link's resolved-and-verified signer (`rooting.verifiedSigners`),
  // plus the card's own `cardSignature` signer (which subsumes the no-chain
  // direct-hit case). Iterating committed members instead lets an attacker with a
  // leaked, now-revoked historical key STUFF the genuine current key into a forged
  // link's committed set and bridge continuity through a key that signed nothing.
  //
  // This still ACCEPTS an honest agent that rotated twice between two warm
  // fetches: the cached interior key is the verified signer of the link it signed,
  // so it is in the basis. It REJECTS the chain-extension fork and the
  // committed-set-stuffing fork alike: the forged head branches from a key that is
  // REVOKED in the cached set, and the genuine cached key signed nothing in the
  // forged chain, so no basis key meets the cached non-revoked set.
  const basis = [cardSignerKey, ...verifiedSigners];
  for (const signer of basis) {
    if (cachedNonRevoked.some((k) => bytesEqual(k, signer))) {
      return { rejected: false, reason: "signed_authenticated" };
    }
  }

  return { rejected: true, reason: "continuity_unreachable_key" };
}

// ── Low-level primitives ──

/**
 * Verify an Ed25519 signature over `domain` + JCS(obj) under RFC 8032 strict
 * (zip215:false). The single verify primitive both the card proof and every
 * rotation link route through. Returns false (never throws) for a malformed
 * signature, an over-cap canonicalization, or a bad key.
 */
async function verifyOverDomain(
  domain: string,
  obj: Record<string, unknown>,
  signature: string,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (!SIGNATURE_RE.test(signature)) return false;
  try {
    const canonical = jcsCanonicalize(obj);
    const bytes = new TextEncoder().encode(domain + canonical);
    const sig = base64urlDecode(signature);
    return await ed.verifyAsync(sig, bytes, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

function stripCardSignature(card: AgentCard): Record<string, unknown> {
  const { cardSignature: _omit, ...rest } = card as Record<string, unknown>;
  return rest;
}

function principalKind(agentId: string): PrincipalKind {
  if (AGENT_ID_KEY_PREFIXES.some((p) => agentId.startsWith(p))) return "key-derived";
  if (agentId.startsWith("did:web:")) return "did:web";
  return "other";
}

function normalizeDidResolution(
  input: DidResolution | undefined,
): { status: "resolved"; keys: Uint8Array[] } | { status: "unavailable" } {
  if (input === undefined) return { status: "unavailable" };
  if (Array.isArray(input)) {
    return { status: "resolved", keys: decodeDidKeys(input) };
  }
  if (input.status === "unavailable") return { status: "unavailable" };
  return { status: "resolved", keys: decodeDidKeys(input.verificationKeys) };
}

function decodeDidKeys(keys: Array<string | Uint8Array>): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (const k of keys) {
    if (k instanceof Uint8Array) {
      if (k.length === 32) out.push(k);
      continue;
    }
    try {
      out.push(decodePublicKeyMultibase(k));
    } catch {
      // A verification method that is not a 0xed01 Ed25519 key (or fails to
      // decode) is not an anchor candidate; skip it.
    }
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function reject(reason: AgentCardVerifyReason): AgentCardVerifyResult {
  return { authenticated: false, rejected: true, reason, auditEvents: [] };
}

/** base64url no-padding, matching the encoder used across the crypto stack. */
function base64urlEncode(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binString).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
