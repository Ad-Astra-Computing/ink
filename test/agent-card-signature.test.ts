/**
 * Self-authenticating Agent Card (ink-agent-card-signature.md, Phase A slice 1).
 *
 * Covers the accept paths and the forgery-rejection cases the spec enumerates
 * (§8 vectors), including the chain-extension fork whose honest residual is a
 * COLD accept and a WARM reject. Keypairs are fixed 32-byte seeds so the vectors
 * are deterministic.
 */
import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import {
  deriveAgentId,
  encodePublicKeyMultibase,
  encodeEncryptionKeyMultibase,
  jcsCanonicalize,
  signAgentCard,
  signRotationLink,
  verifyAgentCardSignature,
  type AgentCard,
  type AgentCardVerifyOptions,
} from "../src/index.js";

interface KP {
  priv: Uint8Array;
  pub: Uint8Array;
  multibase: string;
}

async function fixedKeypair(seed: number): Promise<KP> {
  const priv = new Uint8Array(32).fill(seed);
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, multibase: encodePublicKeyMultibase(pub) };
}

function base64url(bytes: Uint8Array): string {
  const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const VALID_FROM = "2026-01-01T00:00:00Z";
const UPDATED_AT = "2026-07-20T00:00:00Z";

function baseCard(agentId: string, topKeyMultibase: string): AgentCard {
  return {
    protocol: "ink/0.1",
    agentId,
    handle: "agent",
    displayName: "Agent",
    endpoint: "https://example.com/ink",
    publicKeyMultibase: topKeyMultibase,
    capabilities: { intentsAccepted: [], intentsSent: [] },
    availability: { timezone: "UTC" },
  } as AgentCard;
}

function signingEntry(keyId: string, kp: KP, status: "active" | "retired" | "revoked") {
  return { keyId, algorithm: "Ed25519" as const, publicKeyMultibase: kp.multibase, status, validFrom: VALID_FROM };
}

async function attachCardSignature(card: AgentCard, keyId: string, priv: Uint8Array): Promise<AgentCard> {
  const signature = await signAgentCard(card as unknown as Record<string, unknown>, priv);
  return { ...card, cardSignature: { keyId, signature } };
}

const PROFILE_A: AgentCardVerifyOptions = { profile: "pre-1.0" };
const PROFILE_10: AgentCardVerifyOptions = { profile: "1.0" };

// Fixed key material shared across vectors.
let G: KP; // genesis
let A: KP; // rotated / leaked historical key
let B: KP; // genuine current key after rotation
let X: KP; // attacker key
let H: KP; // second active key
let D: KP; // did:web key
let OTHER: KP; // an unrelated key

beforeAll(async () => {
  [G, A, B, X, H, D, OTHER] = await Promise.all([
    fixedKeypair(1),
    fixedKeypair(2),
    fixedKeypair(3),
    fixedKeypair(4),
    fixedKeypair(5),
    fixedKeypair(6),
    fixedKeypair(7),
  ]);
});

describe("verifyAgentCardSignature — accept paths", () => {
  it("signed key-derived, no chain, accept", async () => {
    const agentId = deriveAgentId(G.pub);
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    card.currentSigningKeyId = "g1";
    card.keySetVersion = 1;
    card.updatedAt = UPDATED_AT;
    const signed = await attachCardSignature(card, "g1", G.priv);

    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_10);
    expect(result.authenticated).toBe(true);
    expect(result.rejected).toBe(false);
    expect(result.reason).toBe("signed_authenticated");
    expect(result.auditEvents).toEqual([]);
  });

  it("rotated signer, valid two-link chain, accept", async () => {
    const agentId = deriveAgentId(G.pub);
    const link1Body = { keySetVersion: 1, signing: [signingEntry("kA", A, "active")], prevKeyId: "g" };
    const link1 = { ...link1Body, signature: await signRotationLink(link1Body, G.priv) };
    const link2Body = {
      keySetVersion: 2,
      signing: [signingEntry("kA", A, "retired"), signingEntry("kB", B, "active")],
      prevKeyId: "kA",
    };
    const link2 = { ...link2Body, signature: await signRotationLink(link2Body, A.priv) };

    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("kA", A, "retired"), signingEntry("kB", B, "active")], encryption: [] };
    card.currentSigningKeyId = "kB";
    card.keySetVersion = 2;
    card.rotationChain = [link1, link2];
    const signed = await attachCardSignature(card, "kB", B.priv);

    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_10);
    expect(result.authenticated).toBe(true);
    expect(result.reason).toBe("signed_authenticated");
  });

  it("legacy bootstrap-keyId card, accept", async () => {
    const agentId = deriveAgentId(G.pub);
    // No keys.signing set → legacy single-key card. keyId MUST be `bootstrap`
    // and the top-level publicKeyMultibase is the genesis key.
    const card = baseCard(agentId, G.multibase);
    card.keySetVersion = 1;
    const signed = await attachCardSignature(card, "bootstrap", G.priv);

    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.authenticated).toBe(true);
    expect(result.reason).toBe("signed_authenticated");
  });
});

describe("verifyAgentCardSignature — proof rejects", () => {
  async function keyDerivedSigned(mutate: (c: AgentCard) => void, signerKeyId: string, signerPriv: Uint8Array) {
    const agentId = deriveAgentId(G.pub);
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    card.currentSigningKeyId = "g1";
    card.keySetVersion = 1;
    mutate(card);
    const signed = await attachCardSignature(card, signerKeyId, signerPriv);
    return { agentId, signed };
  }

  it("retired signer, reject", async () => {
    const { agentId, signed } = await keyDerivedSigned((c) => {
      c.keys = { signing: [signingEntry("g1", G, "retired")], encryption: [] };
    }, "g1", G.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("signer_not_active");
  });

  it("revoked signer, reject", async () => {
    const { agentId, signed } = await keyDerivedSigned((c) => {
      c.keys = { signing: [signingEntry("g1", G, "revoked")], encryption: [] };
    }, "g1", G.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("signer_not_active");
  });

  it("cardSignature.keyId not equal to currentSigningKeyId, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const card = baseCard(agentId, G.multibase);
    // Two active keys; the card is signed by the non-current one.
    card.keys = { signing: [signingEntry("g1", G, "active"), signingEntry("g2", H, "active")], encryption: [] };
    card.currentSigningKeyId = "g1";
    card.keySetVersion = 1;
    const signed = await attachCardSignature(card, "g2", H.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("signer_not_current");
  });

  it("keyId absent from keys.signing, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    card.currentSigningKeyId = "g1";
    card.keySetVersion = 1;
    const signed = await attachCardSignature(card, "nope", G.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("signer_absent_from_signing");
  });

  it("wrong-domain signature, reject (never demoted to unsigned)", async () => {
    const agentId = deriveAgentId(G.pub);
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    card.currentSigningKeyId = "g1";
    card.keySetVersion = 1;
    // Sign over the body domain `tulpa/sign\n` instead of `ink/agent-card\n`.
    const canonical = jcsCanonicalize(card as unknown as Record<string, unknown>);
    const bytes = new TextEncoder().encode("tulpa/sign\n" + canonical);
    const wrong = base64url(await ed.signAsync(bytes, G.priv));
    const signed = { ...card, cardSignature: { keyId: "g1", signature: wrong } } as AgentCard;

    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("invalid_signature");
    expect(result.authenticated).toBe(false);
  });

  it("active key material substituted after signing, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    card.currentSigningKeyId = "g1";
    card.keySetVersion = 1;
    const signed = await attachCardSignature(card, "g1", G.priv);
    // Swap the signing key's public material after the signature was computed.
    signed.keys!.signing[0]!.publicKeyMultibase = H.multibase;
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("invalid_signature");
  });
});

describe("verifyAgentCardSignature — rooting rejects", () => {
  it("head keySetVersion disagrees with card, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const link1Body = { keySetVersion: 1, signing: [signingEntry("kA", A, "active")], prevKeyId: "g" };
    const link1 = { ...link1Body, signature: await signRotationLink(link1Body, G.priv) };
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("kA", A, "active")], encryption: [] };
    card.currentSigningKeyId = "kA";
    card.keySetVersion = 2; // head link commits version 1
    card.rotationChain = [link1];
    const signed = await attachCardSignature(card, "kA", A.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("head_version_mismatch");
  });

  it("head set does not correspond to keys.signing, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const link1Body = { keySetVersion: 1, signing: [signingEntry("kA", A, "active")], prevKeyId: "g" };
    const link1 = { ...link1Body, signature: await signRotationLink(link1Body, G.priv) };
    const card = baseCard(agentId, G.multibase);
    // Card carries an extra signing entry the head link does not commit.
    card.keys = { signing: [signingEntry("kA", A, "active"), signingEntry("kC", H, "active")], encryption: [] };
    card.currentSigningKeyId = "kA";
    card.keySetVersion = 1;
    card.rotationChain = [link1];
    const signed = await attachCardSignature(card, "kA", A.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("head_set_mismatch");
  });

  it("non-contiguous keySetVersion, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const link1Body = { keySetVersion: 1, signing: [signingEntry("kA", A, "active")], prevKeyId: "g" };
    const link1 = { ...link1Body, signature: await signRotationLink(link1Body, G.priv) };
    // Gap: link1 v1, link2 v3.
    const link2Body = { keySetVersion: 3, signing: [signingEntry("kB", B, "active")], prevKeyId: "kA" };
    const link2 = { ...link2Body, signature: await signRotationLink(link2Body, A.priv) };
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("kB", B, "active")], encryption: [] };
    card.currentSigningKeyId = "kB";
    card.keySetVersion = 3;
    card.rotationChain = [link1, link2];
    const signed = await attachCardSignature(card, "kB", B.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("chain_noncontiguous_version");
  });

  it("chain link signer not active in the prior set, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    // link1 marks kA retired; link2 claims to be signed by kA.
    const link1Body = { keySetVersion: 1, signing: [signingEntry("kA", A, "retired")], prevKeyId: "g" };
    const link1 = { ...link1Body, signature: await signRotationLink(link1Body, G.priv) };
    const link2Body = { keySetVersion: 2, signing: [signingEntry("kB", B, "active")], prevKeyId: "kA" };
    const link2 = { ...link2Body, signature: await signRotationLink(link2Body, A.priv) };
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("kB", B, "active")], encryption: [] };
    card.currentSigningKeyId = "kB";
    card.keySetVersion = 2;
    card.rotationChain = [link1, link2];
    const signed = await attachCardSignature(card, "kB", B.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("chain_link_signer_not_active");
  });

  it("no-chain signer not byte-equal to the genesis key, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    // Card is signed by A, but no chain roots A to the genesis key G.
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("kA", A, "active")], encryption: [] };
    card.currentSigningKeyId = "kA";
    card.keySetVersion = 1;
    const signed = await attachCardSignature(card, "kA", A.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("genesis_key_mismatch");
  });
});

describe("verifyAgentCardSignature — unsigned ratchet and profile", () => {
  it("unsigned after ratcheted observation, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const unsigned = baseCard(agentId, G.multibase);
    const cachedCard = baseCard(agentId, G.multibase);
    cachedCard.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    cachedCard.keySetVersion = 1;
    const result = await verifyAgentCardSignature(unsigned, agentId, { profile: "pre-1.0", cachedCard });
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("unsigned_after_authenticated");
  });

  it("unsigned first contact, pre-1.0 profile, accept", async () => {
    const agentId = "did:web:example.com";
    const unsigned = baseCard(agentId, G.multibase);
    const result = await verifyAgentCardSignature(unsigned, agentId, PROFILE_A);
    expect(result.authenticated).toBe(true);
    expect(result.reason).toBe("unsigned_first_contact_accepted");
  });

  it("unsigned first contact, 1.0 profile, reject", async () => {
    const agentId = "did:web:example.com";
    const unsigned = baseCard(agentId, G.multibase);
    const result = await verifyAgentCardSignature(unsigned, agentId, PROFILE_10);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("unsigned_1_0_profile");
  });

  it("unsigned key-derived, 1.0 profile, reject even on first contact", async () => {
    const agentId = deriveAgentId(G.pub);
    const unsigned = baseCard(agentId, G.multibase);
    const result = await verifyAgentCardSignature(unsigned, agentId, PROFILE_10);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("unsigned_key_derived_1_0");
  });
});

describe("verifyAgentCardSignature — continuity", () => {
  it("keySetVersion regression versus cached, reject with continuity audit", async () => {
    const agentId = deriveAgentId(G.pub);
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    card.currentSigningKeyId = "g1";
    card.keySetVersion = 1;
    const signed = await attachCardSignature(card, "g1", G.priv);

    const cachedCard = baseCard(agentId, G.multibase);
    cachedCard.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    cachedCard.keySetVersion = 5;

    const result = await verifyAgentCardSignature(signed, agentId, { profile: "1.0", cachedCard });
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("continuity_version_regression");
    expect(result.auditEvents).toContain("card.continuity_violation");
  });
});

describe("verifyAgentCardSignature — chain-extension fork (honest residual)", () => {
  // Genuine history: link1 (v1) commits kA active, signed by genesis G. The
  // genuine link2 (v2) revokes kA and promotes kB, signed by kA. An attacker who
  // leaked kA presents genuine link1, OMITS the genuine revoking link2, and
  // appends a FORGED link2' signed by kA that commits an attacker key kX.
  async function forgedCard(): Promise<{ agentId: string; card: AgentCard }> {
    const agentId = deriveAgentId(G.pub);
    const link1Body = { keySetVersion: 1, signing: [signingEntry("kA", A, "active")], prevKeyId: "g" };
    const link1 = { ...link1Body, signature: await signRotationLink(link1Body, G.priv) };
    const forgedLink2Body = { keySetVersion: 2, signing: [signingEntry("kX", X, "active")], prevKeyId: "kA" };
    const forgedLink2 = { ...forgedLink2Body, signature: await signRotationLink(forgedLink2Body, A.priv) };
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("kX", X, "active")], encryption: [] };
    card.currentSigningKeyId = "kX";
    card.keySetVersion = 2;
    card.rotationChain = [link1, forgedLink2];
    const signed = await attachCardSignature(card, "kX", X.priv);
    return { agentId, card: signed };
  }

  it("COLD verifier accepts the forged extension (documented residual)", async () => {
    const { agentId, card } = await forgedCard();
    // No cached state to constrain the chain: the leaked kA is active in link1,
    // so the forged link and its head bind cleanly. Cold accept is inherent.
    const result = await verifyAgentCardSignature(card, agentId, PROFILE_10);
    expect(result.authenticated).toBe(true);
    expect(result.rejected).toBe(false);
    expect(result.reason).toBe("signed_authenticated");
  });

  it("WARM verifier rejects the forged extension via continuity", async () => {
    const { agentId, card } = await forgedCard();
    // The cached authenticated card records the genuine v2: kA revoked, kB the
    // current key. The forged head branches from kA, which is revoked in the
    // cached non-revoked set, so continuity rejects and keeps the cached card.
    const cachedCard = baseCard(agentId, G.multibase);
    cachedCard.keys = {
      signing: [signingEntry("kA", A, "revoked"), signingEntry("kB", B, "active")],
      encryption: [],
    };
    cachedCard.currentSigningKeyId = "kB";
    cachedCard.keySetVersion = 2;

    const result = await verifyAgentCardSignature(card, agentId, { profile: "1.0", cachedCard });
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("continuity_unreachable_key");
    expect(result.auditEvents).toContain("card.continuity_violation");
  });

  it("WARM verifier rejects a committed-set-stuffing forgery via verified-signer continuity", async () => {
    // Committed-set stuffing: the attacker holds the leaked, now-revoked kA
    // (active in genuine link1). It forges link2' SIGNED BY kA that STUFFS the
    // genuine current key kB into its committed set alongside the attacker key
    // kX — kB signs NOTHING in the forged chain. The head binds to {kX, kB} and
    // the card is signed by kX. Continuity must NOT bridge through kB's mere
    // presence in a committed set: kB never exercised signing authority in this
    // chain, so the only verified signers are the genesis G, kA (leaked, revoked)
    // and the card signer kX — none of which is in the cached non-revoked set.
    const agentId = deriveAgentId(G.pub);
    const link1Body = { keySetVersion: 1, signing: [signingEntry("kA", A, "active")], prevKeyId: "g" };
    const link1 = { ...link1Body, signature: await signRotationLink(link1Body, G.priv) };
    const forgedLink2Body = {
      keySetVersion: 2,
      signing: [signingEntry("kX", X, "active"), signingEntry("kB", B, "active")],
      prevKeyId: "kA",
    };
    const forgedLink2 = { ...forgedLink2Body, signature: await signRotationLink(forgedLink2Body, A.priv) };
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("kX", X, "active"), signingEntry("kB", B, "active")], encryption: [] };
    card.currentSigningKeyId = "kX";
    card.keySetVersion = 2;
    card.rotationChain = [link1, forgedLink2];
    const signed = await attachCardSignature(card, "kX", X.priv);

    // Cached genuine v2: kA revoked, kB the active current key.
    const cachedCard = baseCard(agentId, G.multibase);
    cachedCard.keys = {
      signing: [signingEntry("kA", A, "revoked"), signingEntry("kB", B, "active")],
      encryption: [],
    };
    cachedCard.currentSigningKeyId = "kB";
    cachedCard.keySetVersion = 2;

    const result = await verifyAgentCardSignature(signed, agentId, { profile: "1.0", cachedCard });
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("continuity_unreachable_key");
    expect(result.auditEvents).toContain("card.continuity_violation");
  });
});

describe("verifyAgentCardSignature — did:web anchoring", () => {
  function didCard() {
    const agentId = "did:web:example.com";
    const card = baseCard(agentId, D.multibase);
    card.keys = { signing: [signingEntry("d1", D, "active")], encryption: [] };
    card.currentSigningKeyId = "d1";
    card.keySetVersion = 1;
    return { agentId, card };
  }

  it("signer present in the DID document, accept", async () => {
    const { agentId, card } = didCard();
    const signed = await attachCardSignature(card, "d1", D.priv);
    const result = await verifyAgentCardSignature(signed, agentId, {
      profile: "1.0",
      didVerificationKeys: { status: "resolved", verificationKeys: [D.multibase] },
    });
    expect(result.authenticated).toBe(true);
    expect(result.reason).toBe("signed_authenticated");
  });

  it("signer absent from the DID document, reject", async () => {
    const { agentId, card } = didCard();
    const signed = await attachCardSignature(card, "d1", D.priv);
    const result = await verifyAgentCardSignature(signed, agentId, {
      profile: "1.0",
      didVerificationKeys: { status: "resolved", verificationKeys: [OTHER.multibase] },
    });
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("didweb_signer_not_anchored");
  });

  it("resolver unavailable, cold verifier, 1.0, fails closed", async () => {
    const { agentId, card } = didCard();
    const signed = await attachCardSignature(card, "d1", D.priv);
    const result = await verifyAgentCardSignature(signed, agentId, {
      profile: "1.0",
      didVerificationKeys: { status: "unavailable" },
    });
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("didweb_resolver_unavailable");
  });

  it("resolver unavailable, warm verifier, continues with anchor_unverified", async () => {
    const { agentId, card } = didCard();
    const signed = await attachCardSignature(card, "d1", D.priv);
    const cachedCard = baseCard(agentId, D.multibase);
    cachedCard.keys = { signing: [signingEntry("d1", D, "active")], encryption: [] };
    cachedCard.keySetVersion = 1;
    const result = await verifyAgentCardSignature(signed, agentId, {
      profile: "1.0",
      cachedCard,
      didVerificationKeys: { status: "unavailable" },
    });
    expect(result.authenticated).toBe(true);
    expect(result.auditEvents).toContain("card.anchor_unverified");
  });

  it("did:web card carrying a rotationChain re-rooted on a DID-document key, accept", async () => {
    const agentId = "did:web:example.com";
    // Link 1 is re-rooted on the DID-document key D (§4.2). It rotates to kB,
    // which is also a DID-document verification method so it anchors the card.
    const link1Body = { keySetVersion: 1, signing: [signingEntry("kA", A, "active")], prevKeyId: "did-root" };
    const link1 = { ...link1Body, signature: await signRotationLink(link1Body, D.priv) };
    const link2Body = {
      keySetVersion: 2,
      signing: [signingEntry("kA", A, "retired"), signingEntry("kB", B, "active")],
      prevKeyId: "kA",
    };
    const link2 = { ...link2Body, signature: await signRotationLink(link2Body, A.priv) };
    const card = baseCard(agentId, D.multibase);
    card.keys = { signing: [signingEntry("kA", A, "retired"), signingEntry("kB", B, "active")], encryption: [] };
    card.currentSigningKeyId = "kB";
    card.keySetVersion = 2;
    card.rotationChain = [link1, link2];
    const signed = await attachCardSignature(card, "kB", B.priv);

    const result = await verifyAgentCardSignature(signed, agentId, {
      profile: "1.0",
      didVerificationKeys: { status: "resolved", verificationKeys: [D.multibase, B.multibase] },
    });
    expect(result.authenticated).toBe(true);
    expect(result.reason).toBe("signed_authenticated");
  });

  it("did:web card carrying a rotationChain whose link 1 is not a DID-document key, reject", async () => {
    const agentId = "did:web:example.com";
    // The card signer kB is anchored, but link 1 is signed by G, which is NOT a
    // DID-document verification method, so link-1 re-rooting fails (§4.2).
    const link1Body = { keySetVersion: 1, signing: [signingEntry("kB", B, "active")], prevKeyId: "did-root" };
    const link1 = { ...link1Body, signature: await signRotationLink(link1Body, G.priv) };
    const card = baseCard(agentId, B.multibase);
    card.keys = { signing: [signingEntry("kB", B, "active")], encryption: [] };
    card.currentSigningKeyId = "kB";
    card.keySetVersion = 1;
    card.rotationChain = [link1];
    const signed = await attachCardSignature(card, "kB", B.priv);

    const result = await verifyAgentCardSignature(signed, agentId, {
      profile: "1.0",
      didVerificationKeys: { status: "resolved", verificationKeys: [B.multibase] },
    });
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("didweb_signer_not_anchored");
  });
});

describe("verifyAgentCardSignature — unrooted principal (forgery fix)", () => {
  it("did:key card self-signed by a key in its own keys.signing, reject", async () => {
    // A did:key principal is neither key-derived (tulpa:/ink:) nor did:web, so §4
    // defines no trust root for it. A valid self-signed cardSignature must NOT be
    // accepted with no anchor, and must NOT be demoted to unsigned (§3.4).
    const agentId = `did:key:${G.multibase}`;
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    card.currentSigningKeyId = "g1";
    card.keySetVersion = 1;
    const signed = await attachCardSignature(card, "g1", G.priv);

    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.authenticated).toBe(false);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("unrooted_principal");
  });
});

describe("verifyAgentCardSignature — keySetVersion enforcement (§6)", () => {
  it("signed card lacking keySetVersion, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    card.currentSigningKeyId = "g1";
    // No keySetVersion: a signed card MUST carry it (the sole monotonic quantity).
    const signed = await attachCardSignature(card, "g1", G.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("missing_key_set_version");
  });
});

describe("verifyAgentCardSignature — multi-hop continuity", () => {
  // The agent rotated TWICE between two warm fetches: cached v1 holds kB; the new
  // v3 card carries a genesis→kB→kC→kD chain. The new signer kD is not a cached
  // key and the head-link signer is kC, also not cached, so a one-hop check would
  // wrongly reject. Reachability holds because an INTERIOR link commits kB.
  async function twoHopCard() {
    const agentId = deriveAgentId(G.pub);
    const link1Body = { keySetVersion: 1, signing: [signingEntry("kB", B, "active")], prevKeyId: "g" };
    const link1 = { ...link1Body, signature: await signRotationLink(link1Body, G.priv) };
    const link2Body = {
      keySetVersion: 2,
      signing: [signingEntry("kB", B, "retired"), signingEntry("kC", H, "active")],
      prevKeyId: "kB",
    };
    const link2 = { ...link2Body, signature: await signRotationLink(link2Body, B.priv) };
    const link3Body = {
      keySetVersion: 3,
      signing: [signingEntry("kC", H, "retired"), signingEntry("kD", D, "active")],
      prevKeyId: "kC",
    };
    const link3 = { ...link3Body, signature: await signRotationLink(link3Body, H.priv) };
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("kC", H, "retired"), signingEntry("kD", D, "active")], encryption: [] };
    card.currentSigningKeyId = "kD";
    card.keySetVersion = 3;
    card.rotationChain = [link1, link2, link3];
    const signed = await attachCardSignature(card, "kD", D.priv);
    return { agentId, card: signed };
  }

  it("multi-hop warm rotation reachable through an interior link, accept", async () => {
    const { agentId, card } = await twoHopCard();
    const cachedCard = baseCard(agentId, G.multibase);
    cachedCard.keys = { signing: [signingEntry("kB", B, "active")], encryption: [] };
    cachedCard.currentSigningKeyId = "kB";
    cachedCard.keySetVersion = 1;

    const result = await verifyAgentCardSignature(card, agentId, { profile: "1.0", cachedCard });
    expect(result.authenticated).toBe(true);
    expect(result.rejected).toBe(false);
    expect(result.reason).toBe("signed_authenticated");
  });
});

describe("verifyAgentCardSignature — additional rooting and proof coverage", () => {
  it("rotation chain longer than 32 links, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    card.currentSigningKeyId = "g1";
    card.keySetVersion = 1;
    card.rotationChain = Array.from({ length: 33 }, (_, i) => ({
      keySetVersion: i + 1,
      signing: [signingEntry(`k${i}`, G, "active")],
      prevKeyId: "g",
      signature: "A".repeat(86),
    }));
    const signed = await attachCardSignature(card, "g1", G.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("chain_too_long");
  });

  it("card-level duplicate keyId in keys.signing, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("g1", G, "active"), signingEntry("g1", H, "active")], encryption: [] };
    card.currentSigningKeyId = "g1";
    card.keySetVersion = 1;
    const signed = await attachCardSignature(card, "g1", G.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("duplicate_key_id");
  });

  it("link-level duplicate keyId in a rotation link, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const link1Body = {
      keySetVersion: 1,
      signing: [signingEntry("kA", A, "active"), signingEntry("kA", B, "active")],
      prevKeyId: "g",
    };
    const link1 = { ...link1Body, signature: await signRotationLink(link1Body, G.priv) };
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("kA", A, "active")], encryption: [] };
    card.currentSigningKeyId = "kA";
    card.keySetVersion = 1;
    card.rotationChain = [link1];
    const signed = await attachCardSignature(card, "kA", A.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("chain_duplicate_key_id");
  });

  it("invalid key encoding (wrong multicodec) on the signer entry, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const card = baseCard(agentId, G.multibase);
    // An X25519 (0xec01) multibase where an Ed25519 (0xed01) key is required.
    card.keys = {
      signing: [{ keyId: "g1", algorithm: "Ed25519", publicKeyMultibase: encodeEncryptionKeyMultibase(G.pub), status: "active", validFrom: VALID_FROM }],
      encryption: [],
    } as AgentCard["keys"];
    card.currentSigningKeyId = "g1";
    card.keySetVersion = 1;
    const signed = { ...card, cardSignature: { keyId: "g1", signature: "A".repeat(86) } } as AgentCard;
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("invalid_key_encoding");
  });

  it("signed key-set card with no currentSigningKeyId, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("g1", G, "active")], encryption: [] };
    card.keySetVersion = 1;
    // currentSigningKeyId omitted.
    const signed = await attachCardSignature(card, "g1", G.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("missing_current_signing_key_id");
  });

  it("legacy single-key card whose keyId is not the literal bootstrap, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    // No keys.signing → legacy single-key card; keyId MUST be `bootstrap` (§3.3).
    const card = baseCard(agentId, G.multibase);
    card.keySetVersion = 1;
    const signed = await attachCardSignature(card, "g1", G.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("legacy_bootstrap_mismatch");
  });

  it("head-set status disagreement with keys.signing, reject", async () => {
    const agentId = deriveAgentId(G.pub);
    // Head link commits kB active; the card carries kB as retired, so the status
    // disagrees and the exact head correspondence (§4.1 step 3b) fails.
    const link1Body = {
      keySetVersion: 1,
      signing: [signingEntry("kA", A, "active"), signingEntry("kB", B, "active")],
      prevKeyId: "g",
    };
    const link1 = { ...link1Body, signature: await signRotationLink(link1Body, G.priv) };
    const card = baseCard(agentId, G.multibase);
    card.keys = { signing: [signingEntry("kA", A, "active"), signingEntry("kB", B, "retired")], encryption: [] };
    card.currentSigningKeyId = "kA";
    card.keySetVersion = 1;
    card.rotationChain = [link1];
    const signed = await attachCardSignature(card, "kA", A.priv);
    const result = await verifyAgentCardSignature(signed, agentId, PROFILE_A);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("head_set_mismatch");
  });
});
