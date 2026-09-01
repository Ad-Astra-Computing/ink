import { describe, it, expect } from "vitest";
import {
  AgentCardSchema,
  decodeEncryptionKeyMultibase,
  decodePublicKeyMultibase,
  encodePublicKeyMultibase,
  verifyAgentCardSignature,
  type AgentCard,
} from "@adastracomputing/ink";
import { ed25519 } from "@noble/curves/ed25519.js";
import { buildAgentCard } from "../src/agent-card.js";
import { loadReceiverIdentity, loadEncryptionIdentity, type ReceiverEnv } from "../src/keys.js";

// The live card at ink-echo.tulpa.network carried NO `keys` block at all, so
// the soak's `encrypted` synthetic variant failed every day with "receiver
// Agent Card advertises no active X25519 encryption key". These pin the card
// side: when an encryption identity is configured the card must advertise it in
// a shape a sender can actually seal to, and the card must still validate.

// Derive the public half from the seed rather than pasting a literal, so the
// fixture can never drift out of agreement with itself.
const SIGN_SEED = new Uint8Array(32).fill(4);
const SIGN_PUB_MULTIBASE = encodePublicKeyMultibase(ed25519.getPublicKey(SIGN_SEED));

const env = (extra: Partial<ReceiverEnv> = {}): ReceiverEnv =>
  ({
    INK_RECEIVER_SIGNING_SEED: Buffer.from(SIGN_SEED).toString("base64url"),
    INK_RECEIVER_PUBLIC_KEY_MULTIBASE: SIGN_PUB_MULTIBASE,
    INK_RECEIVER_HOST: "echo.example",
    ...extra,
  }) as ReceiverEnv;

const ENC_SEED = Buffer.from(new Uint8Array(32).fill(11)).toString("hex");

async function card(e: ReceiverEnv) {
  return (await buildAgentCard({
    did: "did:web:echo.example",
    host: "echo.example",
    identity: loadReceiverIdentity(e),
    encryption: loadEncryptionIdentity(e),
    updatedAt: "2026-08-26T00:00:00Z",
  })) as Record<string, any>;
}

describe("agent card encryption advertisement", () => {
  it("advertises an active X25519 encryption key when one is configured", async () => {
    const c = await card(env({ INK_RECEIVER_ENCRYPTION_SEED: ENC_SEED }));
    const enc = c.keys?.encryption ?? [];
    expect(enc.length).toBe(1);
    expect(enc[0].algorithm).toBe("X25519");
    expect(enc[0].status).toBe("active");
    // A sender must be able to decode it to seal against, which is the exact
    // step that was failing.
    expect(decodeEncryptionKeyMultibase(enc[0].publicKeyMultibase).length).toBe(32);
  });

  it("advertises the signing key alongside it, so the key set is complete", async () => {
    const c = await card(env({ INK_RECEIVER_ENCRYPTION_SEED: ENC_SEED }));
    const signing = c.keys?.signing ?? [];
    expect(signing.length).toBe(1);
    expect(signing[0].algorithm).toBe("Ed25519");
    expect(signing[0].status).toBe("active");
    expect(decodePublicKeyMultibase(signing[0].publicKeyMultibase).length).toBe(32);
  });

  it("still validates against the shipped AgentCardSchema", async () => {
    // The §4.1 key-role rule landed in 0.19.0: a signing slot must decode under
    // 0xed01 and an encryption slot under 0xec01. A card that advertises the
    // wrong codec in either slot now rejects, so this is the regression guard.
    const parsed = AgentCardSchema.safeParse(await card(env({ INK_RECEIVER_ENCRYPTION_SEED: ENC_SEED })));
    expect(parsed.success).toBe(true);
  });

  it("signs the key-set card with the named signing key and verifies", async () => {
    // §3.3: once `keys.signing` exists, `cardSignature.keyId` must name the
    // active signing entry and equal `currentSigningKeyId`. `bootstrap` on a
    // key-set card is a verifier reject (`signer_absent_from_signing`), which
    // would make the advertised X25519 key unusable for exactly the strict
    // senders that check the card proof before sealing to it.
    const c = await card(env({ INK_RECEIVER_ENCRYPTION_SEED: ENC_SEED }));
    expect(c.cardSignature?.keyId).toBe("receiver-signing-1");
    const result = await verifyAgentCardSignature(c as AgentCard, "did:web:echo.example", {
      profile: "pre-1.0",
      didVerificationKeys: [SIGN_PUB_MULTIBASE],
    });
    expect(result.authenticated).toBe(true);
  });

  it("keeps the bootstrap signer on the legacy single-key card", async () => {
    const c = await card(env());
    expect(c.cardSignature?.keyId).toBe("bootstrap");
    const result = await verifyAgentCardSignature(c as AgentCard, "did:web:echo.example", {
      profile: "pre-1.0",
      didVerificationKeys: [SIGN_PUB_MULTIBASE],
    });
    expect(result.authenticated).toBe(true);
  });

  it("omits the keys block entirely when no encryption seed is set", async () => {
    // Encryption stays opt-in; an existing deployment that sets no seed keeps
    // serving exactly the card it served before.
    const c = await card(env());
    expect(c.keys).toBeUndefined();
    expect(AgentCardSchema.safeParse(c).success).toBe(true);
  });
});
