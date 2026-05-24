/**
 * Security regression tests — round 18.
 *
 * Findings (Codex convergence pass on round 17):
 *  - isKeyValidAtTime() treated present non-string fields as absent.
 *    Round 18: any present-but-not-a-valid-datetime field fails closed.
 *  - extractCandidateKeys silently dropped malformed window fields,
 *    creating a softer key-discovery path. Round 18: skip the WHOLE
 *    entry instead.
 *  - encryptInkPayload canonicalized caller-controlled scalar AAD
 *    fields without length caps. Round 18: senderDid/timestamp/
 *    messageNonce capped before AAD build (mirrors decrypt).
 *  - Redacted Agent Cards stripped validity metadata, so first-contact
 *    peers seeing only the redacted form lost window enforcement.
 *    Round 18: validFrom/validUntil/revokedAt preserved in redacted
 *    signing entries.
 *  - decryptInkPayload's `recipientDid &&` check disabled binding on
 *    empty string. Round 18: undefined skips, anything else MUST bind.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  encryptInkPayload,
  decryptInkPayload,
  type InkEncryptedEnvelope,
} from "../src/crypto/ink.js";
import { buildRedactedCard } from "../src/ink/discovery-gating.js";
import { encodePublicKeyMultibase, encodeEncryptionKeyMultibase } from "../src/crypto/keys.js";
import type { AgentCard } from "../src/models/agent-card.js";

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

async function makeRecipient() {
  const priv = crypto.getRandomValues(new Uint8Array(32));
  const pub = x25519.getPublicKey(priv);
  return { priv, pub, privHex: bytesToHex(priv), pubHex: bytesToHex(pub) };
}

describe("encryptInkPayload: rejects oversized AAD scalar fields", () => {
  it("rejects senderDid larger than 512 chars", async () => {
    const r = await makeRecipient();
    const huge = "x".repeat(513);
    await expect(
      encryptInkPayload({ msg: "hi" }, huge, r.pubHex, new Date().toISOString(), "n".repeat(16)),
    ).rejects.toThrow(/senderDid/i);
  });

  it("rejects timestamp larger than 64 chars", async () => {
    const r = await makeRecipient();
    const huge = "2026-04-01T00:00:00Z" + "x".repeat(80);
    await expect(
      encryptInkPayload({ msg: "hi" }, "tulpa:zSender", r.pubHex, huge, "n".repeat(16)),
    ).rejects.toThrow(/timestamp/i);
  });

  it("rejects messageNonce larger than 256 chars", async () => {
    const r = await makeRecipient();
    const huge = "x".repeat(257);
    await expect(
      encryptInkPayload({ msg: "hi" }, "tulpa:zSender", r.pubHex, new Date().toISOString(), huge),
    ).rejects.toThrow(/messageNonce/i);
  });

  it("rejects empty-string scalar fields", async () => {
    const r = await makeRecipient();
    await expect(
      encryptInkPayload({ msg: "hi" }, "", r.pubHex, new Date().toISOString(), "n".repeat(16)),
    ).rejects.toThrow();
  });

  it("still round-trips a legitimate payload", async () => {
    const r = await makeRecipient();
    const result = await encryptInkPayload(
      { msg: "hi", from: "did:plc:alice", to: "did:plc:bob" },
      "did:plc:alice",
      r.pubHex,
      "2026-04-01T00:00:00Z",
      "nonce1234567890123",
    );
    const out = await decryptInkPayload(result.envelope, r.privHex);
    expect(out.msg).toBe("hi");
  });
});

describe("decryptInkPayload: recipientDid binding cannot be disabled by empty string", () => {
  async function encryptedFor(toDid: string) {
    const r = await makeRecipient();
    const sender = await makeRecipient();
    const result = await encryptInkPayload(
      { msg: "hi", to: toDid, from: "did:plc:sender" },
      "did:plc:sender",
      r.pubHex,
      "2026-04-01T00:00:00Z",
      "nonce1234567890123",
    );
    return { envelope: result.envelope, privHex: r.privHex };
  }

  it("rejects empty-string recipientDid (no longer treated as 'skip binding')", async () => {
    const { envelope, privHex } = await encryptedFor("did:plc:bob");
    await expect(decryptInkPayload(envelope, privHex, "")).rejects.toThrow();
  });

  it("undefined recipientDid still skips binding (legacy compat)", async () => {
    const { envelope, privHex } = await encryptedFor("did:plc:bob");
    const out = await decryptInkPayload(envelope, privHex);
    expect(out.to).toBe("did:plc:bob");
  });

  it("matching recipientDid succeeds", async () => {
    const { envelope, privHex } = await encryptedFor("did:plc:bob");
    const out = await decryptInkPayload(envelope, privHex, "did:plc:bob");
    expect(out.to).toBe("did:plc:bob");
  });

  it("mismatched recipientDid throws", async () => {
    const { envelope, privHex } = await encryptedFor("did:plc:bob");
    await expect(decryptInkPayload(envelope, privHex, "did:plc:carol")).rejects.toThrow(/'to'/);
  });
});

describe("buildRedactedCard: preserves key validity windows", () => {
  it("redacted signing entries keep validFrom/validUntil/revokedAt", async () => {
    const sigKey = await (async () => {
      const priv = ed.utils.randomPrivateKey();
      const pub = await ed.getPublicKeyAsync(priv);
      return { priv, pub };
    })();
    const sigMultibase = encodePublicKeyMultibase(sigKey.pub);
    const encKey = await makeRecipient();
    const encMultibase = encodeEncryptionKeyMultibase(encKey.pub);

    const card: AgentCard = {
      protocol: "ink/0.1",
      agentId: "tulpa:test",
      handle: "test",
      displayName: "Test",
      endpoint: "https://example.com",
      publicKeyMultibase: sigMultibase,
      capabilities: { intentsAccepted: [], intentsSent: [] },
      availability: { timezone: "UTC" },
      keys: {
        signing: [
          {
            keyId: "k1",
            algorithm: "Ed25519",
            publicKeyMultibase: sigMultibase,
            status: "active",
            validFrom: "2026-01-01T00:00:00Z",
            validUntil: "2026-12-31T23:59:59Z",
          },
        ],
        encryption: [
          {
            keyId: "e1",
            algorithm: "X25519",
            publicKeyMultibase: encMultibase,
            status: "active",
            validFrom: "2026-01-01T00:00:00Z",
          },
        ],
      },
    } as unknown as AgentCard;

    const redacted = buildRedactedCard(card);
    expect(redacted.keys?.signing).toBeDefined();
    expect(redacted.keys!.signing[0]!.validFrom).toBe("2026-01-01T00:00:00Z");
    expect(redacted.keys!.signing[0]!.validUntil).toBe("2026-12-31T23:59:59Z");
  });
});
