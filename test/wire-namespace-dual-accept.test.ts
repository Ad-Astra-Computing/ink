/**
 * ink/0.4 wire-namespace dual-accept: receivers accept both the legacy
 * `network.tulpa.*` and the vendor-neutral `network.ink.*` spelling of every
 * message `type`, while senders keep EMITTING `network.tulpa.*` by default.
 * See specs/ink-compatibility-policy.md §1.3.
 */
import { describe, it, expect } from "vitest";
import {
  InkChallengeSchema,
  InkRejectionSchema,
  InkResolutionSchema,
  InkReceiptSchema,
  shouldSendReceipt,
  encryptInkPayload,
  decryptInkPayload,
  bytesToHex,
} from "../src/index.js";
import { generateEncryptionKeypair } from "../src/crypto/keys.js";

const TS = "2026-01-01T00:00:00.000Z";

describe("handshake schemas dual-accept the type namespace", () => {
  const challenge = (type: string) => ({ protocol: "ink/0.1", type, intentRef: "i1", challengeType: "none", nonce: "n1", timestamp: TS });
  const rejection = (type: string) => ({ protocol: "ink/0.1", type, intentRef: "i1", reason: "policy_violation", nonce: "n1", timestamp: TS });
  const resolution = (type: string) => ({ protocol: "ink/0.1", type, intentRef: "i1", outcome: "accepted", nonce: "n1", timestamp: TS });

  it("accepts both spellings of challenge / rejection / resolution", () => {
    for (const ns of ["network.tulpa", "network.ink"]) {
      expect(InkChallengeSchema.safeParse(challenge(`${ns}.challenge`)).success).toBe(true);
      expect(InkRejectionSchema.safeParse(rejection(`${ns}.rejection`)).success).toBe(true);
      expect(InkResolutionSchema.safeParse(resolution(`${ns}.resolution`)).success).toBe(true);
    }
  });

  it("still rejects an unrelated namespace", () => {
    expect(InkChallengeSchema.safeParse(challenge("network.evil.challenge")).success).toBe(false);
    expect(InkChallengeSchema.safeParse(challenge("network.ink.rejection")).success).toBe(false);
  });
});

describe("audit receipt schema dual-accepts", () => {
  const receipt = (type: string) => ({
    protocol: "ink/0.1", type, messageId: "m1", from: "tulpa:zA", to: "tulpa:zB",
    disposition: "received", dispositionAt: TS, messageHash: "00".repeat(32),
    nonce: "n1", timestamp: TS, signature: "x".repeat(86),
  });
  it("accepts both receipt spellings", () => {
    expect(InkReceiptSchema.safeParse(receipt("network.tulpa.receipt")).success).toBe(true);
    expect(InkReceiptSchema.safeParse(receipt("network.ink.receipt")).success).toBe(true);
  });
});

describe("receipt loop prevention covers both namespaces", () => {
  it("suppresses receipts for tulpa and ink audit/receipt types", () => {
    for (const ns of ["network.tulpa", "network.ink"]) {
      for (const suffix of ["receipt", "audit_query", "audit_response", "audit_submit", "audit_inclusion"]) {
        expect(shouldSendReceipt(`${ns}.${suffix}`)).toBe(false);
      }
    }
    // A normal intent still gets a receipt.
    expect(shouldSendReceipt("ping")).toBe(true);
  });
});

describe("encrypted envelope: default emit tulpa, dual-accept on decrypt, relabel fails", () => {
  async function recipient() {
    const kp = generateEncryptionKeypair();
    return { pubHex: bytesToHex(kp.publicKey), privHex: bytesToHex(kp.privateKey) };
  }
  const plaintext = { protocol: "ink/0.1", from: "did:web:s.example", to: "did:web:r.example", intent: "ping" };

  it("emits network.tulpa.encrypted by default and round-trips", async () => {
    const r = await recipient();
    const { envelope } = await encryptInkPayload(plaintext, "did:web:s.example", r.pubHex, TS, "nonce0000000000001");
    expect(envelope.type).toBe("network.tulpa.encrypted");
    const out = await decryptInkPayload(envelope, r.privHex, "did:web:r.example");
    expect(out.intent).toBe("ping");
  });

  it("emits and decrypts network.ink.encrypted when the sender opts in", async () => {
    const r = await recipient();
    const { envelope } = await encryptInkPayload(plaintext, "did:web:s.example", r.pubHex, TS, "nonce0000000000002", { messageType: "network.ink.encrypted" });
    expect(envelope.type).toBe("network.ink.encrypted");
    const out = await decryptInkPayload(envelope, r.privHex, "did:web:r.example");
    expect(out.intent).toBe("ping");
  });

  it("rejects a relabelled envelope (tulpa ciphertext retagged to ink) — AAD binds the actual type", async () => {
    const r = await recipient();
    const { envelope } = await encryptInkPayload(plaintext, "did:web:s.example", r.pubHex, TS, "nonce0000000000003");
    const relabelled = { ...envelope, type: "network.ink.encrypted" as const };
    await expect(decryptInkPayload(relabelled, r.privHex, "did:web:r.example")).rejects.toThrow();
  });

  it("still rejects an unrelated envelope type", async () => {
    const r = await recipient();
    const { envelope } = await encryptInkPayload(plaintext, "did:web:s.example", r.pubHex, TS, "nonce0000000000004");
    const bad = { ...envelope, type: "network.evil.encrypted" as unknown as "network.ink.encrypted" };
    await expect(decryptInkPayload(bad, r.privHex, "did:web:r.example")).rejects.toThrow();
  });
});
