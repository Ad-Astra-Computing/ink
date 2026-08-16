/**
 * Security regression tests — round 12.
 *
 * Findings (Claude opus-4.7, iter2):
 *  - hexToBytes accepts unbounded input; key-bytes path runs the O(n)
 *    regex and allocation loop before any semantic length check.
 *  - encryptInkPayload / decryptInkPayload had no explicit
 *    `recipientPub.length !== 32` / `recipientPriv.length !== 32` guard
 *    after `hexToBytes`; noble-curves throws on wrong-length input but
 *    only after an unrelated buffer has already been allocated.
 */
import { describe, it, expect } from "vitest";
import { encryptInkPayload, decryptInkPayload } from "../src/crypto/ink.js";

// ── Reject oversize recipient key hex on encrypt ──

describe("encryptInkPayload: rejects malformed recipientEncryptionKeyHex", () => {
  it("rejects an absurdly long hex string before crypto work", async () => {
    const huge = "ab".repeat(100_000); // 200 KB hex
    await expect(
      encryptInkPayload({ msg: "hi", from: "tulpa:zSender", to: "tulpa:zRecipient" }, "tulpa:zSender", huge, new Date().toISOString(), "n".repeat(16)),
    ).rejects.toThrow();
  });

  it("rejects wrong-length but otherwise valid hex with a clean error", async () => {
    const short = "ab".repeat(31); // 31 bytes -- wrong X25519 length
    await expect(
      encryptInkPayload({ msg: "hi", from: "tulpa:zSender", to: "tulpa:zRecipient" }, "tulpa:zSender", short, new Date().toISOString(), "n".repeat(16)),
    ).rejects.toThrow();
  });
});

// ── Round 12.1: low-order recipient public key (encrypt path) ──

describe("encryptInkPayload: rejects low-order recipient public keys", () => {
  it("throws when the recipient public key is in the small subgroup", async () => {
    // A 32-byte all-zero key is in the small subgroup. noble-curves
    // refuses these at getSharedSecret; the explicit all-zeros guard we
    // added in src/crypto/ink.ts is defense-in-depth in case a future
    // ECDH backend drops the upstream check. Either layer must throw.
    const lowOrderHex = "00".repeat(32);
    await expect(
      encryptInkPayload({ msg: "hi", from: "tulpa:zSender", to: "tulpa:zRecipient" }, "tulpa:zSender", lowOrderHex, new Date().toISOString(), "n".repeat(16)),
    ).rejects.toThrow();
  });
});

describe("decryptInkPayload: rejects malformed recipientEncryptionPrivateKeyHex", () => {
  const envelope = {
    protocol: "ink/0.1" as const,
    type: "network.tulpa.encrypted" as const,
    from: "tulpa:zSender",
    ephemeralKey: "x".repeat(43),
    nonce: "n".repeat(16),
    ciphertext: "c".repeat(32),
    timestamp: new Date().toISOString(),
    messageNonce: "m".repeat(32),
  };

  it("rejects oversize hex private key before crypto work", async () => {
    const huge = "ab".repeat(100_000);
    await expect(decryptInkPayload(envelope, huge, "did:plc:bob")).rejects.toThrow();
  });

  it("rejects wrong-length valid hex with a clean error", async () => {
    const short = "ab".repeat(31);
    await expect(decryptInkPayload(envelope, short, "did:plc:bob")).rejects.toThrow();
  });
});
