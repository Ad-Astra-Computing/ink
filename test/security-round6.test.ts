/**
 * Security regression tests — round 6.
 *
 * Findings:
 *  1. checkReplay: NaN timestamp bypass (invalid timestamps pass all freshness checks)
 *  2. checkReplay: no nonce length cap (regex runs on arbitrarily large input)
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { checkReplay } from "../src/crypto/ink.js";

async function makeKeypair() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

// ── checkReplay: NaN timestamp bypass ──

describe("checkReplay: NaN timestamp rejection", () => {
  const goodNonce = "abc123defghijklm";
  const goodClock = new Date().toISOString();
  const freshTs = new Date().toISOString();

  it("rejects when messageTimestamp is not a valid ISO string", () => {
    const result = checkReplay({
      messageTimestamp: "not-a-date",
      receiverClock: goodClock,
      nonce: goodNonce,
      previouslySeenNonces: [],
    });
    expect(result.accepted).toBe(false);
    expect(result.errorCode).toBe("expired_message");
  });

  it("rejects when messageTimestamp is empty string", () => {
    const result = checkReplay({
      messageTimestamp: "",
      receiverClock: goodClock,
      nonce: goodNonce,
      previouslySeenNonces: [],
    });
    expect(result.accepted).toBe(false);
  });

  it("rejects when receiverClock is not a valid ISO string", () => {
    const result = checkReplay({
      messageTimestamp: freshTs,
      receiverClock: "garbage",
      nonce: goodNonce,
      previouslySeenNonces: [],
    });
    expect(result.accepted).toBe(false);
    expect(result.errorCode).toBe("expired_message");
  });

  it("rejects when both timestamps are invalid", () => {
    const result = checkReplay({
      messageTimestamp: "bad",
      receiverClock: "also-bad",
      nonce: goodNonce,
      previouslySeenNonces: [],
    });
    expect(result.accepted).toBe(false);
  });

  it("still accepts a valid fresh message", () => {
    const result = checkReplay({
      messageTimestamp: freshTs,
      receiverClock: goodClock,
      nonce: goodNonce,
      previouslySeenNonces: [],
    });
    expect(result.accepted).toBe(true);
  });
});

// ── Multi-key-verify: key set size cap ──

describe("verifyInkSignatureWithKeys: key set size cap", () => {
  it("still verifies with a valid key placed first even when set has many keys", async () => {
    const { verifyInkSignatureWithKeys } = await import("../src/crypto/multi-key-verify.js");
    const { signInkMessage } = await import("../src/crypto/ink.js");

    const realKp = await makeKeypair();
    const now = new Date().toISOString();
    const input = {
      method: "POST",
      path: "/test",
      recipientDid: "tulpa:zRecipient",
      body: { from: "tulpa:zSender", timestamp: now },
      timestamp: now,
    };
    const sig = await signInkMessage(input, realKp.privateKey);

    // Build 5 fake keys + 1 real key at the start (all within 20-key cap)
    const fakeKeys = await Promise.all(
      Array.from({ length: 5 }, async () => {
        const kp = await makeKeypair();
        return { keyId: `fake-${Math.random().toString(36).slice(2)}`, publicKey: kp.publicKey, status: "active" as const };
      }),
    );
    const realKey = { keyId: "real-key", publicKey: realKp.publicKey, status: "active" as const };
    const keys = [realKey, ...fakeKeys];

    const result = await verifyInkSignatureWithKeys(input, sig, keys);
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("real-key");
  });

  it("does not verify when real key is beyond the cap (key 21+)", async () => {
    const { verifyInkSignatureWithKeys } = await import("../src/crypto/multi-key-verify.js");
    const { signInkMessage } = await import("../src/crypto/ink.js");

    const realKp = await makeKeypair();
    const now = new Date().toISOString();
    const input = {
      method: "POST",
      path: "/test",
      recipientDid: "tulpa:zRecipient",
      body: { from: "tulpa:zSender", timestamp: now },
      timestamp: now,
    };
    const sig = await signInkMessage(input, realKp.privateKey);

    // 20 fake keys before the real key — real key is at position 21, beyond cap
    const fakeKeys = await Promise.all(
      Array.from({ length: 20 }, async () => {
        const kp = await makeKeypair();
        return { keyId: `fake-${Math.random().toString(36).slice(2)}`, publicKey: kp.publicKey, status: "active" as const };
      }),
    );
    const realKey = { keyId: "real-key", publicKey: realKp.publicKey, status: "active" as const };
    const keys = [...fakeKeys, realKey]; // real key is at index 20 (0-indexed) = beyond cap

    const result = await verifyInkSignatureWithKeys(input, sig, keys);
    // Real key is beyond cap — not verified (expected behavior: use keyId hint for this case)
    expect(result.verified).toBe(false);
  });
});

// ── checkReplay: nonce length cap ──

describe("checkReplay: nonce length cap", () => {
  const goodClock = new Date().toISOString();
  const freshTs = new Date().toISOString();

  it("rejects a nonce shorter than the minimum", () => {
    const result = checkReplay({
      messageTimestamp: freshTs,
      receiverClock: goodClock,
      nonce: "abc", // too short
      previouslySeenNonces: [],
    });
    expect(result.accepted).toBe(false);
    expect(result.errorCode).toBe("expired_message");
  });

  it("rejects a nonce longer than the maximum (would cause regex DoS without cap)", () => {
    // 500 chars — well past any reasonable nonce, forces regex on huge string without cap
    const bigNonce = "A".repeat(500);
    const result = checkReplay({
      messageTimestamp: freshTs,
      receiverClock: goodClock,
      nonce: bigNonce,
      previouslySeenNonces: [],
    });
    expect(result.accepted).toBe(false);
    expect(result.errorCode).toBe("expired_message");
  });

  it("accepts a nonce at the maximum allowed length", () => {
    // 256 chars should be accepted (generous upper bound)
    const maxNonce = "A".repeat(256);
    const result = checkReplay({
      messageTimestamp: freshTs,
      receiverClock: goodClock,
      nonce: maxNonce,
      previouslySeenNonces: [],
    });
    expect(result.accepted).toBe(true);
  });

  it("accepts a typical UUID-based nonce", () => {
    const uuidNonce = "550e8400e29b41d4a716446655440000";
    const result = checkReplay({
      messageTimestamp: freshTs,
      receiverClock: goodClock,
      nonce: uuidNonce,
      previouslySeenNonces: [],
    });
    expect(result.accepted).toBe(true);
  });
});
