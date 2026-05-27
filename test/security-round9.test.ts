/**
 * Security regression tests — round 9.
 *
 * Finding:
 *  1. verifyMessage in src/crypto/sign.ts lacks try/catch around
 *     base64urlDecode and ed.verifyAsync. Malformed signatures (invalid
 *     base64url chars, wrong byte length) throw instead of returning false.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { verifyMessage } from "../src/crypto/sign.js";

function base64urlEncode(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binString).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── Finding 1: verifyMessage must return false instead of throwing ──

describe("verifyMessage: malformed input returns false", () => {
  it("returns false for a non-base64url signature (does not throw)", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();

    const msg = { id: "m1", type: "test", signature: "!!!not-base64url!!!" };
    const result = await verifyMessage(msg, pub);
    expect(result).toBe(false);
  });

  it("returns false for a wrong-length signature (does not throw)", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();

    // 10 bytes — not 64 (Ed25519 sig length)
    const shortSig = base64urlEncode(new Uint8Array(10));
    const msg = { id: "m1", type: "test", signature: shortSig };
    const result = await verifyMessage(msg, pub);
    expect(result).toBe(false);
  });

  it("returns false when signature field is missing", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();

    const msg = { id: "m1", type: "test" };
    const result = await verifyMessage(msg, pub);
    expect(result).toBe(false);
  });

  it("returns false for a valid-length but incorrect signature", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();

    const wrongSig = base64urlEncode(new Uint8Array(64));
    const msg = { id: "m1", type: "test", signature: wrongSig };
    const result = await verifyMessage(msg, pub);
    expect(result).toBe(false);
  });

  it("rejects signatures with non-base64url characters before decoding", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();

    // 86 chars including a space (whitespace is not in base64url alphabet)
    const badChars = "A".repeat(85) + " ";
    const msg = { id: "m1", type: "test", signature: badChars };
    const result = await verifyMessage(msg, pub);
    expect(result).toBe(false);
  });

  it("rejects signatures of wrong length even if base64url-clean", async () => {
    const { secretKey: kp, publicKey: pub } = await ed.keygenAsync();

    // 87 chars — wrong length for an Ed25519 signature
    const tooLong = "A".repeat(87);
    const msg = { id: "m1", type: "test", signature: tooLong };
    const result = await verifyMessage(msg, pub);
    expect(result).toBe(false);
  });
});
