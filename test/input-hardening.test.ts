import { describe, it, expect } from "vitest";
import { signMessage, verifyMessage, validateMessage, generateKeypair } from "../src/index.js";
import { isJcsSafeNumber } from "../src/crypto/sign.js";

function validEnvelope(payload: Record<string, unknown>) {
  return {
    protocol: "ink/0.2",
    id: "m".repeat(16),
    correlationId: "c".repeat(16),
    createdAt: "2026-06-10T00:00:00.000Z",
    from: "tulpa:zabc",
    to: "tulpa:zdef",
    intent: "ping",
    payload,
    signature: "a".repeat(86),
  };
}

describe("JCS number safety", () => {
  it("accepts the safe integers INK payloads actually carry", () => {
    for (const n of [0, 1, -1, 42, -5, 1000, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]) {
      expect(isJcsSafeNumber(n), `${n}`).toBe(true);
    }
  });

  it("rejects anything that is not a safe integer", () => {
    for (const n of [1.5, -123.25, 1e20, 1e21, 1e-7, -0, Infinity, -Infinity, NaN, 1e30]) {
      expect(isJcsSafeNumber(n), `${n}`).toBe(false);
    }
  });

  it("locks the exact safe-integer boundary", () => {
    // Only integers in |v| <= 2^53-1 are safe. A fraction, or an integer-valued
    // magnitude above the safe range (1e20 has no exact double), is rejected.
    expect(isJcsSafeNumber(Number.MAX_SAFE_INTEGER)).toBe(true);
    expect(isJcsSafeNumber(Number.MAX_SAFE_INTEGER + 1)).toBe(false);
    expect(isJcsSafeNumber(Number.MIN_SAFE_INTEGER)).toBe(true);
    expect(isJcsSafeNumber(Number.MIN_SAFE_INTEGER - 1)).toBe(false);
    expect(isJcsSafeNumber(1.5)).toBe(false);
    expect(isJcsSafeNumber(1e20)).toBe(false);
    expect(isJcsSafeNumber(-0)).toBe(false);
  });

  it("rejects a JCS-unsafe number nested inside arrays and objects", async () => {
    const kp = await generateKeypair();
    await expect(signMessage({ protocol: "ink/0.2", a: [1, 2, -0] }, kp.privateKey)).rejects.toThrow();
    await expect(signMessage({ protocol: "ink/0.2", a: { b: { c: 1e21 } } }, kp.privateKey)).rejects.toThrow();
  });

  it("signMessage refuses a body containing an exponential-notation number", async () => {
    const kp = await generateKeypair();
    await expect(signMessage({ protocol: "ink/0.2", big: 1e21 }, kp.privateKey)).rejects.toThrow();
  });

  it("signMessage refuses a body containing negative zero", async () => {
    const kp = await generateKeypair();
    await expect(signMessage({ protocol: "ink/0.2", z: -0 }, kp.privateKey)).rejects.toThrow();
  });

  it("verifyMessage rejects a body containing a JCS-unsafe number", async () => {
    const message = { protocol: "ink/0.2", big: 1e21, signature: "a".repeat(86) };
    const kp = await generateKeypair();
    expect(await verifyMessage(message, kp.publicKey)).toBe(false);
  });

  it("safe-integer numbers round-trip through sign and verify", async () => {
    const kp = await generateKeypair();
    const unsigned = { protocol: "ink/0.2", count: 42, negative: -7, zero: 0 };
    const sig = await signMessage(unsigned, kp.privateKey);
    expect(await verifyMessage({ ...unsigned, signature: sig }, kp.publicKey)).toBe(true);
  });
});

describe("validateMessage complexity gate", () => {
  it("rejects an object with more keys than the node budget before Zod runs", () => {
    const huge: Record<string, number> = {};
    for (let i = 0; i < 12_000; i++) huge[`k${i}`] = 1;
    expect(() => validateMessage(huge)).toThrow(/complexity bounds/);
  });

  it("rejects an envelope whose payload carries a JCS-unsafe number", () => {
    expect(() => validateMessage(validEnvelope({ note: "hi", weird: 1e21 }))).toThrow(/complexity bounds/);
  });

  it("still accepts a well-formed envelope", () => {
    expect(() => validateMessage(validEnvelope({ note: "hello" }))).not.toThrow();
  });
});
