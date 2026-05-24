/**
 * Security regression tests — round 24.
 *
 * Findings (final consumer-view pass, Codex + Claude in parallel):
 * Public-API exports must self-defend against malformed/missing inputs
 * even if internal callers always pre-validate. An integrator who
 * spreads `req.body` into a library function should not be able to
 * crash the process or cause expensive intermediate work.
 *
 * This batch adds shape/type guards across 15+ exported functions.
 */
import { describe, it, expect } from "vitest";
import {
  verifyInkAuth,
  verifyMessage,
  signMessage,
  verifyInkSignatureWithKeys,
  verifyAuditEventSignature,
  verifyAuditResponseSignature,
  decryptInkPayload,
  encodePublicKeyMultibase,
  decodePublicKeyMultibase,
  extractPublicKeyFromAgentId,
  extractCandidateKeys,
  hexToBytes,
  bytesToHex,
  base64urlEncode,
  checkReplay,
  HandshakeBudgetTracker,
} from "../src/index.js";

describe("verifyInkAuth: malformed opts.body and authHeader", () => {
  const base = {
    method: "POST",
    path: "/ink/v1/intent",
    recipientAgentId: "did:plc:r",
  };

  it("returns missing_sender for null body", async () => {
    const r = await verifyInkAuth({ ...base, authHeader: "x", body: null as unknown as Record<string, unknown> });
    expect(r.valid).toBe(false);
  });

  it("returns missing_sender for array body", async () => {
    const r = await verifyInkAuth({ ...base, authHeader: "x", body: [] as unknown as Record<string, unknown> });
    expect(r.valid).toBe(false);
  });

  it("returns missing_authorization for array authHeader (Node-style header parsing)", async () => {
    const r = await verifyInkAuth({ ...base, authHeader: ["a", "b"] as unknown as string, body: { from: "x", timestamp: new Date().toISOString() } });
    expect(r.valid).toBe(false);
  });
});

describe("key helpers: type and length guards", () => {
  it("encodePublicKeyMultibase rejects non-Uint8Array", () => {
    expect(() => encodePublicKeyMultibase([1, 2, 3] as unknown as Uint8Array)).toThrow();
  });

  it("encodePublicKeyMultibase rejects wrong-length key", () => {
    expect(() => encodePublicKeyMultibase(new Uint8Array(16))).toThrow(/32 bytes/);
  });

  it("decodePublicKeyMultibase rejects non-string", () => {
    expect(() => decodePublicKeyMultibase(null as unknown as string)).toThrow();
    expect(() => decodePublicKeyMultibase(42 as unknown as string)).toThrow();
  });

  it("decodePublicKeyMultibase rejects oversized input", () => {
    expect(() => decodePublicKeyMultibase("z" + "a".repeat(2000))).toThrow(/under 1024/);
  });

  it("extractPublicKeyFromAgentId rejects oversized agentId", () => {
    expect(() => extractPublicKeyFromAgentId("tulpa:" + "z".repeat(600))).toThrow();
  });
});

describe("extractCandidateKeys: null card guard", () => {
  it("returns [] for null", () => {
    expect(extractCandidateKeys(null as unknown as Parameters<typeof extractCandidateKeys>[0])).toEqual([]);
  });
  it("returns [] for array", () => {
    expect(extractCandidateKeys([] as unknown as Parameters<typeof extractCandidateKeys>[0])).toEqual([]);
  });
});

describe("audit/encryption verifiers: malformed input", () => {
  it("verifyAuditEventSignature returns false for null event", async () => {
    expect(await verifyAuditEventSignature(null as unknown as Record<string, unknown>, new Uint8Array(32))).toBe(false);
  });

  it("verifyAuditResponseSignature returns false for non-array events", async () => {
    expect(await verifyAuditResponseSignature("not-an-array" as unknown as unknown[], "A".repeat(86), new Uint8Array(32))).toBe(false);
    expect(await verifyAuditResponseSignature(null as unknown as unknown[], "A".repeat(86), new Uint8Array(32))).toBe(false);
  });

  it("decryptInkPayload throws on null envelope", async () => {
    await expect(decryptInkPayload(null as unknown as Parameters<typeof decryptInkPayload>[0], "00".repeat(32))).rejects.toThrow();
  });
});

describe("encoding helpers: type guards", () => {
  it("hexToBytes rejects non-string", () => {
    expect(() => hexToBytes(null as unknown as string)).toThrow();
    expect(() => hexToBytes(42 as unknown as string)).toThrow();
  });

  it("bytesToHex rejects non-Uint8Array", () => {
    expect(() => bytesToHex([1, 2, 3] as unknown as Uint8Array)).toThrow();
  });

  it("base64urlEncode rejects non-Uint8Array", () => {
    expect(() => base64urlEncode("not-bytes" as unknown as Uint8Array)).toThrow();
  });
});

describe("signMessage / verifyMessage: shape guards", () => {
  it("signMessage rejects null message", async () => {
    await expect(signMessage(null as unknown as Record<string, unknown>, new Uint8Array(32))).rejects.toThrow();
  });

  it("signMessage rejects wrong-length privateKey", async () => {
    await expect(signMessage({}, new Uint8Array(16))).rejects.toThrow();
  });

  it("verifyMessage returns false for null message", async () => {
    expect(await verifyMessage(null as unknown as Record<string, unknown>, new Uint8Array(32))).toBe(false);
  });
});

describe("verifyInkSignatureWithKeys: shape guards", () => {
  it("returns verified=false for null input", async () => {
    const r = await verifyInkSignatureWithKeys(null as unknown as Parameters<typeof verifyInkSignatureWithKeys>[0], "A".repeat(86), []);
    expect(r.verified).toBe(false);
  });
  it("returns verified=false for non-array keys", async () => {
    const r = await verifyInkSignatureWithKeys({ method: "POST", path: "/x", recipientDid: "y", body: {}, timestamp: new Date().toISOString() }, "A".repeat(86), null as unknown as Parameters<typeof verifyInkSignatureWithKeys>[2]);
    expect(r.verified).toBe(false);
  });
});

describe("checkReplay: shape guards", () => {
  const valid = {
    nonce: "abcdefghijklmnopqrstuv",
    messageTimestamp: new Date().toISOString(),
    receiverClock: new Date().toISOString(),
  };

  it("rejects non-array previouslySeenNonces", () => {
    const r = checkReplay({ ...valid, previouslySeenNonces: null as unknown as string[] });
    expect(r.accepted).toBe(false);
  });

  it("rejects oversized previouslySeenNonces array", () => {
    const huge = new Array(10_001).fill("x");
    const r = checkReplay({ ...valid, previouslySeenNonces: huge });
    expect(r.accepted).toBe(false);
  });
});

describe("HandshakeBudgetTracker: config clamping", () => {
  it("clamps a 10M maxCorrelations to 1M", () => {
    const t = new HandshakeBudgetTracker({ maxCorrelations: 10_000_000 });
    expect((t as unknown as { maxCorrelations: number }).maxCorrelations).toBeLessThanOrEqual(1_000_000);
  });

  it("rejects negative config and falls back to default", () => {
    const t = new HandshakeBudgetTracker({ maxChallenges: -5 });
    expect((t as unknown as { maxChallenges: number }).maxChallenges).toBeGreaterThan(0);
  });

  it("rejects non-finite config", () => {
    const t = new HandshakeBudgetTracker({ maxChallenges: Infinity });
    expect((t as unknown as { maxChallenges: number }).maxChallenges).toBeLessThan(Infinity);
  });
});
