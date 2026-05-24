/**
 * Security regression tests — round 20.
 *
 * Findings (Codex convergence pass on round 19):
 *  - isWithinCanonicalizeBounds only counted nodes/depth, so a single
 *    huge string ({data: "x".repeat(100M)}) passed the precheck and
 *    blew up inside JSON.stringify/canonicalize. Round 20 adds a
 *    byte-budget counter that aggregates string values and object keys.
 *  - resolveEffectiveTransports treated `allowedTransports: []` as
 *    absent and fell through to the permissive legacy set, broadening
 *    a token that should deny everything.
 *  - verifyInkAuth handed `body.timestamp` to new Date() with no length
 *    cap; a multi-megabyte timestamp string burned CPU before any
 *    signature check.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { x25519 } from "@noble/curves/ed25519.js";
import { signInkMessage, encryptInkPayload, signAuditEvent, type InkSignInput } from "../src/crypto/ink.js";
import { signMessage, verifyMessage } from "../src/crypto/sign.js";
import { resolveEffectiveTransports } from "../src/ink/transport-auth.js";
import { verifyInkAuth } from "../src/middleware/ink-auth.js";

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

describe("isWithinCanonicalizeBounds: byte budget catches huge single strings", () => {
  it("rejects a single 5MB string field at sign time", async () => {
    const priv = ed.utils.randomPrivateKey();
    const huge = "x".repeat(5_000_000);
    const input: InkSignInput = {
      method: "POST",
      path: "/ink/v1/intent",
      recipientDid: "did:plc:recipient",
      body: { from: "did:plc:alice", timestamp: "2026-04-01T00:00:00Z", data: huge },
      timestamp: "2026-04-01T00:00:00Z",
    };
    await expect(signInkMessage(input, priv)).rejects.toThrow(/complexity|size/i);
  });

  it("rejects encrypting a single huge plaintext field", async () => {
    const priv = crypto.getRandomValues(new Uint8Array(32));
    const pub = x25519.getPublicKey(priv);
    const huge = "x".repeat(5_000_000);
    await expect(
      encryptInkPayload(
        { from: "did:plc:alice", to: "did:plc:bob", data: huge },
        "did:plc:alice",
        bytesToHex(pub),
        "2026-04-01T00:00:00Z",
        "nonce1234567890123",
      ),
    ).rejects.toThrow(/complexity|size/i);
  });

  it("rejects signing an audit event with a single huge data field", async () => {
    const priv = ed.utils.randomPrivateKey();
    const event = {
      id: "01HEXAMPLE",
      type: "message.sent",
      data: { payload: "x".repeat(5_000_000) },
    };
    await expect(signAuditEvent(event, priv)).rejects.toThrow(/complexity|size/i);
  });

  it("sign.ts verifyMessage rejects a huge single-string body without canonicalizing", async () => {
    const priv = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(priv);
    const huge = "x".repeat(5_000_000);
    const message = { from: "did:plc:alice", note: huge, signature: "A".repeat(86) };
    const ok = await verifyMessage(message, pub);
    expect(ok).toBe(false);
  });

  it("sign.ts signMessage rejects a huge single-string body", async () => {
    const priv = ed.utils.randomPrivateKey();
    await expect(signMessage({ note: "x".repeat(5_000_000) }, priv)).rejects.toThrow(/complexity|size/i);
  });
});

describe("resolveEffectiveTransports: explicit empty array is preserved, not widened", () => {
  it("returns an empty array verbatim when the token allows no transports", () => {
    const out = resolveEffectiveTransports([], "0.3", new Date("2026-06-01T00:00:00Z"));
    expect(out).toEqual([]);
  });

  it("preserves the explicit empty array for legacy tokens too", () => {
    const out = resolveEffectiveTransports([], undefined, new Date("2026-06-01T00:00:00Z"));
    expect(out).toEqual([]);
  });

  it("still distinguishes from undefined (which uses defaults)", () => {
    const out = resolveEffectiveTransports(undefined, undefined, new Date("2026-06-01T00:00:00Z"));
    expect(out.length).toBeGreaterThan(0);
  });
});

describe("verifyInkAuth: timestamp length cap before Date.parse", () => {
  it("rejects a multi-megabyte timestamp without parsing it", async () => {
    const huge = "2026-04-01T00:00:00Z" + "x".repeat(1_000_000);
    const result = await verifyInkAuth({
      authHeader: "INK-Ed25519 " + "A".repeat(86),
      method: "POST",
      path: "/ink/v1/intent",
      recipientAgentId: "did:plc:recipient",
      body: { from: "did:plc:alice", timestamp: huge },
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe("invalid_timestamp");
  });

  it("accepts a normal-length timestamp", async () => {
    const result = await verifyInkAuth({
      authHeader: "INK-Ed25519 " + "A".repeat(86),
      method: "POST",
      path: "/ink/v1/intent",
      recipientAgentId: "did:plc:recipient",
      body: { from: "did:plc:alice", timestamp: new Date().toISOString() },
    });
    // Signature is bogus so verification will fail later, but the
    // timestamp pre-cap should not be the cause.
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).not.toBe("invalid_timestamp");
    }
  });
});
