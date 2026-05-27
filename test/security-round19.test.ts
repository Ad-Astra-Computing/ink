/**
 * Security regression tests — round 19.
 *
 * Findings (Codex convergence pass on round 18):
 *  - decryptInkPayload accepted empty envelope.from/timestamp/messageNonce.
 *  - buildSignatureBase had no scalar type/non-empty/length caps on
 *    method/path/recipientDid/timestamp.
 *  - encryptInkPayload JSON.stringify'd plaintext without a complexity
 *    or size cap.
 *  - transport-auth.ts resolveEffectiveTransports treated `tokenVersion: ""`
 *    as legacy (broader permissions) instead of malformed new.
 *  - handshake-budget checkAndRecord treated `intentExpiresAt: ""` as
 *    absent, falling through to the default 24h TTL.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  signInkMessage,
  encryptInkPayload,
  decryptInkPayload,
  type InkSignInput,
} from "../src/crypto/ink.js";
import { resolveEffectiveTransports } from "../src/ink/transport-auth.js";
import { HandshakeBudgetTracker } from "../src/ink/handshake-budget.js";

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

describe("buildSignatureBase: scalar field caps", () => {
  it("rejects empty method", async () => {
    const priv = ed.utils.randomSecretKey();
    const input: InkSignInput = {
      method: "",
      path: "/ink/v1/intent",
      recipientDid: "did:plc:recipient",
      body: { from: "did:plc:alice", timestamp: "2026-04-01T00:00:00Z" },
      timestamp: "2026-04-01T00:00:00Z",
    };
    await expect(signInkMessage(input, priv)).rejects.toThrow(/method/i);
  });

  it("rejects oversized path", async () => {
    const priv = ed.utils.randomSecretKey();
    const input: InkSignInput = {
      method: "POST",
      path: "/" + "x".repeat(3000),
      recipientDid: "did:plc:recipient",
      body: { from: "did:plc:alice", timestamp: "2026-04-01T00:00:00Z" },
      timestamp: "2026-04-01T00:00:00Z",
    };
    await expect(signInkMessage(input, priv)).rejects.toThrow(/path/i);
  });

  it("rejects oversized recipientDid", async () => {
    const priv = ed.utils.randomSecretKey();
    const input: InkSignInput = {
      method: "POST",
      path: "/ink/v1/intent",
      recipientDid: "did:plc:" + "x".repeat(300),
      body: { from: "did:plc:alice", timestamp: "2026-04-01T00:00:00Z" },
      timestamp: "2026-04-01T00:00:00Z",
    };
    await expect(signInkMessage(input, priv)).rejects.toThrow(/recipientDid/i);
  });

  it("rejects oversized timestamp", async () => {
    const priv = ed.utils.randomSecretKey();
    const input: InkSignInput = {
      method: "POST",
      path: "/ink/v1/intent",
      recipientDid: "did:plc:recipient",
      body: { from: "did:plc:alice", timestamp: "2026-04-01T00:00:00Z" },
      timestamp: "2026-04-01T00:00:00Z" + "x".repeat(100),
    };
    await expect(signInkMessage(input, priv)).rejects.toThrow(/timestamp/i);
  });
});

describe("decryptInkPayload: rejects empty AAD scalar fields", () => {
  async function makeRecipient() {
    const priv = crypto.getRandomValues(new Uint8Array(32));
    const pub = x25519.getPublicKey(priv);
    return { privHex: bytesToHex(priv), pubHex: bytesToHex(pub) };
  }

  it("rejects envelope.from = empty string", async () => {
    const r = await makeRecipient();
    const result = await encryptInkPayload(
      { msg: "hi", from: "did:plc:alice", to: "did:plc:bob" },
      "did:plc:alice",
      r.pubHex,
      "2026-04-01T00:00:00Z",
      "nonce1234567890123",
    );
    const tampered = { ...result.envelope, from: "" };
    await expect(decryptInkPayload(tampered, r.privHex)).rejects.toThrow(/from/i);
  });

  it("rejects envelope.timestamp = empty string", async () => {
    const r = await makeRecipient();
    const result = await encryptInkPayload(
      { msg: "hi", from: "did:plc:alice", to: "did:plc:bob" },
      "did:plc:alice",
      r.pubHex,
      "2026-04-01T00:00:00Z",
      "nonce1234567890123",
    );
    const tampered = { ...result.envelope, timestamp: "" };
    await expect(decryptInkPayload(tampered, r.privHex)).rejects.toThrow(/timestamp/i);
  });

  it("rejects envelope.messageNonce = empty string", async () => {
    const r = await makeRecipient();
    const result = await encryptInkPayload(
      { msg: "hi", from: "did:plc:alice", to: "did:plc:bob" },
      "did:plc:alice",
      r.pubHex,
      "2026-04-01T00:00:00Z",
      "nonce1234567890123",
    );
    const tampered = { ...result.envelope, messageNonce: "" };
    await expect(decryptInkPayload(tampered, r.privHex)).rejects.toThrow(/messageNonce/i);
  });
});

describe("encryptInkPayload: plaintext complexity cap", () => {
  it("rejects pathological plaintext before allocating ciphertext", async () => {
    const priv = crypto.getRandomValues(new Uint8Array(32));
    const pub = x25519.getPublicKey(priv);
    const huge: Record<string, string> = {};
    for (let i = 0; i < 20_000; i++) huge[`k${i}`] = "v";
    await expect(
      encryptInkPayload(
        { ...huge, from: "did:plc:alice", to: "did:plc:bob" },
        "did:plc:alice",
        bytesToHex(pub),
        "2026-04-01T00:00:00Z",
        "nonce1234567890123",
      ),
    ).rejects.toThrow(/complexity|size/i);
  });
});

describe("resolveEffectiveTransports: empty tokenVersion is treated as new, not legacy", () => {
  const beforeDeadline = new Date("2026-06-01T00:00:00Z");
  it("empty-string tokenVersion gets strict default during migration window", () => {
    const out = resolveEffectiveTransports(undefined, "", beforeDeadline);
    expect(out).toEqual(["ink_http"]);
  });
  it("undefined tokenVersion gets permissive legacy set during migration window", () => {
    const out = resolveEffectiveTransports(undefined, undefined, beforeDeadline);
    expect(out.length).toBeGreaterThan(1);
  });
  it("legitimate v0.3 tokenVersion gets strict default", () => {
    const out = resolveEffectiveTransports(undefined, "0.3", beforeDeadline);
    expect(out).toEqual(["ink_http"]);
  });
});

describe("HandshakeBudgetTracker: empty intentExpiresAt is malformed, not absent", () => {
  it("rejects intent with empty-string intentExpiresAt", () => {
    const tracker = new HandshakeBudgetTracker();
    const result = tracker.checkAndRecord({
      correlationId: "corr-1",
      fromDid: "did:plc:alice",
      messageType: "intent",
      intentExpiresAt: "",
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("handshake_budget_exhausted");
  });

  it("accepts intent with no intentExpiresAt (legacy compat)", () => {
    const tracker = new HandshakeBudgetTracker();
    const result = tracker.checkAndRecord({
      correlationId: "corr-2",
      fromDid: "did:plc:alice",
      messageType: "intent",
    });
    expect(result.allowed).toBe(true);
  });

  it("accepts intent with a valid future intentExpiresAt", () => {
    const tracker = new HandshakeBudgetTracker();
    const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    const result = tracker.checkAndRecord({
      correlationId: "corr-3",
      fromDid: "did:plc:alice",
      messageType: "intent",
      intentExpiresAt: future,
    });
    expect(result.allowed).toBe(true);
  });
});
