/**
 * Security regression tests — round 10.
 *
 * Findings (Codex):
 *  1. verifyInkAuth: empty key-set ([]) fell through to bootstrap path,
 *     allowing a revoked bootstrap key to authenticate.
 *  2. verifyInkAuth: senderDid (body.from) had no length cap; huge strings
 *     could drive CPU/memory in key resolvers and base58 decode.
 *  3. HandshakeBudgetTracker.checkAndRecord: unbounded correlationId/fromDid
 *     stored as Map keys could exhaust memory regardless of count caps.
 *  4. HandshakeBudgetTracker sender rate-limit: always returned silentDrop:false,
 *     letting over-limit senders force repeated reject/backoff responses.
 *
 *  Plus a format-validation regression test for signature pre-check
 *  (round 9 follow-up).
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { verifyInkAuth } from "../src/middleware/ink-auth.js";
import { HandshakeBudgetTracker } from "../src/ink/handshake-budget.js";
import { deriveAgentId, encodePublicKeyMultibase } from "../src/crypto/keys.js";

// ── Finding 1: empty key set is authoritative reject ──

describe("verifyInkAuth: empty key set rejects, does not fall through", () => {
  it("returns signature_verification_failed for empty candidate list", async () => {
    const { secretKey: senderKp, publicKey: senderPub } = await ed.keygenAsync();
    const agentId = deriveAgentId(senderPub);

    const body = {
      protocol: "ink/0.1",
      type: "network.tulpa.intent",
      from: agentId,
      to: "tulpa:zRecipient",
      timestamp: new Date().toISOString(),
    };
    // Build a valid-looking auth header signed with the bootstrap key
    const { jcsCanonicalize } = await import("../src/crypto/ink.js");
    const canonical = jcsCanonicalize(body);
    const sigBase = `ink/0.1\nPOST\n/p\ntulpa:zRecipient\n${canonical}\n${body.timestamp}`;
    const sig = await ed.signAsync(new TextEncoder().encode(sigBase), senderKp);
    const sigB64 = btoa(String.fromCharCode(...sig)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const authHeader = `INK-Ed25519 ${sigB64}`;

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader,
      method: "POST",
      path: "/p",
      recipientAgentId: "tulpa:zRecipient",
      body,
      // Key set exists but is empty (e.g. all keys revoked) — must reject.
      resolveKeySet: () => [],
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("signature_verification_failed");
    }
  });

  it("falls through to bootstrap only when key set is null", async () => {
    const { secretKey: senderKp, publicKey: senderPub } = await ed.keygenAsync();
    const agentId = deriveAgentId(senderPub);

    const body = {
      protocol: "ink/0.1",
      type: "network.tulpa.intent",
      from: agentId,
      to: "tulpa:zRecipient",
      timestamp: new Date().toISOString(),
    };
    const { jcsCanonicalize } = await import("../src/crypto/ink.js");
    const canonical = jcsCanonicalize(body);
    const sigBase = `ink/0.1\nPOST\n/p\ntulpa:zRecipient\n${canonical}\n${body.timestamp}`;
    const sig = await ed.signAsync(new TextEncoder().encode(sigBase), senderKp);
    const sigB64 = btoa(String.fromCharCode(...sig)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const authHeader = `INK-Ed25519 ${sigB64}`;

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader,
      method: "POST",
      path: "/p",
      recipientAgentId: "tulpa:zRecipient",
      body,
      // null = "no key set published" → fall through to bootstrap (agentId derivation).
      resolveKeySet: () => null,
    });
    expect(result.valid).toBe(true);
  });
});

// ── Finding 2: senderDid length cap ──

describe("verifyInkAuth: senderDid length cap", () => {
  it("rejects sender DID longer than 256 chars", async () => {
    const longDid = "tulpa:z" + "A".repeat(300);
    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: `INK-Ed25519 ${"A".repeat(86)}`,
      method: "POST",
      path: "/p",
      recipientAgentId: "tulpa:zRecipient",
      body: { from: longDid, timestamp: new Date().toISOString() },
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("invalid_from_field");
    }
  });
});

// ── Finding 3: handshake budget tracker ID length caps ──

describe("HandshakeBudgetTracker: ID length caps", () => {
  it("rejects oversized correlationId without storing it", () => {
    const tracker = new HandshakeBudgetTracker();
    const result = tracker.checkAndRecord({
      correlationId: "x".repeat(500),
      fromDid: "tulpa:zSender",
      messageType: "intent",
    });
    expect(result.allowed).toBe(false);
    expect(result.silentDrop).toBe(true);
  });

  it("rejects oversized fromDid without storing it", () => {
    const tracker = new HandshakeBudgetTracker();
    const result = tracker.checkAndRecord({
      correlationId: "corr-1",
      fromDid: "tulpa:z" + "A".repeat(500),
      messageType: "intent",
    });
    expect(result.allowed).toBe(false);
    expect(result.silentDrop).toBe(true);
  });

  it("accepts IDs at the boundary (256 chars)", () => {
    const tracker = new HandshakeBudgetTracker();
    const result = tracker.checkAndRecord({
      correlationId: "c".repeat(256),
      fromDid: "f".repeat(256),
      messageType: "intent",
    });
    expect(result.allowed).toBe(true);
  });
});

// ── Finding 5: extractCandidateKeys authority semantics for empty + malformed ──

describe("extractCandidateKeys: empty signing array is authoritative", () => {
  it("returns [] (not legacy fallback) when keys.signing is present but empty", async () => {
    const { extractCandidateKeys } = await import("../src/discovery/agent-card.js");
    // A card that publishes an explicit empty signing array means
    // "I have rotated/revoked everything". Returning legacy here would
    // let the bootstrap key still pass — defeats the whole point of empty.
    const card = {
      protocol: "ink/0.1" as const,
      agentId: "tulpa:zVictim",
      publicKeyMultibase: "z6MkbootstrapKey1234567890123456789012345678",
      keys: { signing: [] },
    };
    const out = extractCandidateKeys(card as any);
    expect(out).toEqual([]);
  });

  it("skips malformed entries but keeps valid ones (no collapse to legacy)", async () => {
    const { extractCandidateKeys } = await import("../src/discovery/agent-card.js");
    const { encodePublicKeyMultibase } = await import("../src/crypto/keys.js");
    const validPub = (await ed.keygenAsync()).publicKey;
    const validMb = encodePublicKeyMultibase(validPub);
    const card = {
      protocol: "ink/0.1" as const,
      agentId: "tulpa:zMixed",
      publicKeyMultibase: validMb,
      keys: {
        signing: [
          { keyId: "bad", publicKeyMultibase: "not-valid", status: "active" as const },
          { keyId: "good", publicKeyMultibase: validMb, status: "active" as const },
        ],
      },
    };
    const out = extractCandidateKeys(card as any);
    expect(out.length).toBe(1);
    expect(out[0]!.keyId).toBe("good");
  });

  it("returns [] (not legacy) when all signing entries are malformed", async () => {
    const { extractCandidateKeys } = await import("../src/discovery/agent-card.js");
    const card = {
      protocol: "ink/0.1" as const,
      agentId: "tulpa:zAllBad",
      publicKeyMultibase: "z6MkbootstrapKey1234567890123456789012345678",
      keys: {
        signing: [
          { keyId: "bad1", publicKeyMultibase: "not-valid", status: "active" as const },
          { keyId: "bad2", publicKeyMultibase: "also-bad", status: "active" as const },
        ],
      },
    };
    const out = extractCandidateKeys(card as any);
    expect(out).toEqual([]);
  });

  it("returns [] when signing is present but not an array (malformed card)", async () => {
    const { extractCandidateKeys } = await import("../src/discovery/agent-card.js");
    // signing: object instead of array
    expect(extractCandidateKeys({
      protocol: "ink/0.1",
      agentId: "tulpa:zMalformed1",
      publicKeyMultibase: "z6Mk",
      keys: { signing: { keyId: "k1" } },
    } as any)).toEqual([]);
    // signing: string instead of array
    expect(extractCandidateKeys({
      protocol: "ink/0.1",
      agentId: "tulpa:zMalformed2",
      publicKeyMultibase: "z6Mk",
      keys: { signing: "not-an-array" },
    } as any)).toEqual([]);
  });

  it("legacy card with malformed publicKeyMultibase returns [] (does not throw)", async () => {
    const { extractCandidateKeys } = await import("../src/discovery/agent-card.js");
    expect(extractCandidateKeys({
      protocol: "ink/0.1",
      agentId: "tulpa:zLegacyBad",
      publicKeyMultibase: "not-valid-multibase",
    } as any)).toEqual([]);
    // Non-string publicKeyMultibase
    expect(extractCandidateKeys({
      protocol: "ink/0.1",
      agentId: "tulpa:zLegacyNum",
      publicKeyMultibase: 42,
    } as any)).toEqual([]);
  });

  it("skips non-object entries inside the signing array without throwing", async () => {
    const { extractCandidateKeys } = await import("../src/discovery/agent-card.js");
    const out = extractCandidateKeys({
      protocol: "ink/0.1",
      agentId: "tulpa:zMixed",
      publicKeyMultibase: "z6Mk",
      keys: { signing: [null, 42, "string", [], { keyId: 99, publicKeyMultibase: "z", status: "active" }] },
    } as any);
    expect(out).toEqual([]);
  });
});

// ── Finding 4: sender rate-limit silent-drop after first rejection ──

describe("HandshakeBudgetTracker: sender rate-limit silent-drops repeats", () => {
  it("returns backoff hint on first rate-limit violation, silent-drops next ones", () => {
    const tracker = new HandshakeBudgetTracker({ maxIntentsPerMinute: 2 });
    const sender = "tulpa:zAttacker";

    // First 2 allowed
    expect(tracker.checkAndRecord({ correlationId: "c1", fromDid: sender, messageType: "intent" }).allowed).toBe(true);
    expect(tracker.checkAndRecord({ correlationId: "c2", fromDid: sender, messageType: "intent" }).allowed).toBe(true);

    // 3rd: first rate-limit rejection — has backoff hint, not silent
    const r3 = tracker.checkAndRecord({ correlationId: "c3", fromDid: sender, messageType: "intent" });
    expect(r3.allowed).toBe(false);
    expect(r3.reason).toBe("sender_rate_limited");
    expect(r3.silentDrop).toBe(false);
    expect(r3.backoffHint).toBeDefined();

    // 4th, 5th: subsequent violations within the window — silent drops, no hint
    const r4 = tracker.checkAndRecord({ correlationId: "c4", fromDid: sender, messageType: "intent" });
    expect(r4.allowed).toBe(false);
    expect(r4.silentDrop).toBe(true);
    expect(r4.backoffHint).toBeUndefined();

    const r5 = tracker.checkAndRecord({ correlationId: "c5", fromDid: sender, messageType: "intent" });
    expect(r5.silentDrop).toBe(true);
  });
});
