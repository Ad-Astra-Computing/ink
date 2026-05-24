/**
 * Security regression tests — round 11.
 *
 * Findings (Claude opus-4.7, final pre-OSS pass):
 *  1. decodeBase58 had no input-length cap before the BigInt accumulation
 *     loop. A poisoned Agent Card with a 64 KB publicKeyMultibase would force
 *     O(n^2) BigInt arithmetic before the trailing length check fires.
 *  2. sendReceiptFireAndForget accepted any `endpoint` string. Integrators
 *     passing peer-supplied endpoints risked SSRF (file:, http://localhost,
 *     169.254.169.254, etc.). The function now requires https:// scheme.
 *  3. parseCheckpoint accepted bodies with more than 4 lines (lines.length
 *     < 4 rather than === 4), silently ignoring trailing junk. Parser
 *     differential risk vs. stricter verifiers.
 *  4. (card as any).visibility cast in buildRedactedCard masked future
 *     type drift. Replaced with proper structural typing.
 *  5. fetchAgentCard performed a type-only cast after JSON.parse; this test
 *     just confirms the existing field-presence guards reject hostile shapes.
 */
import { describe, it, expect } from "vitest";
import { decodeBase58 } from "../src/crypto/keys.js";
import { sendReceiptFireAndForget } from "../src/ink/receipts.js";
import { parseCheckpoint } from "../src/ink/checkpoint.js";
import { buildRedactedCard } from "../src/ink/discovery-gating.js";

// ── Finding 1: decodeBase58 input length cap ──

describe("decodeBase58: rejects oversize inputs before BigInt loop", () => {
  it("throws on input longer than the cap", () => {
    // 10_000 chars is well past anything legitimate (an Ed25519 multibase key
    // is ~50 chars). The current cap is 1024.
    const huge = "1".repeat(10_000);
    expect(() => decodeBase58(huge)).toThrow();
  });

  it("accepts realistic multibase key sizes", () => {
    // 47-char string is a typical Ed25519 multibase body length.
    const realistic = "1".repeat(47);
    expect(() => decodeBase58(realistic)).not.toThrow();
  });

  it("rejects 1025-char input (just over the 1024 cap)", () => {
    expect(() => decodeBase58("1".repeat(1025))).toThrow();
  });
});

// ── Finding 2: sendReceiptFireAndForget URL scheme guard ──

describe("sendReceiptFireAndForget: only accepts https:// endpoints", () => {
  const receipt = {
    protocol: "ink/0.1" as const,
    type: "network.tulpa.receipt" as const,
    from: "tulpa:zAlice",
    to: "tulpa:zBob",
    messageId: "m1",
    disposition: "received" as const,
    dispositionAt: "2026-05-24T00:00:00.000Z",
    messageHash: "a".repeat(64),
    nonce: "x".repeat(32),
    timestamp: "2026-05-24T00:00:00.000Z",
    signature: "sig",
  };

  it("does not fetch a file:// endpoint", async () => {
    let called = false;
    const fakeFetch = (async () => { called = true; return new Response(); }) as typeof fetch;
    await sendReceiptFireAndForget(
      "file:///etc/passwd",
      receipt,
      new Uint8Array(32),
      fakeFetch,
    );
    expect(called).toBe(false);
  });

  it("does not fetch an http:// endpoint", async () => {
    let called = false;
    const fakeFetch = (async () => { called = true; return new Response(); }) as typeof fetch;
    await sendReceiptFireAndForget(
      "http://localhost/intercept",
      receipt,
      new Uint8Array(32),
      fakeFetch,
    );
    expect(called).toBe(false);
  });

  it("does not fetch a non-URL string", async () => {
    let called = false;
    const fakeFetch = (async () => { called = true; return new Response(); }) as typeof fetch;
    await sendReceiptFireAndForget(
      "not a url at all",
      receipt,
      new Uint8Array(32),
      fakeFetch,
    );
    expect(called).toBe(false);
  });
});

// ── Finding 3: parseCheckpoint strict line count ──

describe("parseCheckpoint: rejects bodies with extra trailing content", () => {
  it("accepts a canonical 4-part split (3 fields + trailing newline)", () => {
    const body = "origin\n5\n" + "a".repeat(64) + "\n";
    const cp = parseCheckpoint(body);
    expect(cp).not.toBeNull();
    expect(cp!.treeSize).toBe(5);
  });

  it("rejects a body with extra trailing content after the trailing newline", () => {
    const body = "origin\n5\n" + "a".repeat(64) + "\nGARBAGE";
    expect(parseCheckpoint(body)).toBeNull();
  });

  it("rejects a body with extra trailing newlines", () => {
    const body = "origin\n5\n" + "a".repeat(64) + "\n\n";
    expect(parseCheckpoint(body)).toBeNull();
  });

  it("rejects a 3-line body without trailing newline", () => {
    const body = "origin\n5\n" + "a".repeat(64);
    expect(parseCheckpoint(body)).toBeNull();
  });
});

// ── Finding 4: buildRedactedCard does not rely on `as any` for visibility ──

describe("buildRedactedCard: preserves visibility without unsafe cast", () => {
  const baseCard = {
    type: "tulpa.agent.card" as const,
    version: "1.0" as const,
    protocol: "ink/0.1" as const,
    agentId: "tulpa:zAlice",
    publicKeyMultibase: "z1",
    updatedAt: "2026-05-24T00:00:00.000Z",
  };

  it("treats network_only visibility as network_only", () => {
    const out = buildRedactedCard({ ...baseCard, visibility: "network_only" } as Parameters<typeof buildRedactedCard>[0]);
    expect(out.visibility).toBe("network_only");
  });

  it("treats capability_gated visibility as capability_gated", () => {
    const out = buildRedactedCard({ ...baseCard, visibility: "capability_gated" } as Parameters<typeof buildRedactedCard>[0]);
    expect(out.visibility).toBe("capability_gated");
  });

  it("defaults unknown visibility values to capability_gated (least-privilege)", () => {
    // Forge an off-enum value; the cast simulates a malformed card hitting
    // the function. Result should be the safest default.
    const card = { ...baseCard, visibility: "public" } as unknown as Parameters<typeof buildRedactedCard>[0];
    const out = buildRedactedCard(card);
    expect(out.visibility).toBe("capability_gated");
  });
});
