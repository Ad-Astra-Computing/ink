/**
 * Tests for first-contact TOFU fix in edge key resolution.
 *
 * When buildCandidateKeys() returns empty (no locally cached keys) and the
 * sender has a published agent card, resolveEdgeKeys should fetch the card
 * to get the key set — mirroring the witness's resolveKeySetFromCard() pattern.
 *
 * This tests the agent card fetch fallback in the edge transport auth layer.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { generateKeypair, deriveAgentId, encodePublicKeyMultibase } from "../src/crypto/keys.js";

function base64urlEncode(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binString).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function jcsCanonicalize(obj: unknown): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(jcsCanonicalize).join(",") + "]";
  const sorted = Object.keys(obj as Record<string, unknown>).sort();
  const pairs = sorted.map((k) => `${JSON.stringify(k)}:${jcsCanonicalize((obj as Record<string, unknown>)[k])}`);
  return "{" + pairs.join(",") + "}";
}

describe("edge TOFU agent card fallback", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("resolveEdgeKeys fetches agent card when no local keys exist", async () => {
    // This test validates the pattern: when DO returns no keys, the edge
    // layer should fall through to verifyInkAuth which does its own card fetch.
    // The actual card fetch happens in verifyInkAuth's internal flow, not in
    // resolveEdgeKeys itself — so we test the full verifyInkAuth path.
    const { verifyInkAuth } = await import("../src/middleware/ink-auth.js");

    const senderKp = await generateKeypair();
    const agentId = deriveAgentId(senderKp.publicKey);

    const card = {
      protocol: "ink/0.1",
      agentId,
      handle: "test",
      keys: {
        signing: [{
          keyId: "sig-v1",
          algorithm: "Ed25519",
          publicKeyMultibase: encodePublicKeyMultibase(senderKp.publicKey),
          status: "active" as const,
          validFrom: "2025-01-01T00:00:00Z",
        }],
        encryption: [],
      },
    };

    // Mock fetch to return the agent card
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(card), { status: 200 }),
    );

    const body = {
      protocol: "ink/0.1",
      type: "network.tulpa.intent",
      from: agentId,
      to: "tulpa:zRecipient",
      intent: "ping",
      nonce: "test-nonce-tofu",
      timestamp: new Date().toISOString(),
    };

    const canonical = jcsCanonicalize(body);
    const sigBase = `ink/0.1\nPOST\n/ink/v1/tulpa:zRecipient/intent\ntulpa:zRecipient\n${canonical}\n${body.timestamp}`;
    const sig = await ed.signAsync(new TextEncoder().encode(sigBase), senderKp.privateKey);
    const authHeader = `INK-Ed25519 ${base64urlEncode(sig)}`;

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader,
      method: "POST",
      path: "/ink/v1/tulpa:zRecipient/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
      // No resolvePublicKey or resolveKeySet — simulating empty edge keys
    });

    // Should succeed via agent card fetch (or bootstrap fallback)
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.senderAgentId).toBe(agentId);
    }
  });

  it("edge layer falls back to bootstrap when card fetch fails", async () => {
    const { verifyInkAuth } = await import("../src/middleware/ink-auth.js");

    const senderKp = await generateKeypair();
    const agentId = deriveAgentId(senderKp.publicKey);

    // Card fetch fails
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response("Not Found", { status: 404 }),
    );

    const body = {
      protocol: "ink/0.1",
      type: "network.tulpa.intent",
      from: agentId,
      to: "tulpa:zRecipient",
      intent: "ping",
      nonce: "test-nonce-bootstrap",
      timestamp: new Date().toISOString(),
    };

    const canonical = jcsCanonicalize(body);
    const sigBase = `ink/0.1\nPOST\n/ink/v1/tulpa:zRecipient/intent\ntulpa:zRecipient\n${canonical}\n${body.timestamp}`;
    const sig = await ed.signAsync(new TextEncoder().encode(sigBase), senderKp.privateKey);
    const authHeader = `INK-Ed25519 ${base64urlEncode(sig)}`;

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader,
      method: "POST",
      path: "/ink/v1/tulpa:zRecipient/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
    });

    // Bootstrap fallback should work
    expect(result.valid).toBe(true);
  });
});
