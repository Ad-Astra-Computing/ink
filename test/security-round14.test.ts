/**
 * Security regression tests — round 14.
 *
 * Findings (Codex pre-open-source pass, 2026-05):
 *  - verifyInkAuth accepted fresh requests signed by retired keys with no
 *    way for the caller to apply a stricter policy. The spec's authority
 *    rule says receivers MAY refuse retired keys on local policy — we now
 *    expose `requireActiveKey` and surface `keyStatus` on success.
 *  - All verify paths invoked jcsCanonicalize on attacker-controlled
 *    objects before any complexity cap. A cheap pre-canonicalize bound
 *    walk now bails before the expensive recursive sort runs.
 *  - fetchAgentCard's default fetch cannot do connect-time IP filtering,
 *    leaving DNS rebinding open. `requireSafeFetch` lets strict callers
 *    fail closed without supplying a custom dispatcher implicitly.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { signInkMessage, verifyAuditEventSignature, signAuditEvent } from "../src/crypto/ink.js";
import { verifyInkAuth } from "../src/middleware/ink-auth.js";
import { fetchAgentCard } from "../src/discovery/agent-card.js";
import type { CandidateKey } from "../src/models/key-entry.js";

async function makeKey() {
  const { secretKey: priv, publicKey: pub } = await ed.keygenAsync();
  return { priv, pub };
}

const baseInput = {
  protocol: "ink/0.1" as const,
  method: "POST",
  path: "/ink/v1/intent",
  recipientDid: "did:plc:recipient",
};

describe("verifyInkAuth: requireActiveKey rejects retired-key signatures", () => {
  it("accepts a retired-key signature by default (spec authority rule)", async () => {
    const oldKey = await makeKey();
    const body = { from: "did:plc:alice", timestamp: new Date().toISOString() };
    const sig = await signInkMessage(
      { method: baseInput.method, path: baseInput.path, recipientDid: baseInput.recipientDid, body, timestamp: body.timestamp },
      oldKey.priv,
    );
    const keySet: CandidateKey[] = [
      { keyId: "old", publicKey: oldKey.pub, status: "retired" },
    ];
    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: `INK-Ed25519 ${sig}`,
      method: baseInput.method,
      path: baseInput.path,
      recipientAgentId: baseInput.recipientDid,
      body,
      resolveKeySet: () => keySet,
    });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.keyStatus).toBe("retired");
    }
  });

  it("rejects a retired-key signature when requireActiveKey is set", async () => {
    const oldKey = await makeKey();
    const body = { from: "did:plc:alice", timestamp: new Date().toISOString() };
    const sig = await signInkMessage(
      { method: baseInput.method, path: baseInput.path, recipientDid: baseInput.recipientDid, body, timestamp: body.timestamp },
      oldKey.priv,
    );
    const keySet: CandidateKey[] = [
      { keyId: "old", publicKey: oldKey.pub, status: "retired" },
    ];
    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: `INK-Ed25519 ${sig}`,
      method: baseInput.method,
      path: baseInput.path,
      recipientAgentId: baseInput.recipientDid,
      body,
      resolveKeySet: () => keySet,
      requireActiveKey: true,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("retired_key_for_live_auth");
    }
  });

  it("still accepts an active-key signature with requireActiveKey", async () => {
    const liveKey = await makeKey();
    const body = { from: "did:plc:alice", timestamp: new Date().toISOString() };
    const sig = await signInkMessage(
      { method: baseInput.method, path: baseInput.path, recipientDid: baseInput.recipientDid, body, timestamp: body.timestamp },
      liveKey.priv,
    );
    const keySet: CandidateKey[] = [
      { keyId: "live", publicKey: liveKey.pub, status: "active" },
    ];
    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: `INK-Ed25519 ${sig}`,
      method: baseInput.method,
      path: baseInput.path,
      recipientAgentId: baseInput.recipientDid,
      body,
      resolveKeySet: () => keySet,
      requireActiveKey: true,
    });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.keyStatus).toBe("active");
    }
  });
});

describe("pre-canonicalize bound check rejects pathological bodies", () => {
  it("buildSignatureBase bails on bodies that exceed the node cap", async () => {
    const liveKey = await makeKey();
    const huge: Record<string, string> = {};
    for (let i = 0; i < 20_000; i++) huge[`k${i}`] = "v";
    const input = {
      method: "POST",
      path: "/ink/v1/intent",
      recipientDid: "did:plc:recipient",
      body: huge,
      timestamp: new Date().toISOString(),
    };
    await expect(signInkMessage(input, liveKey.priv)).rejects.toThrow();
  });

  it("buildSignatureBase bails on excessively-deep bodies", async () => {
    const liveKey = await makeKey();
    let cur: Record<string, unknown> = {};
    const root = cur;
    for (let i = 0; i < 200; i++) {
      const next: Record<string, unknown> = {};
      cur.next = next;
      cur = next;
    }
    const input = {
      method: "POST",
      path: "/ink/v1/intent",
      recipientDid: "did:plc:recipient",
      body: root,
      timestamp: new Date().toISOString(),
    };
    await expect(signInkMessage(input, liveKey.priv)).rejects.toThrow();
  });

  it("verifyAuditEventSignature returns false on huge audit events without canonicalizing them", async () => {
    const liveKey = await makeKey();
    // Build a legitimate signed event, then mutate it to add huge filler.
    const event: Record<string, unknown> = {
      eventId: "01HEXAMPLE",
      agentId: "did:plc:alice",
      type: "ink.intro.sent",
      timestamp: "2026-04-01T00:00:00Z",
      sequenceNumber: 1,
    };
    const sig = await signAuditEvent(event, liveKey.priv);
    event.agentSignature = sig;
    const huge: Record<string, string> = {};
    for (let i = 0; i < 20_000; i++) huge[`k${i}`] = "v";
    event.payload = huge;
    const ok = await verifyAuditEventSignature(event, liveKey.pub);
    expect(ok).toBe(false);
  });
});

describe("fetchAgentCard: requireSafeFetch fails closed without a custom fetch", () => {
  it("returns null and never touches the network when requireSafeFetch is set and no fetch is supplied", async () => {
    let called = false;
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      called = true;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    try {
      const card = await fetchAgentCard("agent-id", "https://example.com", {
        requireSafeFetch: true,
      });
      expect(card).toBeNull();
      expect(called).toBe(false);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("uses the supplied fetch when requireSafeFetch is set and options.fetch is provided", async () => {
    let called = false;
    const fakeFetch: typeof fetch = (async () => {
      called = true;
      // Empty body → safeParse returns failure → fetchAgentCard returns null,
      // but the point is the fetch was reached.
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch;
    await fetchAgentCard("agent-id", "https://example.com", {
      requireSafeFetch: true,
      fetch: fakeFetch,
    });
    expect(called).toBe(true);
  });
});
