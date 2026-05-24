/**
 * Security regression tests — round 13.
 *
 * Findings (Codex gpt-5/5 final-pass, 2026-05):
 *  - HandshakeBudgetTracker keyed correlations only by correlationId so a
 *    second sender that learned a victim's correlationId could mark the
 *    handshake terminal or exhaust its challenge budget.
 *  - Rejected attempts skipped recordSenderActivity, letting an attacker
 *    vary correlationId to bypass per-sender rate limits via typed
 *    rejections.
 *  - verifyInkSignature ran JCS canonicalization on the body BEFORE the
 *    sig-shape regex check, burning CPU on malformed signatures.
 *  - fetchAgentCard ran encodeURIComponent on unbounded agentId values
 *    before any length cap, allocating arbitrarily large URLs.
 */
import { describe, it, expect } from "vitest";
import { HandshakeBudgetTracker } from "../src/ink/handshake-budget.js";
import { signInkMessage, verifyInkSignature } from "../src/crypto/ink.js";
import * as ed from "@noble/ed25519";
import { fetchAgentCard } from "../src/discovery/agent-card.js";

describe("HandshakeBudgetTracker: per-correlation state is per-sender", () => {
  it("does not let a second sender consume the victim's challenge budget", () => {
    const tracker = new HandshakeBudgetTracker();
    const correlationId = "corr:shared";
    const victim = "did:plc:victim";
    const attacker = "did:plc:attacker";

    for (let i = 0; i < 3; i++) {
      const r = tracker.checkAndRecord({ correlationId, fromDid: victim, messageType: "challenge" });
      expect(r.allowed, `victim challenge ${i + 1}`).toBe(true);
    }
    // Victim's 4th is rejected — budget exhausted for victim only.
    expect(tracker.checkAndRecord({ correlationId, fromDid: victim, messageType: "challenge" }).allowed).toBe(false);

    // Attacker using the same correlationId still has its own fresh budget.
    const attackerFirst = tracker.checkAndRecord({ correlationId, fromDid: attacker, messageType: "challenge" });
    expect(attackerFirst.allowed).toBe(true);
  });

  it("does not let another sender flip the victim's handshake to terminal", () => {
    const tracker = new HandshakeBudgetTracker();
    const correlationId = "corr:terminal";
    const victim = "did:plc:victim";
    const attacker = "did:plc:attacker";

    // Attacker tries to slam the correlation into a rejection state.
    tracker.checkAndRecord({ correlationId, fromDid: attacker, messageType: "rejection" });

    // Victim's challenges on the SAME correlationId must still be accepted —
    // the attacker's rejection only applies to (correlationId, attacker).
    const victimFirst = tracker.checkAndRecord({ correlationId, fromDid: victim, messageType: "challenge" });
    expect(victimFirst.allowed).toBe(true);
  });
});

describe("HandshakeBudgetTracker: per-sender limits apply to rejections", () => {
  it("counts typed rejections toward per-sender rate limits even across new correlationIds", () => {
    const tracker = new HandshakeBudgetTracker();
    const attacker = "did:plc:attacker";

    // Drain per-sender budget with rejection messages, each on a fresh
    // correlationId so the per-correlation budget alone would never trip.
    let blockedAt = -1;
    for (let i = 0; i < 500; i++) {
      const result = tracker.checkAndRecord({
        correlationId: `corr:rej-${i}`,
        fromDid: attacker,
        messageType: "rejection",
      });
      if (!result.allowed) {
        blockedAt = i;
        break;
      }
    }
    expect(blockedAt, "expected per-sender limit to engage within 500 attempts").toBeGreaterThanOrEqual(0);
  });
});

describe("verifyInkSignature: skips canonicalization on malformed signatures", () => {
  it("rejects malformed sigs without invoking the body", async () => {
    const publicKey = await ed.getPublicKeyAsync(ed.utils.randomPrivateKey());
    // Construct a body whose canonicalization would throw if reached —
    // a circular structure causes JSON.stringify to throw.
    const circular: Record<string, unknown> = {};
    circular.self = circular;

    const input = {
      protocol: "ink/0.1" as const,
      method: "POST",
      path: "/ink/v1/intent",
      recipientDid: "did:plc:recipient",
      body: circular as unknown as Record<string, unknown>,
      timestamp: new Date().toISOString(),
    };

    // The sig-shape regex must fail BEFORE buildSignatureBase touches the
    // body, so verifyInkSignature returns false instead of throwing.
    const ok = await verifyInkSignature(input, "not-a-valid-signature", publicKey);
    expect(ok).toBe(false);
  });

  it("still verifies a real signature on a real body", async () => {
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = await ed.getPublicKeyAsync(privateKey);
    const input = {
      protocol: "ink/0.1" as const,
      method: "POST",
      path: "/ink/v1/intent",
      recipientDid: "did:plc:recipient",
      body: { from: "did:plc:sender", note: "hi" },
      timestamp: new Date().toISOString(),
    };
    const sig = await signInkMessage(input, privateKey);
    expect(await verifyInkSignature(input, sig, publicKey)).toBe(true);
  });
});

describe("fetchAgentCard: caps agentId length before URL construction", () => {
  it("rejects an oversized agentId without making a network request", async () => {
    let fetchCalled = false;
    const fakeFetch: typeof fetch = async () => {
      fetchCalled = true;
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    };

    const huge = "a".repeat(300);
    const card = await fetchAgentCard("https://agent.example.com", huge, { fetch: fakeFetch });
    expect(card).toBeNull();
    expect(fetchCalled).toBe(false);
  });

  it("rejects empty agentId without making a network request", async () => {
    let fetchCalled = false;
    const fakeFetch: typeof fetch = async () => {
      fetchCalled = true;
      return new Response("{}", { status: 200 });
    };
    const card = await fetchAgentCard("https://agent.example.com", "", { fetch: fakeFetch });
    expect(card).toBeNull();
    expect(fetchCalled).toBe(false);
  });
});
