/**
 * Security regression tests — round 21.
 *
 * Findings (Codex convergence pass on round 20):
 *   Multiple Date.parse / new Date() sites were reachable from external
 *   input with no upstream length cap. verifyInkAuth had been fixed in
 *   round 20 but its siblings (checkReplay, HandshakeBudgetTracker,
 *   multi-key-verify, extractCandidateKeys) all needed the same cap.
 *
 * Round 21 propagates the 64-char cap to every Date parser reachable
 * from external input.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { signInkMessage, checkReplay, type InkSignInput } from "../src/crypto/ink.js";
import { verifyInkSignatureWithKeys } from "../src/crypto/multi-key-verify.js";
import { HandshakeBudgetTracker } from "../src/ink/handshake-budget.js";
import { extractCandidateKeys } from "../src/discovery/agent-card.js";
import { encodePublicKeyMultibase } from "../src/crypto/keys.js";
import type { CandidateKey } from "../src/models/key-entry.js";
import type { AgentCard } from "../src/models/agent-card.js";

async function makeKey() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub };
}

const HUGE_TS = "2026-04-01T00:00:00Z" + "x".repeat(1_000_000);

describe("checkReplay: rejects oversized timestamp strings before parsing", () => {
  it("returns expired_message for oversized messageTimestamp", () => {
    const result = checkReplay({
      messageTimestamp: HUGE_TS,
      receiverClock: new Date().toISOString(),
      nonce: "abcdefghijklmnopqrstuv",
      previouslySeenNonces: [],
    });
    expect(result.accepted).toBe(false);
    expect(result.errorCode).toBe("expired_message");
  });

  it("returns expired_message for oversized receiverClock", () => {
    const result = checkReplay({
      messageTimestamp: new Date().toISOString(),
      receiverClock: HUGE_TS,
      nonce: "abcdefghijklmnopqrstuv",
      previouslySeenNonces: [],
    });
    expect(result.accepted).toBe(false);
    expect(result.errorCode).toBe("expired_message");
  });

  it("still accepts a normal-shaped fresh timestamp", () => {
    const now = new Date().toISOString();
    const result = checkReplay({
      messageTimestamp: now,
      receiverClock: now,
      nonce: "abcdefghijklmnopqrstuv",
      previouslySeenNonces: [],
    });
    expect(result.accepted).toBe(true);
  });
});

describe("HandshakeBudgetTracker: rejects oversized intentExpiresAt", () => {
  it("rejects intent whose expiry is multi-megabyte", () => {
    const tracker = new HandshakeBudgetTracker();
    const result = tracker.checkAndRecord({
      correlationId: "corr-x",
      fromDid: "did:plc:alice",
      messageType: "intent",
      intentExpiresAt: HUGE_TS,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("handshake_budget_exhausted");
  });
});

describe("verifyInkSignatureWithKeys: rejects oversized input.timestamp", () => {
  it("returns verified=false on oversized timestamp without scanning keys", async () => {
    const key = await makeKey();
    const sig = await signInkMessage(
      {
        method: "POST",
        path: "/ink/v1/intent",
        recipientDid: "did:plc:recipient",
        body: { from: "did:plc:alice", timestamp: "2026-04-01T00:00:00Z" },
        timestamp: "2026-04-01T00:00:00Z",
      },
      key.priv,
    );
    const keys: CandidateKey[] = [
      { keyId: "k1", publicKey: key.pub, status: "active" },
    ];
    const huge = HUGE_TS;
    const input: InkSignInput = {
      method: "POST",
      path: "/ink/v1/intent",
      recipientDid: "did:plc:recipient",
      body: { from: "did:plc:alice", timestamp: huge },
      timestamp: huge,
    };
    const result = await verifyInkSignatureWithKeys(input, sig, keys);
    expect(result.verified).toBe(false);
  });
});

describe("multi-key-verify isValidDatetimeString: 64-char cap on window fields", () => {
  it("rejects a key with multi-megabyte validUntil string", async () => {
    const key = await makeKey();
    const ts = "2026-04-15T12:00:00Z";
    const sig = await signInkMessage(
      {
        method: "POST",
        path: "/ink/v1/intent",
        recipientDid: "did:plc:recipient",
        body: { from: "did:plc:alice", timestamp: ts },
        timestamp: ts,
      },
      key.priv,
    );
    const keys: CandidateKey[] = [
      {
        keyId: "k1",
        publicKey: key.pub,
        status: "active",
        validUntil: HUGE_TS,
      },
    ];
    const result = await verifyInkSignatureWithKeys(
      {
        method: "POST",
        path: "/ink/v1/intent",
        recipientDid: "did:plc:recipient",
        body: { from: "did:plc:alice", timestamp: ts },
        timestamp: ts,
      },
      sig,
      keys,
    );
    expect(result.verified).toBe(false);
  });
});

describe("extractCandidateKeys: 64-char cap on window timestamps in cards", () => {
  function makeCard(pubKeyMultibase: string, entry: Record<string, unknown>): AgentCard {
    return {
      protocol: "ink/0.1",
      agentId: "tulpa:test",
      handle: "test",
      displayName: "Test",
      endpoint: "https://example.com",
      publicKeyMultibase: pubKeyMultibase,
      capabilities: { intentsAccepted: [], intentsSent: [] },
      availability: { timezone: "UTC" },
      keys: { signing: [entry], encryption: [] },
    } as unknown as AgentCard;
  }

  it("rejects entries whose validFrom is oversized", async () => {
    const key = await makeKey();
    const mb = encodePublicKeyMultibase(key.pub);
    const card = makeCard(mb, {
      keyId: "k1",
      publicKeyMultibase: mb,
      status: "active",
      validFrom: HUGE_TS,
    });
    const out = extractCandidateKeys(card);
    expect(out.length).toBe(0);
  });
});
