/**
 * Security regression tests — round 15.
 *
 * Finding (Codex convergence pass, 2026-05):
 *   Key validity windows (`validFrom`/`validUntil`/`revokedAt`) were
 *   parsed by AgentCardSchema but dropped from CandidateKey, so the
 *   verifier accepted fresh requests signed by keys that were past
 *   their expiry, not yet valid, or marked revoked.
 *
 * Fix: CandidateKey now carries the window fields and
 *   verifyInkSignatureWithKeys filters candidates by message timestamp
 *   before any Ed25519 verification.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { signInkMessage, type InkSignInput } from "../src/crypto/ink.js";
import { verifyInkSignatureWithKeys } from "../src/crypto/multi-key-verify.js";
import type { CandidateKey } from "../src/models/key-entry.js";

async function makeKey() {
  const { secretKey: priv, publicKey: pub } = await ed.keygenAsync();
  return { priv, pub };
}

function input(timestamp: string): InkSignInput {
  return {
    method: "POST",
    path: "/ink/v1/intent",
    recipientDid: "did:plc:recipient",
    body: { from: "did:plc:alice", timestamp },
    timestamp,
  };
}

describe("verifyInkSignatureWithKeys: enforces validity window", () => {
  it("rejects an active key whose validFrom is after the message timestamp", async () => {
    const key = await makeKey();
    const ts = "2026-03-01T12:00:00Z";
    const sig = await signInkMessage(input(ts), key.priv);
    const keys: CandidateKey[] = [
      {
        keyId: "future",
        publicKey: key.pub,
        status: "active",
        validFrom: "2026-06-01T00:00:00Z", // not yet valid
      },
    ];
    const result = await verifyInkSignatureWithKeys(input(ts), sig, keys);
    expect(result.verified).toBe(false);
  });

  it("rejects an active key whose validUntil is before the message timestamp", async () => {
    const key = await makeKey();
    const ts = "2026-08-01T12:00:00Z";
    const sig = await signInkMessage(input(ts), key.priv);
    const keys: CandidateKey[] = [
      {
        keyId: "expired",
        publicKey: key.pub,
        status: "active",
        validUntil: "2026-05-01T00:00:00Z", // already expired
      },
    ];
    const result = await verifyInkSignatureWithKeys(input(ts), sig, keys);
    expect(result.verified).toBe(false);
  });

  it("rejects a retired key whose validUntil is before the message timestamp", async () => {
    const key = await makeKey();
    const ts = "2026-08-01T12:00:00Z";
    const sig = await signInkMessage(input(ts), key.priv);
    const keys: CandidateKey[] = [
      {
        keyId: "retired-expired",
        publicKey: key.pub,
        status: "retired",
        validUntil: "2026-05-01T00:00:00Z",
      },
    ];
    const result = await verifyInkSignatureWithKeys(input(ts), sig, keys);
    expect(result.verified).toBe(false);
  });

  it("accepts an active key whose window contains the message timestamp", async () => {
    const key = await makeKey();
    const ts = "2026-04-15T12:00:00Z";
    const sig = await signInkMessage(input(ts), key.priv);
    const keys: CandidateKey[] = [
      {
        keyId: "live",
        publicKey: key.pub,
        status: "active",
        validFrom: "2026-03-01T00:00:00Z",
        validUntil: "2026-12-31T23:59:59Z",
      },
    ];
    const result = await verifyInkSignatureWithKeys(input(ts), sig, keys);
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("live");
  });

  it("treats a key with revokedAt set as unusable regardless of status", async () => {
    const key = await makeKey();
    const ts = "2026-04-15T12:00:00Z";
    const sig = await signInkMessage(input(ts), key.priv);
    const keys: CandidateKey[] = [
      {
        keyId: "leaked",
        publicKey: key.pub,
        status: "active", // miscategorised — defensive check should still reject
        revokedAt: "2026-04-10T00:00:00Z",
      },
    ];
    const result = await verifyInkSignatureWithKeys(input(ts), sig, keys);
    expect(result.verified).toBe(false);
  });

  it("rejects a candidate with a malformed validFrom string (fails closed)", async () => {
    const key = await makeKey();
    const ts = "2026-04-15T12:00:00Z";
    const sig = await signInkMessage(input(ts), key.priv);
    const keys: CandidateKey[] = [
      {
        keyId: "junk-window",
        publicKey: key.pub,
        status: "active",
        validFrom: "not-a-date",
      },
    ];
    const result = await verifyInkSignatureWithKeys(input(ts), sig, keys);
    expect(result.verified).toBe(false);
  });

  it("ignores window check entirely when no validity fields are set (legacy compat)", async () => {
    const key = await makeKey();
    const ts = "2026-04-15T12:00:00Z";
    const sig = await signInkMessage(input(ts), key.priv);
    const keys: CandidateKey[] = [
      {
        keyId: "windowless",
        publicKey: key.pub,
        status: "active",
      },
    ];
    const result = await verifyInkSignatureWithKeys(input(ts), sig, keys);
    expect(result.verified).toBe(true);
  });
});
