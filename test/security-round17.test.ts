/**
 * Security regression tests — round 17.
 *
 * Findings (Codex convergence pass on round 16):
 *   1. isKeyValidAtTime() used truthiness for revokedAt/validFrom/
 *      validUntil; custom resolveKeySet callers returning CandidateKey
 *      with empty strings bypassed the round-15 boundary check.
 *   2. signAuditEvent / signAuditResponse / computeEventHash /
 *      computeMessageHash canonicalized attacker-influenced bodies
 *      before any complexity cap. The verify-side guards were never
 *      propagated to the sign-side siblings.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import {
  signInkMessage,
  signAuditEvent,
  signAuditResponse,
  computeEventHash,
  computeMessageHash,
  type InkSignInput,
} from "../src/crypto/ink.js";
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

function hugeBody(): Record<string, string> {
  const huge: Record<string, string> = {};
  for (let i = 0; i < 20_000; i++) huge[`k${i}`] = "v";
  return huge;
}

describe("isKeyValidAtTime: empty-string window fields fail closed at the verifier", () => {
  it("rejects an active key whose validUntil is empty string", async () => {
    const key = await makeKey();
    const ts = "2026-04-15T12:00:00Z";
    const sig = await signInkMessage(input(ts), key.priv);
    const keys: CandidateKey[] = [
      {
        keyId: "k1",
        publicKey: key.pub,
        status: "active",
        validUntil: "",
      },
    ];
    const result = await verifyInkSignatureWithKeys(input(ts), sig, keys);
    expect(result.verified).toBe(false);
  });

  it("rejects an active key whose validFrom is empty string", async () => {
    const key = await makeKey();
    const ts = "2026-04-15T12:00:00Z";
    const sig = await signInkMessage(input(ts), key.priv);
    const keys: CandidateKey[] = [
      {
        keyId: "k1",
        publicKey: key.pub,
        status: "active",
        validFrom: "",
      },
    ];
    const result = await verifyInkSignatureWithKeys(input(ts), sig, keys);
    expect(result.verified).toBe(false);
  });

  it("rejects any key where revokedAt is present, even as empty string", async () => {
    const key = await makeKey();
    const ts = "2026-04-15T12:00:00Z";
    const sig = await signInkMessage(input(ts), key.priv);
    const keys: CandidateKey[] = [
      {
        keyId: "k1",
        publicKey: key.pub,
        status: "active",
        revokedAt: "",
      },
    ];
    const result = await verifyInkSignatureWithKeys(input(ts), sig, keys);
    expect(result.verified).toBe(false);
  });

  it("rejects keys with non-string window values defensively (round 18)", async () => {
    const key = await makeKey();
    const ts = "2026-04-15T12:00:00Z";
    const sig = await signInkMessage(input(ts), key.priv);
    const keys: CandidateKey[] = [
      {
        keyId: "k1",
        publicKey: key.pub,
        status: "active",
        // Custom resolveKeySet might supply DB nulls here. Round 18
        // changed the semantics: any present-but-not-a-valid-datetime
        // window field fails closed at the verifier.
        validUntil: null as unknown as string,
      },
    ];
    const result = await verifyInkSignatureWithKeys(input(ts), sig, keys);
    expect(result.verified).toBe(false);
  });
});

describe("sign-side bound checks mirror verify-side", () => {
  it("signAuditEvent rejects pathological events rather than minting an over-cap signature", async () => {
    const key = await makeKey();
    const event = {
      id: "01HEXAMPLE",
      agentId: "did:plc:alice",
      type: "message.sent",
      timestamp: "2026-04-01T00:00:00Z",
      sequenceNumber: 1,
      data: hugeBody(),
    };
    await expect(signAuditEvent(event, key.priv)).rejects.toThrow();
  });

  it("signAuditResponse rejects an oversize events array at sign time", async () => {
    const key = await makeKey();
    const events: Record<string, unknown>[] = [];
    // Each event is small but there are many — push node count past the cap.
    for (let i = 0; i < 6_000; i++) {
      events.push({ id: `evt-${i}`, type: "message.sent", t: i });
    }
    await expect(signAuditResponse(events, key.priv)).rejects.toThrow();
  });

  it("computeEventHash rejects pathological events", async () => {
    const event = {
      id: "01HEXAMPLE",
      type: "message.sent",
      data: hugeBody(),
    };
    await expect(computeEventHash(event)).rejects.toThrow();
  });

  it("computeMessageHash rejects pathological bodies", async () => {
    await expect(computeMessageHash(hugeBody())).rejects.toThrow();
  });

  it("legitimate audit event still round-trips through sign", async () => {
    const key = await makeKey();
    const event = {
      id: "01HEXAMPLE",
      agentId: "did:plc:alice",
      type: "message.sent",
      timestamp: "2026-04-01T00:00:00Z",
      sequenceNumber: 1,
    };
    const sig = await signAuditEvent(event, key.priv);
    expect(typeof sig).toBe("string");
    expect(sig.length).toBe(86);
  });
});
