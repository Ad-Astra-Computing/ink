import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { signInkMessage, buildAuthHeader, type InkSignInput } from "../src/crypto/ink.js";
import { verifyInkSignatureWithKeys } from "../src/crypto/multi-key-verify.js";
import { verifyInkAuth } from "../src/middleware/ink-auth.js";
import { extractCandidateKeys } from "../src/discovery/agent-card.js";
import { encodePublicKeyMultibase, deriveAgentId } from "../src/crypto/keys.js";
import { MessageEnvelopeSchema } from "../src/models/intent.js";
import type { CandidateKey } from "../src/models/key-entry.js";
import type { AgentCard } from "../src/models/agent-card.js";

async function makeKeypair() {
  const { secretKey: privateKey, publicKey: publicKey } = await ed.keygenAsync();
  return { privateKey, publicKey };
}

function makeAgentCard(keys: { keyId: string; publicKey: Uint8Array; status: "active" | "retired" | "revoked" }[], opts?: { keySetVersion?: number }): AgentCard {
  return {
    protocol: "ink/0.1",
    agentId: "tulpa:zTest",
    handle: "test.example.network",
    displayName: "Test",
    endpoint: "https://example.network/ink/v1/test/intent",
    publicKeyMultibase: encodePublicKeyMultibase(keys.find((k) => k.status === "active")?.publicKey ?? keys[0]!.publicKey),
    capabilities: { intentsAccepted: ["connection_request"], intentsSent: [] },
    availability: { timezone: "UTC" },
    keys: {
      signing: keys.map((k) => ({
        keyId: k.keyId,
        algorithm: "Ed25519" as const,
        publicKeyMultibase: encodePublicKeyMultibase(k.publicKey),
        status: k.status,
        validFrom: "2026-01-01T00:00:00Z",
        ...(k.status === "retired" ? { validUntil: "2026-03-25T00:00:00Z" } : {}),
        ...(k.status === "revoked" ? { revokedAt: "2026-03-20T00:00:00Z" } : {}),
      })),
      encryption: [],
    },
    currentSigningKeyId: keys.find((k) => k.status === "active")?.keyId,
    keySetVersion: opts?.keySetVersion ?? 1,
  };
}

describe("INK Key Rotation — End-to-End", () => {
  it("rotate key → outbound message includes new keyId in header", async () => {
    const newKey = await makeKeypair();
    const body = {
      from: "tulpa:zSender",
      to: "tulpa:zRecipient",
      type: "ping",
      timestamp: new Date().toISOString(),
    };
    const input: InkSignInput = {
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientDid: "tulpa:zRecipient",
      body,
      timestamp: body.timestamp,
    };

    const sig = await signInkMessage(input, newKey.privateKey);
    const header = buildAuthHeader(sig, "sig-new-key");

    // Header should contain keyId
    expect(header).toContain("keyId=sig-new-key");

    // Verify with the new key
    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: header,
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
      resolveKeySet: () => [
        { keyId: "sig-new-key", publicKey: newKey.publicKey, status: "active" as const },
      ],
    });
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.keyId).toBe("sig-new-key");
  });

  it("counterparty with stale cache → refresh-on-miss verifies with new key set", async () => {
    const oldKey = await makeKeypair();
    const newKey = await makeKeypair();

    // Sender signed with new key after rotation
    const body = {
      from: "tulpa:zSender",
      to: "tulpa:zRecipient",
      type: "ping",
      timestamp: new Date().toISOString(),
    };
    const input: InkSignInput = {
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientDid: "tulpa:zRecipient",
      body,
      timestamp: body.timestamp,
    };
    const sig = await signInkMessage(input, newKey.privateKey);
    const header = buildAuthHeader(sig, "sig-v2");

    // Stale cache only has old key → fails
    const staleResult = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: header,
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
      resolveKeySet: () => [
        { keyId: "sig-v1", publicKey: oldKey.publicKey, status: "retired" as const },
      ],
    });
    expect(staleResult.valid).toBe(false);

    // After "refresh" — fresh card has new key → succeeds
    const freshCard = makeAgentCard([
      { keyId: "sig-v1", publicKey: oldKey.publicKey, status: "retired" },
      { keyId: "sig-v2", publicKey: newKey.publicKey, status: "active" },
    ], { keySetVersion: 2 });
    const freshKeys = extractCandidateKeys(freshCard);

    const freshResult = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: header,
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
      resolveKeySet: () => freshKeys,
    });
    expect(freshResult.valid).toBe(true);
    if (freshResult.valid) expect(freshResult.keyId).toBe("sig-v2");
  });

  it("revoked key → messages rejected", async () => {
    const revokedKey = await makeKeypair();
    const activeKey = await makeKeypair();

    const body = {
      from: "tulpa:zSender",
      to: "tulpa:zRecipient",
      type: "ping",
      timestamp: new Date().toISOString(),
    };
    const input: InkSignInput = {
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientDid: "tulpa:zRecipient",
      body,
      timestamp: body.timestamp,
    };

    // Sign with revoked key
    const sig = await signInkMessage(input, revokedKey.privateKey);
    const header = buildAuthHeader(sig, "sig-revoked");

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: header,
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
      resolveKeySet: () => [
        { keyId: "sig-revoked", publicKey: revokedKey.publicKey, status: "revoked" as const },
        { keyId: "sig-active", publicKey: activeKey.publicKey, status: "active" as const },
      ],
    });
    // Revoked key should not verify, active key doesn't match → fail
    expect(result.valid).toBe(false);
  });

  it("legacy agent (no keyId) still accepted via normal key iteration", async () => {
    const kp = await makeKeypair();
    const body = {
      from: "tulpa:zLegacy",
      to: "tulpa:zRecipient",
      type: "connection_request",
      timestamp: new Date().toISOString(),
    };
    const input: InkSignInput = {
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientDid: "tulpa:zRecipient",
      body,
      timestamp: body.timestamp,
    };

    const sig = await signInkMessage(input, kp.privateKey);
    // Legacy format — no keyId
    const header = `INK-Ed25519 ${sig}`;

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: header,
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
      resolveKeySet: () => [
        { keyId: "legacy-key", publicKey: kp.publicKey, status: "active" as const },
      ],
    });
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.keyId).toBe("legacy-key");
  });

  it("two successive rotations → retired keys still verify historical messages", async () => {
    const keyV1 = await makeKeypair();
    const keyV2 = await makeKeypair();
    const keyV3 = await makeKeypair();

    const body = {
      from: "tulpa:zSender",
      to: "tulpa:zRecipient",
      type: "ping",
      timestamp: new Date().toISOString(),
    };
    const input: InkSignInput = {
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientDid: "tulpa:zRecipient",
      body,
      timestamp: body.timestamp,
    };

    // Message signed with V1 (now retired through two rotations)
    const sigV1 = await signInkMessage(input, keyV1.privateKey);
    const headerV1 = buildAuthHeader(sigV1, "sig-v1");

    const keyset: CandidateKey[] = [
      { keyId: "sig-v1", publicKey: keyV1.publicKey, status: "retired" },
      { keyId: "sig-v2", publicKey: keyV2.publicKey, status: "retired" },
      { keyId: "sig-v3", publicKey: keyV3.publicKey, status: "active" },
    ];

    // V1 message verifies against retired V1 key
    const resultV1 = await verifyInkSignatureWithKeys(input, sigV1, keyset, "sig-v1");
    expect(resultV1.verified).toBe(true);
    expect(resultV1.keyId).toBe("sig-v1");

    // V3 message verifies against active V3 key
    const sigV3 = await signInkMessage(input, keyV3.privateKey);
    const resultV3 = await verifyInkSignatureWithKeys(input, sigV3, keyset, "sig-v3");
    expect(resultV3.verified).toBe(true);
    expect(resultV3.keyId).toBe("sig-v3");
  });

  it("Agent Card keySetVersion triggers cache awareness", async () => {
    const keyA = await makeKeypair();
    const keyB = await makeKeypair();

    // Card v1: only keyA
    const cardV1 = makeAgentCard([
      { keyId: "sig-a", publicKey: keyA.publicKey, status: "active" },
    ], { keySetVersion: 1 });
    const keysV1 = extractCandidateKeys(cardV1);
    expect(keysV1).toHaveLength(1);
    expect(cardV1.keySetVersion).toBe(1);

    // Card v2: keyA retired, keyB active
    const cardV2 = makeAgentCard([
      { keyId: "sig-a", publicKey: keyA.publicKey, status: "retired" },
      { keyId: "sig-b", publicKey: keyB.publicKey, status: "active" },
    ], { keySetVersion: 2 });
    const keysV2 = extractCandidateKeys(cardV2);
    expect(keysV2).toHaveLength(2);
    expect(cardV2.keySetVersion).toBe(2);

    // Sign with new key, verify against v2 key set
    const body = {
      from: "tulpa:zSender",
      to: "tulpa:zRecipient",
      type: "ping",
      timestamp: new Date().toISOString(),
    };
    const input: InkSignInput = {
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientDid: "tulpa:zRecipient",
      body,
      timestamp: body.timestamp,
    };
    const sig = await signInkMessage(input, keyB.privateKey);
    const result = await verifyInkSignatureWithKeys(input, sig, keysV2, "sig-b");
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("sig-b");
  });
});
