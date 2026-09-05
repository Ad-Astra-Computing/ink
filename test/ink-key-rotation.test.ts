import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { verifyInkSignatureWithKeys } from "../src/crypto/multi-key-verify.js";
import { signInkMessage, type InkSignInput } from "../src/crypto/ink.js";
import { verifyInkAuth } from "../src/middleware/ink-auth.js";
import { extractCandidateKeys } from "../src/discovery/agent-card.js";
import { encodePublicKeyMultibase, encodeEncryptionKeyMultibase, deriveAgentId } from "../src/crypto/keys.js";
import { AgentCardSchema } from "../src/models/agent-card.js";
import type { CandidateKey } from "../src/models/key-entry.js";
import type { AgentCard } from "../src/models/agent-card.js";

async function makeKeypair() {
  const { secretKey: privateKey, publicKey: publicKey } = await ed.keygenAsync();
  return { privateKey, publicKey };
}

const testInput: InkSignInput = {
  method: "POST",
  path: "/ink/v1/test/intent",
  recipientDid: "tulpa:zRecipient",
  body: { from: "tulpa:zSender", type: "connection_request", timestamp: "2026-03-25T00:00:00Z" },
  timestamp: "2026-03-25T00:00:00Z",
};

describe("INK Key Rotation — end-to-end test vectors", () => {
  it("sign with active key A, verify against [A=active] → pass", async () => {
    const keyA = await makeKeypair();
    const signature = await signInkMessage(testInput, keyA.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "key-a", publicKey: keyA.publicKey, status: "active" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("key-a");
  });

  it("rotate: sign with key B, verify against [A=retired, B=active] → pass", async () => {
    const keyA = await makeKeypair();
    const keyB = await makeKeypair();
    const signature = await signInkMessage(testInput, keyB.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "key-a", publicKey: keyA.publicKey, status: "retired" },
      { keyId: "key-b", publicKey: keyB.publicKey, status: "active" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("key-b");
  });

  it("verify historical message signed by A against [A=retired, B=active] → pass", async () => {
    const keyA = await makeKeypair();
    const keyB = await makeKeypair();
    const signature = await signInkMessage(testInput, keyA.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "key-a", publicKey: keyA.publicKey, status: "retired" },
      { keyId: "key-b", publicKey: keyB.publicKey, status: "active" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(result.verified).toBe(true);
    expect(result.keyId).toBe("key-a");
  });

  it("verify against [A=revoked, B=active] with A-signed message → fail", async () => {
    const keyA = await makeKeypair();
    const keyB = await makeKeypair();
    const signature = await signInkMessage(testInput, keyA.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "key-a", publicKey: keyA.publicKey, status: "revoked" },
      { keyId: "key-b", publicKey: keyB.publicKey, status: "active" },
    ];

    const result = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(result.verified).toBe(false);
  });

  it("Agent Card with multi-key structure round-trips through schema", async () => {
    const keyA = await makeKeypair();
    const keyB = await makeKeypair();

    const card = {
      protocol: "ink/0.1" as const,
      agentId: "tulpa:zTest",
      handle: "test.example.network",
      displayName: "Test",
      endpoint: "https://example.network/ink/v1/test/intent",
      publicKeyMultibase: encodePublicKeyMultibase(keyA.publicKey),
      capabilities: {
        intentsAccepted: ["connection_request" as const],
        intentsSent: ["connection_request" as const],
      },
      availability: { timezone: "UTC" },
      keys: {
        signing: [
          {
            keyId: "sig-a",
            algorithm: "Ed25519" as const,
            publicKeyMultibase: encodePublicKeyMultibase(keyA.publicKey),
            status: "retired" as const,
            validFrom: "2026-01-01T00:00:00Z",
            validUntil: "2026-03-25T00:00:00Z",
          },
          {
            keyId: "sig-b",
            algorithm: "Ed25519" as const,
            publicKeyMultibase: encodePublicKeyMultibase(keyB.publicKey),
            status: "active" as const,
            validFrom: "2026-03-25T00:00:00Z",
          },
        ],
        encryption: [],
      },
      currentSigningKeyId: "sig-b",
      keySetVersion: 2,
    };

    const serialized = JSON.stringify(card);
    const parsed = AgentCardSchema.parse(JSON.parse(serialized));
    expect(parsed.keys?.signing).toHaveLength(2);
    expect(parsed.currentSigningKeyId).toBe("sig-b");
    expect(parsed.keySetVersion).toBe(2);
  });

  // A malformed keys member must not read as a legacy card: that hands back
  // the top-level key as active and ignores what the set said about rotation.
  for (const keys of [null, "x", 7, [], false]) {
    it(`extractCandidateKeys returns nothing for keys ${JSON.stringify(keys)}`, async () => {
      const key = await makeKeypair();
      const card = {
        agentId: "tulpa:z6Mk",
        publicKeyMultibase: encodePublicKeyMultibase(key.publicKey),
        keys,
      } as unknown as Parameters<typeof extractCandidateKeys>[0];

      expect(extractCandidateKeys(card)).toEqual([]);
    });
  }

  it("extractCandidateKeys builds correct set from card with keys block", async () => {
    const keyA = await makeKeypair();
    const keyB = await makeKeypair();
    const multibaseA = encodePublicKeyMultibase(keyA.publicKey);
    const multibaseB = encodePublicKeyMultibase(keyB.publicKey);

    const card = {
      protocol: "ink/0.1",
      agentId: "tulpa:zTest",
      handle: "test.example.network",
      displayName: "Test",
      endpoint: "https://example.network/ink/v1/test/intent",
      publicKeyMultibase: multibaseB,
      capabilities: { intentsAccepted: [], intentsSent: [] },
      availability: { timezone: "UTC" },
      keys: {
        signing: [
          { keyId: "sig-a", algorithm: "Ed25519", publicKeyMultibase: multibaseA, status: "retired", validFrom: "2026-01-01T00:00:00Z" },
          { keyId: "sig-b", algorithm: "Ed25519", publicKeyMultibase: multibaseB, status: "active", validFrom: "2026-03-25T00:00:00Z" },
        ],
        encryption: [],
      },
    } as AgentCard;

    const candidates = extractCandidateKeys(card);
    expect(candidates).toHaveLength(2);
    expect(candidates[0]!.keyId).toBe("sig-a");
    expect(candidates[0]!.status).toBe("retired");
    expect(candidates[1]!.keyId).toBe("sig-b");
    expect(candidates[1]!.status).toBe("active");

    // Verify the public keys decode correctly
    expect(candidates[0]!.publicKey).toEqual(keyA.publicKey);
    expect(candidates[1]!.publicKey).toEqual(keyB.publicKey);
  });

  // --- Finding 1: verifyInkAuth must use resolveKeySet when provided ---

  it("verifyInkAuth uses resolveKeySet and verifies with rotated key", async () => {
    const oldKp = await makeKeypair();
    const newKp = await makeKeypair();
    const agentId = deriveAgentId(oldKp.publicKey); // agentId embeds old key

    const body = {
      from: agentId,
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

    // Sign with the NEW key (simulates post-rotation)
    const signature = await signInkMessage(input, newKp.privateKey);
    const authHeader = `INK-Ed25519 ${signature}`;

    // Without resolveKeySet: should fail (agentId embeds old key)
    const failResult = await verifyInkAuth({
      nonceStore: "deferred",      authHeader,
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
    });
    expect(failResult.valid).toBe(false);

    // With resolveKeySet providing the new key: should pass
    const passResult = await verifyInkAuth({
      nonceStore: "deferred",      authHeader,
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
      resolveKeySet: () => [
        { keyId: "sig-old", publicKey: oldKp.publicKey, status: "retired" as const },
        { keyId: "sig-new", publicKey: newKp.publicKey, status: "active" as const },
      ],
    });
    expect(passResult.valid).toBe(true);
    if (passResult.valid) {
      expect(passResult.keyId).toBe("sig-new");
    }
  });

  // --- Finding 2: bootstrap key fallback blocked after key rotation ---

  it("verifyInkAuth rejects bootstrap key when resolveKeySet returns candidates", async () => {
    const kp = await makeKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const otherKp = await makeKeypair();

    const body = {
      from: agentId,
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

    // Sign with the key embedded in agentId (bootstrap key)
    const signature = await signInkMessage(input, kp.privateKey);
    const authHeader = `INK-Ed25519 ${signature}`;

    // resolveKeySet returns a stale/wrong key — should NOT fall through to bootstrap
    // because the agent has rotated keys (key set exists)
    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader,
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
      resolveKeySet: () => [
        { keyId: "stale", publicKey: otherKp.publicKey, status: "active" as const },
      ],
    });
    expect(result.valid).toBe(false);
  });

  // --- Finding 3: revoked keys must appear in Agent Card with revokedAt ---

  it("Agent Card includes revoked keys with revokedAt for counterparty evaluation", async () => {
    const cardWithRevoked = {
      protocol: "ink/0.1" as const,
      agentId: "tulpa:zTest",
      handle: "test.example.network",
      displayName: "Test",
      endpoint: "https://example.network/ink/v1/test/intent",
      publicKeyMultibase: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      capabilities: { intentsAccepted: ["connection_request" as const], intentsSent: [] },
      availability: { timezone: "UTC" },
      keys: {
        signing: [
          {
            keyId: "sig-compromised",
            algorithm: "Ed25519" as const,
            publicKeyMultibase: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            status: "revoked" as const,
            validFrom: "2026-01-01T00:00:00Z",
            revokedAt: "2026-03-20T00:00:00Z",
            revokeReason: "compromised",
          },
          {
            keyId: "sig-current",
            algorithm: "Ed25519" as const,
            publicKeyMultibase: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            status: "active" as const,
            validFrom: "2026-03-20T00:00:00Z",
          },
        ],
        encryption: [],
      },
      currentSigningKeyId: "sig-current",
      keySetVersion: 3,
    };

    const parsed = AgentCardSchema.parse(cardWithRevoked);
    expect(parsed.keys?.signing).toHaveLength(2);
    const revoked = parsed.keys?.signing?.find((k) => k.status === "revoked");
    expect(revoked).toBeDefined();
    expect(revoked?.revokedAt).toBe("2026-03-20T00:00:00Z");
    expect(revoked?.revokeReason).toBe("compromised");
  });

  // --- Phase 2: keyId hint optimization ---

  it("hintKeyId skips to correct key when provided", async () => {
    const keyA = await makeKeypair();
    const keyB = await makeKeypair();
    const signature = await signInkMessage(testInput, keyB.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "key-a", publicKey: keyA.publicKey, status: "active" },
      { keyId: "key-b", publicKey: keyB.publicKey, status: "retired" },
    ];

    // Without hint, retired key-b is tried second
    const noHint = await verifyInkSignatureWithKeys(testInput, signature, keys);
    expect(noHint.verified).toBe(true);
    expect(noHint.keyId).toBe("key-b");

    // With hint, key-b is tried first
    const withHint = await verifyInkSignatureWithKeys(testInput, signature, keys, "key-b");
    expect(withHint.verified).toBe(true);
    expect(withHint.keyId).toBe("key-b");
  });

  it("hintKeyId for revoked key is skipped, falls through to other keys", async () => {
    const keyA = await makeKeypair();
    const keyB = await makeKeypair();
    const signature = await signInkMessage(testInput, keyB.privateKey);

    const keys: CandidateKey[] = [
      { keyId: "key-a", publicKey: keyA.publicKey, status: "active" },
      { keyId: "key-b", publicKey: keyB.publicKey, status: "revoked" },
    ];

    // hint points to revoked key — should not verify
    const result = await verifyInkSignatureWithKeys(testInput, signature, keys, "key-b");
    expect(result.verified).toBe(false);
  });

  it("extended auth header with keyId parses correctly in verifyInkAuth", async () => {
    const kp = await makeKeypair();
    const body = {
      from: "tulpa:zSender",
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
    const header = `INK-Ed25519 ${sig} keyId=sig-current`;

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: header,
      method: "POST",
      path: "/ink/v1/test/intent",
      recipientAgentId: "tulpa:zRecipient",
      body,
      resolveKeySet: () => [
        { keyId: "sig-current", publicKey: kp.publicKey, status: "active" as const },
      ],
    });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.keyId).toBe("sig-current");
    }
  });

  it("extractCandidateKeys falls back to publicKeyMultibase for legacy card", async () => {
    const kp = await makeKeypair();
    const multibase = encodePublicKeyMultibase(kp.publicKey);

    const card = {
      protocol: "ink/0.1",
      agentId: "tulpa:zTest",
      handle: "test.example.network",
      displayName: "Test",
      endpoint: "https://example.network/ink/v1/test/intent",
      publicKeyMultibase: multibase,
      capabilities: { intentsAccepted: [], intentsSent: [] },
      availability: { timezone: "UTC" },
    } as AgentCard;

    const candidates = extractCandidateKeys(card);
    expect(candidates).toHaveLength(1);
    expect(candidates[0]!.keyId).toBe("legacy");
    expect(candidates[0]!.status).toBe("active");
    expect(candidates[0]!.publicKey).toEqual(kp.publicKey);
  });

  // ───────────────────────────────────────────────────────
  // Regression: authoritative Agent Card key set
  // (INK review findings #1, #2, #3)
  // ───────────────────────────────────────────────────────

  it("rejects a signature made with a retired key even when the key set resolver lists it retired", async () => {
    // Attacker scenario: agent rotates A → B; Card lists A=retired, B=active.
    // A stolen/stale copy of key A must not be able to authenticate.
    const keyA = await makeKeypair();
    const keyB = await makeKeypair();
    const signature = await signInkMessage(testInput, keyA.privateKey);

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: `INK-Ed25519 ${signature}`,
      method: testInput.method,
      path: testInput.path,
      recipientAgentId: testInput.recipientDid,
      body: testInput.body,
      resolveKeySet: () => [
        { keyId: "key-a", publicKey: keyA.publicKey, status: "retired" },
        { keyId: "key-b", publicKey: keyB.publicKey, status: "active" },
      ],
      // Buggy resolver: returns the retired key via single-key fallback.
      resolvePublicKey: () => keyA.publicKey,
    });
    expect(result.valid).toBe(false);
  });

  it("does not fall through to resolvePublicKey when authoritative key set rejected signature", async () => {
    // Before the fix, ink-auth called resolvePublicKey as a fallback after
    // the key set rejected the signature. A resolver returning a revoked key
    // would then verify — defeating rotation. Guard against regression.
    const keyA = await makeKeypair();
    const keyB = await makeKeypair();
    const signature = await signInkMessage(testInput, keyA.privateKey); // signed with revoked A

    let resolvePublicKeyCalled = false;
    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: `INK-Ed25519 ${signature}`,
      method: testInput.method,
      path: testInput.path,
      recipientAgentId: testInput.recipientDid,
      body: testInput.body,
      resolveKeySet: () => [
        { keyId: "key-a", publicKey: keyA.publicKey, status: "revoked" },
        { keyId: "key-b", publicKey: keyB.publicKey, status: "active" },
      ],
      resolvePublicKey: () => {
        resolvePublicKeyCalled = true;
        return keyA.publicKey; // revoked — must never be consulted
      },
    });
    expect(result.valid).toBe(false);
    expect(resolvePublicKeyCalled).toBe(false);
  });
});
