import { describe, it, expect } from "vitest";
import { verifyInkAuth } from "../src/middleware/ink-auth.js";
import { signInkMessage, buildAuthHeader } from "../src/crypto/ink.js";
import { generateKeypair, deriveAgentId } from "../src/crypto/keys.js";
import type { CandidateKey } from "../src/models/key-entry.js";

describe("INK request signature verification (§3.3)", () => {
  it("accepts a correctly signed request", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const now = new Date().toISOString();

    const body = {
      protocol: "ink/0.1",
      type: "network.tulpa.receipt",
      from: agentId,
      to: "tulpa:zRecipient",
      messageId: "msg-1",
      disposition: "received",
      dispositionAt: now,
      messageHash: "abc123",
      nonce: "nonce1",
      timestamp: now,
    };

    const sig = await signInkMessage({
      method: "POST",
      path: "/ink/v1/tulpa:zRecipient/receipt",
      recipientDid: "tulpa:zRecipient",
      body,
      timestamp: body.timestamp,
    }, kp.privateKey);

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: buildAuthHeader(sig),
      method: "POST",
      path: "/ink/v1/tulpa:zRecipient/receipt",
      recipientAgentId: "tulpa:zRecipient",
      body,
    });

    expect(result.valid).toBe(true);
  });

  it("rejects missing Authorization header", async () => {
    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: undefined,
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientAgentId: "agent",
      body: { from: "sender", timestamp: "2026-03-25T12:00:00Z" },
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("missing_authorization");
    }
  });

  it("rejects wrong auth scheme", async () => {
    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: "Bearer token123",
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientAgentId: "agent",
      body: { from: "sender", timestamp: "2026-03-25T12:00:00Z" },
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("invalid_auth_scheme");
    }
  });

  it("rejects missing from field", async () => {
    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: "INK-Ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientAgentId: "agent",
      body: { timestamp: "2026-03-25T12:00:00Z" },
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("missing_sender");
    }
  });

  it("rejects missing timestamp field", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: "INK-Ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientAgentId: "agent",
      body: { from: agentId },
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("missing_timestamp");
    }
  });

  it("rejects signature from wrong key", async () => {
    const kp1 = await generateKeypair();
    const kp2 = await generateKeypair();
    const agentId1 = deriveAgentId(kp1.publicKey);

    const body = {
      from: agentId1,
      timestamp: new Date().toISOString(),
    };

    // Sign with kp2's private key but claim to be kp1
    const sig = await signInkMessage({
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientDid: "agent",
      body,
      timestamp: body.timestamp,
    }, kp2.privateKey);

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: buildAuthHeader(sig),
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientAgentId: "agent",
      body,
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("invalid_signature");
    }
  });

  it("rejects tampered body", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);

    const body = {
      from: agentId,
      timestamp: new Date().toISOString(),
      messageId: "msg-original",
    };

    const sig = await signInkMessage({
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientDid: "agent",
      body,
      timestamp: body.timestamp,
    }, kp.privateKey);

    // Tamper with the body
    const tamperedBody = { ...body, messageId: "msg-tampered" };

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: buildAuthHeader(sig),
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientAgentId: "agent",
      body: tamperedBody,
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("invalid_signature");
    }
  });

  it("rejects expired timestamp (older than 5 minutes)", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const staleTime = new Date(Date.now() - 6 * 60 * 1000).toISOString(); // 6 min ago

    const body = {
      from: agentId,
      timestamp: staleTime,
    };

    const sig = await signInkMessage({
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientDid: "agent",
      body,
      timestamp: staleTime,
    }, kp.privateKey);

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: buildAuthHeader(sig),
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientAgentId: "agent",
      body,
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("timestamp_expired");
    }
  });

  it("rejects timestamp too far in the future (>30s)", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);
    const futureTime = new Date(Date.now() + 60 * 1000).toISOString(); // 60s in future

    const body = {
      from: agentId,
      timestamp: futureTime,
    };

    const sig = await signInkMessage({
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientDid: "agent",
      body,
      timestamp: futureTime,
    }, kp.privateKey);

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: buildAuthHeader(sig),
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientAgentId: "agent",
      body,
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("timestamp_too_far_future");
    }
  });

  it("rejects invalid timestamp format", async () => {
    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: "INK-Ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientAgentId: "agent",
      body: { from: "tulpa:zFake", timestamp: "not-a-date" },
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("invalid_timestamp");
    }
  });

  it("rejects tampered path", async () => {
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);

    const body = {
      from: agentId,
      timestamp: new Date().toISOString(),
    };

    const sig = await signInkMessage({
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientDid: "agent",
      body,
      timestamp: body.timestamp,
    }, kp.privateKey);

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: buildAuthHeader(sig),
      method: "POST",
      path: "/ink/v1/agent/audit", // wrong path
      recipientAgentId: "agent",
      body,
    });

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("invalid_signature");
    }
  });

  it("rejects bootstrap key fallback when agent has rotated keys", async () => {
    // Scenario: agent rotated to kp2 but attacker has compromised the
    // bootstrap key (kp1) embedded in the agentId. The bootstrap key
    // must NOT be accepted as a fallback after key rotation.
    const kp1 = await generateKeypair(); // original/bootstrap key
    const kp2 = await generateKeypair(); // rotated key
    const agentId = deriveAgentId(kp1.publicKey);

    const body = {
      from: agentId,
      timestamp: new Date().toISOString(),
    };

    // Attacker signs with the compromised bootstrap key
    const sig = await signInkMessage({
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientDid: "agent",
      body,
      timestamp: body.timestamp,
    }, kp1.privateKey);

    // resolveKeySet returns only the rotated key (kp2) — the bootstrap
    // key is no longer in the key set
    const candidates: CandidateKey[] = [
      { keyId: "rotated-key", publicKey: kp2.publicKey, status: "active" as const },
    ];

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: buildAuthHeader(sig),
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientAgentId: "agent",
      body,
      resolveKeySet: () => candidates,
    });

    // Must reject — the bootstrap key embedded in agentId must not be
    // used when the agent has a key set (meaning keys have been rotated).
    // The authoritative key set rejected the signature, so the error is
    // signature_verification_failed rather than unresolvable_sender_key.
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("signature_verification_failed");
    }
  });

  it("allows bootstrap key when no key set exists", async () => {
    // Agent has never rotated keys — resolveKeySet returns null.
    // Bootstrap key extraction from agentId should work.
    const kp = await generateKeypair();
    const agentId = deriveAgentId(kp.publicKey);

    const body = {
      from: agentId,
      timestamp: new Date().toISOString(),
    };

    const sig = await signInkMessage({
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientDid: "agent",
      body,
      timestamp: body.timestamp,
    }, kp.privateKey);

    const result = await verifyInkAuth({
      nonceStore: "deferred",      authHeader: buildAuthHeader(sig),
      method: "POST",
      path: "/ink/v1/agent/receipt",
      recipientAgentId: "agent",
      body,
      resolveKeySet: () => null, // no key set — never rotated
    });

    expect(result.valid).toBe(true);
  });
});
