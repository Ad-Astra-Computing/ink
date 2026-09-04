/**
 * Evidence for compliance-checklist rows that had cited a test file which did
 * not exercise them. Each block names the rows it stands behind so the
 * checklist's Tests column points at something a reader can open and see.
 */
import { describe, it, expect } from "vitest";
import { checkReplay, signInkMessage, buildAuthHeader } from "../src/crypto/ink.js";
import { verifyInkAuth } from "../src/middleware/ink-auth.js";
import { generateKeypair, deriveAgentId } from "../src/crypto/keys.js";
import { InkChallengeSchema } from "../src/models/ink-handshake.js";
import { MessageEnvelopeSchema, MessageProvenanceSchema } from "../src/models/intent.js";
import { InkAuditEventTypeSchema, InkReceiptDispositionSchema } from "../src/models/ink-audit.js";
import { jcsCanonicalize } from "../src/index.js";
import type { CandidateKey } from "../src/models/key-entry.js";

const NONCE = "nonce-0123456789abcdef";

// R3, ER6e: the standalone replay helper refuses a nonce already in the seen
// set with duplicate_nonce, and accepts the same request when the set is
// empty (R4). The freshness edges of R1 and R2 sit in test/ink-auth.test.ts
// and the replay-freshness conformance category.
describe("checkReplay single-use nonce (R3, R4, ER6e)", () => {
  const clock = "2026-06-11T00:00:00.000Z";
  it("rejects a nonce already seen with duplicate_nonce", () => {
    const r = checkReplay({ messageTimestamp: clock, receiverClock: clock, nonce: NONCE, previouslySeenNonces: ["other-0123456789abc", NONCE] });
    expect(r).toEqual({ accepted: false, errorCode: "duplicate_nonce" });
  });
  it("accepts a fresh nonce with a fresh timestamp", () => {
    expect(checkReplay({ messageTimestamp: clock, receiverClock: clock, nonce: NONCE, previouslySeenNonces: [] })).toEqual({ accepted: true });
  });
  it("judges freshness before the seen set: a stale duplicate is expired_message", () => {
    const r = checkReplay({ messageTimestamp: "2026-06-10T23:00:00.000Z", receiverClock: clock, nonce: NONCE, previouslySeenNonces: [NONCE] });
    expect(r).toEqual({ accepted: false, errorCode: "expired_message" });
  });
});

// H5, H6: a handshake message is authenticated with the same §3.3 transport
// base as any other request, so its signature is bound to the path it was
// signed for. The challenge signed for /challenge verifies there and fails
// at /rejection with invalid_signature.
describe("handshake transport signing (H5, H6)", () => {
  async function signedChallenge() {
    const kp = await generateKeypair();
    const from = deriveAgentId(kp.publicKey);
    const to = "tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX";
    const timestamp = new Date().toISOString();
    const body = {
      protocol: "ink/0.1",
      type: "network.tulpa.challenge",
      intentRef: "msg:intent-001",
      challengeType: "identity_verification",
      nonce: NONCE,
      timestamp,
      from,
    };
    expect(InkChallengeSchema.safeParse(body).success).toBe(true);
    const path = `/ink/v1/${to}/challenge`;
    const sig = await signInkMessage({ method: "POST", path, recipientDid: to, body, timestamp }, kp.privateKey);
    return { body, to, path, authHeader: buildAuthHeader(sig) };
  }

  it("verifies a challenge under the transport base at the path it was signed for", async () => {
    const { body, to, path, authHeader } = await signedChallenge();
    const r = await verifyInkAuth({ nonceStore: "deferred", authHeader, method: "POST", path, recipientAgentId: to, body });
    expect(r.valid).toBe(true);
  });

  it("rejects the same signed challenge presented at the rejection path", async () => {
    const { body, to, authHeader } = await signedChallenge();
    const r = await verifyInkAuth({
      nonceStore: "deferred",
      authHeader,
      method: "POST",
      path: `/ink/v1/${to}/rejection`,
      recipientAgentId: to,
      body,
    });
    expect(r).toEqual({ valid: false, error: "invalid_signature" });
  });
});

// AC1: the optional provenance member on the intent envelope is a closed
// shape with a closed origin set.
describe("envelope provenance (AC1)", () => {
  const base = {
    protocol: "ink/0.1",
    id: "01ABC",
    correlationId: "01DEF",
    createdAt: "2026-06-03T00:00:00Z",
    from: "did:key:zSender",
    to: "did:key:zRecipient",
    intent: "connection_request",
    payload: { method: "discovery" },
    signature: "x".repeat(86),
  };
  const provenance = { origin: "agent_approved", extensionId: "ext-1", installationId: "6f1c2a4e-9b3d-4c5e-8f7a-1b2c3d4e5f60" };

  it("accepts an envelope carrying a well-formed provenance member", () => {
    expect(MessageEnvelopeSchema.safeParse({ ...base, provenance }).success).toBe(true);
    expect(MessageEnvelopeSchema.safeParse(base).success).toBe(true);
  });
  it("accepts exactly the three origins", () => {
    for (const origin of ["human", "agent_approved", "agent_autonomous"]) {
      expect(MessageProvenanceSchema.safeParse({ ...provenance, origin }).success).toBe(true);
    }
    expect(MessageProvenanceSchema.safeParse({ ...provenance, origin: "bot" }).success).toBe(false);
  });
  it("rejects an unknown member and a non-uuid installationId", () => {
    expect(MessageProvenanceSchema.safeParse({ ...provenance, extra: 1 }).success).toBe(false);
    expect(MessageProvenanceSchema.safeParse({ ...provenance, installationId: "not-a-uuid" }).success).toBe(false);
  });
});

// K12, CT16: the rotation and containment audit event types are registered
// in the audit event type set.
describe("audit event type registry (K12, CT16)", () => {
  it("registers the key lifecycle events", () => {
    for (const t of ["key.rotated", "key.revoked"]) {
      expect(InkAuditEventTypeSchema.safeParse(t).success).toBe(true);
    }
  });
  it("registers the containment events", () => {
    for (const t of ["transport_scope_violation", "handshake_rate_limited", "handshake_budget_exhausted"]) {
      expect(InkAuditEventTypeSchema.safeParse(t).success).toBe(true);
    }
    expect(InkAuditEventTypeSchema.options.some((t) => t.startsWith("discovery_query"))).toBe(true);
  });
  it("rejects an unregistered event type", () => {
    expect(InkAuditEventTypeSchema.safeParse("key.lost").success).toBe(false);
  });
});

// M1: the intent envelope's required members, with timestamp and nonce
// optional in the schema (they are required at receipt by the replay checks).
describe("intent envelope required members (M1)", () => {
  const full = {
    protocol: "ink/0.1",
    id: "01ABC",
    correlationId: "01DEF",
    createdAt: "2026-06-03T00:00:00Z",
    from: "did:key:zSender",
    to: "did:key:zRecipient",
    intent: "connection_request",
    payload: { method: "discovery" },
    signature: "x".repeat(86),
    timestamp: "2026-06-03T00:00:00Z",
    nonce: NONCE,
  };
  it("accepts the full envelope and one without timestamp and nonce", () => {
    expect(MessageEnvelopeSchema.safeParse(full).success).toBe(true);
    const { timestamp: _t, nonce: _n, ...rest } = full;
    expect(MessageEnvelopeSchema.safeParse(rest).success).toBe(true);
  });
  it("rejects an envelope missing any required member", () => {
    for (const member of ["protocol", "id", "correlationId", "createdAt", "from", "to", "intent", "payload", "signature"]) {
      const { [member]: _dropped, ...rest } = full as Record<string, unknown>;
      expect(MessageEnvelopeSchema.safeParse(rest).success, member).toBe(false);
    }
  });
});

// M4: canonicalization carries every member through, so an unknown member is
// part of the signed bytes rather than silently dropped.
describe("canonicalization preserves unknown members (M4)", () => {
  it("keeps an unknown member, sorted into place", () => {
    expect(jcsCanonicalize({ zeta: 1, unknownMember: { b: 2, a: 1 }, alpha: "x" })).toBe('{"alpha":"x","unknownMember":{"a":1,"b":2},"zeta":1}');
  });
});

// K9: when the Authorization header carries keyId and the body carries
// signingKeyId, the header names the key tried first.
describe("header keyId takes precedence over body signingKeyId (K9)", () => {
  it("attributes the verification to the header's key", async () => {
    const k1 = await generateKeypair();
    const k2 = await generateKeypair();
    const from = deriveAgentId(k1.publicKey);
    const to = "tulpa:z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX";
    const timestamp = new Date().toISOString();
    const body = { protocol: "ink/0.1", intent: "ping", from, to, timestamp, nonce: NONCE, signingKeyId: "k2" };
    const path = `/ink/v1/${to}/intent`;
    const sig = await signInkMessage({ method: "POST", path, recipientDid: to, body, timestamp }, k1.privateKey);
    const keys: CandidateKey[] = [
      { keyId: "k1", publicKey: k1.publicKey, status: "active" },
      { keyId: "k2", publicKey: k2.publicKey, status: "active" },
    ];
    const r = await verifyInkAuth({
      nonceStore: "deferred",
      authHeader: buildAuthHeader(sig, "k1"),
      method: "POST",
      path,
      recipientAgentId: to,
      body,
      resolveKeySet: () => keys,
    });
    expect(r.valid).toBe(true);
    if (r.valid) expect(r.keyId).toBe("k1");
  });
});

// RC2: the receipt disposition set.
describe("receipt dispositions (RC2)", () => {
  it("is exactly the five dispositions of Auditability §1", () => {
    expect([...InkReceiptDispositionSchema.options].sort()).toEqual(["acted", "delivered", "expired", "received", "rejected"]);
  });
});
