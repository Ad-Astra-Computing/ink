/**
 * signAuditQueryResponse / verifyAuditQueryResponseSignature.
 *
 * Canonical signed bytes:
 *   "ink/audit-query-response/v1\n" + JCS(response object minus serviceSignature)
 *
 * Distinct from signAuditResponse (the bilateral peer-to-peer audit
 * exchange between agents). This is the witness-side primitive: the
 * witness signs over its serviceDid, the messageId queried, the
 * returned events, per-event Merkle proofs, treeSize and rootHash at
 * response time.
 */
import { describe, it, expect } from "vitest";
import {
  generateKeypair,
  signAuditQueryResponse,
  verifyAuditQueryResponseSignature,
} from "../src/index.js";

function basePayload() {
  return {
    protocol: "ink/0.1",
    type: "network.tulpa.audit_query_response",
    serviceDid: "did:web:witness.example.com",
    messageId: "msg-test-001",
    requester: "did:plc:requester",
    events: [
      // Conforms to §7.3 per-event scope: event.messageId matches
      // envelope, requester is a party (agentId), agentSignature is
      // present (signature contents are not verified by the low-level
      // primitive — high-level verifier uses a caller-supplied callback).
      { id: "evt-001", agentId: "did:plc:requester", messageId: "msg-test-001", agentSignature: "A".repeat(86) },
    ],
    proofs: [
      { eventId: "evt-001", leafIndex: 0, inclusionProof: [] as string[] },
    ],
    treeSize: 1,
    rootHash: "a".repeat(64),
    timestamp: "2026-05-27T00:00:00.000Z",
  };
}

describe("signAuditQueryResponse / verifyAuditQueryResponseSignature", () => {
  it("round-trips a valid response", async () => {
    const kp = await generateKeypair();
    const payload = basePayload();
    const sig = await signAuditQueryResponse(payload, kp.privateKey);
    const ok = await verifyAuditQueryResponseSignature(payload, sig, kp.publicKey);
    expect(ok).toBe(true);
  });

  it("rejects a signature from the wrong witness key", async () => {
    const witnessKp = await generateKeypair();
    const attackerKp = await generateKeypair();
    const payload = basePayload();
    const sig = await signAuditQueryResponse(payload, attackerKp.privateKey);
    const ok = await verifyAuditQueryResponseSignature(payload, sig, witnessKp.publicKey);
    expect(ok).toBe(false);
  });

  it("rejects after rootHash tampered", async () => {
    const kp = await generateKeypair();
    const payload = basePayload();
    const sig = await signAuditQueryResponse(payload, kp.privateKey);
    const tampered = { ...payload, rootHash: "f".repeat(64) };
    const ok = await verifyAuditQueryResponseSignature(tampered, sig, kp.publicKey);
    expect(ok).toBe(false);
  });

  it("rejects after messageId tampered", async () => {
    const kp = await generateKeypair();
    const payload = basePayload();
    const sig = await signAuditQueryResponse(payload, kp.privateKey);
    const tampered = { ...payload, messageId: "msg-test-002" };
    const ok = await verifyAuditQueryResponseSignature(tampered, sig, kp.publicKey);
    expect(ok).toBe(false);
  });

  it("rejects after serviceDid tampered (cross-witness substitution defense)", async () => {
    const kp = await generateKeypair();
    const payload = basePayload();
    const sig = await signAuditQueryResponse(payload, kp.privateKey);
    const tampered = { ...payload, serviceDid: "did:web:other-witness.example.com" };
    const ok = await verifyAuditQueryResponseSignature(tampered, sig, kp.publicKey);
    expect(ok).toBe(false);
  });

  it("rejects after requester tampered (cross-requester replay defense)", async () => {
    const kp = await generateKeypair();
    const payload = basePayload();
    const sig = await signAuditQueryResponse(payload, kp.privateKey);
    const tampered = { ...payload, requester: "did:plc:attacker" };
    const ok = await verifyAuditQueryResponseSignature(tampered, sig, kp.publicKey);
    expect(ok).toBe(false);
  });

  it("rejects after events array tampered (extra event injected)", async () => {
    const kp = await generateKeypair();
    const payload = basePayload();
    const sig = await signAuditQueryResponse(payload, kp.privateKey);
    const tampered = {
      ...payload,
      events: [...payload.events, { id: "evt-injected", agentId: "tulpa:zX" }],
    };
    const ok = await verifyAuditQueryResponseSignature(tampered, sig, kp.publicKey);
    expect(ok).toBe(false);
  });

  it("rejects malformed signature shape without throwing", async () => {
    const kp = await generateKeypair();
    const payload = basePayload();
    const ok = await verifyAuditQueryResponseSignature(payload, "not-a-real-signature", kp.publicKey);
    expect(ok).toBe(false);
  });

  it("rejects non-object payload", async () => {
    const kp = await generateKeypair();
    const ok = await verifyAuditQueryResponseSignature(
      null as unknown as Record<string, unknown>,
      "A".repeat(86),
      kp.publicKey,
    );
    expect(ok).toBe(false);
  });

  it("sign-side rejects an event with messageId that differs from envelope (scope smuggling)", async () => {
    const kp = await generateKeypair();
    const payload = basePayload();
    payload.events[0]!.messageId = "msg-DIFFERENT";
    await expect(signAuditQueryResponse(payload, kp.privateKey))
      .rejects.toThrow(/scope/i);
  });

  it("sign-side rejects an event where requester is not a party", async () => {
    const kp = await generateKeypair();
    const payload = basePayload();
    payload.events[0]!.agentId = "did:plc:someone-else";
    // no counterpartyId on the event
    await expect(signAuditQueryResponse(payload, kp.privateKey))
      .rejects.toThrow(/scope/i);
  });

  it("rejects (does not throw) on payload containing undefined field", async () => {
    // jcsCanonicalize throws on `undefined` values; the verifier must catch it.
    const kp = await generateKeypair();
    const payload = basePayload() as Record<string, unknown>;
    (payload as Record<string, unknown>).bogus = undefined;
    const ok = await verifyAuditQueryResponseSignature(payload, "A".repeat(86), kp.publicKey);
    expect(ok).toBe(false);
  });
});
