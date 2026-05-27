/**
 * verifyAuditQueryResponse — the recommended consumer-side verifier for
 * INK Auditability §7.3 audit-query responses. Composes
 * verifyAuditQueryResponseSignature with envelope-shape, requester
 * binding, events↔proofs alignment, and per-event Merkle proof walk.
 */
import { describe, it, expect } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import {
  generateKeypair,
  signAuditQueryResponse,
  jcsCanonicalize,
  base64urlEncode,
  bytesToHex,
  computeAuditMerkleLeafHash,
  verifyAuditQueryResponse,
  type AuditQueryResponse,
} from "../src/index.js";

/** Sign canonical audit-query-response bytes directly via Ed25519,
 *  bypassing signAuditQueryResponse's alpha.3 scope enforcement. This
 *  simulates a malicious or non-conformant witness so we can verify
 *  the verifier still rejects on scope violations. */
async function signRawForTest(payload: Record<string, unknown>, privateKey: Uint8Array): Promise<string> {
  const canonical = jcsCanonicalize(payload);
  const bytes = new TextEncoder().encode(`ink/audit-query-response/v1\n${canonical}`);
  const sig = await ed.signAsync(bytes, privateKey);
  return base64urlEncode(sig);
}

const REQUESTER = "did:plc:requester";
const OTHER_REQUESTER = "did:plc:attacker";
const SERVICE_DID = "did:web:witness.example.com";
const MESSAGE_ID = "msg-test-001";

function makeEvent(id: string) {
  return {
    id,
    version: "ink-audit/1",
    agentId: REQUESTER,
    // Placeholder signature: the high-level verifier requires the field
    // to be present, but only enforces signature validity when the
    // caller supplies a `verifyEventSignature` callback.
    agentSignature: "A".repeat(86),
    sequence: 1,
    previousEventHash: null,
    eventType: "message.sent",
    timestamp: "2026-05-27T00:00:00.000Z",
    messageId: MESSAGE_ID,
  } as Record<string, unknown> & { id: string };
}

async function makeSingleLeafResponse(kp: { privateKey: Uint8Array; publicKey: Uint8Array }, overrides: Partial<AuditQueryResponse> = {}) {
  const event = makeEvent("evt-001");
  const leafHash = await computeAuditMerkleLeafHash(event);
  const payload = {
    protocol: "ink/0.1" as const,
    type: "network.tulpa.audit_query_response" as const,
    serviceDid: SERVICE_DID,
    messageId: MESSAGE_ID,
    requester: REQUESTER,
    events: [event],
    proofs: [{ eventId: event.id, leafIndex: 0, inclusionProof: [] as string[] }],
    treeSize: 1,
    rootHash: leafHash, // single-leaf tree: rootHash == leafHash
    timestamp: "2026-05-27T00:00:00.000Z",
    ...overrides,
  };
  const sig = await signAuditQueryResponse(payload as unknown as Record<string, unknown>, kp.privateKey);
  return { ...payload, serviceSignature: sig } as AuditQueryResponse;
}

describe("verifyAuditQueryResponse", () => {
  it("accepts a valid single-leaf response", async () => {
    const kp = await generateKeypair();
    const response = await makeSingleLeafResponse(kp);
    const r = await verifyAuditQueryResponse({
      response,
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      expectedServiceDid: SERVICE_DID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(true);
  });

  it("rejects cross-requester replay", async () => {
    const kp = await generateKeypair();
    const response = await makeSingleLeafResponse(kp);
    const r = await verifyAuditQueryResponse({
      response,
      witnessPublicKey: kp.publicKey,
      expectedRequester: OTHER_REQUESTER, // verifier expected Bob; response signed for Alice
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(false);
    expect(r.steps.some((s) => s.name === "binding" && !s.pass)).toBe(true);
  });

  it("rejects wrong messageId", async () => {
    const kp = await generateKeypair();
    const response = await makeSingleLeafResponse(kp);
    const r = await verifyAuditQueryResponse({
      response,
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: "msg-different",
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(false);
  });

  it("rejects wrong protocol", async () => {
    const kp = await generateKeypair();
    const response = await makeSingleLeafResponse(kp, { protocol: "ink/0.2" as unknown as "ink/0.1" });
    const r = await verifyAuditQueryResponse({
      response,
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(false);
  });

  it("rejects wrong type", async () => {
    const kp = await generateKeypair();
    const response = await makeSingleLeafResponse(kp, {
      type: "network.tulpa.audit_response" as unknown as "network.tulpa.audit_query_response",
    });
    const r = await verifyAuditQueryResponse({
      response,
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(false);
  });

  it("rejects when events and proofs differ in length", async () => {
    const kp = await generateKeypair();
    const response = await makeSingleLeafResponse(kp);
    const broken = { ...response, proofs: [] };
    // Re-sign so signature passes, isolating the alignment check
    const { serviceSignature: _, ...payload } = broken;
    const sig = await signAuditQueryResponse(payload as unknown as Record<string, unknown>, kp.privateKey);
    const r = await verifyAuditQueryResponse({
      response: { ...broken, serviceSignature: sig },
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(false);
    expect(r.steps.some((s) => s.name === "proofs" && !s.pass)).toBe(true);
  });

  it("rejects when leaf-to-root walk does not reach rootHash", async () => {
    const kp = await generateKeypair();
    const response = await makeSingleLeafResponse(kp);
    const broken = { ...response, rootHash: "f".repeat(64) };
    const { serviceSignature: _, ...payload } = broken;
    const sig = await signAuditQueryResponse(payload as unknown as Record<string, unknown>, kp.privateKey);
    const r = await verifyAuditQueryResponse({
      response: { ...broken, serviceSignature: sig },
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(false);
    expect(r.steps.some((s) => s.name === "proof-walk" && !s.pass)).toBe(true);
  });

  it("rejects when an event has no matching proof entry", async () => {
    const kp = await generateKeypair();
    const eventA = makeEvent("evt-A");
    const eventB = makeEvent("evt-B");
    const leafA = await computeAuditMerkleLeafHash(eventA);
    // Two-leaf tree, internal node = SHA256(0x01 || leafA || leafB)
    const leafB = await computeAuditMerkleLeafHash(eventB);
    const concat = new Uint8Array(1 + 32 + 32);
    concat[0] = 0x01;
    const leafABytes = hexToBytesLocal(leafA);
    const leafBBytes = hexToBytesLocal(leafB);
    concat.set(leafABytes, 1);
    concat.set(leafBBytes, 33);
    const rootHex = bytesToHex(sha256(concat));
    const payload = {
      protocol: "ink/0.1" as const,
      type: "network.tulpa.audit_query_response" as const,
      serviceDid: SERVICE_DID,
      messageId: MESSAGE_ID,
      requester: REQUESTER,
      events: [eventA, eventB],
      proofs: [{ eventId: eventA.id, leafIndex: 0, inclusionProof: [leafB] }],
      treeSize: 2,
      rootHash: rootHex,
      timestamp: "2026-05-27T00:00:00.000Z",
    };
    const sig = await signAuditQueryResponse(payload as unknown as Record<string, unknown>, kp.privateKey);
    const r = await verifyAuditQueryResponse({
      response: { ...payload, serviceSignature: sig },
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(false);
    expect(r.steps.some((s) => s.name === "proofs" && !s.pass)).toBe(true);
  });

  it("rejects on duplicate proof eventIds", async () => {
    const kp = await generateKeypair();
    const response = await makeSingleLeafResponse(kp);
    const dup: AuditQueryResponse = {
      ...response,
      proofs: [...response.proofs, ...response.proofs],
      events: [...response.events, ...response.events],
    };
    const { serviceSignature: _, ...payload } = dup;
    const sig = await signAuditQueryResponse(payload as unknown as Record<string, unknown>, kp.privateKey);
    const r = await verifyAuditQueryResponse({
      response: { ...dup, serviceSignature: sig },
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(false);
  });

  it("rejects an event whose messageId does not match the envelope (scope smuggling)", async () => {
    const kp = await generateKeypair();
    // Build a single-leaf response, but the event itself is from a different messageId.
    const event = makeEvent("evt-smuggled");
    event.messageId = "msg-DIFFERENT";
    const leafHash = await computeAuditMerkleLeafHash(event);
    const payload = {
      protocol: "ink/0.1" as const,
      type: "network.tulpa.audit_query_response" as const,
      serviceDid: SERVICE_DID,
      messageId: MESSAGE_ID,
      requester: REQUESTER,
      events: [event],
      proofs: [{ eventId: event.id, leafIndex: 0, inclusionProof: [] as string[] }],
      treeSize: 1,
      rootHash: leafHash,
      timestamp: "2026-05-27T00:00:00.000Z",
    };
    const sig = await signRawForTest(payload as unknown as Record<string, unknown>, kp.privateKey);
    const r = await verifyAuditQueryResponse({
      response: { ...payload, serviceSignature: sig },
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(false);
    expect(r.steps.some((s) => s.name === "scope" && !s.pass)).toBe(true);
  });

  it("rejects an event where requester is not a party (agentId/counterpartyId)", async () => {
    const kp = await generateKeypair();
    const event = makeEvent("evt-notparty");
    event.agentId = "did:plc:someone-else";
    // counterpartyId unset
    const leafHash = await computeAuditMerkleLeafHash(event);
    const payload = {
      protocol: "ink/0.1" as const,
      type: "network.tulpa.audit_query_response" as const,
      serviceDid: SERVICE_DID,
      messageId: MESSAGE_ID,
      requester: REQUESTER,
      events: [event],
      proofs: [{ eventId: event.id, leafIndex: 0, inclusionProof: [] as string[] }],
      treeSize: 1,
      rootHash: leafHash,
      timestamp: "2026-05-27T00:00:00.000Z",
    };
    const sig = await signRawForTest(payload as unknown as Record<string, unknown>, kp.privateKey);
    const r = await verifyAuditQueryResponse({
      response: { ...payload, serviceSignature: sig },
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(false);
    expect(r.steps.some((s) => s.name === "scope" && !s.pass)).toBe(true);
  });

  it("accepts a valid empty-tree response (treeSize=0, empty events, empty-tree root)", async () => {
    const kp = await generateKeypair();
    const EMPTY_TREE_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const payload = {
      protocol: "ink/0.1" as const,
      type: "network.tulpa.audit_query_response" as const,
      serviceDid: SERVICE_DID,
      messageId: MESSAGE_ID,
      requester: REQUESTER,
      events: [],
      proofs: [],
      treeSize: 0,
      rootHash: EMPTY_TREE_ROOT,
      timestamp: "2026-05-27T00:00:00.000Z",
    };
    const sig = await signAuditQueryResponse(payload as unknown as Record<string, unknown>, kp.privateKey);
    const r = await verifyAuditQueryResponse({
      response: { ...payload, serviceSignature: sig },
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(true);
  });

  it("rejects treeSize=0 with a non-empty-tree rootHash (fabrication)", async () => {
    const kp = await generateKeypair();
    const payload = {
      protocol: "ink/0.1" as const,
      type: "network.tulpa.audit_query_response" as const,
      serviceDid: SERVICE_DID,
      messageId: MESSAGE_ID,
      requester: REQUESTER,
      events: [],
      proofs: [],
      treeSize: 0,
      rootHash: "a".repeat(64),
      timestamp: "2026-05-27T00:00:00.000Z",
    };
    const sig = await signAuditQueryResponse(payload as unknown as Record<string, unknown>, kp.privateKey);
    const r = await verifyAuditQueryResponse({
      response: { ...payload, serviceSignature: sig },
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(false);
    expect(r.steps.some((s) => s.name === "structure" && !s.pass)).toBe(true);
  });

  it("accepts treeSize>0 with empty events (requester has no visible events for messageId)", async () => {
    const kp = await generateKeypair();
    // Witness has 5 leaves total but none visible to this requester for this messageId.
    const payload = {
      protocol: "ink/0.1" as const,
      type: "network.tulpa.audit_query_response" as const,
      serviceDid: SERVICE_DID,
      messageId: MESSAGE_ID,
      requester: REQUESTER,
      events: [],
      proofs: [],
      treeSize: 5,
      rootHash: "deadbeef".repeat(8),
      timestamp: "2026-05-27T00:00:00.000Z",
    };
    const sig = await signAuditQueryResponse(payload as unknown as Record<string, unknown>, kp.privateKey);
    const r = await verifyAuditQueryResponse({
      response: { ...payload, serviceSignature: sig },
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(true);
  });

  it("rejects when verifyEventSignature is not supplied (§7.5 trust model)", async () => {
    const kp = await generateKeypair();
    const response = await makeSingleLeafResponse(kp);
    // Defense-in-depth check: TS marks the callback REQUIRED, but a
    // caller in JS (or TS with relaxed config) could still call without
    // it. We assert the runtime refuses.
    const opts: unknown = {
      response,
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
    };
    const r = await verifyAuditQueryResponse(opts as Parameters<typeof verifyAuditQueryResponse>[0]);
    expect(r.valid).toBe(false);
    const sigStep = r.steps.find((s) => s.name === "agent-signature");
    expect(sigStep?.pass).toBe(false);
    expect(sigStep?.detail).toMatch(/required/i);
  });

  it("rejects when verifyEventSignature returns false for any event", async () => {
    const kp = await generateKeypair();
    const response = await makeSingleLeafResponse(kp);
    const r = await verifyAuditQueryResponse({
      response,
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => false,
    });
    expect(r.valid).toBe(false);
    expect(r.steps.some((s) => s.name === "agent-signature" && !s.pass)).toBe(true);
  });

  it("accepts when verifyEventSignature returns true for every event", async () => {
    const kp = await generateKeypair();
    const response = await makeSingleLeafResponse(kp);
    const r = await verifyAuditQueryResponse({
      response,
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
    });
    expect(r.valid).toBe(true);
  });

  it("rejects a response whose event is missing agentSignature (structural)", async () => {
    const kp = await generateKeypair();
    const event = makeEvent("evt-nosig");
    delete (event as { agentSignature?: unknown }).agentSignature;
    const leafHash = await computeAuditMerkleLeafHash(event);
    const payload = {
      protocol: "ink/0.1" as const,
      type: "network.tulpa.audit_query_response" as const,
      serviceDid: SERVICE_DID,
      messageId: MESSAGE_ID,
      requester: REQUESTER,
      events: [event],
      proofs: [{ eventId: event.id, leafIndex: 0, inclusionProof: [] as string[] }],
      treeSize: 1,
      rootHash: leafHash,
      timestamp: "2026-05-27T00:00:00.000Z",
    };
    const sig = await signRawForTest(payload as unknown as Record<string, unknown>, kp.privateKey);
    const r = await verifyAuditQueryResponse({
      response: { ...payload, serviceSignature: sig },
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true, // would never be reached: shape check fires first
    });
    expect(r.valid).toBe(false);
    expect(r.steps.some((s) => s.name === "structure" && !s.pass)).toBe(true);
  });

  it("rejects when laterCheckpoint shows tree rewind", async () => {
    const kp = await generateKeypair();
    const response = await makeSingleLeafResponse(kp);
    const r = await verifyAuditQueryResponse({
      response,
      witnessPublicKey: kp.publicKey,
      expectedRequester: REQUESTER,
      expectedMessageId: MESSAGE_ID,
      verifyEventSignature: async () => true,
      laterCheckpoint: { treeSize: 0, rootHash: "0".repeat(64) },
    });
    expect(r.valid).toBe(false);
    expect(r.steps.some((s) => s.name === "checkpoint" && !s.pass)).toBe(true);
  });
});

// Local hex helper to avoid cycling through the lib for the two-leaf
// test fixture construction.
function hexToBytesLocal(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// keep `jcsCanonicalize` imported for any future fixture that needs it
void jcsCanonicalize;
