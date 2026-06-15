import { describe, it, expect } from "vitest";
import canonicalize from "canonicalize";
import * as ed from "@noble/ed25519";
import {
  generateKeypair,
  verifyInclusionReceipt,
  computeAuditMerkleLeafHash,
  base64urlEncode,
  type InclusionReceipt,
} from "../src/index.js";

const EVENT = {
  id: "01JBTEST00000001",
  version: "ink-audit/1",
  agentId: "tulpa:zABC",
  agentSignature: "sig",
  sequence: 1,
  previousEventHash: null,
  eventType: "message.sent",
  timestamp: "2026-06-10T00:00:00.000Z",
};

/** Build a single-leaf receipt (treeSize 1, empty proof) whose rootHash is the
 *  leaf hash of `event`, signed by `privateKey`. */
async function receiptForEvent(
  privateKey: Uint8Array,
  event: Record<string, unknown>,
  overrides: Partial<InclusionReceipt> = {},
): Promise<InclusionReceipt> {
  const rootHash = await computeAuditMerkleLeafHash(event);
  const base: InclusionReceipt = {
    eventId: event.id as string,
    leafIndex: 0,
    treeSize: 1,
    rootHash,
    inclusionProof: [],
    timestamp: "2026-06-10T00:00:00.000Z",
    serviceSignature: "",
    ...overrides,
  };
  const signed = {
    eventId: base.eventId,
    leafIndex: base.leafIndex,
    treeSize: base.treeSize,
    rootHash: base.rootHash,
    timestamp: base.timestamp,
  };
  const sigBase = `ink/audit-inclusion/v1\n${canonicalize(signed)}`;
  const sig = await ed.signAsync(new TextEncoder().encode(sigBase), privateKey);
  return { ...base, serviceSignature: base64urlEncode(sig) };
}

describe("verifyInclusionReceipt event binding", () => {
  it("verifies the proof when the event is supplied and matches the receipt", async () => {
    const kp = await generateKeypair();
    const receipt = await receiptForEvent(kp.privateKey, EVENT);
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: kp.publicKey, event: EVENT });
    expect(r.valid).toBe(true);
    expect(r.steps.find((s) => s.name === "proof")?.pass).toBe(true);
  });

  it("rejects when event.id does not match receipt.eventId", async () => {
    const kp = await generateKeypair();
    const receipt = await receiptForEvent(kp.privateKey, EVENT);
    const otherEvent = { ...EVENT, id: "01JBOTHER0000002" };
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: kp.publicKey, event: otherEvent });
    expect(r.valid).toBe(false);
    expect(r.steps.find((s) => s.name === "proof")?.detail).toMatch(/does not match/);
  });

  it("rejects when the event content was tampered (same id, different bytes)", async () => {
    const kp = await generateKeypair();
    const receipt = await receiptForEvent(kp.privateKey, EVENT);
    const tampered = { ...EVENT, eventType: "message.rejected" };
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: kp.publicKey, event: tampered });
    expect(r.valid).toBe(false);
    expect(r.steps.find((s) => s.name === "proof")?.detail).toMatch(/did not reach/);
  });

  it("uses event over eventHash when both are supplied (a bad eventHash cannot override)", async () => {
    const kp = await generateKeypair();
    const receipt = await receiptForEvent(kp.privateKey, EVENT);
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      event: EVENT,
      eventHash: "b".repeat(64), // garbage hash that would fail the walk if used
    });
    expect(r.valid).toBe(true);
  });

  it("rejects an event whose id is missing or not a string", async () => {
    const kp = await generateKeypair();
    const receipt = await receiptForEvent(kp.privateKey, EVENT);
    const noId = { ...EVENT, id: 42 } as unknown as Record<string, unknown>;
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: kp.publicKey, event: noId });
    expect(r.valid).toBe(false);
    expect(r.steps.find((s) => s.name === "proof")?.detail).toMatch(/object with a string id/);
  });

  it("still supports the legacy eventHash path", async () => {
    const kp = await generateKeypair();
    const receipt = await receiptForEvent(kp.privateKey, EVENT);
    const eventHash = await computeAuditMerkleLeafHash(EVENT);
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: kp.publicKey, eventHash });
    expect(r.valid).toBe(true);
  });
});
