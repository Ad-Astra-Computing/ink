/**
 * computeAuditMerkleLeafHash — RFC 6962 leaf-hash primitive for INK
 * Auditability §7.3.
 *
 * leaf = SHA-256(0x00 || JCS(event-without-agentSignature))
 *
 * Distinct from computeEventHash (no 0x00 prefix) which is used for
 * previousEventHash chain linkage. A consumer of inclusion proofs that
 * derives leaves via the chain hash would fail verification against a
 * conformant witness; this test pins the difference.
 */
import { describe, it, expect } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import {
  computeAuditMerkleLeafHash,
  computeEventHash,
  jcsCanonicalize,
  bytesToHex,
} from "../src/index.js";

const sampleEvent = {
  id: "evt-001",
  version: "ink-audit/1",
  agentId: "did:tulpa:zAlice",
  sequence: 1,
  previousEventHash: null,
  eventType: "message_sent",
  timestamp: "2026-05-27T00:00:00.000Z",
  agentSignature: "AAAA",
};

describe("computeAuditMerkleLeafHash", () => {
  it("prefixes 0x00 before hashing (RFC 6962 leaf rule)", async () => {
    const leaf = await computeAuditMerkleLeafHash(sampleEvent);
    const { agentSignature: _, ...withoutSig } = sampleEvent;
    const canonical = new TextEncoder().encode(jcsCanonicalize(withoutSig));
    const prefixed = new Uint8Array(canonical.length + 1);
    prefixed[0] = 0x00;
    prefixed.set(canonical, 1);
    const expected = bytesToHex(sha256(prefixed));
    expect(leaf).toBe(expected);
  });

  it("differs from computeEventHash for the same event", async () => {
    const leaf = await computeAuditMerkleLeafHash(sampleEvent);
    const chain = await computeEventHash(sampleEvent);
    expect(leaf).not.toBe(chain);
  });

  it("strips agentSignature before hashing", async () => {
    const a = await computeAuditMerkleLeafHash(sampleEvent);
    const b = await computeAuditMerkleLeafHash({ ...sampleEvent, agentSignature: "DIFFERENT" });
    expect(a).toBe(b);
  });

  it("rejects non-object event", async () => {
    await expect(computeAuditMerkleLeafHash(null as unknown as Record<string, unknown>))
      .rejects.toThrow();
    await expect(computeAuditMerkleLeafHash([] as unknown as Record<string, unknown>))
      .rejects.toThrow();
  });
});
