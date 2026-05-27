/**
 * verifyInclusionReceipt: spec-conformance + step-by-step verifier.
 */
import { describe, it, expect } from "vitest";
import canonicalize from "canonicalize";
import * as ed from "@noble/ed25519";
import {
  generateKeypair,
  verifyInclusionReceipt,
  base64urlEncode,
  type InclusionReceipt,
} from "../src/index.js";

async function signedReceipt(
  privateKey: Uint8Array,
  overrides: Partial<InclusionReceipt> = {},
): Promise<InclusionReceipt> {
  const base = {
    eventId: "01JBTEST00000001",
    leafIndex: 0,
    treeSize: 1,
    rootHash: "a".repeat(64),
    inclusionProof: [],
    timestamp: "2026-05-27T00:00:00.000Z",
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

describe("verifyInclusionReceipt: structure", () => {
  it("rejects missing eventId", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey);
    delete (receipt as unknown as Record<string, unknown>).eventId;
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: kp.publicKey });
    expect(r.valid).toBe(false);
    expect(r.steps[0]!.name).toBe("structure");
  });

  it("rejects negative leafIndex", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey, { leafIndex: -1 });
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: kp.publicKey });
    expect(r.valid).toBe(false);
    expect(r.steps[0]!.name).toBe("structure");
  });

  it("rejects leafIndex >= treeSize", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey, { leafIndex: 5, treeSize: 5 });
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: kp.publicKey });
    expect(r.valid).toBe(false);
  });

  it("rejects malformed rootHash", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey, { rootHash: "not-hex" });
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: kp.publicKey });
    expect(r.valid).toBe(false);
  });
});

describe("verifyInclusionReceipt: signature", () => {
  it("accepts a correctly signed receipt", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey);
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: kp.publicKey });
    expect(r.valid).toBe(true);
    expect(r.steps.find((s) => s.name === "signature")!.pass).toBe(true);
  });

  it("rejects a receipt signed by the wrong key", async () => {
    const witnessKp = await generateKeypair();
    const attackerKp = await generateKeypair();
    const receipt = await signedReceipt(attackerKp.privateKey);
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: witnessKp.publicKey });
    expect(r.valid).toBe(false);
    expect(r.steps.find((s) => s.name === "signature")!.pass).toBe(false);
  });

  it("rejects when rootHash was tampered post-signing", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey);
    receipt.rootHash = "f".repeat(64);
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: kp.publicKey });
    expect(r.valid).toBe(false);
  });
});

describe("verifyInclusionReceipt: laterCheckpoint cross-check", () => {
  it("accepts when checkpoint treeSize > receipt treeSize", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey);
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      laterCheckpoint: { treeSize: 100, rootHash: "f".repeat(64) },
    });
    expect(r.valid).toBe(true);
  });

  it("rejects when checkpoint treeSize < receipt treeSize (rewound)", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey, { treeSize: 10, leafIndex: 5 });
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      laterCheckpoint: { treeSize: 5, rootHash: "f".repeat(64) },
    });
    expect(r.valid).toBe(false);
    const cp = r.steps.find((s) => s.name === "checkpoint");
    expect(cp?.pass).toBe(false);
  });

  it("rejects when rootHash differs at the same treeSize (fork)", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey, { treeSize: 7, leafIndex: 3 });
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      laterCheckpoint: { treeSize: 7, rootHash: "b".repeat(64) },
    });
    expect(r.valid).toBe(false);
  });
});

describe("verifyInclusionReceipt: inclusion-proof walk", () => {
  it("accepts a single-leaf tree where rootHash equals leaf hash", async () => {
    const kp = await generateKeypair();
    const leafHash = "1234567890abcdef".repeat(4);
    const receipt = await signedReceipt(kp.privateKey, {
      treeSize: 1,
      leafIndex: 0,
      rootHash: leafHash,
      inclusionProof: [],
    });
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      eventHash: leafHash,
    });
    expect(r.valid).toBe(true);
  });

  it("rejects when proof does not reach claimed rootHash", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey, {
      treeSize: 1,
      leafIndex: 0,
      rootHash: "abcdef".repeat(10) + "00aabb",
      inclusionProof: [],
    });
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      eventHash: "1".repeat(64),
    });
    expect(r.valid).toBe(false);
  });
});

// ── Multi-leaf parity tests ──
// Build a tree using the exact convention the witness uses, generate
// inclusion proofs the same way, then prove the verifier accepts them.
// Pins the proof-order convention (root-to-leaf siblings) end-to-end.

const enc = new TextEncoder();

async function hashLeaf(content: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", enc.encode(content));
  return Array.from(new Uint8Array(bytes)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytesT(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return out;
}

function bytesToHexT(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hashInternal(left: string, right: string): Promise<string> {
  const l = hexToBytesT(left), r = hexToBytesT(right);
  const buf = new Uint8Array(1 + l.length + r.length);
  buf[0] = 0x01; buf.set(l, 1); buf.set(r, 1 + l.length);
  const out = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  return bytesToHexT(out);
}

function lpot2(n: number): number {
  if (n <= 1) return 0;
  let p = 1;
  while (p * 2 < n) p *= 2;
  return p;
}

async function rootOf(leaves: string[], start: number, size: number): Promise<string> {
  if (size === 1) return leaves[start]!;
  const split = lpot2(size);
  return hashInternal(
    await rootOf(leaves, start, split),
    await rootOf(leaves, start + split, size - split),
  );
}

async function proofFor(leaves: string[], leafIndex: number, start: number, size: number): Promise<string[]> {
  if (size === 1) return [];
  const split = lpot2(size);
  if (leafIndex - start < split) {
    const rightHash = await rootOf(leaves, start + split, size - split);
    return [rightHash, ...(await proofFor(leaves, leafIndex, start, split))];
  }
  const leftHash = await rootOf(leaves, start, split);
  return [leftHash, ...(await proofFor(leaves, leafIndex, start + split, size - split))];
}

async function buildSignedReceipt(
  privateKey: Uint8Array,
  leaves: string[],
  leafIndex: number,
): Promise<InclusionReceipt> {
  const treeSize = leaves.length;
  const rootHash = await rootOf(leaves, 0, treeSize);
  const proof = await proofFor(leaves, leafIndex, 0, treeSize);
  const payload = {
    eventId: `evt-${leafIndex}`,
    leafIndex,
    treeSize,
    rootHash,
    timestamp: "2026-05-27T00:00:00.000Z",
  };
  const sigBase = `ink/audit-inclusion/v1\n${canonicalize(payload)}`;
  const sig = await ed.signAsync(enc.encode(sigBase), privateKey);
  return {
    ...payload,
    inclusionProof: proof,
    serviceSignature: base64urlEncode(sig),
  };
}

describe("verifyInclusionReceipt: hardening", () => {
  it("rejects an under-length proof (treeSize>1 with empty proof and eventHash==rootHash)", async () => {
    // The bypass Codex flagged: receipt declares treeSize 2, proof is
    // empty, eventHash matches rootHash. Walker MUST refuse instead of
    // returning currentHash early.
    const kp = await generateKeypair();
    const leafHash = "9".repeat(64);
    const receipt = await signedReceipt(kp.privateKey, {
      treeSize: 2,
      leafIndex: 0,
      rootHash: leafHash,
      inclusionProof: [],
    });
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      eventHash: leafHash,
    });
    expect(r.valid).toBe(false);
    expect(r.steps.find((s) => s.name === "proof")?.pass).toBe(false);
  });

  it("rejects an over-length proof (extras appended after sig)", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey, {
      treeSize: 1,
      leafIndex: 0,
      rootHash: "a".repeat(64),
      inclusionProof: ["b".repeat(64), "c".repeat(64)],
    });
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      eventHash: "a".repeat(64),
    });
    expect(r.valid).toBe(false);
  });

  it("rejects proofs longer than the protocol cap", async () => {
    const kp = await generateKeypair();
    const hugeProof = Array.from({ length: 65 }, () => "a".repeat(64));
    const receipt = await signedReceipt(kp.privateKey, { inclusionProof: hugeProof });
    const r = await verifyInclusionReceipt({ receipt, witnessPublicKey: kp.publicKey });
    expect(r.valid).toBe(false);
    expect(r.steps[0]!.name).toBe("structure");
  });

  it("rejects laterCheckpoint with NaN treeSize", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey);
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      laterCheckpoint: { treeSize: NaN, rootHash: "f".repeat(64) },
    });
    expect(r.valid).toBe(false);
    expect(r.steps.find((s) => s.name === "checkpoint")?.pass).toBe(false);
  });

  it("rejects laterCheckpoint with malformed rootHash", async () => {
    const kp = await generateKeypair();
    const receipt = await signedReceipt(kp.privateKey);
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      laterCheckpoint: { treeSize: 10, rootHash: "not-hex" },
    });
    expect(r.valid).toBe(false);
  });
});

describe("verifyInclusionReceipt: multi-leaf proof parity", () => {
  it("verifies a leaf-0 proof in a 3-leaf tree", async () => {
    const kp = await generateKeypair();
    const leaves = [
      await hashLeaf("evt-0-content"),
      await hashLeaf("evt-1-content"),
      await hashLeaf("evt-2-content"),
    ];
    const receipt = await buildSignedReceipt(kp.privateKey, leaves, 0);
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      eventHash: leaves[0],
    });
    expect(r.valid).toBe(true);
    expect(r.steps.find((s) => s.name === "proof")!.pass).toBe(true);
  });

  it("verifies leaf-3 in a 7-leaf tree (unbalanced split exercises both sides)", async () => {
    const kp = await generateKeypair();
    const leaves: string[] = [];
    for (let i = 0; i < 7; i++) leaves.push(await hashLeaf(`evt-${i}`));
    const receipt = await buildSignedReceipt(kp.privateKey, leaves, 3);
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      eventHash: leaves[3],
    });
    expect(r.valid).toBe(true);
  });

  it("rejects a proof where one sibling hash is tampered (4-leaf tree)", async () => {
    const kp = await generateKeypair();
    const leaves = [
      await hashLeaf("a"), await hashLeaf("b"),
      await hashLeaf("c"), await hashLeaf("d"),
    ];
    const receipt = await buildSignedReceipt(kp.privateKey, leaves, 1);
    receipt.inclusionProof[0] = "f".repeat(64);
    // Need to re-sign because rootHash stays but proof was rebuilt by the
    // attacker. Here we want to test that the proof walk fails BEFORE the
    // sig check fails. So we keep the original signature; the structure
    // is fine, sig verifies, but proof walk to root fails.
    const r = await verifyInclusionReceipt({
      receipt,
      witnessPublicKey: kp.publicKey,
      eventHash: leaves[1],
    });
    expect(r.valid).toBe(false);
    const proofStep = r.steps.find((s) => s.name === "proof");
    expect(proofStep?.pass).toBe(false);
  });
});
