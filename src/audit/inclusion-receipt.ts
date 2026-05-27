/**
 * INK Auditability Section 7 inclusion-receipt verification.
 *
 * A witness returns a signed inclusion receipt when an agent submits
 * an audit event. The receipt commits the witness to a specific
 * (leafIndex, treeSize, rootHash) for the submitted event.
 *
 * To verify a receipt independently:
 *  1. Check the witness's serviceSignature against its published
 *     Ed25519 public key. The signed bytes are
 *     `ink/audit-inclusion/v1\n` + JCS({eventId, leafIndex, treeSize,
 *     rootHash, timestamp}).
 *  2. (Optional) Re-hash the audit event to derive the leaf hash and
 *     walk the inclusion proof up to the witness's claimed rootHash.
 *  3. (Optional) Cross-check the receipt against a later signed
 *     checkpoint: the tree only grew (treeSize >= receipt.treeSize)
 *     and if equal, the rootHash matches.
 *
 * This module ships the pure verification logic. The bin/verify-inclusion
 * CLI is a thin wrapper that fetches the witness DID document + a
 * current checkpoint and calls verifyInclusionReceipt.
 */
import * as ed from "@noble/ed25519";
import { base64urlDecode, jcsCanonicalize, hexToBytes, bytesToHex } from "../crypto/ink.js";

export interface InclusionReceipt {
  eventId: string;
  leafIndex: number;
  treeSize: number;
  rootHash: string;
  inclusionProof: string[];
  /** ISO 8601 timestamp at which the witness committed the leaf. */
  timestamp: string;
  /** Base64url Ed25519 signature over the canonical bytes. */
  serviceSignature: string;
}

export interface VerifyStep {
  name: string;
  pass: boolean;
  detail?: string;
}

export interface InclusionReceiptVerifyResult {
  valid: boolean;
  steps: VerifyStep[];
}

/**
 * Verify an INK inclusion receipt.
 *
 * Always performs:
 *  - Structural validation of the receipt object
 *  - Service signature verification against `witnessPublicKey`
 *
 * Optionally performs (when the corresponding input is provided):
 *  - Leaf-to-root proof walk (`eventHash`)
 *  - Cross-check against a later signed checkpoint (`laterCheckpoint`)
 */
export async function verifyInclusionReceipt(opts: {
  receipt: InclusionReceipt;
  /** Raw 32-byte Ed25519 public key of the witness service. */
  witnessPublicKey: Uint8Array;
  /** Optional leaf hash (SHA-256 of JCS(audit event without agentSignature),
   *  hex-encoded). When provided, the inclusion proof is walked from
   *  the leaf up to the claimed rootHash. */
  eventHash?: string;
  /** Optional later checkpoint to cross-check the receipt against.
   *  Must come from a `/ink/v1/checkpoint` response that the verifier
   *  has separately validated as authentic. */
  laterCheckpoint?: { treeSize: number; rootHash: string };
}): Promise<InclusionReceiptVerifyResult> {
  const steps: VerifyStep[] = [];
  const { receipt, witnessPublicKey, eventHash, laterCheckpoint } = opts;

  // ── Step 1: structural validation ──
  const structuralProblem = checkReceiptShape(receipt);
  if (structuralProblem) {
    steps.push({ name: "structure", pass: false, detail: structuralProblem });
    return { valid: false, steps };
  }
  steps.push({ name: "structure", pass: true });

  // ── Step 2: signature ──
  const signedPayload = {
    eventId: receipt.eventId,
    leafIndex: receipt.leafIndex,
    treeSize: receipt.treeSize,
    rootHash: receipt.rootHash,
    timestamp: receipt.timestamp,
  };
  const sigBase = `ink/audit-inclusion/v1\n${jcsCanonicalize(signedPayload)}`;
  let sigValid = false;
  try {
    const sig = base64urlDecode(receipt.serviceSignature);
    sigValid = await ed.verifyAsync(sig, new TextEncoder().encode(sigBase), witnessPublicKey);
  } catch (e) {
    steps.push({
      name: "signature",
      pass: false,
      detail: e instanceof Error ? e.message : "signature decode failed",
    });
    return { valid: false, steps };
  }
  if (!sigValid) {
    steps.push({ name: "signature", pass: false, detail: "Ed25519 verification failed" });
    return { valid: false, steps };
  }
  steps.push({ name: "signature", pass: true });

  // ── Step 3: inclusion-proof walk (optional) ──
  if (eventHash !== undefined) {
    if (!/^[0-9a-f]{64}$/.test(eventHash)) {
      steps.push({ name: "proof", pass: false, detail: "eventHash must be 64 lowercase hex chars" });
      return { valid: false, steps };
    }
    const verified = await verifyInclusionProof(
      eventHash,
      receipt.inclusionProof,
      receipt.leafIndex,
      receipt.treeSize,
      receipt.rootHash,
    );
    if (!verified) {
      steps.push({ name: "proof", pass: false, detail: "leaf-to-root walk did not reach claimed rootHash" });
      return { valid: false, steps };
    }
    steps.push({ name: "proof", pass: true });
  }

  // ── Step 4: later-checkpoint cross-check (optional) ──
  if (laterCheckpoint !== undefined) {
    const cpShape = checkCheckpointShape(laterCheckpoint);
    if (cpShape) {
      steps.push({ name: "checkpoint", pass: false, detail: cpShape });
      return { valid: false, steps };
    }
    if (laterCheckpoint.treeSize < receipt.treeSize) {
      steps.push({
        name: "checkpoint",
        pass: false,
        detail: `checkpoint treeSize ${laterCheckpoint.treeSize} < receipt treeSize ${receipt.treeSize} (witness rewound the tree)`,
      });
      return { valid: false, steps };
    }
    if (laterCheckpoint.treeSize === receipt.treeSize && laterCheckpoint.rootHash !== receipt.rootHash) {
      steps.push({
        name: "checkpoint",
        pass: false,
        detail: "checkpoint rootHash differs from receipt rootHash at same treeSize (fork)",
      });
      return { valid: false, steps };
    }
    steps.push({ name: "checkpoint", pass: true });
  }

  return { valid: true, steps };
}

// ── Internal helpers ──

/** Generous upper bound on inclusion-proof length. Real proofs are
 *  ceil(log2(treeSize)) entries; a treeSize > 2^60 is implausible for
 *  any real log, so capping at 64 entries bounds memory + walker depth
 *  without rejecting legitimate input. The signed payload binds
 *  treeSize but not the proof array itself, so an attacker could
 *  otherwise append unbounded garbage to a valid receipt. */
const MAX_PROOF_LENGTH = 64;

function checkReceiptShape(receipt: InclusionReceipt): string | null {
  if (receipt === null || typeof receipt !== "object") return "receipt is not an object";
  if (typeof receipt.eventId !== "string" || receipt.eventId.length === 0) return "eventId missing";
  if (!Number.isInteger(receipt.leafIndex) || receipt.leafIndex < 0) return "leafIndex must be non-negative integer";
  if (!Number.isInteger(receipt.treeSize) || receipt.treeSize < 1) return "treeSize must be positive integer";
  if (receipt.leafIndex >= receipt.treeSize) return "leafIndex must be < treeSize";
  if (typeof receipt.rootHash !== "string" || !/^[0-9a-f]{64}$/.test(receipt.rootHash)) {
    return "rootHash must be 64 lowercase hex chars";
  }
  if (!Array.isArray(receipt.inclusionProof)) return "inclusionProof must be an array";
  if (receipt.inclusionProof.length > MAX_PROOF_LENGTH) {
    return `inclusionProof exceeds max length of ${MAX_PROOF_LENGTH} entries`;
  }
  for (const p of receipt.inclusionProof) {
    if (typeof p !== "string" || !/^[0-9a-f]{64}$/.test(p)) {
      return "every inclusionProof entry must be 64 lowercase hex chars";
    }
  }
  if (typeof receipt.timestamp !== "string" || receipt.timestamp.length === 0) return "timestamp missing";
  if (typeof receipt.serviceSignature !== "string" || receipt.serviceSignature.length === 0) {
    return "serviceSignature missing";
  }
  return null;
}

function checkCheckpointShape(cp: { treeSize: number; rootHash: string }): string | null {
  if (cp === null || typeof cp !== "object") return "laterCheckpoint must be an object";
  if (!Number.isInteger(cp.treeSize) || cp.treeSize < 0) {
    return "laterCheckpoint.treeSize must be a non-negative integer";
  }
  if (typeof cp.rootHash !== "string" || !/^[0-9a-f]{64}$/.test(cp.rootHash)) {
    return "laterCheckpoint.rootHash must be 64 lowercase hex chars";
  }
  return null;
}

async function hashPair(left: string, right: string): Promise<string> {
  const l = hexToBytes(left);
  const r = hexToBytes(right);
  const buf = new Uint8Array(1 + l.length + r.length);
  buf[0] = 0x01;
  buf.set(l, 1);
  buf.set(r, 1 + l.length);
  const out = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  return bytesToHex(out);
}

function largestPowerOf2LessThan(n: number): number {
  if (n <= 1) return 0;
  let p = 1;
  while (p * 2 < n) p *= 2;
  return p;
}

async function recomputeRoot(
  currentHash: string,
  proof: string[],
  proofIdx: number,
  leafIndex: number,
  start: number,
  size: number,
): Promise<string> {
  if (size === 1) {
    // Reached the leaf. Any proof entries left over mean the proof was
    // padded with extras; reject it as malformed.
    if (proofIdx !== proof.length) throw new Error("inclusion proof has unused entries");
    return currentHash;
  }
  if (proofIdx >= proof.length) {
    // Proof exhausted before walking down to the leaf. Without this,
    // an attacker can present a short proof against a tree > 1 leaf
    // and the walker returns currentHash (the leaf), which a verifier
    // might mistakenly equate to rootHash.
    throw new Error("inclusion proof too short for declared treeSize");
  }
  const split = largestPowerOf2LessThan(size);
  if (leafIndex - start < split) {
    const leftResult = await recomputeRoot(currentHash, proof, proofIdx + 1, leafIndex, start, split);
    return hashPair(leftResult, proof[proofIdx]!);
  }
  const rightResult = await recomputeRoot(currentHash, proof, proofIdx + 1, leafIndex, start + split, size - split);
  return hashPair(proof[proofIdx]!, rightResult);
}

async function verifyInclusionProof(
  leafHash: string,
  proof: string[],
  leafIndex: number,
  treeSize: number,
  expectedRootHash: string,
): Promise<boolean> {
  if (leafIndex < 0 || leafIndex >= treeSize) return false;
  try {
    const computed = await recomputeRoot(leafHash, proof, 0, leafIndex, 0, treeSize);
    return computed === expectedRootHash;
  } catch {
    return false;
  }
}
