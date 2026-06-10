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
import {
  base64urlDecode,
  jcsCanonicalize,
  hexToBytes,
  bytesToHex,
  computeAuditMerkleLeafHash,
  verifyAuditQueryResponseSignature,
} from "../crypto/ink.js";

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
 *  - Leaf-to-root proof walk: pass `event` (recommended — recomputes the leaf
 *    hash and binds it to `receipt.eventId`) or `eventHash` (legacy, unbound)
 *  - Cross-check against a later signed checkpoint (`laterCheckpoint`)
 */
export async function verifyInclusionReceipt(opts: {
  receipt: InclusionReceipt;
  /** Raw 32-byte Ed25519 public key of the witness service. */
  witnessPublicKey: Uint8Array;
  /** Optional audit event the receipt claims inclusion for. This is the
   *  RECOMMENDED way to verify the proof: the leaf hash is recomputed from the
   *  event with `computeAuditMerkleLeafHash`, and `event.id` is bound to
   *  `receipt.eventId`, so the proof attests that the event named by the
   *  receipt is in the tree — not merely that some caller-chosen hash is. */
  event?: Record<string, unknown>;
  /** Optional pre-computed RFC 6962 leaf hash (hex). LEGACY / lower-assurance:
   *  unlike `event`, a bare hash is NOT bound to `receipt.eventId`, so the proof
   *  only attests "this hash is in the tree", not "the event the receipt names
   *  is in the tree". Prefer `event`. Ignored when `event` is provided. */
  eventHash?: string;
  /** Optional later checkpoint to cross-check the receipt against. This MUST be
   *  the parsed body of a checkpoint whose Ed25519 signature and origin the
   *  caller has already verified with `verifyCheckpoint` against the witness
   *  key. Passing an unverified (merely parsed) checkpoint gives the
   *  anti-rollback / fork cross-check no security, because the treeSize and
   *  rootHash would then be attacker-controllable. */
  laterCheckpoint?: { treeSize: number; rootHash: string };
}): Promise<InclusionReceiptVerifyResult> {
  const steps: VerifyStep[] = [];
  const { receipt, witnessPublicKey, event, eventHash, laterCheckpoint } = opts;

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
    sigValid = await ed.verifyAsync(sig, new TextEncoder().encode(sigBase), witnessPublicKey, { zip215: false });
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
  // Prefer the `event` path: recompute the leaf hash from the event and bind it
  // to receipt.eventId, so the proof attests the named event's inclusion.
  let leafHash: string | undefined;
  if (event !== undefined) {
    if (typeof event.id !== "string") {
      steps.push({ name: "proof", pass: false, detail: "event.id is missing or not a string" });
      return { valid: false, steps };
    }
    if (event.id !== receipt.eventId) {
      steps.push({ name: "proof", pass: false, detail: "event.id does not match receipt.eventId" });
      return { valid: false, steps };
    }
    try {
      leafHash = await computeAuditMerkleLeafHash(event);
    } catch {
      steps.push({ name: "proof", pass: false, detail: "could not compute leaf hash from event" });
      return { valid: false, steps };
    }
  } else if (eventHash !== undefined) {
    if (!/^[0-9a-f]{64}$/.test(eventHash)) {
      steps.push({ name: "proof", pass: false, detail: "eventHash must be 64 lowercase hex chars" });
      return { valid: false, steps };
    }
    leafHash = eventHash;
  }
  if (leafHash !== undefined) {
    const verified = await verifyInclusionProof(
      leafHash,
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

// ── Audit-query response verification (INK Auditability §7.3) ──
//
// The low-level `verifyAuditQueryResponseSignature` only checks the
// Ed25519 signature over caller-supplied canonical bytes. This wrapper
// is the recommended verifier for consumers of a witness response: it
// re-derives the canonical bytes, then performs every additional
// envelope and proof check §7.3 mandates.

export interface AuditQueryResponse {
  protocol: "ink/0.1";
  type: "network.tulpa.audit_query_response";
  serviceDid: string;
  messageId: string;
  requester: string;
  events: Array<Record<string, unknown> & { id: string }>;
  proofs: Array<{ eventId: string; leafIndex: number; inclusionProof: string[] }>;
  treeSize: number;
  rootHash: string;
  timestamp: string;
  serviceSignature: string;
}

export interface AuditQueryResponseVerifyResult {
  valid: boolean;
  steps: VerifyStep[];
}

/**
 * Full §7.3 verification of a witness audit-query response. Use this in
 * preference to `verifyAuditQueryResponseSignature`, which is the
 * underlying primitive and verifies only the Ed25519 signature. This
 * function additionally enforces:
 *
 *  - Envelope shape (protocol, type, serviceDid, requester, messageId,
 *    timestamp, treeSize, rootHash, events[], proofs[])
 *  - Service signature with the right canonical bytes
 *  - Optional caller-supplied bindings: expected `messageId`,
 *    `requester`, `serviceDid` (each rejected on mismatch)
 *  - `events` and `proofs` align one-to-one by `eventId`
 *  - Every event includes a non-empty `agentSignature` field
 *  - Every proof walks from `computeAuditMerkleLeafHash(event)` up to
 *    the response's `rootHash` at `treeSize`
 *  - Optional `laterCheckpoint`: tree only grew, no fork at same size
 *
 * **Per-event agent-signature verification (§7.5 trust model).** A
 * Merkle-valid response is necessary but not sufficient: the witness
 * could in principle commit a fabricated "event" not signed by any
 * agent, sign the resulting `(treeSize, rootHash)`, and the Merkle
 * proof walks just fine. To detect this, callers MUST pass a
 * `verifyEventSignature` callback that resolves the agent's published
 * Ed25519 keys (typically via Agent Card §2) and validates
 * `event.agentSignature`. The callback is REQUIRED, not optional: the
 * verifier refuses to return `valid: true` without it, so a caller
 * cannot accidentally accept witness-fabricated events.
 *
 * **Freshness.** A `valid: true` result attests that the response was a
 * complete enumeration of the requester's visible events at the
 * `(treeSize, rootHash)` snapshot the witness signed, NOT that it is
 * the witness's current authoritative view. The signed envelope binds
 * `timestamp`, but verifiers wanting "is this still current?"
 * semantics MUST additionally fetch a fresh witness checkpoint and
 * compare it (e.g. require `laterCheckpoint.treeSize === response.treeSize
 * && laterCheckpoint.rootHash === response.rootHash` for "current", or
 * use `laterCheckpoint` here only to prove the tree never rewound or
 * forked).
 *
 * Returns `{valid, steps}` where each step explains pass/fail with detail.
 * Pure function. Does not perform network I/O.
 */
export async function verifyAuditQueryResponse(opts: {
  response: AuditQueryResponse;
  /** Raw 32-byte Ed25519 public key of the witness service. */
  witnessPublicKey: Uint8Array;
  /** Locally authenticated requester DID. Verifier MUST supply this so
   *  a response signed for Alice cannot be replayed to Bob. */
  expectedRequester: string;
  /** The `messageId` the verifier asked about. Bound for paranoia: the
   *  signed envelope already commits to messageId, so this catches
   *  client-side routing bugs before they become trust bugs. */
  expectedMessageId: string;
  /** Optional: witness DID the verifier expects (pinned out of band). */
  expectedServiceDid?: string;
  /** Optional later checkpoint to cross-check against. Same semantics
   *  as `verifyInclusionReceipt`. */
  laterCheckpoint?: { treeSize: number; rootHash: string };
  /** Per-event agent-signature verifier (REQUIRED by Auditability §7.5).
   *  The caller resolves the event's submitting agent's public key set
   *  (typically from the Agent Card) and returns true if
   *  `event.agentSignature` verifies. The verifier refuses to return
   *  `valid: true` without this: Merkle inclusion alone does not prove
   *  the agent produced the event. If a caller genuinely wants to
   *  bypass per-event signature checks (e.g. during a pure Merkle
   *  audit), they MUST explicitly pass a callback that does so. */
  verifyEventSignature: (event: Record<string, unknown>) => Promise<boolean>;
}): Promise<AuditQueryResponseVerifyResult> {
  const steps: VerifyStep[] = [];
  const { response, witnessPublicKey, expectedRequester, expectedMessageId, expectedServiceDid, laterCheckpoint, verifyEventSignature } = opts;

  // ── Step 1: structural validation ──
  const structuralProblem = checkAuditQueryResponseShape(response);
  if (structuralProblem) {
    steps.push({ name: "structure", pass: false, detail: structuralProblem });
    return { valid: false, steps };
  }
  steps.push({ name: "structure", pass: true });

  // ── Step 2: caller-supplied binding checks ──
  if (response.messageId !== expectedMessageId) {
    steps.push({ name: "binding", pass: false, detail: `messageId mismatch: response=${response.messageId} expected=${expectedMessageId}` });
    return { valid: false, steps };
  }
  if (response.requester !== expectedRequester) {
    steps.push({ name: "binding", pass: false, detail: "requester mismatch (response signed for a different requester)" });
    return { valid: false, steps };
  }
  if (expectedServiceDid !== undefined && response.serviceDid !== expectedServiceDid) {
    steps.push({ name: "binding", pass: false, detail: `serviceDid mismatch: response=${response.serviceDid} expected=${expectedServiceDid}` });
    return { valid: false, steps };
  }
  steps.push({ name: "binding", pass: true });

  // ── Step 3: signature over canonical bytes ──
  const { serviceSignature, ...payload } = response;
  const sigValid = await verifyAuditQueryResponseSignature(
    payload as unknown as Record<string, unknown>,
    serviceSignature,
    witnessPublicKey,
  );
  if (!sigValid) {
    steps.push({ name: "signature", pass: false, detail: "Ed25519 verification failed" });
    return { valid: false, steps };
  }
  steps.push({ name: "signature", pass: true });

  // ── Step 4: per-event scope check ──
  //
  // The envelope binds messageId and requester, but until we look INTO
  // each event we don't know the witness isn't returning a Merkle-valid
  // event from a different messageId or one the requester is not a
  // party to. Reject any event whose own fields contradict the envelope.
  for (const event of response.events) {
    const eMessageId = (event as { messageId?: unknown }).messageId;
    if (typeof eMessageId !== "string" || eMessageId !== response.messageId) {
      steps.push({ name: "scope", pass: false, detail: `event ${event.id}: messageId does not match envelope` });
      return { valid: false, steps };
    }
    const eAgentId = (event as { agentId?: unknown }).agentId;
    const eCounterpartyId = (event as { counterpartyId?: unknown }).counterpartyId;
    const requesterIsParty =
      (typeof eAgentId === "string" && eAgentId === expectedRequester) ||
      (typeof eCounterpartyId === "string" && eCounterpartyId === expectedRequester);
    if (!requesterIsParty) {
      steps.push({ name: "scope", pass: false, detail: `event ${event.id}: requester ${expectedRequester} is not a party (agentId/counterpartyId)` });
      return { valid: false, steps };
    }
  }
  steps.push({ name: "scope", pass: true });

  // ── Step 5: events ↔ proofs strict one-to-one by eventId ──
  //
  // §7.3 mandates a one-to-one mapping. Enforce both directions:
  //   - No duplicate event.id (otherwise `events: [A, A]` paired with
  //     `proofs: [proof(A), proof(extra)]` could pass length + has-proof
  //     checks while including a proof for an unverified event).
  //   - No duplicate proof.eventId.
  //   - Every proof.eventId corresponds to some event.id (no "extra"
  //     proofs for events not in the response).
  if (response.events.length !== response.proofs.length) {
    steps.push({ name: "proofs", pass: false, detail: `events and proofs length differ: ${response.events.length} vs ${response.proofs.length}` });
    return { valid: false, steps };
  }
  const eventIds = new Set<string>();
  for (const event of response.events) {
    if (eventIds.has(event.id)) {
      steps.push({ name: "proofs", pass: false, detail: `duplicate event id ${event.id}` });
      return { valid: false, steps };
    }
    eventIds.add(event.id);
  }
  const proofById = new Map<string, { leafIndex: number; inclusionProof: string[] }>();
  for (const p of response.proofs) {
    if (proofById.has(p.eventId)) {
      steps.push({ name: "proofs", pass: false, detail: `duplicate proof for eventId ${p.eventId}` });
      return { valid: false, steps };
    }
    if (!eventIds.has(p.eventId)) {
      steps.push({ name: "proofs", pass: false, detail: `proof references unknown eventId ${p.eventId}` });
      return { valid: false, steps };
    }
    proofById.set(p.eventId, { leafIndex: p.leafIndex, inclusionProof: p.inclusionProof });
  }
  for (const event of response.events) {
    if (!proofById.has(event.id)) {
      steps.push({ name: "proofs", pass: false, detail: `event ${event.id} has no matching proof` });
      return { valid: false, steps };
    }
  }
  steps.push({ name: "proofs", pass: true });

  // ── Step 6: walk each inclusion proof ──
  for (const event of response.events) {
    const p = proofById.get(event.id)!;
    let leafHash: string;
    try {
      leafHash = await computeAuditMerkleLeafHash(event as unknown as Record<string, unknown>);
    } catch (e) {
      steps.push({ name: "proof-walk", pass: false, detail: `event ${event.id}: leaf-hash computation failed: ${e instanceof Error ? e.message : String(e)}` });
      return { valid: false, steps };
    }
    const ok = await verifyInclusionProof(leafHash, p.inclusionProof, p.leafIndex, response.treeSize, response.rootHash);
    if (!ok) {
      steps.push({ name: "proof-walk", pass: false, detail: `event ${event.id}: leaf-to-root walk did not reach claimed rootHash` });
      return { valid: false, steps };
    }
  }
  steps.push({ name: "proof-walk", pass: true });

  // ── Step 6: per-event agent signature ──
  //
  // Merkle validity proves the witness committed to these exact event
  // bytes; it does NOT prove an agent ever signed them. The caller
  // MUST supply `verifyEventSignature`; we refuse to return valid
  // otherwise.
  if (typeof verifyEventSignature !== "function") {
    steps.push({
      name: "agent-signature",
      pass: false,
      detail: "verifyEventSignature callback is required (Auditability §7.5); refusing to accept witness Merkle inclusion as proof of agent provenance",
    });
    return { valid: false, steps };
  }
  for (const event of response.events) {
    let ok = false;
    try {
      ok = await verifyEventSignature(event as unknown as Record<string, unknown>);
    } catch (e) {
      steps.push({ name: "agent-signature", pass: false, detail: `event ${event.id}: verifier threw: ${e instanceof Error ? e.message : String(e)}` });
      return { valid: false, steps };
    }
    if (!ok) {
      steps.push({ name: "agent-signature", pass: false, detail: `event ${event.id}: agentSignature did not verify` });
      return { valid: false, steps };
    }
  }
  steps.push({ name: "agent-signature", pass: true });

  // ── Step 7: optional later-checkpoint cross-check ──
  if (laterCheckpoint !== undefined) {
    const cpShape = checkCheckpointShape(laterCheckpoint);
    if (cpShape) {
      steps.push({ name: "checkpoint", pass: false, detail: cpShape });
      return { valid: false, steps };
    }
    if (laterCheckpoint.treeSize < response.treeSize) {
      steps.push({
        name: "checkpoint",
        pass: false,
        detail: `checkpoint treeSize ${laterCheckpoint.treeSize} < response treeSize ${response.treeSize} (witness rewound the tree)`,
      });
      return { valid: false, steps };
    }
    if (laterCheckpoint.treeSize === response.treeSize && laterCheckpoint.rootHash !== response.rootHash) {
      steps.push({
        name: "checkpoint",
        pass: false,
        detail: "checkpoint rootHash differs from response rootHash at same treeSize (fork)",
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

// SHA-256("") in hex, used as the empty-log Merkle root per RFC 6962 §2.1.
// A fresh witness with no submissions reports treeSize=0 and rootHash=EMPTY_TREE_ROOT.
const EMPTY_TREE_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

function checkAuditQueryResponseShape(r: AuditQueryResponse): string | null {
  if (r === null || typeof r !== "object") return "response is not an object";
  if (r.protocol !== "ink/0.1") return `protocol must be "ink/0.1"`;
  if (r.type !== "network.tulpa.audit_query_response") return `type must be "network.tulpa.audit_query_response"`;
  if (typeof r.serviceDid !== "string" || r.serviceDid.length === 0) return "serviceDid missing";
  if (typeof r.messageId !== "string" || r.messageId.length === 0) return "messageId missing";
  if (typeof r.requester !== "string" || r.requester.length === 0) return "requester missing";
  if (typeof r.timestamp !== "string" || r.timestamp.length === 0) return "timestamp missing";
  if (typeof r.serviceSignature !== "string" || r.serviceSignature.length === 0) return "serviceSignature missing";
  if (!Number.isInteger(r.treeSize) || r.treeSize < 0) return "treeSize must be a non-negative integer";
  if (typeof r.rootHash !== "string" || !/^[0-9a-f]{64}$/.test(r.rootHash)) {
    return "rootHash must be 64 lowercase hex chars";
  }
  if (!Array.isArray(r.events)) return "events must be an array";
  if (!Array.isArray(r.proofs)) return "proofs must be an array";
  // Empty-log case: a fresh witness can sign treeSize=0 with the
  // canonical empty-tree root and zero events/proofs. Any other shape
  // at treeSize=0 is the witness fabricating a state.
  if (r.treeSize === 0) {
    if (r.events.length !== 0) return "treeSize=0 response must have empty events";
    if (r.proofs.length !== 0) return "treeSize=0 response must have empty proofs";
    if (r.rootHash !== EMPTY_TREE_ROOT) return "treeSize=0 response must have the empty-tree rootHash";
  }
  for (const e of r.events) {
    if (e === null || typeof e !== "object") return "every event must be an object";
    if (typeof (e as { id?: unknown }).id !== "string") return "every event must have a string id";
    const agentSig = (e as { agentSignature?: unknown }).agentSignature;
    if (typeof agentSig !== "string" || agentSig.length === 0) {
      return "every event must include a non-empty agentSignature";
    }
  }
  for (const p of r.proofs) {
    if (p === null || typeof p !== "object") return "every proof must be an object";
    if (typeof p.eventId !== "string" || p.eventId.length === 0) return "every proof must have an eventId";
    if (!Number.isInteger(p.leafIndex) || p.leafIndex < 0) return "every proof.leafIndex must be a non-negative integer";
    if (p.leafIndex >= r.treeSize) return "every proof.leafIndex must be < treeSize";
    if (!Array.isArray(p.inclusionProof)) return "every proof.inclusionProof must be an array";
    if (p.inclusionProof.length > MAX_PROOF_LENGTH) {
      return `proof.inclusionProof exceeds max length of ${MAX_PROOF_LENGTH} entries`;
    }
    for (const h of p.inclusionProof) {
      if (typeof h !== "string" || !/^[0-9a-f]{64}$/.test(h)) {
        return "every inclusionProof entry must be 64 lowercase hex chars";
      }
    }
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
