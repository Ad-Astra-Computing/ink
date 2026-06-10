/**
 * INK Checkpoint formatting (C2SP tlog-checkpoint compatible).
 * Used for the public checkpoint endpoint (INK Auditability §7.7).
 */

import * as ed from "@noble/ed25519";
import { base64urlDecode } from "../crypto/ink.js";

export interface CheckpointData {
  origin: string;
  treeSize: number;
  rootHash: string;
}

/**
 * Format a checkpoint body per C2SP tlog-checkpoint spec:
 *   line 1: origin (log identity)
 *   line 2: tree size (decimal)
 *   line 3: root hash (hex)
 *   line 4: empty (trailing newline)
 */
export function formatCheckpoint(data: CheckpointData): string {
  return `${data.origin}\n${data.treeSize}\n${data.rootHash}\n`;
}

/** Maximum input size for parseCheckpoint. A real checkpoint is:
 *   origin (up to ~256 chars) + "\n" + treeSize (up to 16 chars) + "\n"
 *   + rootHash (exactly 64 chars) + "\n" + final "" => ≤ ~340 chars.
 * 1024 leaves comfortable headroom while bounding the body cap so a
 * caller that hands us an attacker-controlled checkpoint blob can't
 * force String.split / regex / parseInt to scan megabytes before
 * rejecting. The 256-char per-line cap below is defense-in-depth. */
const MAX_CHECKPOINT_BODY = 1024;
const MAX_CHECKPOINT_LINE = 256;

/** Parse a checkpoint body. Returns null if invalid. */
export function parseCheckpoint(body: string): CheckpointData | null {
  // Reject oversized input BEFORE String.split allocates a partition
  // array. A caller that fetches a checkpoint from an attacker-
  // controlled witness should not pay megabyte allocation costs to
  // discover it is malformed.
  if (typeof body !== "string" || body.length === 0 || body.length > MAX_CHECKPOINT_BODY) {
    return null;
  }
  const lines = body.split("\n");
  // Expect exactly: origin, treeSize, rootHash, trailing newline (produces 4 parts).
  // Strict equality (=== 4) rejects bodies with extra trailing junk or
  // additional blank lines, eliminating parser differential with stricter
  // verifiers (e.g. C2SP tlog-checkpoint reference implementations).
  if (lines.length !== 4) return null;
  // The 4th part is the empty string after the final newline.
  if (lines[3] !== "") return null;

  const origin = lines[0]!;
  const treeSizeLine = lines[1]!;
  const rootHash = lines[2]!;

  // Per-line caps: each line must fit the per-line bound BEFORE its
  // regex or parseInt scan. Without this, a single huge line that
  // still split into the right number of parts could force regex
  // catastrophic-backtracking-class work pre-reject.
  if (origin.length > MAX_CHECKPOINT_LINE) return null;
  if (treeSizeLine.length > MAX_CHECKPOINT_LINE) return null;
  if (rootHash.length > MAX_CHECKPOINT_LINE) return null;

  // Origin must be non-empty
  if (!origin) return null;

  // Tree size must be a non-negative safe integer with no trailing junk
  if (!/^\d+$/.test(treeSizeLine)) return null;
  const treeSize = parseInt(treeSizeLine, 10);
  if (isNaN(treeSize) || treeSize < 0 || treeSize > Number.MAX_SAFE_INTEGER) return null;

  // Root hash must be exactly 64 lowercase hex chars
  if (!/^[0-9a-f]{64}$/.test(rootHash)) return null;

  return { origin, treeSize, rootHash };
}

/** A signed checkpoint is the 3-line body, a blank line, then one or more
 *  signature lines, plus a trailing newline. Bound the whole thing so an
 *  attacker-supplied blob cannot drive large scans before rejection. */
const MAX_SIGNED_CHECKPOINT_BODY = 4096;
/** Cap the number of cosignature lines a verifier will scan. */
const MAX_CHECKPOINT_SIGNATURES = 8;

/**
 * Verify a signed checkpoint and return its parsed body, or `null` if the
 * signature, origin, or format is invalid.
 *
 * The signed form is the C2SP-style note used by the INK witness:
 *
 *   <origin>\n<treeSize>\n<rootHash>\n\n-- <origin> <base64url(sig)>\n
 *
 * The Ed25519 signature covers the body bytes `<origin>\n<treeSize>\n<rootHash>`
 * exactly (no trailing newline), so the `origin` first line is the domain
 * separator binding the signed bytes to this log. Verification REQUIRES the
 * caller's `expectedOrigin`: a checkpoint whose body origin, or whose matching
 * signature-line origin, is not `expectedOrigin` is rejected, so a witness that
 * operates several logs (or an attacker replaying another log's signed
 * checkpoint) cannot substitute a different tree. This is the authenticated
 * input that anti-rollback / freshness checks MUST consume; an unverified
 * checkpoint body provides no security.
 *
 * Verification uses RFC 8032 strict mode (small-order keys rejected).
 */
export async function verifyCheckpoint(
  signed: string,
  witnessPublicKey: Uint8Array,
  expectedOrigin: string,
): Promise<CheckpointData | null> {
  if (typeof signed !== "string" || signed.length === 0 || signed.length > MAX_SIGNED_CHECKPOINT_BODY) {
    return null;
  }
  if (!(witnessPublicKey instanceof Uint8Array) || witnessPublicKey.length !== 32) {
    return null;
  }
  if (typeof expectedOrigin !== "string" || expectedOrigin.length === 0 || expectedOrigin.length > MAX_CHECKPOINT_LINE) {
    return null;
  }
  const SEP = "\n\n-- ";
  const idx = signed.indexOf(SEP);
  if (idx === -1) return null;
  const body = signed.slice(0, idx); // <origin>\n<treeSize>\n<rootHash>
  const data = parseCheckpoint(body + "\n");
  if (!data) return null;
  // Bind the body's own origin to the caller's expectation before any crypto.
  if (data.origin !== expectedOrigin) return null;

  // Signature block starts at the "-- " that began the separator.
  const sigBlock = signed.slice(idx + 2);
  const sigLines = sigBlock.split("\n").filter((l) => l.length > 0);
  if (sigLines.length === 0 || sigLines.length > MAX_CHECKPOINT_SIGNATURES) return null;
  const bodyBytes = new TextEncoder().encode(body);
  for (const line of sigLines) {
    if (!line.startsWith("-- ")) return null; // any malformed signature line is fatal
    const rest = line.slice(3);
    const sp = rest.indexOf(" ");
    if (sp === -1) return null;
    const lineOrigin = rest.slice(0, sp);
    const sigB64 = rest.slice(sp + 1);
    if (lineOrigin !== expectedOrigin) continue; // a cosigner whose key we were not given
    try {
      const sig = base64urlDecode(sigB64);
      if (sig.length !== 64) return null;
      const ok = await ed.verifyAsync(sig, bodyBytes, witnessPublicKey, { zip215: false });
      return ok ? data : null; // a matching-origin signature that fails verification is fatal
    } catch {
      return null;
    }
  }
  return null; // no signature line for the expected origin
}
