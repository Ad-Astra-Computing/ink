/**
 * INK Checkpoint formatting (C2SP-shaped, not wire-compatible).
 * Used for the public checkpoint endpoint (INK Auditability §7.7).
 *
 * The line structure and field order follow C2SP tlog-checkpoint, but this
 * is not an implementation of that spec and no C2SP tool can consume these
 * bytes. Known divergences: the root hash is lowercase hex here, C2SP uses
 * base64; the cosignature separator is the ASCII string "-- ", C2SP notes
 * use an em dash; signatures here are a bare base64url(64 bytes), C2SP
 * prepends a 4-byte key-hint. A real C2SP profile, negotiated and additive,
 * is out of scope for this format.
 */

import { base64urlDecode } from "../crypto/ink.js";
import { verifyDetachedSignatureWithKeys, type MultiKeyVerifyResult } from "../crypto/multi-key-verify.js";
import type { CandidateKey } from "../models/key-entry.js";
import { verifyStrictEd25519 } from "../crypto/ed25519-strict.js";

export interface CheckpointData {
  origin: string;
  treeSize: number;
  rootHash: string;
}

/**
 * Format a checkpoint body:
 *   line 1: origin (log identity)
 *   line 2: tree size (decimal, no leading zero)
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

/**
 * Bytes a fetcher MUST cap a checkpoint response at before decoding it to a
 * string. MAX_CHECKPOINT_BODY and MAX_CHECKPOINT_LINE are measured in UTF-16
 * code units, which undercounts a multi-byte UTF-8 origin on the wire; this
 * constant bounds the actual network payload a consumer reads. It is not
 * enforced by this module (there is no network fetch here), it exists for a
 * consumer to import and apply at its own fetch site.
 */
export const MAX_CHECKPOINT_WIRE_BYTES = 4096;

/** Characters forbidden anywhere in a checkpoint origin: C0 controls, DEL,
 *  C1 controls, and U+002B '+' (which would be ambiguous against a
 *  percent-encoded origin in an operator's configuration). */
const CHECKPOINT_ORIGIN_FORBIDDEN_CHARS = /[\u0000-\u001F\u007F-\u009F+]/;
/** Any Unicode White_Space code point. Banning whitespace keeps the
 *  "-- <origin> <sig>" first-space split in verifyCheckpointCore
 *  unambiguous: an origin can never itself contain the character the
 *  signature-line grammar uses as a delimiter. */
const CHECKPOINT_ORIGIN_WHITESPACE = /\p{White_Space}/u;
/** A high surrogate not followed by its low surrogate, or a low surrogate
 *  not preceded by its high surrogate: a lone (unpaired) surrogate, which
 *  has no valid UTF-8 encoding. Go's side of this grammar enforces the
 *  equivalent rule via utf8.ValidString, since a Go string is arbitrary
 *  bytes with no such guarantee either. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Whether `origin` is a well-formed checkpoint origin: a well-formed
 * Unicode string (no lone surrogate), non-empty, at most 256 UTF-16 code
 * units, with no C0/C1 control character, DEL, '+', or Unicode whitespace.
 * Applied to both an origin read out of a parsed checkpoint body and a
 * caller-supplied expectedOrigin, so the same grammar governs what a
 * checkpoint may claim and what a verifier may be configured to expect. A
 * witness or verifier SHOULD apply this to its own configured origin at
 * startup and fail construction rather than accept or reject checkpoints
 * unpredictably at request time (see go/ink/witnesslog.go's NewWitnessLog
 * for the Go-side witness-construction instance of this).
 */
export function isValidCheckpointOrigin(origin: unknown): origin is string {
  if (typeof origin !== "string") return false;
  if (origin.length === 0 || origin.length > MAX_CHECKPOINT_LINE) return false;
  if (LONE_SURROGATE.test(origin)) return false;
  if (CHECKPOINT_ORIGIN_FORBIDDEN_CHARS.test(origin)) return false;
  if (CHECKPOINT_ORIGIN_WHITESPACE.test(origin)) return false;
  return true;
}

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

  // Origin must satisfy the checkpoint origin grammar.
  if (!isValidCheckpointOrigin(origin)) return null;

  // Tree size must be a non-negative safe integer with no trailing junk
  // and no leading zero: "007" and "7" are different byte strings, and
  // permitting both to parse to the same value would make the body's
  // canonical serialization ambiguous. "0" itself is the one single-digit
  // form and is always valid.
  if (!/^(0|[1-9]\d*)$/.test(treeSizeLine)) return null;
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
 * Shared parsing, origin binding, and signature-line walk for a signed
 * checkpoint note. `trySignature` is called once, with the decoded
 * signature bytes and the exact signed body bytes, for the one signature
 * line whose origin matches `expectedOrigin`; its result decides the
 * outcome. `verifyCheckpoint` and `verifyCheckpointWithKeys` differ only in
 * how that one signature is checked, so both delegate here.
 */
async function verifyCheckpointCore(
  signed: string,
  expectedOrigin: string,
  trySignature: (sig: Uint8Array, bodyBytes: Uint8Array) => Promise<MultiKeyVerifyResult>,
): Promise<CheckpointVerifyWithKeysResult> {
  if (typeof signed !== "string" || signed.length === 0 || signed.length > MAX_SIGNED_CHECKPOINT_BODY) {
    return null;
  }
  if (!isValidCheckpointOrigin(expectedOrigin)) {
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
    let sig: Uint8Array;
    try {
      sig = base64urlDecode(sigB64);
    } catch {
      return null;
    }
    if (sig.length !== 64) return null;
    let result: MultiKeyVerifyResult;
    try {
      result = await trySignature(sig, bodyBytes);
    } catch {
      return null;
    }
    if (!result.verified) return null; // a matching-origin signature that fails verification is fatal
    return result.keyId !== undefined
      ? { ...data, keyId: result.keyId, keyStatus: result.keyStatus, usedRetiredKey: result.usedRetiredKey }
      : data;
  }
  return null; // no signature line for the expected origin
}

/**
 * Verify a signed checkpoint and return its parsed body, or `null` if the
 * signature, origin, or format is invalid.
 *
 * The signed form is the note used by the INK witness, C2SP-shaped but not
 * wire-compatible with it (see the module header):
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
  if (!(witnessPublicKey instanceof Uint8Array) || witnessPublicKey.length !== 32) {
    return null;
  }
  return verifyCheckpointCore(signed, expectedOrigin, async (sig, bodyBytes) => {
    const ok = await verifyStrictEd25519(sig, bodyBytes, witnessPublicKey);
    return { verified: ok };
  });
}

export type CheckpointVerifyWithKeysResult = (CheckpointData & Partial<MultiKeyVerifyResult>) | null;

/**
 * Verify a signed checkpoint against a rotation-aware candidate witness key
 * set (spec §6.2/§12.1/§12.3). A checkpoint note carries no intrinsic
 * timestamp of its own, it commits only to (origin, treeSize, rootHash), so
 * the caller MUST supply `artifactMs` explicitly: typically the time the
 * checkpoint was fetched, or a timestamp pinned out of band. A non-finite
 * `artifactMs` fails closed.
 *
 * Preserves every other behavior of `verifyCheckpoint` exactly, including
 * the origin-matching rule: the checkpoint body's own origin, and the
 * origin on the one signature line tried, must both equal `expectedOrigin`.
 * Only that origin-matching signature line's candidates are tried; a
 * matching-origin line that no candidate key verifies is fatal, mirroring
 * the single-key verifier's "no fallback to a later line" behavior.
 */
export async function verifyCheckpointWithKeys(
  signed: string,
  keys: CandidateKey[],
  expectedOrigin: string,
  artifactMs: number,
  hintKeyId?: string,
): Promise<CheckpointVerifyWithKeysResult> {
  return verifyCheckpointCore(signed, expectedOrigin, (sig, bodyBytes) =>
    verifyDetachedSignatureWithKeys(
      (publicKey) => verifyStrictEd25519(sig, bodyBytes, publicKey),
      keys,
      artifactMs,
      hintKeyId,
    ),
  );
}
