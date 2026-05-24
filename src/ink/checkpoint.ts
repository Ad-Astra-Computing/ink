/**
 * INK Checkpoint formatting (C2SP tlog-checkpoint compatible).
 * Used for the public checkpoint endpoint (INK Auditability §7.7).
 */

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
