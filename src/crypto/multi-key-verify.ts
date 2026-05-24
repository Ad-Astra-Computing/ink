import { verifyInkSignature, type InkSignInput } from "./ink.js";
import type { CandidateKey, KeyStatus } from "../models/key-entry.js";

export interface MultiKeyVerifyResult {
  verified: boolean;
  keyId?: string;
  /** Status of the key that verified the signature (for observability). */
  keyStatus?: KeyStatus;
  /** True when the signature was verified using a retired key. Callers should track this for key rotation observability. */
  usedRetiredKey?: boolean;
}

/** Maximum number of candidate keys tried during multi-key verification.
 * Prevents a poisoned Agent Card from forcing O(n) Ed25519 verifications. */
const MAX_CANDIDATE_KEYS = 20;

/**
 * Check whether a candidate key's validity window contains a given
 * message timestamp. Returns true when the key is usable. Both window
 * endpoints are optional; missing endpoints are treated as open (so a
 * key with no validFrom is usable arbitrarily far back, and a key with
 * no validUntil is usable arbitrarily far forward — preserving the
 * legacy behaviour for callers that don't track windows).
 *
 * Defense in depth at the verifier:
 *   - status === "revoked" is already filtered upstream; this function
 *     ALSO refuses any key whose `revokedAt` field is present, in case
 *     a caller forgot to set status.
 *   - Non-string OR empty-string window fields are treated as malformed
 *     and fail closed. An integrator that maps a NULL/blank database
 *     column to "" must not get the same behaviour as "field absent" —
 *     that would let an expired key slip through under the legacy
 *     "no window = open" rule. The matching boundary check lives in
 *     extractCandidateKeys; this guard catches custom resolveKeySet
 *     implementations that bypass that boundary.
 *   - Malformed timestamp strings (Date.parse returns NaN) also fail
 *     closed for the same reason.
 */
function isKeyValidAtTime(key: CandidateKey, messageMs: number): boolean {
  // Any field that is PRESENT but not a non-empty parseable datetime
  // string is treated as malformed and fails closed. "Present" means
  // !== undefined, so a `null`, number, object, or empty string here
  // is a misuse — refusing it stops a custom resolveKeySet that maps a
  // DB NULL to "" (or to literal null) from looking like "no window".
  const isPresent = (x: unknown): boolean => x !== undefined;
  // Cap length BEFORE Date.parse — a multi-megabyte string would
  // otherwise burn CPU in the date parser before the parse failure.
  // 64 chars matches the cap used everywhere else in INK (ISO 8601
  // with subsecond + timezone fits in ~30; 64 leaves headroom).
  const isValidDatetimeString = (x: unknown): x is string =>
    typeof x === "string" && x.length > 0 && x.length <= 64 && Number.isFinite(Date.parse(x));

  if (isPresent(key.revokedAt)) {
    // revokedAt present at all is a "do not verify" signal regardless
    // of whether the value parses. A revoked key with an unparseable
    // revokedAt is still revoked.
    return false;
  }
  if (isPresent(key.validFrom)) {
    if (!isValidDatetimeString(key.validFrom)) return false;
    if (messageMs < Date.parse(key.validFrom)) return false;
  }
  if (isPresent(key.validUntil)) {
    if (!isValidDatetimeString(key.validUntil)) return false;
    if (messageMs > Date.parse(key.validUntil)) return false;
  }
  return true;
}

/**
 * Verify an INK signature against a set of candidate keys.
 *
 * Verification order per spec §6.4:
 *   1. Hinted key (if provided and found) — optimization for keyId header
 *   2. Active keys first
 *   3. Retired keys second
 *   4. Revoked keys are always skipped
 *
 * In all three cases the key's `[validFrom, validUntil]` window MUST
 * contain the message timestamp. A key that has expired (validUntil in
 * the past) or is not yet valid (validFrom in the future) is skipped
 * even if its status would otherwise admit it. This closes the window
 * where an attacker who steals an expired key — even one still listed
 * as "retired" for historical verification — could sign fresh messages.
 *
 * Returns the matching keyId and keyStatus on success.
 */
export async function verifyInkSignatureWithKeys(
  input: InkSignInput,
  signature: string,
  keys: CandidateKey[],
  hintKeyId?: string,
): Promise<MultiKeyVerifyResult> {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return { verified: false };
  }
  if (!Array.isArray(keys) || keys.length === 0) {
    return { verified: false };
  }
  if (typeof signature !== "string") {
    return { verified: false };
  }

  // Parse the message timestamp once so window checks are O(1) per key.
  // verifyInkAuth caps timestamp length upstream, but this helper is
  // exported, so guard locally too: a non-string, empty, oversized, or
  // non-parseable timestamp all fail closed. The 64-char cap stops a
  // multi-megabyte string from reaching Date.parse.
  if (typeof input.timestamp !== "string" || input.timestamp.length === 0 || input.timestamp.length > 64) {
    return { verified: false };
  }
  const messageMs = Date.parse(input.timestamp);
  if (!Number.isFinite(messageMs)) {
    return { verified: false };
  }

  // Enforce an upper bound on key set size to prevent DoS via poisoned Agent Cards
  // that contain hundreds of keys, forcing that many Ed25519 operations per request.
  const bounded = keys.slice(0, MAX_CANDIDATE_KEYS);

  // Try hinted key first if provided.
  // Allowlist of acceptable statuses. A deny-list (k.status !== "revoked") would
  // accept entries with malformed/unrecognised status — e.g. case-mismatched
  // "Revoked" or empty string would slip past here while being skipped by the
  // active/retired partition iteration below.
  if (hintKeyId) {
    const hinted = bounded.find(
      (k) => k.keyId === hintKeyId && (k.status === "active" || k.status === "retired"),
    );
    if (hinted && isKeyValidAtTime(hinted, messageMs)) {
      try {
        const valid = await verifyInkSignature(input, signature, hinted.publicKey);
        if (valid) return { verified: true, keyId: hinted.keyId, keyStatus: hinted.status, usedRetiredKey: hinted.status === "retired" };
      } catch {
        // Fall through to normal iteration
      }
    }
  }

  // Partition by status: active first, then retired. Skip revoked.
  // Drop any candidate whose validity window doesn't contain the
  // message timestamp before reaching the verify loop.
  const active = bounded.filter((k) => k.status === "active" && isKeyValidAtTime(k, messageMs));
  const retired = bounded.filter((k) => k.status === "retired" && isKeyValidAtTime(k, messageMs));

  // Try active keys first
  for (const key of active) {
    // Skip if already tried as hint
    if (hintKeyId && key.keyId === hintKeyId) continue;
    try {
      const valid = await verifyInkSignature(input, signature, key.publicKey);
      if (valid) return { verified: true, keyId: key.keyId, keyStatus: key.status, usedRetiredKey: false };
    } catch {
      // Key failed verification, try next
    }
  }

  // Try retired keys
  for (const key of retired) {
    if (hintKeyId && key.keyId === hintKeyId) continue;
    try {
      const valid = await verifyInkSignature(input, signature, key.publicKey);
      if (valid) return { verified: true, keyId: key.keyId, keyStatus: key.status, usedRetiredKey: true };
    } catch {
      // Key failed verification, try next
    }
  }

  return { verified: false };
}
