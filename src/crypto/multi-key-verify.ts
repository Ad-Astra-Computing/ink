import { verifyInkSignature, type InkSignInput } from "./ink.js";
import { parseInkTimestampMs } from "./timestamp.js";
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
 *   - Window strings that are not strict RFC 3339 timestamps (parseInkTimestampMs
 *     returns null) also fail closed for the same reason.
 */
export function isKeyValidAtTime(key: CandidateKey, messageMs: number): boolean {
  // Any field that is PRESENT but not a non-empty parseable datetime
  // string is treated as malformed and fails closed. "Present" means
  // !== undefined, so a `null`, number, object, or empty string here
  // is a misuse — refusing it stops a custom resolveKeySet that maps a
  // DB NULL to "" (or to literal null) from looking like "no window".
  const isPresent = (x: unknown): boolean => x !== undefined;

  if (isPresent(key.revokedAt)) {
    // revokedAt present at all is a "do not verify" signal regardless
    // of whether the value parses. A revoked key with an unparseable
    // revokedAt is still revoked.
    return false;
  }
  // Window bounds are parsed with the strict RFC 3339 / millisecond grammar
  // shared across implementations, so a present-but-malformed or lenient
  // (date-only, no-zone) bound fails closed and is read identically everywhere.
  if (isPresent(key.validFrom)) {
    const from = parseInkTimestampMs(key.validFrom);
    if (from === null) return false;
    if (messageMs < from) return false;
  }
  if (isPresent(key.validUntil)) {
    const until = parseInkTimestampMs(key.validUntil);
    if (until === null) return false;
    if (messageMs > until) return false;
  }
  return true;
}

/**
 * Verify a detached signature against a set of candidate keys. This is the
 * artifact-agnostic policy primitive behind every `...WithKeys` verifier in
 * this package: it knows nothing about the artifact's shape, only the
 * rotation rules that govern which key is allowed to have produced the
 * signature over it.
 *
 * Verification order per spec §6.4:
 *   1. Hinted key (if provided and found) — optimization for keyId header
 *   2. Active keys first
 *   3. Retired keys second
 *   4. Revoked keys are always skipped
 *
 * In all three cases the key's `[validFrom, validUntil]` window MUST
 * contain the artifact timestamp. A key that has expired (validUntil in
 * the past) or is not yet valid (validFrom in the future) is skipped
 * even if its status would otherwise admit it. This closes the window
 * where an attacker who steals an expired key, even one still listed
 * as "retired" for historical verification, could sign fresh artifacts.
 *
 * `verifyWithKey` is supplied by the caller and closes over the specific
 * artifact and signature; it need only answer "does this raw public key
 * verify the artifact". Returns the matching keyId and keyStatus on success.
 */
export async function verifyDetachedSignatureWithKeys(
  verifyWithKey: (publicKey: Uint8Array) => Promise<boolean>,
  keys: CandidateKey[],
  artifactMs: number,
  hintKeyId?: string,
): Promise<MultiKeyVerifyResult> {
  if (!Array.isArray(keys) || keys.length === 0) {
    return { verified: false };
  }
  if (typeof artifactMs !== "number" || !Number.isFinite(artifactMs)) {
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
    if (hinted && isKeyValidAtTime(hinted, artifactMs)) {
      try {
        const valid = await verifyWithKey(hinted.publicKey);
        if (valid) return { verified: true, keyId: hinted.keyId, keyStatus: hinted.status, usedRetiredKey: hinted.status === "retired" };
      } catch {
        // Fall through to normal iteration
      }
    }
  }

  // Partition by status: active first, then retired. Skip revoked.
  // Drop any candidate whose validity window doesn't contain the
  // artifact timestamp before reaching the verify loop.
  const active = bounded.filter((k) => k.status === "active" && isKeyValidAtTime(k, artifactMs));
  const retired = bounded.filter((k) => k.status === "retired" && isKeyValidAtTime(k, artifactMs));

  // Try active keys first
  for (const key of active) {
    // Skip if already tried as hint
    if (hintKeyId && key.keyId === hintKeyId) continue;
    try {
      const valid = await verifyWithKey(key.publicKey);
      if (valid) return { verified: true, keyId: key.keyId, keyStatus: key.status, usedRetiredKey: false };
    } catch {
      // Key failed verification, try next
    }
  }

  // Try retired keys
  for (const key of retired) {
    if (hintKeyId && key.keyId === hintKeyId) continue;
    try {
      const valid = await verifyWithKey(key.publicKey);
      if (valid) return { verified: true, keyId: key.keyId, keyStatus: key.status, usedRetiredKey: true };
    } catch {
      // Key failed verification, try next
    }
  }

  return { verified: false };
}

/**
 * Verify an INK signature against a set of candidate keys. Thin wrapper
 * over `verifyDetachedSignatureWithKeys`: parses `input.timestamp` into
 * the artifact clock and closes over `verifyInkSignature` for the actual
 * cryptographic check. The rotation policy itself lives in exactly one
 * place, `verifyDetachedSignatureWithKeys`, so this function must not
 * grow its own copy of the ordering/window logic.
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
  if (typeof signature !== "string") {
    return { verified: false };
  }

  // Parse the message timestamp once so window checks are O(1) per key.
  // parseInkTimestampMs caps length and applies the strict RFC 3339 grammar, so
  // a non-string, empty, oversized, or non-conforming timestamp all fail closed
  // here even though verifyInkAuth already guards upstream.
  const messageMs = parseInkTimestampMs(input.timestamp);
  if (messageMs === null) {
    return { verified: false };
  }

  return verifyDetachedSignatureWithKeys(
    (publicKey) => verifyInkSignature(input, signature, publicKey),
    keys,
    messageMs,
    hintKeyId,
  );
}
