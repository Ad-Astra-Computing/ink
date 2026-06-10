import { verifyInkSignature, type InkSignInput, MAX_TIMESTAMP_AGE_MS, MAX_FUTURE_TIMESTAMP_MS } from "../crypto/ink.js";
import { extractPublicKeyFromAgentId, canonicalAgentPrincipal } from "../crypto/keys.js";
import { verifyInkSignatureWithKeys } from "../crypto/multi-key-verify.js";
import type { CandidateKey, KeyStatus } from "../models/key-entry.js";

/**
 * Pluggable nonce-record interface. The middleware uses this to enforce
 * single-use semantics on body.nonce so a captured-and-replayed request
 * is rejected even within the timestamp freshness window.
 */
export interface NonceStore {
  has(nonce: string): boolean | Promise<boolean>;
  add(nonce: string): void | Promise<void>;
}

/**
 * Parse and verify an INK-Ed25519 Authorization header.
 *
 * The spec (§3.3) defines request signing as:
 *   Authorization: INK-Ed25519 <base64url(sig)>
 *
 * Signature base: ink/0.1\nMETHOD\nPATH\nrecipientDid\nJCS(body)\ntimestamp
 *
 * The body must contain `from` (sender DID/agentId — used to resolve the public key)
 * and `timestamp` (used in the signature base).
 *
 * Also enforces timestamp freshness per §3.5:
 * - Rejects timestamps older than 5 minutes
 * - Rejects timestamps more than 30 seconds in the future
 *
 * Key resolution order:
 * 1. resolveKeySet (multi-key, if provided and returns candidates)
 * 2. resolvePublicKey (single-key from connection store)
 * 3. extractPublicKeyFromAgentId (bootstrap fallback — only when no key set exists)
 */
export async function verifyInkAuth(opts: {
  authHeader: string | undefined;
  method: string;
  path: string;
  recipientAgentId: string;
  body: Record<string, unknown>;
  resolvePublicKey?: (agentId: string) => Uint8Array | null;
  resolveKeySet?: (agentId: string) => CandidateKey[] | null;
  /**
   * When true, signatures that only verify against a retired key are
   * rejected with `retired_key_for_live_auth`. Defaults to false so the
   * middleware stays spec-conformant (active OR retired during rotation
   * grace per the authority rule) but lets callers opt into the stricter
   * policy for endpoints that should never accept a possibly-stolen
   * retired key. Bootstrap and single-key (resolvePublicKey) verification
   * paths are unaffected because they do not have status metadata.
   */
  requireActiveKey?: boolean;
  /**
   * Single-use nonce enforcement. Required (fail-closed) because the
   * 5-minute freshness window otherwise allows a captured signed request
   * to replay. Pass a NonceStore to have the middleware check+record
   * body.nonce, or pass the literal "deferred" to explicitly take
   * responsibility for calling `checkReplay` (or equivalent) in the
   * caller's own request pipeline. Omitting this option returns
   * `nonce_handling_required` so misconfigured production deployments
   * fail loudly.
   */
  nonceStore: NonceStore | "deferred";
}): Promise<
  // `senderAgentId` is the raw, sender-chosen spelling (useful for audit and
  // display). `principal` is the canonical, prefix-independent identity:
  // authorization, block lists, rate limits, and every per-sender abuse
  // control MUST key on `principal`, never on `senderAgentId`, or a sender can
  // switch the tulpa:/ink: prefix to evade them.
  | { valid: true; senderAgentId: string; principal: string; keyId?: string; keyStatus?: KeyStatus }
  | { valid: false; error: string }
> {
  if (typeof opts.authHeader !== "string" || opts.authHeader.length === 0) {
    return { valid: false, error: "missing_authorization" };
  }

  if (opts.body === null || typeof opts.body !== "object" || Array.isArray(opts.body)) {
    return { valid: false, error: "missing_sender" };
  }

  if (opts.authHeader.length > 512) {
    return { valid: false, error: "invalid_auth_scheme" };
  }
  // Ed25519 signatures are exactly 86 base64url chars — tighten the regex to
  // {86} so clearly-wrong lengths get rejected up front, rather than burning
  // CPU on verifyInkSignature for a malformed value.
  const match = opts.authHeader.match(/^INK-Ed25519\s+([A-Za-z0-9_-]{86})(?:\s+keyId=([A-Za-z0-9_:.-]{1,128}))?$/);
  if (!match) {
    return { valid: false, error: "invalid_auth_scheme" };
  }
  const signature = match[1]!;
  const hintKeyId = match[2] ?? undefined;

  const senderDid = opts.body.from;
  if (senderDid !== undefined && typeof senderDid !== "string") {
    return { valid: false, error: "invalid_from_field" };
  }
  if (!senderDid) {
    return { valid: false, error: "missing_sender" };
  }
  // Cap sender DID length before passing to key resolvers and base58 decoding.
  // Real agent IDs are ~50-100 chars; 256 leaves generous headroom while
  // preventing CPU/memory waste on huge attacker-supplied values.
  if (senderDid.length > 256) {
    return { valid: false, error: "invalid_from_field" };
  }

  const timestamp = opts.body.timestamp;
  if (typeof timestamp !== "string" || timestamp.length === 0) {
    return { valid: false, error: "missing_timestamp" };
  }
  // Cap length BEFORE handing to Date.parse. Real ISO 8601 timestamps
  // are ≤ ~30 chars; we cap at 64 (matches buildSignatureBase). Without
  // this, an unauthenticated request with a multi-megabyte timestamp
  // string burns CPU inside the engine's Date parser before the
  // signature ever runs.
  if (timestamp.length > 64) {
    return { valid: false, error: "invalid_timestamp" };
  }

  // Timestamp freshness check (§3.5)
  const msgTime = new Date(timestamp).getTime();
  if (isNaN(msgTime)) {
    return { valid: false, error: "invalid_timestamp" };
  }
  const now = Date.now();
  const drift = msgTime - now;
  if (drift > MAX_FUTURE_TIMESTAMP_MS) {
    return { valid: false, error: "timestamp_too_far_future" };
  }
  if (-drift > MAX_TIMESTAMP_AGE_MS) {
    return { valid: false, error: "timestamp_expired" };
  }

  // Fail-closed nonce policy. Callers must either pass a NonceStore
  // (middleware enforces single-use within the freshness window) or
  // explicitly pass "deferred" (caller commits to calling checkReplay
  // or equivalent in their request pipeline). An omitted/malformed
  // nonceStore returns nonce_handling_required so a production
  // deployment without nonce handling fails loudly rather than
  // silently accepting replays.
  const storeIsObject =
    opts.nonceStore !== "deferred" &&
    opts.nonceStore !== undefined &&
    opts.nonceStore !== null &&
    typeof (opts.nonceStore as NonceStore).has === "function" &&
    typeof (opts.nonceStore as NonceStore).add === "function";
  if (opts.nonceStore !== "deferred" && !storeIsObject) {
    return { valid: false, error: "nonce_handling_required" };
  }
  const usingNonceStore = storeIsObject;
  let bodyNonce: string | undefined;
  if (usingNonceStore) {
    const candidate = opts.body.nonce;
    if (
      typeof candidate !== "string" ||
      candidate.length < 16 ||
      candidate.length > 256 ||
      !/^[A-Za-z0-9_-]+$/.test(candidate)
    ) {
      return { valid: false, error: "missing_nonce" };
    }
    bodyNonce = candidate;
  }

  const input: InkSignInput = {
    method: opts.method,
    path: opts.path,
    recipientDid: opts.recipientAgentId,
    body: opts.body,
    timestamp,
  };

  // Post-verify nonce check+record. Runs only when the caller provided
  // a NonceStore object. Checking after signature verification means a
  // forged request never pollutes the nonce store, but a replay of an
  // authentic signed request is still rejected within the freshness
  // window. Backend errors fail closed.
  async function recordNonce(): Promise<{ ok: true } | { ok: false; error: string }> {
    if (!usingNonceStore) return { ok: true };
    const store = opts.nonceStore as NonceStore;
    const nonce = bodyNonce!;
    let alreadySeen: boolean;
    try {
      alreadySeen = await Promise.resolve(store.has(nonce));
    } catch {
      return { ok: false, error: "nonce_store_error" };
    }
    if (alreadySeen) return { ok: false, error: "nonce_replay" };
    try {
      await Promise.resolve(store.add(nonce));
    } catch {
      return { ok: false, error: "nonce_store_error" };
    }
    return { ok: true };
  }

  // Try multi-key verification first (Phase 1 key rotation support).
  // If the agent has published a key set, it is authoritative: we must NOT
  // fall through to resolvePublicKey or the bootstrap derivation, because
  // either could surface a key (retired/revoked or stale conn-stored) that
  // was already rejected — or deliberately excluded — from the key set.
  if (opts.resolveKeySet) {
    const candidates = opts.resolveKeySet(senderDid);
    // null/undefined = no key set published for this agent → fall through to bootstrap.
    // Empty array = key set exists but no usable signing keys (e.g. all revoked) →
    // authoritative reject. Falling through here would let an attacker with the
    // bootstrap-derived key authenticate even after the agent has revoked it.
    if (candidates !== null && candidates !== undefined) {
      if (candidates.length === 0) {
        return { valid: false, error: "signature_verification_failed" };
      }
      try {
        const result = await verifyInkSignatureWithKeys(input, signature, candidates, hintKeyId);
        if (result.verified) {
          // Local-policy gate: a retired key still verifies per the spec's
          // authority rule, but a caller that runs sensitive endpoints
          // (writes, capability grants, etc.) can require an active key.
          // This closes the "stolen retired key signs a fresh message"
          // window: even though the spec allows retired keys for grace,
          // callers don't have to.
          if (opts.requireActiveKey && result.keyStatus === "retired") {
            return { valid: false, error: "retired_key_for_live_auth" };
          }
          const noncePass = await recordNonce();
          if (!noncePass.ok) return { valid: false, error: noncePass.error };
          return {
            valid: true,
            senderAgentId: senderDid,
            principal: canonicalAgentPrincipal(senderDid),
            keyId: result.keyId,
            keyStatus: result.keyStatus,
          };
        }
      } catch { /* treated as verification failure below */ }
      // Authoritative key set rejected the signature — do not fall back.
      return { valid: false, error: "signature_verification_failed" };
    }
  }

  // No key set published yet — first-contact / bootstrap path.
  let publicKey: Uint8Array | null = null;
  if (opts.resolvePublicKey) {
    publicKey = opts.resolvePublicKey(senderDid);
  }
  if (!publicKey) {
    try {
      publicKey = extractPublicKeyFromAgentId(senderDid);
    } catch {
      return { valid: false, error: "unresolvable_sender_key" };
    }
  }
  if (!publicKey) {
    return { valid: false, error: "unresolvable_sender_key" };
  }

  try {
    const valid = await verifyInkSignature(input, signature, publicKey);
    if (!valid) {
      return { valid: false, error: "invalid_signature" };
    }
    const noncePass = await recordNonce();
    if (!noncePass.ok) return { valid: false, error: noncePass.error };
    return { valid: true, senderAgentId: senderDid, principal: canonicalAgentPrincipal(senderDid) };
  } catch {
    return { valid: false, error: "signature_verification_failed" };
  }
}
