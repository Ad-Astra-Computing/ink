import { verifyInkSignature, type InkSignInput, MAX_TIMESTAMP_AGE_MS, MAX_FUTURE_TIMESTAMP_MS } from "../crypto/ink.js";
import { isSignableBody, type SignableBody } from "../crypto/sign.js";
import { parseInkTimestampMs } from "../crypto/timestamp.js";
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
  /**
   * Optional atomic check-and-record. Returns true if the nonce was newly
   * recorded (accept) or false if it was already present (replay). When a
   * store provides this, the middleware uses it INSTEAD of the separate
   * has()+add() calls, which have a check-then-act race: on a distributed or
   * async store, two concurrent replays of one signed request can both
   * observe "not seen" before either records it, defeating single-use. A
   * distributed store SHOULD implement this atomically (a conditional put,
   * `INSERT ... ON CONFLICT DO NOTHING`, or `SET key val NX`).
   *
   * Retention: a store MUST retain a recorded nonce for at least the message
   * freshness window (`MAX_TIMESTAMP_AGE_MS`, 5 minutes). Evicting sooner
   * reopens the replay this is meant to close.
   */
  addIfAbsent?(nonce: string): boolean | Promise<boolean>;
}

/**
 * The INK-Ed25519 Authorization header grammar (spec §3.3):
 *
 *   INK-Ed25519 <base64url(signature)> [keyId=<keyId>]
 *
 * The signature is exactly 86 base64url characters (a 64-byte Ed25519 signature,
 * no padding). The optional keyId parameter is 1-128 characters from
 * `[A-Za-z0-9_:.-]`, which excludes spaces and CR/LF so the value cannot inject a
 * header boundary. Single literal spaces (never `\s`) match the exact bytes
 * `buildAuthHeader` emits and keep CR/LF/TAB out of a parsed value. This is the
 * one regex; `parseInkAuthHeader` and `verifyInkAuth` both use it, and the Go
 * `ParseInkAuthHeader` mirrors it byte for byte.
 */
export const INK_AUTH_HEADER_RE = /^INK-Ed25519 ([A-Za-z0-9_-]{86})(?: keyId=([A-Za-z0-9_:.-]{1,128}))?$/;

/** The outcome of parsing an INK-Ed25519 Authorization header value. */
export type InkAuthHeaderParse =
  | { ok: true; signature: string; keyId?: string }
  | { ok: false; reason: "missing_authorization" | "invalid_auth_scheme" };

/**
 * Parse an INK-Ed25519 Authorization header value into its signature and
 * optional keyId, purely from the §3.3 grammar. This is the parse half of
 * transport auth with no key resolution, timestamp, or signature work: it is the
 * grammar a second implementation must agree with byte for byte, exercised by the
 * `authorization-header` conformance category. `verifyInkAuth` calls it, so the
 * live verifier and the pinned grammar never diverge.
 *
 * An empty header is `missing_authorization`; any value that does not match the
 * grammar (wrong scheme, wrong signature length or alphabet, stray whitespace,
 * an embedded CR/LF, an empty or over-long or ill-formed keyId, or trailing
 * data) is `invalid_auth_scheme`. It never throws.
 */
export function parseInkAuthHeader(header: string): InkAuthHeaderParse {
  if (header.length === 0) {
    return { ok: false, reason: "missing_authorization" };
  }
  // A fast-path length cap before the regex: any header this long cannot match
  // the bounded grammar anyway, so it rejects as invalid_auth_scheme, the same
  // verdict the regex would give, without scanning the whole value.
  if (header.length > 512) {
    return { ok: false, reason: "invalid_auth_scheme" };
  }
  const match = header.match(INK_AUTH_HEADER_RE);
  if (!match) {
    return { ok: false, reason: "invalid_auth_scheme" };
  }
  return match[2] !== undefined
    ? { ok: true, signature: match[1]!, keyId: match[2] }
    : { ok: true, signature: match[1]! };
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
  body: SignableBody;
  resolvePublicKey?: (agentId: string) => Uint8Array | null;
  resolveKeySet?: (agentId: string) => CandidateKey[] | null;
  /**
   * Whether a signature that only verifies against a retired key is rejected
   * with `retired_key_for_live_auth`. Defaults to TRUE: live transport auth
   * refuses retired keys so a stolen retired key (which the key-rotation
   * authority rule otherwise lets verify within its window, and indefinitely
   * when it has no `validUntil`) cannot authenticate fresh requests. Set to
   * `false` to opt into a rotation grace window where a recently-retired key
   * still authenticates live traffic. Retired keys remain usable for
   * historical-artifact verification via `verifyInkSignatureWithKeys`
   * directly; this gate only governs live transport auth. Bootstrap and
   * single-key (resolvePublicKey) paths are unaffected because they carry no
   * status metadata.
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

  if (!isSignableBody(opts.body)) {
    return { valid: false, error: "missing_sender" };
  }
  const body = opts.body;

  // Parse the header against the shared §3.3 grammar. The Ed25519 signature is
  // exactly 86 base64url chars, so a clearly-wrong length or alphabet is rejected
  // up front rather than burning CPU on verifyInkSignature for a malformed value.
  const parsed = parseInkAuthHeader(opts.authHeader);
  if (!parsed.ok) {
    return { valid: false, error: parsed.reason };
  }
  const signature = parsed.signature;
  const hintKeyId = parsed.keyId;

  const senderDid = body.from;
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

  const timestamp = body.timestamp;
  if (typeof timestamp !== "string" || timestamp.length === 0) {
    return { valid: false, error: "missing_timestamp" };
  }
  // Parse with the strict RFC 3339 / millisecond grammar shared across
  // implementations: a date-only, zone-less, space-separated, or otherwise
  // lenient value another implementation rejects is rejected here too. The
  // 64-char cap inside the parser bounds work before the date parser runs, so
  // a multi-megabyte timestamp cannot burn CPU ahead of the signature check.
  const msgTime = parseInkTimestampMs(timestamp);
  if (msgTime === null) {
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
    const candidate = body.nonce;
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
    // Prefer an atomic check-and-record when the store provides one: it
    // closes the has()/add() check-then-act race that lets two concurrent
    // replays of one signed request both pass on a distributed store.
    if (typeof store.addIfAbsent === "function") {
      let added: boolean;
      try {
        added = await Promise.resolve(store.addIfAbsent(nonce));
      } catch {
        return { ok: false, error: "nonce_store_error" };
      }
      return added ? { ok: true } : { ok: false, error: "nonce_replay" };
    }
    // Fallback: non-atomic has()+add(). Single-use holds for an in-process
    // store; a distributed store SHOULD implement addIfAbsent for atomicity.
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
          // Local-policy gate, default-on: a retired key still verifies at the
          // primitive per the spec's authority rule, but live transport auth
          // refuses it so a stolen retired key (valid within its window, and
          // indefinitely when it has no validUntil) cannot sign fresh requests.
          // A caller that wants a rotation grace window opts out with
          // requireActiveKey: false.
          if (opts.requireActiveKey !== false && result.keyStatus === "retired") {
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
