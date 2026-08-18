import { z } from "zod";
import { dualWireType } from "./wire-type.js";
import { AgentCardVisibilitySchema } from "./ink-handshake.js";
import { isInkTimestamp, parseInkTimestampMs } from "../crypto/timestamp.js";
import { isWithinBounds, signMessage, verifyMessage } from "../crypto/sign.js";
import { hasUnpairedSurrogate } from "../crypto/surrogate.js";
import { parseSignedBodyBytes } from "../crypto/parse-signed-body.js";

// Caps mirror the DID/agent-id bound used across INK payloads and the discovery
// descriptor's tag constraints (#188), so a query cannot express more than a
// card's descriptor advertises.
const ID_MAX = 512;
const NONCE_MIN = 16;
const NONCE_MAX = 256;
const TAG_MAX_LEN = 64;
const TAGS_MAX = 32;
const LIMIT_MAX = 100;

// The bounded set of facts a requester may ask a directory to match on. It
// reuses the discovery descriptor's scope enum and tag shape so a query can
// never request a scope or tag form a card could not have advertised. It
// carries no ranking, response, consent, or field-release semantics: those are
// the directory's responsibility and are deliberately out of scope here.
export const DiscoveryQuerySchema = z
  .object({
    tags: z.array(z.string().min(1).max(TAG_MAX_LEN)).min(1).max(TAGS_MAX).optional(),
    scope: AgentCardVisibilitySchema.optional(),
    limit: z.number().int().min(1).max(LIMIT_MAX).optional(),
  })
  .strict();

export type DiscoveryQuery = z.infer<typeof DiscoveryQuerySchema>;

// A requester-signed request to look up discoverable agents at a directory. The
// signature covers every field except `signature` itself (protocol, type, from,
// to, nonce, timestamp, query), so a directory can bind the request to the
// requester's key and reject replay or tampering. The wire `type` accepts the
// vendor-neutral network.ink spelling alongside the legacy network.tulpa one.
export const DiscoveryQueryEnvelopeSchema = z
  .object({
    protocol: z.literal("ink/0.1"),
    type: dualWireType("discovery_query"),
    from: z.string().min(1).max(ID_MAX),
    to: z.string().min(1).max(ID_MAX),
    nonce: z.string().min(NONCE_MIN).max(NONCE_MAX),
    timestamp: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
    query: DiscoveryQuerySchema,
    // The signature is 64 raw bytes, 86 base64url characters with no padding. A
    // string that is not that exact shape is a structural failure, rejected as
    // "schema" before any signature work, so both implementations agree on the
    // reason for a malformed signature.
    signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  })
  .strict();

export type DiscoveryQueryEnvelope = z.infer<typeof DiscoveryQueryEnvelopeSchema>;

const UnsignedDiscoveryQueryEnvelopeSchema = DiscoveryQueryEnvelopeSchema.omit({ signature: true });

export interface DiscoveryQueryInput {
  /** Defaults to the legacy `network.tulpa.discovery_query` spelling. */
  type?: "network.tulpa.discovery_query" | "network.ink.discovery_query";
  from: string;
  to: string;
  nonce: string;
  timestamp: string;
  query: DiscoveryQuery;
}

// Build a signed discovery query envelope. The unsigned envelope is validated
// before signing, so a malformed query is rejected at build time rather than
// producing a signature over an out-of-profile request.
export async function buildDiscoveryQueryEnvelope(
  input: DiscoveryQueryInput,
  privateKey: Uint8Array,
): Promise<DiscoveryQueryEnvelope> {
  const unsigned = {
    protocol: "ink/0.1" as const,
    type: input.type ?? ("network.tulpa.discovery_query" as const),
    from: input.from,
    to: input.to,
    nonce: input.nonce,
    timestamp: input.timestamp,
    query: input.query,
  };
  UnsignedDiscoveryQueryEnvelopeSchema.parse(unsigned);
  const signature = await signMessage(unsigned, privateKey);
  return { ...unsigned, signature };
}

/**
 * Maximum age of a discovery query at the verifying directory's clock. It is the
 * INK message freshness window (`ink-protocol.md` §3.5): a query is a single
 * signed request, not a credential with its own window, so it ages by the same
 * rule every other INK message does.
 */
export const MAX_DISCOVERY_QUERY_AGE_MS = 5 * 60 * 1000;

/**
 * How far ahead of the verifying directory's clock a query timestamp may sit.
 * The same 30 second skew allowance INK grants any signed message, so a
 * marginally fast requester clock is not a rejection.
 */
export const MAX_DISCOVERY_QUERY_SKEW_MS = 30 * 1000;

/**
 * Byte ceiling on a raw discovery query envelope, enforced before the body is
 * decoded. It is derived from the schema bounds at the wire escape-expansion
 * worst case: a maximal envelope carries about 3,300 schema-bounded code units
 * (32 tags of 64, a `from` and `to` of 512 each, a 256-unit nonce, a timestamp,
 * a scope literal and an 86-character signature), and the wire form is not
 * canonical JSON, so a sender may spell any character as a six-byte `\uXXXX`
 * escape: roughly 20 KiB of wire bytes. Rounding to a flat 64 KiB, the same
 * figure `MAX_GRANT_BODY_BYTES` rounds to, leaves headroom for a fully escaped
 * valid envelope while refusing a blob orders of magnitude past the schema.
 *
 * The cap is not redundant with the structural bounds walk: JSON permits
 * unbounded whitespace between tokens, and whitespace vanishes at
 * canonicalization, so a schema-valid envelope padded with megabytes of spaces
 * carries a signature that still verifies. Without a byte cap that body is
 * admitted; the Go `MaxDiscoveryQueryBodyBytes` refuses it.
 */
export const MAX_DISCOVERY_QUERY_BODY_BYTES = 64 * 1024;

/**
 * Which check rejected a discovery query. Callers discriminate on this stable
 * field rather than any message prose. `schema` covers every structural failure
 * and every verifier input error (an empty audience set, a clock that is not a
 * strict INK timestamp); the rest are the individual security decisions.
 */
export type DiscoveryQueryReason = "schema" | "signature" | "audience" | "expired" | "not_yet_valid" | "replay";

/**
 * A query identity for replay. The key is the pair of the signed `from` and the
 * requester-chosen `nonce`. A nonce is chosen by the requester, so two
 * requesters can pick the same string; keying replay on the pair keeps one
 * requester's nonces from burning another's, which would otherwise let a hostile
 * requester deny queries it never sent.
 */
export interface DiscoveryQueryKey {
  from: string;
  nonce: string;
}

/**
 * Everything a verifier needs beyond the requester key.
 *
 * `audience` is the directory's own identity: the signed `to` must equal it
 * exactly. A directory that answers to several spellings of itself (an origin,
 * a bare host, a `did:web`) passes all of them and the signed `to` must equal
 * one. Comparison is exact: this module never lowercases, never strips a
 * trailing slash and never derives one spelling from another, so a directory
 * that accepts a spelling states it. An empty set is a verifier input error and
 * fails closed as `schema` rather than admitting every audience.
 *
 * `now` is the verifier clock, a strict INK timestamp. A query is fresh within
 * `[now - MAX_DISCOVERY_QUERY_AGE_MS, now + MAX_DISCOVERY_QUERY_SKEW_MS]`, both
 * bounds inclusive.
 *
 * `seenNonces` is the replay seam, the same shape the grant verifier's
 * `seenGrants` hook takes: the `(from, nonce)` pairs this directory has already
 * accepted. It is optional and defaults to "not seen", so a directory that omits
 * it is stating that it enforces replay somewhere else; the verifier makes no
 * replay decision it was given no state for. A directory MUST record an accepted
 * pair atomically with acceptance (check-and-insert under one guard) so two
 * concurrent presentations of one nonce cannot both be accepted; this verifier
 * reads the seam but never records into it.
 */
export interface DiscoveryQueryVerifyContext {
  audience: string | readonly string[];
  now: string;
  seenNonces?: Iterable<DiscoveryQueryKey>;
}

export type DiscoveryQueryVerifyResult =
  | { ok: true; envelope: DiscoveryQueryEnvelope }
  | { ok: false; reason: DiscoveryQueryReason };

/**
 * Verify a discovery query envelope against the requester's public key and a
 * verification context. The key is caller-supplied: resolving `from` to a key is
 * the directory's job. Fails closed: every structural, verifier-input or
 * security failure returns a typed rejection, and the function never throws.
 *
 * The input is the **raw body bytes**, not a parsed value. An envelope is a
 * signed body, so it is subject to the raw-body gate of
 * [`specs/ink-signed-string-safety.md`](../../specs/ink-signed-string-safety.md)
 * §"Enforcement order": invalid UTF-8, a lone UTF-16 surrogate escape and a
 * number literal outside the IEEE-754 double range are all rules about the bytes
 * that no longer exist once the body is parsed. A verifier that took a parsed
 * value could not run them, and could not run them on a caller's behalf either:
 * a duplicate member shadows an out-of-range literal (JSON member semantics are
 * last-wins), so the value layer never sees it, the envelope canonicalizes
 * cleanly and its signature verifies, while an implementation that gates the
 * bytes refuses the same envelope outright. That is an accept-versus-reject
 * split in a signed path, choosable by anyone who can write the bytes, so the
 * bytes are the input.
 *
 * The envelope signs `to`, `nonce` and `timestamp`, so this verifier consumes
 * all three rather than leaving a caller to rediscover that it must. The
 * signature is checked before any context decision, so a rejection never reveals
 * whether the audience or the window would have passed.
 *
 * Check order (each returns its own reason on the first failure):
 *   1. byte cap, raw-body gate, JSON parse       -> "schema"
 *   2. structural schema + string safety          -> "schema"
 *   3. requester signature over the canonical body -> "signature"
 *   4. audience binding (confused-deputy defense)  -> "audience"
 *   5. freshness window                            -> "expired" | "not_yet_valid"
 *   6. replay (from + nonce already seen)          -> "replay"
 *
 * A `now` that is not a strict INK timestamp and an empty audience set are
 * verifier input errors and reject as "schema", not a verdict the verifier never
 * computed.
 */
export async function verifyDiscoveryQueryEnvelope(
  raw: Uint8Array,
  requesterPublicKey: Uint8Array,
  context: DiscoveryQueryVerifyContext,
): Promise<DiscoveryQueryVerifyResult> {
  // Fail closed on anything, including a hostile object whose getters or proxy
  // traps throw during bounds checking or parsing.
  try {
    // A caller on an untyped boundary can still hand over something that is not
    // bytes; that is a verifier input error, not an envelope this function can
    // rule on, and it fails closed rather than being coerced.
    if (!ArrayBuffer.isView(raw) || !(raw instanceof Uint8Array)) {
      return { ok: false, reason: "schema" };
    }
    // The byte cap runs before the decoder: an oversized blob is refused without
    // being decoded at all.
    if (raw.length > MAX_DISCOVERY_QUERY_BODY_BYTES) {
      return { ok: false, reason: "schema" };
    }
    // The raw-body gate, then the parse. ParseSignedBodyError and the native
    // SyntaxError from a malformed body are both structural rejections.
    let value: unknown;
    try {
      value = parseSignedBodyBytes(raw);
    } catch {
      return { ok: false, reason: "schema" };
    }
    if (!isWithinBounds(value)) {
      return { ok: false, reason: "schema" };
    }
    const parsed = DiscoveryQueryEnvelopeSchema.safeParse(value);
    if (!parsed.success) {
      return { ok: false, reason: "schema" };
    }
    const envelope = parsed.data;

    // String safety is structural: an envelope carrying a lone UTF-16 surrogate
    // is not portable across implementations, so it is rejected as "schema"
    // before the signature check rather than surfacing as a signature failure.
    if (hasUnpairedSurrogate(envelope)) {
      return { ok: false, reason: "schema" };
    }

    // Signature before any context decision.
    if (!(await verifyMessage(envelope, requesterPublicKey))) {
      return { ok: false, reason: "signature" };
    }

    // Confused-deputy defense: a query addressed to one directory must not be
    // relayed to another. The signed `to` must equal one of this directory's own
    // identifiers, compared exactly.
    const audiences = typeof context.audience === "string" ? [context.audience] : [...context.audience];
    if (audiences.length === 0 || audiences.some((a) => typeof a !== "string" || a.length === 0)) {
      return { ok: false, reason: "schema" };
    }
    if (!audiences.includes(envelope.to)) {
      return { ok: false, reason: "audience" };
    }

    // Freshness. The verifier clock must itself be a strict INK timestamp; a
    // caller that supplies a malformed clock fails closed as a verifier input
    // error. Both bounds are inclusive.
    const now = parseInkTimestampMs(context.now);
    const sent = parseInkTimestampMs(envelope.timestamp);
    if (now === null || sent === null) {
      return { ok: false, reason: "schema" };
    }
    const drift = sent - now;
    if (drift > MAX_DISCOVERY_QUERY_SKEW_MS) {
      return { ok: false, reason: "not_yet_valid" };
    }
    if (-drift > MAX_DISCOVERY_QUERY_AGE_MS) {
      return { ok: false, reason: "expired" };
    }

    // Replay: a (from, nonce) pair already seen at this directory is a replay.
    // The seen set is receiver state, not part of the envelope.
    if (context.seenNonces) {
      for (const seen of context.seenNonces) {
        if (seen.from === envelope.from && seen.nonce === envelope.nonce) {
          return { ok: false, reason: "replay" };
        }
      }
    }

    return { ok: true, envelope };
  } catch {
    return { ok: false, reason: "schema" };
  }
}
