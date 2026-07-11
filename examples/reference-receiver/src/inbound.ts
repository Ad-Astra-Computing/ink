/**
 * Inbound envelope handler.
 *
 * Flow:
 *  1. Read the body (capped at MAX_BODY_BYTES so a 10 MB POST cannot
 *     pin the worker on the read).
 *  2. Parse JSON. Reject malformed.
 *  3. Validate against `validateMessage()` from the OSS package.
 *     Schema validation runs BEFORE signature verification because
 *     verification depends on canonicalizing the body, and we should
 *     refuse to canonicalize clearly-invalid input.
 *  4. Resolve the sender's signing keys: `did:key` is decoded inline
 *     from the identifier (no fetch); `did:web` is resolved from the
 *     sender's published agent card behind the SSRF guards. Other DID
 *     methods are unsupported and resolve to no keys.
 *  5. Run `verifyInkAuth` from the OSS package against the request
 *     Authorization header, body, and resolved key set. That call
 *     enforces the spec's signature, timestamp freshness and nonce
 *     checks in one place — the receiver does not reimplement them.
 *  6. Build a simple JSON ack carrying { ok, inReplyTo, receiverDid,
 *     receivedIntent }. Phase A does NOT sign the response. Phase B
 *     can either sign the ack envelope (so the caller has a verifiable
 *     audit trail) or POST a separate signed INK envelope back to the
 *     sender's inbox.
 *
 * NOT in scope here:
 *  - End-to-end payload encryption.
 *  - Receipt persistence beyond the rolling 7-day KV audit log.
 *  - Signed responses (see Phase B note above).
 */

import {
  validateMessage,
  verifyInkAuth,
  extractCandidateKeys,
  decodePublicKeyMultibase,
  parseSignedBodyBytes,
  ParseSignedBodyError,
  type CandidateKey,
  type MessageEnvelope,
} from "@adastracomputing/ink";
import type { ReceiverIdentity } from "./keys.js";
import { SUPPORTED_INTENTS } from "./agent-card.js";
import { resolveAgentCardForDidWeb } from "./did-web-resolver.js";

export const MAX_BODY_BYTES = 64 * 1024;

export interface InboundConfig {
  identity: ReceiverIdentity;
  receiverDid: string;
  /** Injected for tests. */
  now?: () => number;
  /** Injected for tests. */
  fetcher?: typeof fetch;
  /**
   * Nonce store. The OSS middleware fails closed if not supplied — we
   * provide an in-memory ring buffer at the worker level. Production
   * adopters should swap in a KV-backed store.
   */
  nonceStore: { has(n: string): boolean | Promise<boolean>; add(n: string): void | Promise<void> };
}

export type InboundOutcome =
  | { kind: "ok"; intent: string; sender: string; response: unknown }
  | {
      kind: "rejected";
      verdict: "utf8" | "schema" | "signature" | "unsupported_intent" | "oversize";
      sender: string;
      intent: string;
      errorCode: string;
    };

/**
 * Read at most MAX_BODY_BYTES from the request. If the client sends
 * more we drop the connection — the receiver should never canonicalize
 * something we couldn't fully observe.
 *
 * Returns the raw bytes, not a decoded string. A signed body is verified
 * over its raw bytes, so the receiver must gate on those bytes before
 * decoding: a lenient decode substitutes U+FFFD for an invalid sequence
 * and the original bytes are gone. `processInbound` runs that gate through
 * `parseSignedBodyBytes`.
 */
export async function readBoundedBody(
  req: Request,
  max = MAX_BODY_BYTES,
): Promise<{ ok: true; bytes: Uint8Array } | { ok: false; reason: "oversize" | "read_error" }> {
  if (!req.body) return { ok: true, bytes: new Uint8Array(0) };
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > max) {
          try { await reader.cancel(); } catch { /* ignore */ }
          return { ok: false, reason: "oversize" };
        }
        chunks.push(value);
      }
    }
  } catch {
    return { ok: false, reason: "read_error" };
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return { ok: true, bytes: buf };
}

/**
 * Decode the signing key embedded in a `did:key:` identifier. A
 * did:key is self-certifying — the multibase string after the prefix
 * IS the Ed25519 public key (with a multicodec tag) — so there is NO
 * network fetch and NO SSRF surface. This is the simplest and safest
 * sender type for a public test target, and the one the `interop-cli`
 * reference sender uses by default. Returns [] on any decode failure.
 */
export function resolveDidKeySenderKeys(senderDid: string): CandidateKey[] {
  const multibase = senderDid.slice("did:key:".length);
  // did:key MAY carry a URL fragment (did:key:z6Mk...#z6Mk...); the
  // verification key is the part before any fragment.
  const keyPart = multibase.split("#")[0] ?? "";
  if (!keyPart.startsWith("z")) return [];
  try {
    const publicKey = decodePublicKeyMultibase(keyPart);
    return [{ keyId: keyPart, publicKey, status: "active" }];
  } catch {
    return [];
  }
}

/**
 * Resolve the sender's candidate signing keys.
 *
 * - `did:key:` — decoded inline from the identifier (no fetch).
 * - `did:web:` — resolved from the sender's published agent card,
 *   behind the SSRF guards in `did-web-resolver.ts`.
 * - anything else — unsupported; returns [] so `verifyInkAuth` treats
 *   it as a rejected signature.
 */
export async function resolveSenderKeys(
  senderDid: string,
  opts: { fetcher?: typeof fetch } = {},
): Promise<CandidateKey[]> {
  if (senderDid.startsWith("did:key:")) {
    return resolveDidKeySenderKeys(senderDid);
  }
  if (senderDid.startsWith("did:web:")) {
    const card = await resolveAgentCardForDidWeb(senderDid, opts);
    if (!card) return [];
    // resolveAgentCardForDidWeb has already AgentCardSchema-parsed it.
    return extractCandidateKeys(card as Parameters<typeof extractCandidateKeys>[0]);
  }
  return [];
}

/**
 * Build the (unsigned) ack response. Phase A returns a plain JSON
 * object; the integration test confirms it carries the expected
 * fields. Phase B can wrap this in a signed INK envelope.
 */
export function buildAckResponse(envelope: MessageEnvelope, cfg: InboundConfig): unknown {
  const now = cfg.now ?? (() => Date.now());
  return {
    ok: true,
    receiverDid: cfg.receiverDid,
    receivedAt: new Date(now()).toISOString(),
    receivedIntent: envelope.intent,
    inReplyTo: envelope.id,
    correlationId: envelope.correlationId,
  };
}

/**
 * Drive an inbound envelope through validation + verification.
 *
 * Returns the outcome. The HTTP handler in index.ts is a thin wrapper
 * around this function — kept thin for testability.
 */
export async function processInbound(
  bodyBytes: Uint8Array,
  authHeader: string | undefined,
  cfg: InboundConfig,
): Promise<InboundOutcome> {
  // Gate the RAW bytes before parsing. `parseSignedBodyBytes` decodes with a
  // fatal UTF-8 decoder (so an invalid sequence is rejected rather than
  // substituted with U+FFFD), scans the decoded text for a lone UTF-16
  // surrogate escape, then parses. A signed body is verified over its raw
  // bytes; a receiver that decodes leniently would canonicalize bytes the
  // signer never signed and could disagree with the signer, so this runs on
  // the bytes before any parse (see specs/ink-signed-string-safety.md).
  let raw: unknown;
  try {
    raw = parseSignedBodyBytes(bodyBytes);
  } catch (err) {
    if (err instanceof ParseSignedBodyError) {
      if (err.reason === "utf8") {
        return { kind: "rejected", verdict: "utf8", sender: "", intent: "", errorCode: "invalid_utf8" };
      }
      return { kind: "rejected", verdict: "schema", sender: "", intent: "", errorCode: "lone_surrogate" };
    }
    return { kind: "rejected", verdict: "schema", sender: "", intent: "", errorCode: "json_parse_failed" };
  }
  let envelope: MessageEnvelope;
  try {
    envelope = validateMessage(raw);
  } catch (err) {
    const code = err instanceof Error ? err.message.slice(0, 64) : "schema_error";
    const sender = safeReadString(raw, "from");
    const intent = safeReadString(raw, "intent");
    return { kind: "rejected", verdict: "schema", sender, intent, errorCode: `schema:${code}` };
  }
  // Intent allowlist BEFORE we go fetch the sender's card. Saves a
  // network round-trip on unsupported intents.
  if (!SUPPORTED_INTENTS.includes(envelope.intent as typeof SUPPORTED_INTENTS[number])) {
    return {
      kind: "rejected",
      verdict: "unsupported_intent",
      sender: envelope.from,
      intent: envelope.intent,
      errorCode: `unsupported_intent:${envelope.intent}`,
    };
  }
  // Confirm the envelope is actually addressed to us. A mis-addressed
  // signed envelope would still satisfy the cryptographic check but
  // is a clear protocol error — refuse explicitly.
  if (envelope.to !== cfg.receiverDid) {
    return {
      kind: "rejected",
      verdict: "schema",
      sender: envelope.from,
      intent: envelope.intent,
      errorCode: "recipient_mismatch",
    };
  }
  // Resolve the sender's key set BEFORE invoking the verifier, since
  // the verifier's `resolveKeySet` callback is synchronous.
  const candidateKeys = await resolveSenderKeys(envelope.from, { fetcher: cfg.fetcher });
  if (candidateKeys.length === 0) {
    return {
      kind: "rejected",
      verdict: "signature",
      sender: envelope.from,
      intent: envelope.intent,
      errorCode: "sender_key_unresolved",
    };
  }
  const authResult = await verifyInkAuth({
    authHeader,
    method: "POST",
    path: "/ink/v1/inbound",
    recipientAgentId: cfg.receiverDid,
    body: raw as Record<string, unknown>,
    resolveKeySet: (agentId) => agentId === envelope.from ? candidateKeys : null,
    nonceStore: cfg.nonceStore,
  });
  if (!authResult.valid) {
    return {
      kind: "rejected",
      verdict: "signature",
      sender: envelope.from,
      intent: envelope.intent,
      errorCode: `auth:${String(authResult.error).slice(0, 64)}`,
    };
  }
  // Belt-and-braces: the auth header binds the body to the sender's
  // key set, but the body's `from` field could theoretically claim a
  // different agentId. Refuse the mismatch explicitly.
  if (authResult.senderAgentId !== envelope.from) {
    return {
      kind: "rejected",
      verdict: "signature",
      sender: envelope.from,
      intent: envelope.intent,
      errorCode: "from_field_mismatch",
    };
  }
  return {
    kind: "ok",
    intent: envelope.intent,
    // Canonicalize the sender so the per-sender rate-limit bucket and
    // audit record key on the identity, not on an alias. For did:key,
    // the fragment (did:key:z...#frag) selects a verification method
    // but does NOT change which key authenticated — so a single key
    // holder must not be able to mint unbounded distinct buckets by
    // varying the fragment.
    sender: canonicalizeSenderDid(envelope.from),
    response: buildAckResponse(envelope, cfg),
  };
}

/**
 * Strip the URL fragment from a `did:key:` sender so aliases like
 * `did:key:z...#a` and `did:key:z...#b` collapse to one identity for
 * rate-limiting and audit. Other DID methods are returned unchanged.
 */
export function canonicalizeSenderDid(did: string): string {
  if (did.startsWith("did:key:")) {
    const hash = did.indexOf("#");
    return hash === -1 ? did : did.slice(0, hash);
  }
  return did;
}

function safeReadString(o: unknown, k: string): string {
  if (!o || typeof o !== "object") return "";
  const v = (o as Record<string, unknown>)[k];
  return typeof v === "string" ? v.slice(0, 200) : "";
}
