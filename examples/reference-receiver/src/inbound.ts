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
 *  4. Resolve the sender's signing keys from their published agent
 *     card (did:web only — `did:key` senders are out of scope here).
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
      verdict: "schema" | "signature" | "unsupported_intent" | "oversize";
      sender: string;
      intent: string;
      errorCode: string;
    };

/**
 * Read at most MAX_BODY_BYTES from the request. If the client sends
 * more we drop the connection — the receiver should never canonicalize
 * something we couldn't fully observe.
 */
export async function readBoundedBody(
  req: Request,
  max = MAX_BODY_BYTES,
): Promise<{ ok: true; text: string } | { ok: false; reason: "oversize" | "read_error" }> {
  if (!req.body) return { ok: true, text: "" };
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
  return { ok: true, text: new TextDecoder().decode(buf) };
}

/**
 * Resolve the sender's candidate signing keys via their did:web agent
 * card. Returns an empty array on any failure — `verifyInkAuth`
 * treats an empty key set as a rejected signature.
 *
 * Only handles `did:web:` senders. Other DID methods need a different
 * resolver; supporting them is out of scope for the reference receiver.
 */
export async function resolveSenderKeys(
  senderDid: string,
  opts: { fetcher?: typeof fetch } = {},
): Promise<CandidateKey[]> {
  if (!senderDid.startsWith("did:web:")) return [];
  const card = await resolveAgentCardForDidWeb(senderDid, opts);
  if (!card) return [];
  // resolveAgentCardForDidWeb has already AgentCardSchema-parsed it.
  return extractCandidateKeys(card as Parameters<typeof extractCandidateKeys>[0]);
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
  bodyText: string,
  authHeader: string | undefined,
  cfg: InboundConfig,
): Promise<InboundOutcome> {
  let raw: unknown;
  try {
    raw = JSON.parse(bodyText);
  } catch {
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
    sender: envelope.from,
    response: buildAckResponse(envelope, cfg),
  };
}

function safeReadString(o: unknown, k: string): string {
  if (!o || typeof o !== "object") return "";
  const v = (o as Record<string, unknown>)[k];
  return typeof v === "string" ? v.slice(0, 200) : "";
}
