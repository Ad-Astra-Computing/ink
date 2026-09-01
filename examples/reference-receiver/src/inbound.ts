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
 * Encrypted envelopes (§3.4): when the receiver has an encryption identity
 * configured, an outer `network.tulpa.encrypted` / `network.ink.encrypted`
 * envelope is accepted on the same endpoint. Transport auth is verified over
 * the OUTER body first (the sender §3.3-signs what it POSTs), then the
 * ciphertext is opened with the recipient-DID binding and the inner envelope
 * runs through the same schema validation and intent allowlist as a plaintext
 * one. The authentication chain needs no separate inner-signature check: the
 * transport signature covers the ciphertext, the AAD binds the outer fields,
 * and decryptInkPayload enforces inner.from === outer.from — the same
 * transport-auth-is-the-authenticator stance as the plaintext path.
 *
 * NOT in scope here:
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
  decryptInkPayload,
  bytesToHex,
  type CandidateKey,
  type MessageEnvelope,
} from "@adastracomputing/ink";
import type { ReceiverIdentity, ReceiverEncryptionIdentity } from "./keys.js";
import { SUPPORTED_INTENTS } from "./agent-card.js";
import {
  resolveAgentCardForDidWebDetailed,
  CARD_RESOLUTION_HINTS,
  type CardResolutionReason,
} from "./did-web-resolver.js";

export const MAX_BODY_BYTES = 64 * 1024;

/**
 * A candidate signing key plus where it came from.
 *
 * `CandidateKey.status` is a CARD lifecycle term — `active`, `retired`,
 * `revoked` are the states a published key set moves a key through, and the
 * verifier uses them as its eligibility allowlist. A key decoded inline out of
 * a `did:key:` identifier has no card, no key set, and no rotation that could
 * ever retire it, so `status` cannot honestly describe it. `provenance` says
 * what `status` cannot:
 *
 *   - `card`      — read from the sender's published agent card. Card
 *                   lifecycle rules apply.
 *   - `bootstrap` — decoded from the sender's own `did:key:` identifier. Self
 *                   certifying, unrotatable, published by nobody.
 *
 * Any policy that means "a key a card currently publishes as active" MUST
 * test `provenance === "card"` as well as the status. Testing status alone
 * would silently admit every did:key sender.
 */
export type ResolvedCandidateKey = CandidateKey & {
  provenance: "card" | "bootstrap";
};

export interface InboundConfig {
  identity: ReceiverIdentity;
  /**
   * Optional §3.4 decryption identity. Absent means the receiver serves no
   * encryption key on its card and refuses encrypted envelopes explicitly.
   */
  encryption?: ReceiverEncryptionIdentity | null;
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
  nonceStore: {
    has(n: string): boolean | Promise<boolean>;
    add(n: string): void | Promise<void>;
    /** Atomic check-and-record; preferred when present (see the OSS NonceStore). */
    addIfAbsent?(n: string): boolean | Promise<boolean>;
  };
}

export type InboundOutcome =
  | { kind: "ok"; intent: string; sender: string; response: unknown }
  | {
      kind: "rejected";
      verdict: "utf8" | "schema" | "signature" | "unsupported_intent" | "oversize" | "encryption";
      sender: string;
      intent: string;
      errorCode: string;
      /**
       * Machine-readable cause when the rejection came from failing to resolve
       * the sender's card, plus prose the receiver hands back to the sender.
       * This is a public test target: "sender_key_unresolved" with nothing
       * else tells an adopter only that something upstream of the signature
       * check went wrong.
       */
      reason?: SenderKeyFailureReason;
      hint?: string;
    };

/** Why the sender's signing keys could not be resolved. */
export type SenderKeyFailureReason =
  | CardResolutionReason
  | "did_key_undecodable"
  | "unsupported_did_method"
  | "card_publishes_no_usable_key";

const SENDER_KEY_HINTS: Record<
  Exclude<SenderKeyFailureReason, CardResolutionReason>,
  string
> = {
  did_key_undecodable:
    "The did:key identifier does not decode to an Ed25519 public key. It must be a multibase 'z' string carrying the ed25519-pub multicodec.",
  unsupported_did_method:
    "This receiver resolves did:key and did:web senders only.",
  card_publishes_no_usable_key:
    "The sender's agent card resolved but publishes no usable signing key. Set publicKeyMultibase, or an active entry under keys.signing.",
};

export function senderKeyHint(reason: SenderKeyFailureReason): string {
  return reason in CARD_RESOLUTION_HINTS
    ? CARD_RESOLUTION_HINTS[reason as CardResolutionReason]
    : SENDER_KEY_HINTS[reason as Exclude<SenderKeyFailureReason, CardResolutionReason>];
}

export type SenderKeyResolution =
  | { keys: ResolvedCandidateKey[]; reason?: undefined }
  | { keys: []; reason: SenderKeyFailureReason };

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
export function resolveDidKeySenderKeys(senderDid: string): ResolvedCandidateKey[] {
  const multibase = senderDid.slice("did:key:".length);
  // did:key MAY carry a URL fragment (did:key:z6Mk...#z6Mk...); the
  // verification key is the part before any fragment.
  const keyPart = multibase.split("#")[0] ?? "";
  if (!keyPart.startsWith("z")) return [];
  try {
    const publicKey = decodePublicKeyMultibase(keyPart);
    // `status` is the verifier's eligibility allowlist, not a description of
    // where the key came from: `verifyInkAuth` only tries keys that are
    // `active` or `retired`, so an inline did:key has to be `active` to be
    // usable at all. `provenance` carries the fact that `status` cannot:
    // this key is not published by any card, no rotation can retire it, and
    // no card lifecycle applies to it. A rule that means "an active key on a
    // published card" must test provenance, not status alone.
    return [{ keyId: keyPart, publicKey, status: "active", provenance: "bootstrap" }];
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
export async function resolveSenderKeysDetailed(
  senderDid: string,
  opts: { fetcher?: typeof fetch } = {},
): Promise<SenderKeyResolution> {
  if (senderDid.startsWith("did:key:")) {
    const keys = resolveDidKeySenderKeys(senderDid);
    return keys.length > 0 ? { keys } : { keys: [], reason: "did_key_undecodable" };
  }
  if (senderDid.startsWith("did:web:")) {
    const resolved = await resolveAgentCardForDidWebDetailed(senderDid, opts);
    if (!resolved.ok) return { keys: [], reason: resolved.reason };
    // resolveAgentCardForDidWebDetailed has already AgentCardSchema-parsed it.
    const keys = extractCandidateKeys(resolved.card as Parameters<typeof extractCandidateKeys>[0])
      .map((k) => ({ ...k, provenance: "card" as const }));
    return keys.length > 0 ? { keys } : { keys: [], reason: "card_publishes_no_usable_key" };
  }
  return { keys: [], reason: "unsupported_did_method" };
}

/** Keys-only form of `resolveSenderKeysDetailed`. */
export async function resolveSenderKeys(
  senderDid: string,
  opts: { fetcher?: typeof fetch } = {},
): Promise<ResolvedCandidateKey[]> {
  return (await resolveSenderKeysDetailed(senderDid, opts)).keys;
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
  // surrogate escape and for a number literal outside the IEEE-754 double
  // range (which one parser turns into Infinity and another refuses outright),
  // then parses. A signed body is verified over its raw
  // bytes; a receiver that decodes leniently would canonicalize bytes the
  // signer never signed and could disagree with the signer, so this runs on
  // the bytes before any parse (see specs/ink-signed-string-safety.md).
  let raw: unknown;
  try {
    raw = parseSignedBodyBytes(bodyBytes);
  } catch (err) {
    if (err instanceof ParseSignedBodyError) {
      // One branch per gate reason. This used to fall through to
      // `lone_surrogate` for anything that was not utf8 or number-range, which
      // meant a body refused for an escaped member name told the sender it had
      // a surrogate problem. A reference endpoint that misnames why it refused
      // is worse than one that refuses less: an implementer calibrating against
      // it debugs the wrong thing.
      switch (err.reason) {
        case "utf8":
          return { kind: "rejected", verdict: "utf8", sender: "", intent: "", errorCode: "invalid_utf8" };
        case "surrogate":
          return { kind: "rejected", verdict: "schema", sender: "", intent: "", errorCode: "lone_surrogate" };
        case "number-range":
          return { kind: "rejected", verdict: "schema", sender: "", intent: "", errorCode: "number_out_of_range" };
        case "member-name-escape":
          return { kind: "rejected", verdict: "schema", sender: "", intent: "", errorCode: "escaped_member_name" };
        default:
          // A reason this example does not know about, which means the package
          // gained a gate rule and this switch was not updated. Refuse, and say
          // so rather than borrowing another rule's name.
          return { kind: "rejected", verdict: "schema", sender: "", intent: "", errorCode: "signed_body_rejected" };
      }
    }
    return { kind: "rejected", verdict: "schema", sender: "", intent: "", errorCode: "json_parse_failed" };
  }
  // Encrypted outer envelopes (§3.4) take their own path: they do not fit the
  // plaintext MessageEnvelope schema, and the plaintext order (schema before
  // signature) maps here to "outer shape caps before transport auth, transport
  // auth before decryption" — never AES work on an unauthenticated body.
  if (isEncryptedEnvelope(raw)) {
    return processEncryptedInbound(raw, authHeader, cfg);
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
  const resolution = await resolveSenderKeysDetailed(envelope.from, { fetcher: cfg.fetcher });
  const candidateKeys = resolution.keys;
  if (candidateKeys.length === 0) {
    const reason = resolution.reason ?? "card_publishes_no_usable_key";
    return {
      kind: "rejected",
      verdict: "signature",
      sender: envelope.from,
      intent: envelope.intent,
      errorCode: "sender_key_unresolved",
      reason,
      hint: senderKeyHint(reason),
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

/** The two accepted outer spellings; receivers dual-accept both (§6). */
export const ENCRYPTED_MESSAGE_TYPES = ["network.tulpa.encrypted", "network.ink.encrypted"] as const;

/** Whether a parsed body claims to be a §3.4 encrypted outer envelope. */
export function isEncryptedEnvelope(raw: unknown): raw is Record<string, unknown> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  const t = (raw as Record<string, unknown>).type;
  return typeof t === "string" && (ENCRYPTED_MESSAGE_TYPES as readonly string[]).includes(t);
}

/**
 * Cheap scalar caps on the outer envelope BEFORE it is canonicalized for
 * transport-auth verification. Mirrors the caps decryptInkPayload enforces, so
 * nothing that would later be refused gets JCS-canonicalized first. Returns an
 * errorCode or null.
 */
function encryptedOuterShapeError(outer: Record<string, unknown>): string | null {
  if (outer.protocol !== "ink/0.1") return "outer_protocol_unsupported";
  const s = (v: unknown, max: number): v is string =>
    typeof v === "string" && v.length > 0 && v.length <= max;
  if (!s(outer.from, 512)) return "outer_from_invalid";
  if (!s(outer.timestamp, 64)) return "outer_timestamp_invalid";
  // messageNonce is the §3.5 replay nonce for an encrypted envelope (the outer
  // `nonce` is the AES-GCM IV), so it must meet the replay-nonce grammar, not
  // just the AAD length cap.
  if (typeof outer.messageNonce !== "string" || !/^[A-Za-z0-9_-]{16,256}$/.test(outer.messageNonce)) {
    return "outer_message_nonce_invalid";
  }
  if (!s(outer.ephemeralKey, 64)) return "outer_ephemeral_key_invalid";
  if (!s(outer.nonce, 32)) return "outer_nonce_invalid";
  if (!s(outer.ciphertext, 1_400_000)) return "outer_ciphertext_invalid";
  return null;
}

/**
 * Drive a §3.4 encrypted outer envelope: shape caps, sender key resolution,
 * transport auth over the OUTER body, decrypt with the recipient-DID binding,
 * then the inner envelope through the same schema validation and intent
 * allowlist as the plaintext path.
 */
export async function processEncryptedInbound(
  outer: Record<string, unknown>,
  authHeader: string | undefined,
  cfg: InboundConfig,
): Promise<InboundOutcome> {
  const sender = safeReadString(outer, "from");
  if (!cfg.encryption) {
    // Explicit refusal, not a schema error: a conformant sender only seals to
    // a key our card advertises, so reaching this means the sender ignored
    // the card. Name the actual problem.
    return {
      kind: "rejected",
      verdict: "encryption",
      sender,
      intent: "",
      errorCode: "encryption_unsupported",
      hint: "This receiver advertises no encryption key on its agent card and cannot decrypt. Send a plaintext signed envelope.",
    };
  }
  const shape = encryptedOuterShapeError(outer);
  if (shape !== null) {
    return { kind: "rejected", verdict: "encryption", sender, intent: "", errorCode: shape };
  }
  const senderDid = outer.from as string;
  const resolution = await resolveSenderKeysDetailed(senderDid, { fetcher: cfg.fetcher });
  if (resolution.keys.length === 0) {
    const reason = resolution.reason ?? "card_publishes_no_usable_key";
    return {
      kind: "rejected",
      verdict: "signature",
      sender,
      intent: "",
      errorCode: "sender_key_unresolved",
      reason,
      hint: senderKeyHint(reason),
    };
  }
  // Transport auth over the OUTER body: the sender §3.3-signs exactly what it
  // POSTs, so the ciphertext and every AAD-bound outer field are covered. The
  // §3.5 replay nonce for an encrypted envelope is `messageNonce`, but the
  // middleware reads `body.nonce` — which here is the AES-GCM IV. Recording
  // the IV would let an authenticated sender replay one `messageNonce` under
  // fresh IVs, so nonce handling is deferred to the explicit messageNonce
  // check after verification.
  const authResult = await verifyInkAuth({
    authHeader,
    method: "POST",
    path: "/ink/v1/inbound",
    recipientAgentId: cfg.receiverDid,
    body: outer,
    resolveKeySet: (agentId) => (agentId === senderDid ? resolution.keys : null),
    nonceStore: "deferred",
  });
  if (!authResult.valid) {
    return {
      kind: "rejected",
      verdict: "signature",
      sender,
      intent: "",
      errorCode: `auth:${String(authResult.error).slice(0, 64)}`,
    };
  }
  if (authResult.senderAgentId !== senderDid) {
    return { kind: "rejected", verdict: "signature", sender, intent: "", errorCode: "from_field_mismatch" };
  }
  // Single-use check on `messageNonce`, AFTER signature verification (so a
  // forged request never pollutes the store, matching the middleware's own
  // ordering) and BEFORE decryption. Prefer the atomic form when the store
  // has one; store errors fail closed.
  const messageNonce = outer.messageNonce as string;
  try {
    let fresh: boolean;
    if (typeof cfg.nonceStore.addIfAbsent === "function") {
      fresh = await Promise.resolve(cfg.nonceStore.addIfAbsent(messageNonce));
    } else {
      fresh = !(await Promise.resolve(cfg.nonceStore.has(messageNonce)));
      if (fresh) await Promise.resolve(cfg.nonceStore.add(messageNonce));
    }
    if (!fresh) {
      return { kind: "rejected", verdict: "signature", sender, intent: "", errorCode: "auth:nonce_replay" };
    }
  } catch {
    return { kind: "rejected", verdict: "signature", sender, intent: "", errorCode: "auth:nonce_store_error" };
  }
  // Decrypt AFTER auth. decryptInkPayload rebuilds the AAD (binding the type
  // as received, the outer scalars, and our own static key), enforces
  // inner.from === outer.from, and requires inner.to to equal the recipient
  // DID we assert — so a mis-addressed or re-attributed envelope fails here,
  // not in application code.
  let inner: Record<string, unknown>;
  try {
    inner = await decryptInkPayload(
      outer as unknown as Parameters<typeof decryptInkPayload>[0],
      bytesToHex(cfg.encryption.privateKey),
      cfg.receiverDid,
    );
  } catch (err) {
    const code = err instanceof Error ? err.message.slice(0, 64) : "decrypt_error";
    return { kind: "rejected", verdict: "encryption", sender, intent: "", errorCode: `decrypt:${code}` };
  }
  let envelope: MessageEnvelope;
  try {
    envelope = validateMessage(inner);
  } catch (err) {
    const code = err instanceof Error ? err.message.slice(0, 64) : "schema_error";
    return { kind: "rejected", verdict: "schema", sender, intent: safeReadString(inner, "intent"), errorCode: `schema:${code}` };
  }
  if (!SUPPORTED_INTENTS.includes(envelope.intent as typeof SUPPORTED_INTENTS[number])) {
    return {
      kind: "rejected",
      verdict: "unsupported_intent",
      sender: envelope.from,
      intent: envelope.intent,
      errorCode: `unsupported_intent:${envelope.intent}`,
    };
  }
  return {
    kind: "ok",
    intent: envelope.intent,
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
