/**
 * Sketch: the verify-then-forward inbound flow for the INK contact endpoint.
 *
 * Mirrors examples/reference-receiver/src/inbound.ts — the SAME verification
 * pipeline (bounded read -> validateMessage -> resolve sender keys ->
 * verifyInkAuth). The only behavioural difference is the terminal action
 * (forward to a human inbox instead of returning a JSON ack) and the four design
 * decisions called out below.
 *
 * Illustrative, not a tested service. The load-bearing helpers (readBoundedBody,
 * resolveSenderKeys, canonicalizeSenderDid, the nonce store) are exported by the
 * reference receiver and imported here rather than re-sketched, so this example
 * cannot drift from the reference's security floor.
 */
import {
  validateMessage,
  verifyInkAuth,
  parseSignedBodyBytes,
  ParseSignedBodyError,
  type CandidateKey,
  type MessageEnvelope,
} from "@adastracomputing/ink";
import {
  readBoundedBody,
  resolveSenderKeys,
  canonicalizeSenderDid,
} from "../../reference-receiver/src/inbound.js";
import { checkRateLimits } from "./rate-limit.js";
import { buildForwardEmail, sendEmail } from "./forward-email.js";

const OUR_DID = "did:web:mcp.example.com"; // decision 1
const INBOUND_PATH = "/ink/v1/inbound";
// Plaintext first-contact intents only. Every intent INK requires encryption for
// (schedule_meeting, context_share, multi_party_sync) is excluded by design.
const ACCEPTED_INTENTS = new Set(["connection_request", "intro_request", "ask"]);
const MAX_BODY_BYTES = 64 * 1024;

interface Env {
  RL: RateStore;
  // verifyInkAuth needs a has/add nonce store (not bare KV get/put). Lift the
  // KV-backed adapter from ../../reference-receiver/src/nonce-store.ts.
  NONCES: { has(n: string): boolean | Promise<boolean>; add(n: string): void | Promise<void> };
  fetcher?: typeof fetch;
  [k: string]: unknown;
}
type RateStore = {
  get(k: string): Promise<string | null>;
  put(k: string, v: string, o?: { expirationTtl?: number }): Promise<void>;
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function rateLimited(gate: { scope: "ip" | "did"; retryAfter: number }): Response {
  return new Response(
    JSON.stringify({ error: "rate_limited", scope: gate.scope, retryable: true }),
    { status: 429, headers: { "content-type": "application/json", "Retry-After": String(gate.retryAfter) } },
  );
}

export async function handleInbound(req: Request, env: Env): Promise<Response> {
  // Assumes Cloudflare's CF-Connecting-IP. Behind another proxy, read a trusted
  // forwarded-for header instead — never an attacker-settable one.
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";

  // Pre-parse per-IP limit: cheap, runs before we read or trust anything. Typed
  // rejection with a backoff hint, not a bare 429.
  const ipGate = await checkRateLimits(env.RL, { ip, did: null, firstContact: true });
  if (!ipGate.ok) return rateLimited(ipGate);

  // 1. Read the body under a hard cap so a multi-megabyte POST cannot pin the
  //    worker on the read, then gate the raw bytes and parse. `parseSignedBodyBytes`
  //    rejects invalid UTF-8 and a lone UTF-16 surrogate escape before parsing,
  //    because a signed body is verified over its raw bytes and a lenient decode
  //    would canonicalize bytes the signer never signed (see
  //    ../../specs/ink-signed-string-safety.md). Reject malformed.
  const read = await readBoundedBody(req, MAX_BODY_BYTES);
  if (!read.ok) {
    return json(read.reason === "oversize" ? 413 : 400, { error: read.reason === "oversize" ? "payload_too_large" : "read_error" });
  }
  let raw: unknown;
  try {
    raw = parseSignedBodyBytes(read.bytes);
  } catch (err) {
    if (err instanceof ParseSignedBodyError) {
      const error =
        err.reason === "utf8"
          ? "invalid_utf8"
          : // Compared as a string so this example typechecks against the
            // published package as well as the current source, which is where
            // the `number-range` reason was added.
            (err.reason as string) === "number-range"
            ? "number_out_of_range"
            : "lone_surrogate";
      return json(400, { error });
    }
    return json(400, { error: "invalid_json" });
  }

  // 2. Decision 2 (encryption rejected): an encrypted envelope has a different
  //    shape (`type: "network.tulpa.encrypted"`, ciphertext, ...) and would fail
  //    validateMessage below, so detect it on the RAW object FIRST to return a
  //    clear capability error rather than a generic schema rejection.
  if (raw && typeof raw === "object" && (raw as { type?: unknown }).type === "network.tulpa.encrypted") {
    return json(400, { error: "encryption_not_supported" });
  }

  // 3. Validate envelope AND payload shape. validateMessage runs BEFORE
  //    signature verification — we refuse to canonicalize clearly-invalid input.
  let envelope: MessageEnvelope;
  try {
    envelope = validateMessage(raw);
  } catch (err) {
    return json(400, { error: "invalid_envelope", detail: err instanceof Error ? err.message.slice(0, 120) : "schema_error" });
  }

  // 4. Decision 1 (recipient binding): recipientDid is part of the signed
  //    transport base, so an envelope not addressed to us is misrouted or a
  //    replay against a different endpoint — refuse it.
  if (envelope.to !== OUR_DID) return json(400, { error: "wrong_recipient" });

  // 5. Intent allowlist, before resolving the sender's card — saves a network
  //    round-trip on unsupported intents.
  if (!ACCEPTED_INTENTS.has(envelope.intent)) {
    return json(400, { error: "unsupported_intent", accepted: [...ACCEPTED_INTENTS] });
  }

  // 6. Resolve the sender's verification keys: did:key decoded inline (no fetch);
  //    did:web resolved from its published card behind the SSRF guards; other
  //    methods resolve to []. Rotation-aware candidate set.
  const candidateKeys: CandidateKey[] = await resolveSenderKeys(envelope.from, { fetcher: env.fetcher });
  if (candidateKeys.length === 0) return json(400, { error: "unresolvable_sender" });

  // 7. Authenticate the request: verifyInkAuth checks the transport-auth
  //    signature (the Authorization header) against the resolved key set, plus
  //    the nonce store and the timestamp window. Its signature base covers the
  //    canonical JSON of the whole body, so a valid result also proves the
  //    envelope's canonical contents arrived intact and bound to OUR_DID — which
  //    is all a receiver that acts on the envelope now (forward a notification) needs.
  //    It does NOT separately verify the envelope's own `signature` field: that
  //    body signature is the portable, transport-independent proof of authorship.
  //    A receiver that RELAYS, STORES, or AUDITS the envelope should additionally
  //    call verifyMessage against the sender key set; this endpoint does not.
  const auth = await verifyInkAuth({
    authHeader: req.headers.get("Authorization") ?? undefined,
    method: "POST",
    path: INBOUND_PATH,
    recipientAgentId: OUR_DID,
    body: raw as Record<string, unknown>,
    resolveKeySet: (agentId) => (agentId === envelope.from ? candidateKeys : null),
    nonceStore: env.NONCES,
  });
  if (!auth.valid) return json(401, { error: "signature_verification_failed", reason: String(auth.error) });
  // The body's `from` could claim a different agentId than the key that actually
  // signed. Refuse the mismatch explicitly.
  if (auth.senderAgentId !== envelope.from) return json(401, { error: "from_field_mismatch" });

  // 8. Now the sender is authenticated: per-DID limit on the CANONICAL identity.
  //    For did:key, the URL fragment selects a verification method but does not
  //    change which key authenticated, so fragments must collapse to one bucket.
  const didGate = await checkRateLimits(env.RL, {
    ip,
    did: canonicalizeSenderDid(envelope.from),
    firstContact: envelope.intent === "connection_request",
  });
  if (!didGate.ok) return rateLimited(didGate);

  // 9. Terminal action: forward to the human inbox with verified-vs-claimed
  //    labels (decision 4).
  await sendEmail(env, buildForwardEmail(envelope));

  return json(200, { ok: true, inReplyTo: envelope.id, receiverDid: OUR_DID, correlationId: envelope.correlationId });
}
