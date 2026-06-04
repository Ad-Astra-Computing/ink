/**
 * Sketch: the verify-then-forward inbound flow for the INK contact endpoint.
 *
 * Mirrors examples/reference-receiver/src/inbound.ts. The only behavioural
 * difference is the terminal action (forward to email instead of JSON ack) and
 * the four design decisions called out below. Names like resolveSenderKey,
 * verifyInkAuth and MessageEnvelopeSchema track the @adastracomputing/ink public
 * surface; confirm exact signatures against the installed version before wiring.
 *
 * This is illustrative, not a tested service.
 */
import {
  MessageEnvelopeSchema,
  verifyInkAuth,
  // resolveSenderKey: did:key decoded inline; did:web resolved behind the SSRF
  // guard. Lift the implementation from ../reference-receiver/src.
} from "@adastracomputing/ink";
import { checkRateLimits } from "./rate-limit.js";
import { buildForwardEmail, sendEmail } from "./forward-email.js";

const OUR_DID = "did:web:mcp.example.com"; // decision 1
const INBOUND_PATH = "/ink/v1/inbound";
const ACCEPTED_INTENTS = new Set(["connection_request", "intro_request", "ask"]);

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

export async function handleInbound(req: Request, env: Env): Promise<Response> {
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";

  // Pre-parse per-IP limit (cheap, before we trust anything). Typed rejection
  // with a backoff hint, not a bare 429.
  const ipGate = await checkRateLimits(env.RL, { ip, did: null, firstContact: true });
  if (!ipGate.ok) {
    return new Response(JSON.stringify({ error: "rate_limited", scope: ipGate.scope, retryable: true }),
      { status: 429, headers: { "content-type": "application/json", "Retry-After": String(ipGate.retryAfter) } });
  }

  // 1. Parse + schema-validate. MessageEnvelopeSchema accepts ink/0.1 and ink/0.2
  //    and rejects any other protocol value.
  const raw = await req.json().catch(() => null);
  const parsed = MessageEnvelopeSchema.safeParse(raw);
  if (!parsed.success) return json(400, { error: "invalid_envelope", details: parsed.error.issues });
  const envelope = parsed.data;

  // 2. Decision 1: recipient binding. recipientDid is inside the signed
  //    transport base, so an envelope not addressed to us is either misrouted or
  //    a replay attempt against a different endpoint.
  if (envelope.to !== OUR_DID) return json(400, { error: "wrong_recipient" });

  // 3. Decision 2: reject encryption. We advertise no encryption keys and only
  //    accept first-contact plaintext intents.
  if ((envelope as { type?: string }).type === "network.tulpa.encrypted") {
    return json(400, { error: "encryption_not_supported" });
  }
  if (!ACCEPTED_INTENTS.has(envelope.intent)) {
    return json(400, { error: "unsupported_intent", accepted: [...ACCEPTED_INTENTS] });
  }

  // 4. Resolve the sender's verification key (did:key inline, did:web SSRF-guarded).
  const senderKey = await resolveSenderKey(envelope.from, env);
  if (!senderKey) return json(400, { error: "unresolvable_sender" });

  // 5. Verify BOTH signatures and replay. verifyInkAuth checks the transport
  //    header against the §3.3 base and the nonce/timestamp window; the body
  //    signature is verified under the domain keyed off the signed `protocol`.
  const auth = await verifyInkAuth(
    {
      method: "POST",
      path: INBOUND_PATH,
      recipientDid: OUR_DID,
      body: envelope,
      authHeader: req.headers.get("Authorization"),
      nonceStore: env.NONCES,
      now: Date.now(),
    },
    senderKey,
  );
  if (!auth.valid) return json(401, { error: "signature_verification_failed", reason: auth.reason });

  // 6. Now that the sender is authenticated, the per-DID limit (decision 3).
  const didGate = await checkRateLimits(env.RL, {
    ip, did: envelope.from, firstContact: envelope.intent === "connection_request",
  });
  if (!didGate.ok) {
    return new Response(JSON.stringify({ error: "rate_limited", scope: didGate.scope, retryable: true }),
      { status: 429, headers: { "content-type": "application/json", "Retry-After": String(didGate.retryAfter) } });
  }

  // 7. Terminal action: forward to the human inbox with verified-vs-claimed
  //    labels (decision 4).
  await sendEmail(env, buildForwardEmail(envelope));

  return json(200, { ok: true, inReplyTo: envelope.id, receiverDid: OUR_DID, correlationId: envelope.correlationId });
}

// Wiring helpers (env shape, resolveSenderKey) live in index.ts / the lifted
// reference-receiver modules and are omitted from this sketch.
declare function resolveSenderKey(did: string, env: Env): Promise<Uint8Array | null>;
interface Env { RL: KVNamespace; NONCES: KVNamespace; [k: string]: unknown }
type KVNamespace = { get(k: string): Promise<string | null>; put(k: string, v: string, o?: { expirationTtl?: number }): Promise<void> };
