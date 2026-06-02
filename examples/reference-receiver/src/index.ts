/**
 * INK Reference Receiver — Cloudflare Worker entry point.
 *
 * Routes:
 *   GET  /.well-known/did.json            → did:web doc
 *   GET  /.well-known/ink/agent.json      → agent card
 *   POST /ink/v1/inbound                  → envelope handler
 *   GET  /                                → minimal HTML landing page
 *
 * The worker is the smallest plausibly-useful INK receiver: it
 * publishes a stable DID, accepts envelopes from any
 * `did:web:`-resolvable sender, verifies the signature against the
 * sender's published agent card, and replies with a signed
 * `ping_ack` or `ask_response` envelope.
 *
 * It's intentionally NOT a model for a production receiver: there is
 * no user authentication, no policy layer, no spam scoring, no
 * receipt persistence. Adopters who want those should fork this
 * worker, lift the validation + signing scaffolding, and bolt on
 * their own intent handlers.
 */

import { buildAgentCard } from "./agent-card.js";
import { buildDidDocument } from "./did-web.js";
import { loadReceiverIdentity, deriveDidWeb, selfCheckIdentity } from "./keys.js";
import type { ReceiverEnv } from "./keys.js";
import { processInbound, readBoundedBody } from "./inbound.js";
import { checkRateLimit } from "./rate-limit.js";
import { recordAudit } from "./audit-log.js";
import { InMemoryNonceStore } from "./nonce-store.js";

export interface Env extends ReceiverEnv {
  INK_RECEIVER: KVNamespace;
}

/**
 * One-time per-isolate identity load + sanity check. Cached in
 * module-scope so a deluge of inbound requests doesn't re-do the
 * key decode + canary signature on every call.
 */
let cachedIdentity: Awaited<ReturnType<typeof prepareIdentity>> | null = null;
const isolateNonceStore = new InMemoryNonceStore({ capacity: 4096 });
async function prepareIdentity(env: Env) {
  const identity = loadReceiverIdentity(env);
  await selfCheckIdentity(identity);
  const host = env.INK_RECEIVER_HOST?.trim() ?? "";
  if (!host) throw new Error("missing_host: set INK_RECEIVER_HOST in wrangler vars");
  const did = deriveDidWeb(host);
  return { identity, host, did };
}

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), {
    status: init.status ?? 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      ...(init.headers as Record<string, string> | undefined),
    },
  });
}

function safeJsonText(value: unknown): string {
  try { return JSON.stringify(value); } catch { return "{}"; }
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    let id: { identity: Awaited<ReturnType<typeof loadReceiverIdentity>>; host: string; did: string };
    try {
      if (!cachedIdentity) cachedIdentity = await prepareIdentity(env);
      id = cachedIdentity;
    } catch (err) {
      const msg = err instanceof Error ? err.message : "unknown";
      return jsonResponse({ error: "receiver_misconfigured", detail: msg }, { status: 500 });
    }
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;
    if (method === "GET" && path === "/.well-known/did.json") {
      return jsonResponse(buildDidDocument({ did: id.did, host: id.host, identity: id.identity }));
    }
    if (method === "GET" && path === "/.well-known/ink/agent.json") {
      return jsonResponse(buildAgentCard({ did: id.did, host: id.host, identity: id.identity }));
    }
    if (method === "POST" && path === "/ink/v1/inbound") {
      return handleInbound(req, env, ctx, id);
    }
    if (method === "GET" && path === "/") {
      return new Response(landingHtml(id.did), {
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
      });
    }
    if (method === "OPTIONS") {
      return new Response(null, { status: 204 });
    }
    return jsonResponse({ error: "not_found" }, { status: 404 });
  },
};

async function handleInbound(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  id: { identity: Awaited<ReturnType<typeof loadReceiverIdentity>>; host: string; did: string },
): Promise<Response> {
  const ct = req.headers.get("content-type") ?? "";
  if (!ct.toLowerCase().startsWith("application/json")) {
    return jsonResponse({ error: "unsupported_content_type" }, { status: 415 });
  }
  const body = await readBoundedBody(req);
  if (!body.ok) {
    ctx.waitUntil(recordAudit({
      kv: env.INK_RECEIVER, sender: "?", intent: "?",
      verdict: "rejected_oversize", errorCode: body.reason,
    }));
    return jsonResponse({ error: body.reason }, { status: 413 });
  }
  // Rate limit on the source IP first (so a single attacker can't
  // saturate us before we even parse the envelope). The per-sender
  // DID limit is layered on top, applied AFTER parsing succeeds.
  const ipKey = req.headers.get("cf-connecting-ip") ?? "anon";
  const ipVerdict = await checkRateLimit({
    kv: env.INK_RECEIVER,
    senderKey: `ip:${ipKey}`,
    limit: 120,
    windowSec: 60,
  });
  if (!ipVerdict.allowed) {
    ctx.waitUntil(recordAudit({
      kv: env.INK_RECEIVER, sender: ipKey, intent: "?",
      verdict: "rejected_rate_limit", errorCode: "ip_limit",
    }));
    return jsonResponse({ error: "rate_limited", scope: "ip", resetSec: ipVerdict.resetSec }, { status: 429 });
  }
  const outcome = await processInbound(body.text, req.headers.get("authorization") ?? undefined, {
    identity: id.identity,
    receiverDid: id.did,
    nonceStore: isolateNonceStore,
  });
  if (outcome.kind === "rejected") {
    ctx.waitUntil(recordAudit({
      kv: env.INK_RECEIVER, sender: outcome.sender, intent: outcome.intent,
      verdict: `rejected_${outcome.verdict === "schema" ? "schema"
        : outcome.verdict === "signature" ? "signature"
        : outcome.verdict === "unsupported_intent" ? "unsupported_intent"
        : "oversize"}`,
      errorCode: outcome.errorCode,
    }));
    return jsonResponse({ error: outcome.verdict, code: outcome.errorCode }, { status: 400 });
  }
  // Per-sender-DID rate limit, applied after we know the sender. A
  // signature-fraud attacker could rotate DIDs to evade this, so the
  // IP-bucket above is the primary backstop and the DID bucket is
  // mostly to keep one well-behaved sender from running away.
  const senderVerdict = await checkRateLimit({
    kv: env.INK_RECEIVER,
    senderKey: `did:${outcome.sender}`,
    limit: 30,
    windowSec: 60,
  });
  if (!senderVerdict.allowed) {
    ctx.waitUntil(recordAudit({
      kv: env.INK_RECEIVER, sender: outcome.sender, intent: outcome.intent,
      verdict: "rejected_rate_limit", errorCode: "sender_limit",
    }));
    return jsonResponse({ error: "rate_limited", scope: "sender", resetSec: senderVerdict.resetSec }, { status: 429 });
  }
  ctx.waitUntil(recordAudit({
    kv: env.INK_RECEIVER, sender: outcome.sender, intent: outcome.intent,
    verdict: "accepted",
  }));
  return new Response(safeJsonText(outcome.response), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}

function landingHtml(did: string): string {
  const safeDid = did.replace(/[<>&]/g, (c) => c === "<" ? "&lt;" : c === ">" ? "&gt;" : "&amp;");
  return [
    "<!doctype html>",
    "<html lang=\"en\"><head><meta charset=\"utf-8\">",
    "<title>INK Reference Receiver</title>",
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
    "<style>body{font:14px/1.5 system-ui;max-width:720px;margin:48px auto;padding:0 20px;color:#111}code{background:#eee;padding:2px 6px;border-radius:4px}h1{font-size:20px}</style>",
    "</head><body>",
    "<h1>INK Reference Receiver</h1>",
    "<p>A public test target for the <a href=\"https://ink.tulpa.network\">INK protocol</a>. ",
    "Send a signed envelope to <code>/ink/v1/inbound</code> and receive a signed response.</p>",
    `<p>DID: <code>${safeDid}</code></p>`,
    "<ul>",
    "<li><a href=\"/.well-known/did.json\">DID document</a></li>",
    "<li><a href=\"/.well-known/ink/agent.json\">Agent card</a></li>",
    "</ul>",
    "<p>Source code lives in the <a href=\"https://github.com/Ad-Astra-Computing/ink\">ink repo</a> ",
    "under <code>examples/reference-receiver/</code>. Reuse, fork, lift.</p>",
    "</body></html>",
  ].join("\n");
}
