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

// Defense-in-depth headers applied to every response. The JSON
// endpoints don't need a meaningful CSP but `nosniff` is cheap and
// stops content-type confusion; the landing HTML gets a strict CSP
// (set in landingResponse) because it carries inline CSS.
const BASE_SECURITY_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
};

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), {
    status: init.status ?? 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      ...BASE_SECURITY_HEADERS,
      ...(init.headers as Record<string, string> | undefined),
    },
  });
}

function landingResponse(html: string): Response {
  return new Response(html, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      ...BASE_SECURITY_HEADERS,
      // Inline styles only, no scripts, no external assets, no forms.
      "content-security-policy":
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
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
      return landingResponse(landingHtml(id.did, id.host));
    }
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: { ...BASE_SECURITY_HEADERS } });
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
      ...BASE_SECURITY_HEADERS,
    },
  });
}

function landingHtml(did: string, host: string): string {
  const escapeHtml = (value: string) =>
    value.replace(/[<>&"]/g, (c) =>
      c === "<" ? "&lt;" : c === ">" ? "&gt;" : c === "&" ? "&amp;" : "&quot;",
    );
  const safeDid = escapeHtml(did);
  const origin = `https://${host}`;
  const didDocUrl = `${origin}/.well-known/did.json`;
  const agentUrl = `${origin}/.well-known/ink/agent.json`;
  const inboundUrl = `${origin}/ink/v1/inbound`;
  return [
    "<!doctype html>",
    "<html lang=\"en\">",
    "<head>",
    "<meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
    "<title>INK Reference Receiver</title>",
    "<style>",
    ":root{color-scheme:dark;--bg:#0b0b12;--surface:#121220;--text:#f6f2ff;--muted:#b9b4c9;--accent:#c4b5fd;--line:#2a2540;--code:#171528}",
    "*{box-sizing:border-box}",
    "body{margin:0;background:radial-gradient(circle at 20% 0%,#17142a 0,#0b0b12 34rem);color:var(--text);font:16px/1.55 system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif}",
    "main{width:min(960px,100%);margin:0 auto;padding:48px 20px 36px}",
    "header{padding:28px 0 30px;border-bottom:1px solid var(--line)}",
    ".logo{width:160px;height:auto;display:block;margin-bottom:34px}",
    "h1,h2{font-family:Georgia,\"Times New Roman\",serif;font-weight:600;letter-spacing:0;margin:0;color:var(--text)}",
    "h1{max-width:760px;font-size:clamp(2.2rem,7vw,4.7rem);line-height:.98}",
    "h2{font-size:1.25rem;margin-bottom:12px}",
    "p{margin:0;color:var(--muted);max-width:680px}",
    ".lede{font-size:1.1rem;margin-top:18px}",
    ".accent{color:var(--accent)}",
    ".grid{display:grid;grid-template-columns:1.1fr .9fr;gap:18px;margin-top:24px}",
    "section{padding:22px 0;border-bottom:1px solid var(--line)}",
    ".panel{background:color-mix(in srgb,var(--surface) 86%,black);border:1px solid var(--line);border-radius:8px;padding:18px}",
    ".flow{display:grid;grid-template-columns:1fr auto 1fr;gap:12px;align-items:center;margin-top:16px}",
    ".step{min-height:92px;border:1px solid var(--line);border-radius:8px;padding:16px;background:var(--surface)}",
    ".step strong{display:block;color:var(--text);font-size:.95rem;margin-bottom:6px}",
    ".arrow{color:var(--accent);font-size:1.4rem}",
    ".kv{display:grid;gap:12px;margin-top:14px}",
    ".item span{display:block;color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}",
    "code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,\"Liberation Mono\",monospace}",
    "code{color:var(--text);background:var(--code);border:1px solid var(--line);border-radius:6px;padding:3px 6px}",
    "pre{margin:0;overflow:auto;white-space:pre-wrap;word-break:break-word;color:var(--text);background:var(--code);border:1px solid var(--line);border-radius:8px;padding:12px}",
    "a{color:var(--accent);text-decoration-thickness:1px;text-underline-offset:3px}",
    ".links{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}",
    ".links a{border:1px solid var(--line);border-radius:8px;padding:8px 10px;background:var(--surface);text-decoration:none}",
    "footer{padding-top:22px;color:var(--muted);font-size:.92rem}",
    "@media (max-width:760px){main{padding-top:30px}.grid,.flow{grid-template-columns:1fr}.arrow{display:none}.logo{width:132px}h1{font-size:2.5rem}}",
    "</style>",
    "</head>",
    "<body>",
    "<main>",
    "<header>",
    "<svg class=\"logo\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 80 28\" fill=\"none\" role=\"img\" aria-label=\"INK\">",
    "<path d=\"M10 1 L16 9 L16 16 L13.5 23 L12.5 23 L11.5 17 L10 14.5 L8.5 17 L7.5 23 L6.5 23 L4 16 L4 9 Z\" fill=\"#c4b5fd\"/>",
    "<circle cx=\"10\" cy=\"7.5\" r=\"1.5\" fill=\"#121220\"/>",
    "<path d=\"M24 9.5 L24 23 L27.5 23 L27.5 14.5 C27.5 12 29.5 10.5 32 10.5 C34 10.5 35.5 12 35.5 14 L35.5 23 L39 23 L39 13.5 C39 10 36.5 8 33 8 C30.5 8 28.5 9 27.5 10.5 L27.5 9.5 Z\" fill=\"#c4b5fd\"/>",
    "<path d=\"M45 1 L45 23 L48.5 23 L48.5 16 L51 14 L57.5 23 L62 23 L54 13 L60 5 L56 5 L48.5 14 L48.5 1 Z\" fill=\"#c4b5fd\"/>",
    "</svg>",
    "<h1>Reference Receiver</h1>",
    "<p class=\"lede\">A public INK test target. Send a signed envelope to the inbound endpoint and receive an acknowledgement response.</p>",
    "</header>",
    "<section aria-labelledby=\"what\">",
    "<h2 id=\"what\">What Happens Here</h2>",
    "<div class=\"flow\">",
    "<div class=\"step\"><strong>1. Send envelope</strong><p>Post a signed INK envelope to the receiver endpoint.</p></div>",
    "<div class=\"arrow\" aria-hidden=\"true\">&#8594;</div>",
    "<div class=\"step\"><strong>2. Get ack</strong><p>The receiver validates the envelope and returns an acknowledgement.</p></div>",
    "</div>",
    "</section>",
    "<div class=\"grid\">",
    "<section class=\"panel\" aria-labelledby=\"identity\">",
    "<h2 id=\"identity\">Identity</h2>",
    "<div class=\"kv\">",
    "<div class=\"item\"><span>DID</span><pre><code>" + safeDid + "</code></pre></div>",
    "<div class=\"item\"><span>Inbound endpoint</span><pre><code>" + escapeHtml(inboundUrl) + "</code></pre></div>",
    "</div>",
    "</section>",
    "<section class=\"panel\" aria-labelledby=\"documents\">",
    "<h2 id=\"documents\">Documents</h2>",
    "<div class=\"kv\">",
    "<div class=\"item\"><span>DID document</span><pre><code>" + escapeHtml(didDocUrl) + "</code></pre></div>",
    "<div class=\"item\"><span>Agent card</span><pre><code>" + escapeHtml(agentUrl) + "</code></pre></div>",
    "</div>",
    "<div class=\"links\">",
    "<a href=\"/.well-known/did.json\">Open DID doc</a>",
    "<a href=\"/.well-known/ink/agent.json\">Open agent card</a>",
    "</div>",
    "</section>",
    "</div>",
    "<section aria-labelledby=\"try\">",
    "<h2 id=\"try\">Try It</h2>",
    "<pre><code>curl -sS " + escapeHtml(agentUrl) + "</code></pre>",
    "<p style=\"margin-top:12px\">Use the <a href=\"https://github.com/Ad-Astra-Computing/ink/tree/main/examples/interop-cli\">interop CLI</a> to send a signed envelope to <code>" + escapeHtml(inboundUrl) + "</code>.</p>",
    "</section>",
    "<footer>",
    "Source: <a href=\"https://github.com/Ad-Astra-Computing/ink\">github.com/Ad-Astra-Computing/ink</a> / <code>examples/reference-receiver</code>",
    "</footer>",
    "</main>",
    "</body>",
    "</html>",
  ].join("\n");
}
