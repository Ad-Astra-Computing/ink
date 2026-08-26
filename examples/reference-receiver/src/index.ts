/**
 * INK Reference Receiver — Cloudflare Worker entry point.
 *
 * Routes:
 *   GET  /.well-known/did.json               → did:web doc
 *   GET  /ink/v1/:agentId/agent.json         → agent card (discovery surface)
 *   GET  /.well-known/ink/agent.json         → agent card (alias, identical bytes)
 *   POST /ink/v1/inbound                     → envelope handler
 *   GET  /                                   → minimal HTML landing page
 *
 * `/ink/v1/:agentId/agent.json` is the path the reference library's
 * `fetchAgentCard` builds, so a consumer that only knows the DID and the
 * origin can reach this receiver's card. `/.well-known/ink/agent.json` stays
 * as an alias serving byte-identical bytes for consumers that resolve through
 * the well-known convention. The two agree because the card is a deterministic
 * function of configuration and key material, not because anything is cached.
 *
 * The worker is the smallest plausibly-useful INK receiver: it
 * publishes a stable DID, accepts envelopes from `did:key:` and
 * `did:web:`-resolvable senders, verifies the transport signature
 * against the resolved sender key, and replies with a plain (unsigned)
 * JSON acknowledgement. Signing the response is a Phase B follow-up.
 *
 * It's intentionally NOT a model for a production receiver: there is
 * no user authentication, no policy layer, no spam scoring, no
 * receipt persistence. Adopters who want those should fork this
 * worker, lift the validation + signing scaffolding, and bolt on
 * their own intent handlers.
 */

import { buildAgentCard, resolveCardUpdatedAt } from "./agent-card.js";
import { buildDidDocument } from "./did-web.js";
import { loadReceiverIdentity, loadEncryptionIdentity, deriveDidWeb, selfCheckIdentity } from "./keys.js";
import type { ReceiverEnv } from "./keys.js";
import { processInbound, readBoundedBody } from "./inbound.js";
import { checkRateLimit } from "./rate-limit.js";
import { recordAudit } from "./audit-log.js";
import { InMemoryNonceStore } from "./nonce-store.js";

export interface Env extends ReceiverEnv {
  INK_RECEIVER: KVNamespace;
}

type PreparedIdentity = Awaited<ReturnType<typeof prepareIdentity>>;

/**
 * One-time per-isolate identity load + sanity check. Cached in
 * module-scope so a deluge of inbound requests doesn't re-do the
 * key decode + canary signature on every call.
 *
 * The PROMISE is cached, not the resolved value: on a cold isolate several
 * requests can enter `fetch` before the first load settles, and caching only
 * the result would let each of them run its own load. One shared promise means
 * one decode and one canary signature per isolate.
 *
 * The cache is keyed by nothing, so an isolate that has already loaded an
 * identity keeps serving it for its whole life — a signing-config change (or a
 * change to the card's configured `updatedAt`, resolved here alongside it) is
 * NOT picked up hot. That is safe in the deployed topology and only there:
 * updating a Worker secret or var publishes a new deployment version, and
 * every isolate runs exactly one version, so the old identity dies with the
 * old code. Do not read this as support for hot key rotation; a receiver that
 * loads its key from somewhere mutable at runtime needs a real invalidation
 * signal here, not this cache.
 */
let cachedIdentity: Promise<PreparedIdentity> | null = null;
const isolateNonceStore = new InMemoryNonceStore({ capacity: 4096 });
async function prepareIdentity(env: Env) {
  const identity = loadReceiverIdentity(env);
  await selfCheckIdentity(identity);
  // Optional: absent unless INK_RECEIVER_ENCRYPTION_SEED is set. A malformed
  // seed throws here rather than at request time, so a bad deploy fails loudly
  // instead of quietly serving a card with no encryption key.
  const encryption = loadEncryptionIdentity(env);
  const host = env.INK_RECEIVER_HOST?.trim() ?? "";
  if (!host) throw new Error("missing_host: set INK_RECEIVER_HOST in wrangler vars");
  const did = deriveDidWeb(host);
  const cardUpdatedAt = resolveCardUpdatedAt(env);
  return { identity, encryption, host, did, cardUpdatedAt };
}

/**
 * Shared in-flight identity load. A rejected load is evicted so a
 * misconfiguration that is later corrected does not stay cached as a
 * permanent 500 for the life of the isolate.
 */
function identityOnce(env: Env): Promise<PreparedIdentity> {
  if (cachedIdentity) return cachedIdentity;
  const pending = prepareIdentity(env);
  cachedIdentity = pending;
  pending.catch(() => { if (cachedIdentity === pending) cachedIdentity = null; });
  return pending;
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

/**
 * Match `/ink/v1/<agentId>/agent.json` and return the decoded agentId, or
 * null when the path is not a versioned card path. The segment is a single
 * path component: a DID's colons arrive percent-encoded, and anything that
 * is not valid percent-encoding is not a card path.
 */
export function matchVersionedCardPath(path: string): string | null {
  const m = /^\/ink\/v1\/([^/]+)\/agent\.json$/.exec(path);
  if (!m) return null;
  try {
    return decodeURIComponent(m[1]!);
  } catch {
    return null;
  }
}

/**
 * The served card body, built and signed once per isolate.
 *
 * This cache is a PERFORMANCE optimization and nothing else. It keeps the
 * Ed25519 signature and the JCS canonicalization off the hot path for every
 * request after the first one an isolate serves.
 *
 * It is NOT what makes the versioned path and the well-known alias agree. That
 * rests on `buildAgentCard` being a pure function of configuration and key
 * material (see `agent-card.ts`): the same config produces the same bytes in
 * any isolate, in any process, at any time. Caching could never have carried
 * that claim — Cloudflare gives a low-traffic worker a cold isolate for nearly
 * every request, so in production almost every fetch missed this cache. Delete
 * the cache and the alias contract still holds; reintroduce a clock read into
 * the card and no cache can save it.
 *
 * The PROMISE is cached, not the finished body, so a burst of concurrent cold
 * requests shares one build instead of running one each.
 */
let cachedCard: { key: string; body: Promise<string> } | null = null;
function cachedCardBody(id: PreparedIdentity): Promise<string> {
  // Keyed by every input the card body depends on, so a config change can
  // never be served from a stale entry.
  // The encryption key is part of the cache key: a deployment that gains or
  // rotates one must not keep serving the card that predates it.
  const key = JSON.stringify([
    id.did,
    id.host,
    id.cardUpdatedAt,
    id.identity.publicKeyMultibase,
    id.encryption?.publicKeyMultibase ?? null,
  ]);
  if (cachedCard && cachedCard.key === key) return cachedCard.body;
  const body = buildAgentCard({
    did: id.did,
    host: id.host,
    identity: id.identity,
    encryption: id.encryption,
    updatedAt: id.cardUpdatedAt,
  }).then((card) => JSON.stringify(card));
  const entry = { key, body };
  cachedCard = entry;
  // Never cache a failed build: evict so the next request retries instead of
  // pinning a rejected promise for the life of the isolate.
  body.catch(() => { if (cachedCard === entry) cachedCard = null; });
  return body;
}

/**
 * Serve the card, or a JSON 500 if the build fails. A throw out of `fetch`
 * would hand the caller the runtime's opaque error page instead of a
 * machine-readable body on an endpoint whose whole job is being fetched by
 * other people's code.
 */
async function cardRoute(id: PreparedIdentity): Promise<Response> {
  try {
    return cardResponse(await cachedCardBody(id));
  } catch (err) {
    const msg = err instanceof Error ? err.message : "unknown";
    return jsonResponse({ error: "agent_card_unavailable", detail: msg }, { status: 500 });
  }
}

function cardResponse(body: string): Response {
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      ...BASE_SECURITY_HEADERS,
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

// INK favicon: the nib mark (the wordmark's "I") in lavender on a dark
// rounded square so it reads at 16px. Served same-origin so the CSP
// `img-src 'self'` covers it; cached a day since it never changes.
const FAVICON_SVG = [
  "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\">",
  "<rect width=\"32\" height=\"32\" rx=\"7\" fill=\"#121220\"/>",
  "<g transform=\"translate(6 4)\">",
  "<path d=\"M10 1 L16 9 L16 16 L13.5 23 L12.5 23 L11.5 17 L10 14.5 L8.5 17 L7.5 23 L6.5 23 L4 16 L4 9 Z\" fill=\"#c4b5fd\"/>",
  "<circle cx=\"10\" cy=\"7.5\" r=\"1.5\" fill=\"#121220\"/>",
  "</g>",
  "</svg>",
].join("");

function faviconResponse(): Response {
  return new Response(FAVICON_SVG, {
    status: 200,
    headers: {
      "content-type": "image/svg+xml",
      "cache-control": "public, max-age=86400",
      ...BASE_SECURITY_HEADERS,
    },
  });
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    let id: PreparedIdentity;
    try {
      id = await identityOnce(env);
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
      return cardRoute(id);
    }
    // Versioned discovery path. The agentId segment is percent-encoded by the
    // client (a DID carries colons), so decode before comparing. A card is
    // served only for THIS receiver's own agentId: any other id is a 404, not
    // a card for someone else.
    if (method === "GET") {
      const versioned = matchVersionedCardPath(path);
      if (versioned !== null) {
        if (versioned !== id.did) return jsonResponse({ error: "not_found" }, { status: 404 });
        return cardRoute(id);
      }
    }
    if (method === "POST" && path === "/ink/v1/inbound") {
      return handleInbound(req, env, ctx, id);
    }
    if (method === "GET" && path === "/") {
      return landingResponse(landingHtml(id.did, id.host));
    }
    if (method === "GET" && (path === "/favicon.svg" || path === "/favicon.ico")) {
      return faviconResponse();
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
  id: PreparedIdentity,
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
  const outcome = await processInbound(body.bytes, req.headers.get("authorization") ?? undefined, {
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
        : outcome.verdict === "utf8" ? "utf8"
        : "oversize"}`,
      errorCode: outcome.errorCode,
    }));
    if (outcome.reason) {
      // Structured, one line, greppable in `wrangler tail`. This is the only
      // place the receiver explains itself to its OPERATOR; the same reason
      // goes back to the sender below. Fixed enum plus the sender's own DID:
      // nothing fetched from a third-party host is logged.
      console.warn(JSON.stringify({
        event: "sender_key_unresolved",
        reason: outcome.reason,
        sender: outcome.sender.slice(0, 200),
        intent: outcome.intent.slice(0, 64),
      }));
    }
    return jsonResponse({
      error: outcome.verdict,
      code: outcome.errorCode,
      ...(outcome.reason ? { reason: outcome.reason, hint: outcome.hint } : {}),
    }, { status: 400 });
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
  const agentUrl = `${origin}/ink/v1/${encodeURIComponent(did)}/agent.json`;
  const inboundUrl = `${origin}/ink/v1/inbound`;
  return [
    "<!doctype html>",
    "<html lang=\"en\">",
    "<head>",
    "<meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
    "<title>INK Reference Receiver</title>",
    "<link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\">",
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
    "footer{margin-top:30px;padding-top:24px;border-top:1px solid var(--line);display:flex;flex-wrap:wrap;gap:16px;align-items:flex-end;justify-content:space-between;color:var(--muted);font-size:.88rem}",
    "footer .brand{font-family:Georgia,\"Times New Roman\",serif;font-size:1rem;color:var(--text);letter-spacing:.01em}",
    "footer .copy{margin-top:4px;color:var(--muted);font-size:.8rem}",
    ".footer-links{display:flex;flex-wrap:wrap;gap:10px;align-items:center}",
    ".footer-link{display:inline-flex;align-items:center;gap:7px;min-height:32px;padding:0 12px;border:1px solid var(--line);border-radius:999px;background:rgba(18,18,32,.72);color:var(--muted);font:500 13px/1 system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;text-decoration:none;white-space:nowrap;transition:color .16s ease,border-color .16s ease,background-color .16s ease}",
    ".footer-link:hover{color:#fff;border-color:rgba(196,181,253,.58);background:rgba(196,181,253,.08)}",
    ".footer-link:focus-visible{outline:2px solid var(--accent);outline-offset:3px}",
    ".footer-link svg{width:16px;height:16px;flex:0 0 auto}",
    ".footer-link .ink-mark{color:var(--accent)}",
    "@media (max-width:760px){main{padding-top:30px}.grid,.flow{grid-template-columns:1fr}.arrow{display:none}.logo{width:132px}h1{font-size:2.4rem}footer{flex-direction:column;align-items:flex-start}.footer-links{justify-content:flex-start}}",
    "@media (max-width:380px){main{padding-left:14px;padding-right:14px}.lede{font-size:1rem}}",
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
    "<a href=\"" + escapeHtml(new URL(agentUrl).pathname) + "\">Open agent card</a>",
    "</div>",
    "</section>",
    "</div>",
    "<section aria-labelledby=\"try\">",
    "<h2 id=\"try\">Try It</h2>",
    "<pre><code>curl -sS " + escapeHtml(agentUrl) + "</code></pre>",
    "<p style=\"margin-top:12px\">Then send a signed envelope to the inbound endpoint above with the <a href=\"https://github.com/Ad-Astra-Computing/ink/tree/main/examples/interop-cli\">interop CLI</a>.</p>",
    "</section>",
    "<footer>",
    "<div>",
    "<div class=\"brand\">Ad Astra Computing</div>",
    "<div class=\"copy\">&copy; 2026 Ad Astra Computing, Inc. All rights reserved.</div>",
    "</div>",
    "<nav class=\"footer-links\" aria-label=\"Footer links\">",
    "<a class=\"footer-link\" href=\"https://ink.tulpa.network\" aria-label=\"INK protocol docs\">",
    "<svg class=\"ink-mark\" viewBox=\"3 0 14 26\" fill=\"currentColor\" aria-hidden=\"true\" focusable=\"false\">",
    "<path d=\"M10 1 L16 9 L16 16 L13.5 23 L12.5 23 L11.5 17 L10 14.5 L8.5 17 L7.5 23 L6.5 23 L4 16 L4 9 Z\"/>",
    "<circle cx=\"10\" cy=\"7.5\" r=\"1.5\" fill=\"#0b0b12\"/>",
    "</svg><span>INK</span></a>",
    "<a class=\"footer-link\" href=\"https://github.com/Ad-Astra-Computing/ink/tree/main/examples/reference-receiver\" aria-label=\"View INK source on GitHub\">",
    "<svg viewBox=\"0 0 16 16\" fill=\"currentColor\" aria-hidden=\"true\" focusable=\"false\">",
    "<path d=\"M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82A7.63 7.63 0 0 1 8 3.86c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z\"/>",
    "</svg><span>Source</span></a>",
    "</nav>",
    "</footer>",
    "</main>",
    "</body>",
    "</html>",
  ].join("\n");
}
