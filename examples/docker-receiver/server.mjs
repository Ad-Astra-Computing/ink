/**
 * node:http adapter around the bundled INK reference receiver.
 *
 * The receiver is a Web `fetch(request, env, ctx)` handler. This wraps it so
 * a plain Node process (and therefore any container) can serve it:
 *
 *   - Each Node request is converted to a Web `Request`.
 *   - `env` is `process.env` plus an in-memory `INK_RECEIVER` KV shim (the
 *     receiver only calls `get` and `put` on it, for rate-limit counters and
 *     the audit ring). A real deployment swaps in a shared store (Redis,
 *     Postgres, a KV service) so limits and audit survive restarts and scale
 *     across replicas.
 *   - `ctx.waitUntil` runs the receiver's fire-and-forget audit writes without
 *     blocking the response, mirroring the Workers contract.
 *
 * The receiver code is unchanged from `../reference-receiver`; only the
 * transport host differs. Config comes from the environment, same as the
 * Worker: INK_RECEIVER_SIGNING_SEED, INK_RECEIVER_PUBLIC_KEY_MULTIBASE,
 * INK_RECEIVER_HOST, and PORT.
 */

import { createServer } from "node:http";
import worker from "./dist/worker.mjs";

const PORT = Number(process.env.PORT ?? 8787);
const HOST = process.env.HOST ?? "0.0.0.0";
const MAX_REQUEST_BYTES = 256 * 1024; // the receiver caps the body again at 64 KiB

/** In-memory KV shim: `get` and `put` with TTL, the surface the receiver uses. */
export function createMemoryKv() {
  const store = new Map();
  return {
    async get(key) {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expireAt && entry.expireAt <= Date.now()) {
        store.delete(key);
        return null;
      }
      return entry.value;
    },
    async put(key, value, options) {
      const ttl = options?.expirationTtl;
      store.set(key, {
        value: String(value),
        expireAt: typeof ttl === "number" && ttl > 0 ? Date.now() + ttl * 1000 : 0,
      });
    },
  };
}

/** Build the env object the Worker handler reads its config and bindings from. */
export function createEnv(overrides = {}) {
  return { ...process.env, INK_RECEIVER: createMemoryKv(), ...overrides };
}

/** Read the request body with a hard byte cap so a giant POST cannot pin us. */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_REQUEST_BYTES) {
        reject(new Error("request_too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// The receiver keys its IP rate limit on the `cf-connecting-ip` header (it runs
// on Cloudflare in production). Off Cloudflare that header is attacker-supplied,
// so we never forward the client's copy: by default we set it from the real TCP
// peer, and behind a trusted proxy we read it from a configured forwarding
// header instead. Set `TRUST_PROXY_HEADER=x-forwarded-for` (or whatever your
// proxy sets) only when a proxy you control overwrites that header.
const TRUST_PROXY_HEADER = (process.env.TRUST_PROXY_HEADER ?? "").toLowerCase();

function clientIp(nodeReq) {
  if (TRUST_PROXY_HEADER) {
    const raw = nodeReq.headers[TRUST_PROXY_HEADER];
    const value = Array.isArray(raw) ? raw[0] : raw;
    const first = typeof value === "string" ? value.split(",")[0]?.trim() : "";
    if (first) return first;
  }
  return nodeReq.socket?.remoteAddress ?? "";
}

/** Turn a Node request into a Web Request for the Worker handler. */
async function toWebRequest(nodeReq) {
  const host = nodeReq.headers.host ?? `localhost:${PORT}`;
  const url = `http://${host}${nodeReq.url}`;
  const hasBody = nodeReq.method !== "GET" && nodeReq.method !== "HEAD";
  const body = hasBody ? await readBody(nodeReq) : undefined;
  const headers = new Headers();
  for (const [key, value] of Object.entries(nodeReq.headers)) {
    if (value === undefined) continue;
    if (key.toLowerCase() === "cf-connecting-ip") continue; // never trust the client's copy
    headers.set(key, Array.isArray(value) ? value.join(", ") : value);
  }
  const ip = clientIp(nodeReq);
  if (ip) headers.set("cf-connecting-ip", ip);
  return new Request(url, {
    method: nodeReq.method,
    headers,
    body: body && body.length > 0 ? body : undefined,
  });
}

export function createApp(env = createEnv()) {
  const ctx = {
    waitUntil(promise) {
      Promise.resolve(promise).catch(() => {});
    },
    passThroughOnException() {},
  };
  return async (nodeReq, nodeRes) => {
    let request;
    try {
      request = await toWebRequest(nodeReq);
    } catch {
      nodeRes.statusCode = 413;
      nodeRes.setHeader("content-type", "application/json");
      nodeRes.end(JSON.stringify({ error: "request_too_large" }));
      return;
    }
    let response;
    try {
      response = await worker.fetch(request, env, ctx);
    } catch (err) {
      nodeRes.statusCode = 500;
      nodeRes.setHeader("content-type", "application/json");
      nodeRes.end(JSON.stringify({ error: "internal_error" }));
      console.error("handler error:", err);
      return;
    }
    nodeRes.statusCode = response.status;
    response.headers.forEach((value, key) => nodeRes.setHeader(key, value));
    const buf = Buffer.from(await response.arrayBuffer());
    nodeRes.end(buf);
  };
}

/** Start the HTTP server. Returns the node server (for tests / graceful stop). */
export function startServer(port = PORT, host = HOST) {
  const env = createEnv();
  const server = createServer(createApp(env));
  return new Promise((resolve) => {
    server.listen(port, host, () => resolve(server));
  });
}

// Run directly (not when imported by a test).
if (import.meta.url === `file://${process.argv[1]}`) {
  const server = await startServer();
  const addr = server.address();
  const shown = typeof addr === "object" && addr ? `${addr.address}:${addr.port}` : String(addr);
  console.log(`INK reference receiver listening on http://${shown}`);
  console.log(`  did:web host: ${process.env.INK_RECEIVER_HOST ?? "(unset — set INK_RECEIVER_HOST)"}`);
  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => server.close(() => process.exit(0)));
  }
}
