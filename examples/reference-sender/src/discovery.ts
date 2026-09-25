/**
 * Inbox endpoint discovery.
 *
 * Where does a signed envelope get POSTed? It depends on the recipient
 * DID method:
 *
 *   - `did:key:` cannot publish a service endpoint — the identifier is
 *     just a key. There is nowhere to look it up, so the caller MUST
 *     supply the endpoint URL explicitly.
 *   - `did:web:` publishes an Agent Card at the versioned discovery path
 *     `<origin>/ink/v1/<agentId>/agent.json`. This module resolves the DID
 *     document first and honours an `InkAgentCard` service entry on the same
 *     authority when one is declared, otherwise it fetches the versioned
 *     path. It applies the discovery response contract (status 200, JSON
 *     content type, size cap, schema, protocol, and the agentId identity
 *     binding) and reads the inbox from the validated card with
 *     `resolveAgentInbox`. An explicit endpoint, when supplied, overrides
 *     discovery.
 *
 * The versioned path is the sole normative discovery surface
 * (`specs/ink-resolver.md` §3.2): a resolver MUST NOT depend on the
 * `/.well-known/ink/agent.json` alias or fall back to it, so a peer that
 * publishes only the alias is not discoverable here. This matches the
 * reference receiver's resolver.
 *
 * The SSRF gate here is the same static-literal classifier used on the
 * send path: https only, no userinfo, no fragment, no IP-literal or
 * private/loopback/special-use host. It does NOT defend against DNS
 * rebinding; pass a connect-time-IP-pinning `fetchImpl` when the host is
 * untrusted.
 */

import { evaluateAgentCardFetch, resolveAgentInbox } from "@adastracomputing/ink";
import { validateTargetUrl } from "./transport.ts";
import { didWebOrigin } from "./host-safety.ts";

const TIMEOUT_MS = 5_000;
/** Discovery response body cap, matching the receiver's 64 KiB card cap. */
const MAX_CARD_BYTES = 64 * 1024;

export type DiscoveryError =
  | "endpoint_required_for_did_key"
  | "unsupported_did_method"
  | "invalid_did_web"
  | "card_unreachable"
  | "card_rejected"
  | "private_host_blocked";

export type EndpointResolution =
  | { ok: true; endpoint: string; source: "explicit" | "did-web-card" }
  | { ok: false; reason: DiscoveryError };

export interface ResolveEndpointInput {
  recipientDid: string;
  /** Caller-supplied endpoint; always wins when present. */
  explicitEndpoint?: string;
  /** Injectable fetch for tests / connect-time IP pinning. */
  fetchImpl?: typeof fetch;
  /** Allow private/loopback card hosts (local dev only). */
  allowPrivateHosts?: boolean;
  /** Card-fetch budget covering connect AND body read. Default 5s. */
  timeoutMs?: number;
}

export interface DidWebTargets {
  /** Serialized authority: host, plus `:port` for any non-default port. */
  host: string;
  /** The DID document URL, per did:web 1.0. */
  didDocUrl: string;
  /**
   * The versioned discovery path. The sole normative discovery surface: no
   * `/.well-known/ink/agent.json` alias URL is derived, because a resolver
   * MUST NOT depend on it (`specs/ink-resolver.md` §3.2).
   */
  versionedCardUrl: string;
}

/**
 * Derive the URLs a `did:web:` identifier resolves through.
 *   did:web:host          → https://host/.well-known/did.json
 *   did:web:host:a:b      → https://host/a/b/did.json
 *   card, either form     → https://host/ink/v1/<encoded did>/agent.json
 *
 * A `%3A`-encoded port is carried, never dropped: resolving at the default
 * port would silently target a different origin than the identifier names.
 */
export function didWebTargets(did: string): DidWebTargets | null {
  if (!did.startsWith("did:web:")) return null;
  const rest = did.slice("did:web:".length);
  if (rest.length === 0 || rest.length > 1024) return null;
  const segments = rest.split(":");
  if (segments.some((seg) => seg.length === 0)) return null;
  const origin = didWebOrigin(segments[0]!);
  if (origin === null) return null;
  const pathSegments = segments.slice(1);
  const safeSegment = /^[A-Za-z0-9._~\-]+$/;
  for (const seg of pathSegments) {
    // "." and ".." satisfy the safe-char class but are traversal in a URL.
    if (seg === "." || seg === ".." || !safeSegment.test(seg)) return null;
  }
  const didDocUrl = pathSegments.length === 0
    ? `${origin}/.well-known/did.json`
    : `${origin}/${pathSegments.join("/")}/did.json`;
  return {
    host: new URL(origin).host,
    didDocUrl,
    versionedCardUrl: `${origin}/ink/v1/${encodeURIComponent(did)}/agent.json`,
  };
}

export async function resolveInboxEndpoint(
  input: ResolveEndpointInput,
): Promise<EndpointResolution> {
  if (input.explicitEndpoint) {
    return { ok: true, endpoint: input.explicitEndpoint, source: "explicit" };
  }
  if (input.recipientDid.startsWith("did:key:")) {
    return { ok: false, reason: "endpoint_required_for_did_key" };
  }
  if (!input.recipientDid.startsWith("did:web:")) {
    return { ok: false, reason: "unsupported_did_method" };
  }
  const targets = didWebTargets(input.recipientDid);
  if (!targets) return { ok: false, reason: "invalid_did_web" };

  // SSRF gate on the derived URLs. The card host equals the DID host by
  // construction, so the value here is the https / userinfo / fragment /
  // IP-literal / private-host checks; `allowPrivateHosts` relaxes only the
  // private-host refusal for local dev. The derived URL is well-formed https,
  // so the only reachable failure is a blocked private host.
  const validated = validateTargetUrl(targets.versionedCardUrl, {
    allowPrivateHosts: input.allowPrivateHosts,
  });
  if (!validated.ok) {
    return { ok: false, reason: "private_host_blocked" };
  }

  const doFetch = input.fetchImpl ?? fetch;
  const timeoutMs = input.timeoutMs ?? TIMEOUT_MS;

  // The DID document is OPTIONAL input: it can name an `InkAgentCard` service
  // endpoint, and when it does not (or is unreachable) the versioned discovery
  // path stands on its own. There is no alias fallback beyond it.
  let cardUrl = targets.versionedCardUrl;
  const serviceEndpoint = await resolveServiceEndpoint(
    targets, doFetch, timeoutMs, input.allowPrivateHosts,
  );
  if (serviceEndpoint) cardUrl = serviceEndpoint;

  const fetched = await fetchCardBytes(cardUrl, doFetch, timeoutMs);
  if (!fetched) return { ok: false, reason: "card_unreachable" };

  // The response contract (status 200, JSON content type, size cap, the
  // signed-body byte gates, schema, protocol, agentId binding) is decided by
  // the library against the raw response bytes, never a decoded string: a
  // lenient decode would substitute U+FFFD for an invalid byte and strip a
  // leading BOM before the signed-body gate ever saw them.
  const evaluated = evaluateAgentCardFetch({
    status: fetched.status,
    contentType: fetched.contentType,
    contentLength: fetched.contentLength,
    bodyRaw: fetched.bodyRaw,
    requestedAgentId: input.recipientDid,
  });
  if (!evaluated.accepted || !evaluated.card) return { ok: false, reason: "card_rejected" };
  return { ok: true, endpoint: resolveAgentInbox(evaluated.card), source: "did-web-card" };
}

/**
 * Fetch the DID document and return the `InkAgentCard` service endpoint it
 * declares, or null. The endpoint MUST be https and on the DID's own
 * authority (host AND port): did:web identity binding puts the card on the
 * host the identifier names, and the https check stops a document pointing at
 * `http://example.com/agent.json` from letting an on-path attacker substitute
 * a key. Any failure returns null, which leaves the versioned path in place.
 */
async function resolveServiceEndpoint(
  targets: DidWebTargets,
  doFetch: typeof fetch,
  timeoutMs: number,
  allowPrivateHosts?: boolean,
): Promise<string | null> {
  const fetched = await fetchDidDocument(targets.didDocUrl, doFetch, timeoutMs);
  if (!fetched || fetched.status !== 200) return null;
  let doc: unknown;
  try {
    doc = JSON.parse(fetched.body);
  } catch {
    return null;
  }
  if (doc === null || typeof doc !== "object") return null;
  const services = (doc as { service?: unknown }).service;
  if (!Array.isArray(services)) return null;
  for (const entry of services) {
    if (entry === null || typeof entry !== "object") continue;
    const { type, serviceEndpoint } = entry as { type?: unknown; serviceEndpoint?: unknown };
    if (type !== "InkAgentCard") continue;
    if (typeof serviceEndpoint !== "string") return null;
    let u: URL;
    try {
      u = new URL(serviceEndpoint);
    } catch {
      return null;
    }
    if (u.protocol !== "https:" || u.host.toLowerCase() !== targets.host) return null;
    // Re-run the outbound gate: the endpoint came from a remote document.
    const validated = validateTargetUrl(serviceEndpoint, { allowPrivateHosts });
    return validated.ok ? serviceEndpoint : null;
  }
  return null;
}

interface FetchedDidDocument {
  status: number;
  contentType: string | null;
  body: string;
}

interface FetchedCardBytes {
  status: number;
  contentType: string | null;
  contentLength: string | null;
  bodyRaw: Uint8Array;
}

/** GET the DID document at a did:web identifier's document URL, with a bounded
 *  timeout, no redirects, and a body cap. Unlike `fetchCardBytes` below, the
 *  DID document is unsigned, so it is read and decoded as text, not bytes. */
async function fetchDidDocument(
  url: string,
  doFetch: typeof fetch,
  timeoutMs: number,
): Promise<FetchedDidDocument | null> {
  const controller = new AbortController();
  // The timer covers the body read too: a hostile card host can return
  // headers then stall the body, and the byte cap only fires once bytes
  // arrive. Cleared once in `finally`.
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response: Response;
    try {
      response = await doFetch(url, {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: controller.signal,
        redirect: "manual",
      });
    } catch {
      return null;
    }
    let body: string | null;
    try {
      body = await readCappedText(response, MAX_CARD_BYTES);
    } catch {
      return null;
    }
    if (body === null) return null;
    return {
      status: response.status,
      contentType: response.headers.get("Content-Type"),
      body,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function readCappedText(response: Response, max: number): Promise<string | null> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const decoder = new TextDecoder();
  let received = 0;
  let out = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      received += value.byteLength;
      if (received > max) {
        try {
          await reader.cancel();
        } catch {
          /* ignore */
        }
        return null;
      }
      out += decoder.decode(value, { stream: true });
    }
  }
  return out;
}

/**
 * GET the Agent Card with a bounded timeout, no redirects, and a body cap,
 * handing back the response bytes exactly as received. The card carries a
 * signature verified over its canonical form, so it must reach
 * `evaluateAgentCardFetch` un-decoded: a lenient UTF-8 decode would
 * substitute U+FFFD for an invalid byte and strip a leading BOM before the
 * signed-body gate ever saw them.
 */
async function fetchCardBytes(
  url: string,
  doFetch: typeof fetch,
  timeoutMs: number,
): Promise<FetchedCardBytes | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response: Response;
    try {
      response = await doFetch(url, {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: controller.signal,
        redirect: "manual",
      });
    } catch {
      return null;
    }
    let bodyRaw: Uint8Array | null;
    try {
      bodyRaw = await readCappedBytes(response, MAX_CARD_BYTES);
    } catch {
      return null;
    }
    if (bodyRaw === null) return null;
    return {
      status: response.status,
      contentType: response.headers.get("Content-Type"),
      contentLength: response.headers.get("Content-Length"),
      bodyRaw,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function readCappedBytes(response: Response, max: number): Promise<Uint8Array | null> {
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      received += value.byteLength;
      if (received > max) {
        try {
          await reader.cancel();
        } catch {
          /* ignore */
        }
        return null;
      }
      chunks.push(value);
    }
  }
  const merged = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}
