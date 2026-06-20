/**
 * Inbox endpoint discovery.
 *
 * Where does a signed envelope get POSTed? It depends on the recipient
 * DID method:
 *
 *   - `did:key:` cannot publish a service endpoint — the identifier is
 *     just a key. There is nowhere to look it up, so the caller MUST
 *     supply the endpoint URL explicitly.
 *   - `did:web:` publishes an Agent Card at a well-known URL. This module
 *     fetches that card behind an SSRF gate, applies the discovery
 *     response contract (status 200, JSON content type, size cap, schema,
 *     protocol, and the agentId identity binding), and reads the inbox
 *     from the validated card with `resolveAgentInbox`. An explicit
 *     endpoint, when supplied, overrides discovery.
 *
 * The card URL convention for `did:web:` matches the reference receiver:
 * the host-only form serves the card at `/.well-known/ink/agent.json`.
 *
 * The SSRF gate here is the same static-literal classifier used on the
 * send path: https only, no userinfo, no fragment, no IP-literal or
 * private/loopback/special-use host. It does NOT defend against DNS
 * rebinding; pass a connect-time-IP-pinning `fetchImpl` when the host is
 * untrusted.
 */

import { AgentCardSchema, resolveAgentInbox } from "@adastracomputing/ink";
import { validateTargetUrl } from "./transport.ts";

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

/**
 * Derive the https URL the `did:web:` Agent Card is served from.
 *   did:web:host            → https://host/.well-known/ink/agent.json
 *   did:web:host:a:b        → https://host/a/b/ink/agent.json
 */
export function didWebCardUrl(did: string): string | null {
  if (!did.startsWith("did:web:")) return null;
  const rest = did.slice("did:web:".length);
  if (rest.length === 0) return null;
  const segments = rest.split(":");
  const decoded: string[] = [];
  for (const seg of segments) {
    try {
      const d = decodeURIComponent(seg);
      if (!d) return null;
      decoded.push(d);
    } catch {
      return null;
    }
  }
  const [authority, ...pathSegments] = decoded;
  // A port-bearing did:web (`host%3Aport`) is unsupported and rejected, so
  // discovery and the delivery host binding (`didWebHost`) stay on the same
  // authority. A literal `:` in the decoded first segment is a port.
  if (authority.includes(":")) return null;
  if (pathSegments.length === 0) {
    return `https://${authority}/.well-known/ink/agent.json`;
  }
  return `https://${authority}/${pathSegments.join("/")}/ink/agent.json`;
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
  const cardUrl = didWebCardUrl(input.recipientDid);
  if (!cardUrl) return { ok: false, reason: "invalid_did_web" };

  // SSRF gate on the card URL. The card host equals the DID host by
  // construction, so the value here is the https / userinfo / fragment /
  // IP-literal / private-host checks; `allowPrivateHosts` relaxes only the
  // private-host refusal for local dev. The derived URL is well-formed https,
  // so the only reachable failure is a blocked private host.
  const validated = validateTargetUrl(cardUrl, { allowPrivateHosts: input.allowPrivateHosts });
  if (!validated.ok) {
    return { ok: false, reason: "private_host_blocked" };
  }

  const fetched = await fetchCard(cardUrl, input.fetchImpl ?? fetch, input.timeoutMs ?? TIMEOUT_MS);
  if (!fetched) return { ok: false, reason: "card_unreachable" };

  const card = evaluateCardResponse(fetched, input.recipientDid);
  if (!card) return { ok: false, reason: "card_rejected" };
  return { ok: true, endpoint: resolveAgentInbox(card), source: "did-web-card" };
}

interface FetchedCard {
  status: number;
  contentType: string | null;
  body: string;
}

/**
 * The discovery response contract: status 200, a JSON content type with
 * at most a utf-8 charset, a schema-valid card, protocol ink/0.1, and the
 * card's agentId bound to the requested DID. Returns the validated card or
 * null. (The same decision the package pins for the handle convention; an
 * adopter on a newer package can swap in its `evaluateAgentCardFetch`.)
 */
function evaluateCardResponse(
  res: FetchedCard,
  requestedAgentId: string,
): ReturnType<typeof AgentCardSchema.parse> | null {
  if (res.status !== 200) return null;
  const contentType = res.contentType;
  if (!contentType || contentType.includes(",")) return null;
  const [mediaType, ...params] = contentType.split(";").map((s) => s.trim().toLowerCase());
  if (mediaType !== "application/json") return null;
  for (const p of params) {
    if (p.startsWith("charset=") && p.slice("charset=".length) !== "utf-8") return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(res.body);
  } catch {
    return null;
  }
  const result = AgentCardSchema.safeParse(parsed);
  if (!result.success) return null;
  const card = result.data;
  if (card.protocol !== "ink/0.1") return null;
  if (card.agentId !== requestedAgentId) return null;
  return card;
}

/** GET the card with a bounded timeout, no redirects, and a body cap. */
async function fetchCard(
  url: string,
  doFetch: typeof fetch,
  timeoutMs: number,
): Promise<FetchedCard | null> {
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
