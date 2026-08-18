/**
 * Resolve a sender's did:web identifier to their agent card.
 *
 * Two-step lookup:
 *  1. did:web → DID document URL (per did:web 1.0)
 *  2. DID document → InkAgentCard service endpoint, or the versioned
 *     discovery path `/ink/v1/<agentId>/agent.json` when the document
 *     declares none. The `/.well-known/ink/agent.json` alias is never
 *     reached for: `specs/ink-resolver.md` §3.2 forbids a resolver from
 *     depending on it or falling back to it.
 *
 * The SSRF guards (`isIpLiteralHost`, `isPrivateHost`) are an
 * intentional copy of the patterns shipped in
 * `examples/foreign-sender-receiver/src/did-web-resolver.ts`. Until
 * `@adastracomputing/ink` exports a canonical helper, every receiver
 * has to bake these checks in — the alternative is letting an
 * attacker-controllable DID host turn this resolver into an SSRF
 * gadget.
 */

import { AgentCardSchema } from "@adastracomputing/ink";

const DID_WEB_HOST_RE =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

export function isIpLiteralHost(hostname: string): boolean {
  if (!hostname) return false;
  const bare = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bare)) return true;
  if (/^\d+$/.test(bare)) return true;
  if (bare.includes(":") && /^[0-9a-fA-F:%.]+$/.test(bare)) return true;
  return false;
}

export function isPrivateHost(hostname: string): boolean {
  let lower = hostname.toLowerCase();
  while (lower.endsWith(".")) lower = lower.slice(0, -1);
  if (!lower) return true;
  if (lower === "localhost" || lower.endsWith(".localhost")) return true;
  if (lower === "127.0.0.1" || lower === "::1") return true;
  const bare = lower.startsWith("[") && lower.endsWith("]") ? lower.slice(1, -1) : lower;
  if (bare === "::1" || bare === "0:0:0:0:0:0:0:1") return true;
  if (bare.startsWith("fe80:") || bare.startsWith("fe80%")) return true;
  if (bare.startsWith("fc") || bare.startsWith("fd")) return true;
  const dq = bare.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (dq) {
    const a = Number(dq[1]);
    const b = Number(dq[2]);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true;
  }
  if (/^\d+$/.test(bare)) return true;
  return false;
}

function isValidDidWebHost(host: string): boolean {
  if (!host || host.length > 253) return false;
  return DID_WEB_HOST_RE.test(host);
}

/**
 * A port is a decimal 1 to 65535 with no leading zeros.
 *
 * An explicit `443` is ACCEPTED: the W3C did:web method allows an optional
 * percent-encoded port and bans no value, so refusing a spec-legal identifier
 * would be an interop bug. A URL carrying `:443` normalizes to the default
 * https origin on fetch, so carrying it resolves the right document.
 *
 * This grammar is otherwise the library's `deriveRpOrigin` grammar, but it is
 * NOT that function. The sign-in profile additionally bans an explicit 443
 * because it derives a single canonical origin STRING from the identifier and
 * two spellings of one origin would break that derivation. That is a
 * profile-local rule and it must not be copied back onto the general
 * resolution path.
 */
function isDidWebPort(port: string): boolean {
  if (!/^[1-9][0-9]{0,4}$/.test(port)) return false;
  const n = Number(port);
  return n >= 1 && n <= 65535;
}

/**
 * Split the host component of a did:web identifier into host and optional
 * port. `%3A` is the did:web spelling of the port separator.
 *
 * The port is CARRIED, never dropped: resolving `did:web:example.com%3A8443`
 * at the default port would silently target a different origin than the
 * identifier names. Anything we cannot carry faithfully is rejected — a
 * second `%3A`, a leftover `%` (a lowercase `%3a` the uppercase marker
 * missed), or a port outside the grammar. This mirrors `deriveRpOrigin` in
 * `@adastracomputing/ink` except for the explicit-443 rule; see
 * `isDidWebPort`.
 */
export function parseDidWebAuthority(
  hostComponent: string,
): { host: string; port?: string } | null {
  const idx = hostComponent.indexOf("%3A");
  if (idx === -1) {
    if (hostComponent.includes("%")) return null;
    return { host: hostComponent };
  }
  const host = hostComponent.slice(0, idx);
  const port = hostComponent.slice(idx + 3);
  if (port.includes("%3A")) return null;
  if (host.includes("%") || port.includes("%")) return null;
  if (!isDidWebPort(port)) return null;
  return { host, port };
}

export interface DidWebTargets {
  /** Serialized authority: host, plus `:port` for any non-default port. */
  host: string;
  didDocUrl: string;
  /**
   * Versioned discovery path, the one `fetchAgentCard` builds. This is the
   * sole normative discovery surface: a resolver MUST NOT depend on the
   * `/.well-known/ink/agent.json` alias or fall back to it, so no alias URL is
   * derived here (`specs/ink-resolver.md` §3.2).
   */
  versionedCardUrl: string;
}

/**
 * Resolve a did:web id to the URLs we'd fetch. Returns null on any
 * malformed input or rejected host. Supports the path-form did:web
 * shape `did:web:host:user:alice`.
 */
export function resolveDidWebTargets(did: string): DidWebTargets | null {
  if (!did.startsWith("did:web:")) return null;
  const id = did.slice("did:web:".length);
  if (id.length === 0 || id.length > 1024) return null;
  const parts = id.split(":");
  if (parts.some((p) => p.length === 0)) return null;
  const host = parts[0]!;
  const authority = parseDidWebAuthority(host);
  if (!authority) return null;
  const hostBare = authority.host;
  const port = authority.port;
  const hostPort = port === undefined ? hostBare : `${hostBare}:${port}`;
  if (!isValidDidWebHost(hostBare) || isPrivateHost(hostBare) || isIpLiteralHost(hostBare)) {
    return null;
  }
  // SSRF defense: the URL parser normalizes shorthand IPv4 forms like
  // `127.1` to `127.0.0.1`. The raw-string checks above wouldn't catch
  // those because they pass the host pattern AND the dotted-quad
  // regex misses 2/3-octet IP shorthands. Re-derive the canonical
  // hostname through `new URL` and re-run the checks against that.
  let canonical: URL;
  try {
    canonical = new URL(`https://${hostPort}`);
  } catch {
    return null;
  }
  const canonicalHost = canonical.hostname;
  // The serializer drops an explicit default port and normalizes numeric
  // forms. `:443` IS the default, so its serialized form is the empty port and
  // the identifier still resolves at the origin it names; any other port must
  // survive verbatim or we refuse rather than resolve somewhere else.
  const expectedSerializedPort = port === undefined || port === "443" ? "" : port;
  if (!canonicalHost
      || isPrivateHost(canonicalHost)
      || isIpLiteralHost(canonicalHost)
      || canonicalHost !== hostBare
      || canonical.port !== expectedSerializedPort) {
    return null;
  }
  // Every derived URL is built from the SERIALIZED origin, so `%3A443` and the
  // portless spelling resolve to the same origin (which is what they mean)
  // while any other port is carried through.
  const origin = canonical.origin;
  const safePath = /^[A-Za-z0-9._~\-]+$/;
  let didDocUrl: string;
  if (parts.length === 1) {
    didDocUrl = `${origin}/.well-known/did.json`;
  } else {
    const rest = parts.slice(1);
    for (const seg of rest) {
      // Reject "." and ".." segments explicitly. They satisfy the
      // safe-char regex but a literal dot-segment in the resolved URL
      // is a traversal vector even after URL normalization elsewhere.
      if (seg === "." || seg === "..") return null;
      if (!safePath.test(seg)) return null;
    }
    didDocUrl = `${origin}/${rest.join("/")}/did.json`;
  }
  return {
    host: canonical.host,
    didDocUrl,
    versionedCardUrl: `${origin}/ink/v1/${encodeURIComponent(did)}/agent.json`,
  };
}

const MAX_FETCH_BYTES = 64 * 1024;
const FETCH_TIMEOUT_MS = 4000;

async function fetchJson(
  url: string,
  opts: { fetcher?: typeof fetch } = {},
): Promise<unknown | null> {
  const fetcher = opts.fetcher ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetcher(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: { accept: "application/json" },
    });
    if (!res.ok) return null;
    if (!res.body) return null;
    // Stream the body so a server can't deliver a multi-megabyte
    // response into memory before we apply the cap. Stop reading and
    // cancel the stream as soon as we cross MAX_FETCH_BYTES.
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          total += value.byteLength;
          if (total > MAX_FETCH_BYTES) {
            try { await reader.cancel(); } catch { /* ignore */ }
            return null;
          }
          chunks.push(value);
        }
      }
    } finally {
      try { await reader.cancel(); } catch { /* ignore */ }
    }
    const buf = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      buf.set(c, off);
      off += c.byteLength;
    }
    const text = new TextDecoder().decode(buf);
    try { return JSON.parse(text); } catch { return null; }
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Walk did:web → DID doc → InkAgentCard service → agent.json.
 *
 * Without a usable service entry the card is fetched from the versioned
 * discovery path, and that is the end of the walk: `specs/ink-resolver.md`
 * §3.2 forbids depending on the `/.well-known/ink/agent.json` alias or falling
 * back to it on failure, so a peer that publishes ONLY the alias is not
 * discoverable here. Returns null on any failure.
 */
export async function resolveAgentCardForDidWeb(
  did: string,
  opts: { fetcher?: typeof fetch } = {},
): Promise<unknown | null> {
  const targets = resolveDidWebTargets(did);
  if (!targets) return null;
  const didDoc = await fetchJson(targets.didDocUrl, opts);
  // Without a service entry the versioned discovery path is the only URL we
  // will try. No alias fallback: see the note on this function.
  let cardUrl = targets.versionedCardUrl;
  if (didDoc && typeof didDoc === "object") {
    const services = (didDoc as { service?: Array<Record<string, unknown>> }).service;
    if (Array.isArray(services)) {
      for (const s of services) {
        if (typeof s.type === "string" && s.type === "InkAgentCard"
            && typeof s.serviceEndpoint === "string") {
          // Confirm the discovered card URL is HTTPS AND on the same
          // authority as the DID. did:web identity binding requires the
          // card to live on the DID's host (and port, when the identifier
          // names one); the https: check stops a DID doc that points at
          // http://example.com/agent.json from letting an on-path attacker
          // substitute a key.
          try {
            const u = new URL(s.serviceEndpoint);
            if (u.protocol === "https:" && u.host.toLowerCase() === targets.host) {
              cardUrl = s.serviceEndpoint;
            }
          } catch { /* ignore malformed entries */ }
          break;
        }
      }
    }
  }
  const rawCard = await fetchJson(cardUrl, opts);
  if (!rawCard) return null;
  const parsed = AgentCardSchema.safeParse(rawCard);
  if (!parsed.success) return null;
  // Identity binding: the card MUST announce a matching agentId.
  if (parsed.data.agentId !== did) return null;
  return parsed.data;
}
