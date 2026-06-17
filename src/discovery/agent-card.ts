import type { AgentCard } from "../models/agent-card.js";
import { evaluateAgentCardFetch, contentLengthExceedsCap, MAX_AGENT_CARD_BYTES } from "./agent-card-fetch.js";
import type { CandidateKey } from "../models/key-entry.js";
import { decodePublicKeyMultibase } from "../crypto/keys.js";
import { isInkTimestamp } from "../crypto/timestamp.js";

/** Same cap used by multi-key verification — applied early to bound the
 * cost of the base58 decode loop on poisoned cards with thousands of entries. */
const MAX_PARSE_KEYS = 20;

/** True if the URL passes the same SSRF gate as baseUrl: https only, no
 * userinfo, no literal private/loopback/IANA-special hostnames. Used to
 * vet URL-shaped fields inside a fetched card before returning it. */
function isSafePublicUrl(rawUrl: string, allowPrivate: boolean): boolean {
  if (typeof rawUrl !== "string" || rawUrl.length === 0) return false;
  let u: URL;
  try { u = new URL(rawUrl); } catch { return false; }
  if (u.protocol !== "https:") return false;
  if (u.username || u.password) return false;
  if (!allowPrivate && isPrivateHostname(u.hostname)) return false;
  return true;
}

/** Stream-read a Response body with a hard byte cap. Aborts after the cap is
 * exceeded so a chunked-transfer response without Content-Length cannot
 * force unbounded buffering. Returns null on cap-exceeded. */
async function readResponseBodyWithCap(res: Response, capBytes: number): Promise<string | null> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > capBytes) {
          try { await reader.cancel(); } catch { /* ignore */ }
          return null;
        }
        chunks.push(value);
      }
    }
  } finally {
    try { reader.releaseLock(); } catch { /* ignore */ }
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { merged.set(c, off); off += c.byteLength; }
  return new TextDecoder().decode(merged);
}

/** Reject hostnames that resolve (statically) to loopback, private, or
 * link-local addresses. This is an SSRF defense for integrators that may
 * pass user-controlled baseUrl values. Returns true if the hostname is
 * a literal IP in a reserved range, a loopback name, or an IPv6 unique
 * local / link-local address.
 *
 * Note: this does NOT defend against DNS rebinding — a public hostname
 * that resolves to 127.0.0.1 at fetch time will still hit loopback.
 * That defense lives at the runtime / platform layer. */
export function isPrivateHostname(hostname: string): boolean {
  let h = hostname.toLowerCase();
  // Strip trailing dots (FQDN form) so `localhost.` doesn't bypass.
  while (h.endsWith(".")) h = h.slice(0, -1);
  if (!h) return true;
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  // IPv6 in brackets — WHATWG URL canonicalizes bracketed v6 to lowercase
  // with `::` collapsed, but a caller might still pass an un-collapsed form.
  const bare = h.startsWith("[") && h.endsWith("]") ? h.slice(1, -1) : h;
  // IPv4-mapped IPv6 in dotted form (::ffff:1.2.3.4) — checked before
  // general IPv6 so the v4 octet checks apply.
  const v4m = bare.match(/^::ffff:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4m) return dottedV4Unsafe(Number(v4m[1]), Number(v4m[2]), Number(v4m[3]), Number(v4m[4]));
  // General IPv6 literal: parse and apply v6 special-use ranges. We use a
  // real expansion (not string prefix matches) so that, e.g., a 5-group
  // hex address with `fc` in the high byte of the *last* segment doesn't
  // false-positive as ULA. Unparseable v6 → reject (refuse to fetch
  // something we can't classify).
  if (bare.includes(":")) {
    const groups = expandIPv6(bare);
    if (!groups) return true;
    // IPv4-mapped (::ffff:HHHH:HHHH) — extract embedded v4 and use v4 rules.
    if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 &&
        groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff) {
      const hi = groups[6]!, lo = groups[7]!;
      return isPrivateIPv4((hi >>> 8) & 0xff, hi & 0xff, (lo >>> 8) & 0xff, lo & 0xff);
    }
    return isPrivateIPv6Groups(groups);
  }
  // Dotted-quad IPv4 (decimal only — common encodings)
  const dq = bare.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (dq) return dottedV4Unsafe(Number(dq[1]), Number(dq[2]), Number(dq[3]), Number(dq[4]));
  // Single-segment numeric forms (e.g. "2130706433") are suspicious — reject.
  if (/^\d+$/.test(bare)) return true;
  return false;
}

/** A dotted IPv4 hostname is unsafe to fetch if any octet is out of range (a
 *  malformed IP-shaped name — fail closed rather than treat 8.8.8.999 as a
 *  public host) or if the address is in a private/special-use block. */
function dottedV4Unsafe(a: number, b: number, c: number, d: number): boolean {
  if (a > 255 || b > 255 || c > 255 || d > 255) return true;
  return isPrivateIPv4(a, b, c, d);
}

/** Classify an IPv6 address (8 16-bit groups) against the IANA special-use
 * registry. Returns true if the address falls in any non-global block.
 * Public addresses (e.g. 2606:4700:: Cloudflare) return false. */
function isPrivateIPv6Groups(g: number[]): boolean {
  if (g.length !== 8) return true;
  // ::/128 unspecified + ::1/128 loopback
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 &&
      g[4] === 0 && g[5] === 0 && g[6] === 0 && (g[7] === 0 || g[7] === 1)) return true;
  const high = g[0]!;
  // fe80::/10 link-local: first 10 bits = 1111 1110 10
  if ((high & 0xffc0) === 0xfe80) return true;
  // fc00::/7 unique-local (ULA): first 7 bits = 1111 110
  if ((high & 0xfe00) === 0xfc00) return true;
  // ff00::/8 multicast
  if ((high & 0xff00) === 0xff00) return true;
  // 2001:*/* IANA special-use blocks within 2001::/16
  if (high === 0x2001) {
    if (g[1] === 0x0000) return true;                                  // 2001::/32     Teredo
    if (g[1] === 0x0002 && g[2] === 0) return true;                    // 2001:2::/48   BMWG benchmarking
    if ((g[1]! & 0xfff0) === 0x0010) return true;                       // 2001:10::/28  ORCHID (deprecated)
    if ((g[1]! & 0xfff0) === 0x0020) return true;                       // 2001:20::/28  ORCHIDv2
    if (g[1] === 0x0db8) return true;                                  // 2001:db8::/32 documentation
  }
  // 2002::/16 6to4 — embeds a v4 address in groups[1] and groups[2].
  // If the embedded v4 is in a private/special-use block, treat the whole
  // v6 as private. (RFC 7526 deprecated 6to4 anycast 192.88.99/24 — already
  // blocked separately — but tunneled 6to4 traffic to a private v4 is still
  // an SSRF vector.)
  if (high === 0x2002) {
    const a = (g[1]! >>> 8) & 0xff;
    const b = g[1]! & 0xff;
    const c = (g[2]! >>> 8) & 0xff;
    const d = g[2]! & 0xff;
    if (isPrivateIPv4(a, b, c, d)) return true;
  }
  // 64:ff9b::/96 NAT64 well-known prefix
  if (high === 0x0064 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 &&
      g[4] === 0 && g[5] === 0) return true;
  // 64:ff9b:1::/48 local-use IPv4/IPv6 translation (RFC 8215, not globally reachable)
  if (high === 0x0064 && g[1] === 0xff9b && g[2] === 0x0001) return true;
  // 100::/64 discard-only address block
  if (high === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return true;
  // 100:0:0:1::/64 dummy IPv6 prefix (RFC 7600)
  if (high === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0x0001) return true;
  // 3fff::/20 BMWG IPv6 benchmarking (RFC 9637)
  if ((high & 0xfff0) === 0x3ff0) return true;
  // 5f00::/16 Segment Routing SRv6 SIDs (RFC 9602)
  if (high === 0x5f00) return true;
  // NOTE on partial coverage of certain IANA-listed prefixes:
  //   ::ffff:0:0/96   IPv4-mapped — checked per-embedded-v4 above; the
  //                   block is in the registry because mapped addresses
  //                   must not appear on the wire, but the bytes can be
  //                   global IPv4 routes. We block the private subset.
  //   2002::/16       6to4 — same pattern; we block when the embedded v4
  //                   is private, allow when it's public.
  //   2001::/23       IETF Protocol Assignments aggregate — we list the
  //                   specific non-global subblocks above (Teredo, BMWG,
  //                   ORCHID(v2), docs) rather than blanket-blocking the
  //                   aggregate, which would break legitimate v6 routing
  //                   that uses other 2001:* allocations.
  return false;
}

/** Expand an IPv6 address with optional `::` into 8 16-bit groups.
 *  Returns null on malformed input. */
function expandIPv6(addr: string): number[] | null {
  // Reject any zone/scope id (`fe80::1%eth0`). Stripping it would let a public
  // literal with a zone suffix bypass the gate; a zoned address is also not a
  // routable public destination. Fail closed.
  if (addr.includes("%")) return null;
  const dcIdx = addr.indexOf("::");
  let leftStr: string;
  let rightStr: string;
  if (dcIdx === -1) {
    leftStr = addr;
    rightStr = "";
  } else {
    leftStr = addr.slice(0, dcIdx);
    rightStr = addr.slice(dcIdx + 2);
    if (leftStr.includes("::") || rightStr.includes("::")) return null;
  }
  const leftParts = leftStr ? leftStr.split(":") : [];
  const rightParts = rightStr ? rightStr.split(":") : [];
  const fill = 8 - (leftParts.length + rightParts.length);
  if (fill < 0) return null;
  if (dcIdx === -1 && fill !== 0) return null;
  const parts = [
    ...leftParts,
    ...new Array<string>(fill).fill("0"),
    ...rightParts,
  ];
  if (parts.length !== 8) return null;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^[0-9a-f]{1,4}$/.test(p)) return null;
    out.push(parseInt(p, 16));
  }
  return out;
}

/** Refuse any IPv4 that isn't a globally-routable unicast address.
 * Covers the full IANA Special-Purpose IPv4 Address Registry (RFC 6890
 * + later updates) using exact /CIDR-block checks on all 4 octets. */
function isPrivateIPv4(a: number, b: number, c: number, _d: number): boolean {
  if (a === 0) return true;                                       // 0.0.0.0/8        this-network
  if (a === 10) return true;                                       // 10.0.0.0/8       private
  if (a === 100 && b >= 64 && b <= 127) return true;               // 100.64.0.0/10    CGNAT
  if (a === 127) return true;                                      // 127.0.0.0/8      loopback
  if (a === 169 && b === 254) return true;                         // 169.254.0.0/16   link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;                // 172.16.0.0/12    private
  if (a === 192 && b === 0 && c === 0) return true;                // 192.0.0.0/24     IETF protocol assignments
  if (a === 192 && b === 0 && c === 2) return true;                // 192.0.2.0/24     TEST-NET-1
  if (a === 192 && b === 31 && c === 196) return true;             // 192.31.196.0/24  AS112-v4
  if (a === 192 && b === 52 && c === 193) return true;             // 192.52.193.0/24  AMT
  if (a === 192 && b === 88 && c === 99) return true;              // 192.88.99.0/24   6to4 relay (deprecated)
  if (a === 192 && b === 168) return true;                         // 192.168.0.0/16   private
  if (a === 192 && b === 175 && c === 48) return true;             // 192.175.48.0/24  Direct Delegation AS112
  if (a === 198 && (b === 18 || b === 19)) return true;            // 198.18.0.0/15    benchmarking
  if (a === 198 && b === 51 && c === 100) return true;             // 198.51.100.0/24  TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true;              // 203.0.113.0/24   TEST-NET-3
  if (a >= 224) return true;                                       // 224.0.0.0/4      multicast + 240.0.0.0/4 reserved + 255.255.255.255 broadcast
  return false;
}

export interface FetchAgentCardOptions {
  /** Allow baseUrls whose hostname is a literal loopback / private /
   * link-local / IANA special-use address. Off by default — flip on for
   * unit tests or for an INK integrator running against an intentional
   * intranet endpoint. */
  allowPrivateHosts?: boolean;
  /** Override the fetch implementation used to retrieve the card. This is
   * the integrator's hook for connect-time SSRF defense (DNS rebinding):
   * a public hostname can resolve to a private IP at fetch time and
   * bypass the literal-hostname allowlist below. Wrap your platform's
   * fetch with one that resolves + pins the IP and rejects private
   * connect targets (e.g. undici with a custom dispatcher on Node, or
   * `cf: { resolveOverride: validatedIp }` on Cloudflare Workers). */
  fetch?: typeof fetch;
  /** Strict mode: require that the caller supply `options.fetch`, returning
   * null (without fetching) if it is absent. This only guarantees that *some*
   * fetch override was provided; it does NOT and cannot verify that the
   * override pins connect-time IPs, so passing `requireSafeFetch: true` with
   * the plain global `fetch` does not close the DNS-rebinding window. The
   * literal-private-IP allowlist this module applies to `baseUrl` does not stop
   * a public hostname that resolves to a private address at fetch time; only a
   * connect-time-IP-pinning `options.fetch` (for example a custom undici
   * dispatcher) does. Off by default for backwards compatibility. */
  requireSafeFetch?: boolean;
}

/**
 * Fetch an Agent Card from a remote INK endpoint.
 * Convention: GET /ink/v1/:agentId/agent.json
 *
 * SECURITY: this function applies several SSRF defenses by default —
 * https-only baseUrl, no userinfo, literal-hostname allowlist excluding
 * loopback / private / link-local / IANA special-use blocks (both v4 and
 * v4-mapped v6), no redirect following, body-size cap, identity binding.
 *
 * It does NOT defend against DNS rebinding: a public hostname that
 * resolves to a private IP at fetch time will still be reached. The
 * runtime-agnostic library cannot solve this on its own — pass
 * `options.fetch` with a connect-time IP-filtering implementation
 * (undici dispatcher on Node, `cf.resolveOverride` on Cloudflare
 * Workers, an egress proxy, etc.) when the baseUrl is not fully trusted.
 */
export async function fetchAgentCard(
  agentId: string,
  baseUrl: string,
  options?: FetchAgentCardOptions,
): Promise<AgentCard | null> {
  // Reject any baseUrl that isn't a plain https:// URL. Without this guard,
  // a caller that takes baseUrl from user input could fetch http://,
  // file://, or javascript: URLs — or send credentials to a path under an
  // attacker-chosen origin.
  let parsedBase: URL;
  try {
    parsedBase = new URL(baseUrl);
  } catch {
    return null;
  }
  if (parsedBase.protocol !== "https:") return null;
  if (parsedBase.username || parsedBase.password) return null;
  // SSRF defense: reject baseUrls pointing at loopback / private / link-local
  // hosts. Opt-in override for tests + intentional intranet deployments.
  if (!options?.allowPrivateHosts && isPrivateHostname(parsedBase.hostname)) {
    return null;
  }
  // Reject obviously-bad agentIds before they hit encodeURIComponent and
  // URL construction:
  //   - non-strings (defensive, the type system already requires string)
  //   - oversized values (real agentIds are ~50-100 chars; cap matches the
  //     limits used by the middleware so we don't allocate giant URLs)
  //   - dot-segments (".", "..", or anything containing "/" or "\") which
  //     would let the WHATWG URL pathname setter normalise the fetch
  //     target away from /ink/v1/<id>/agent.json
  if (typeof agentId !== "string" || agentId.length === 0 || agentId.length > 256) {
    return null;
  }
  if (agentId === "." || agentId === ".." || agentId.includes("/") || agentId.includes("\\")) {
    return null;
  }
  // Build the URL from the parsed object, not the raw string. Otherwise a
  // baseUrl containing URL-encoded CRLF or other parser/serializer edge
  // cases could pass validation but still produce the original raw fetch
  // string. Using URL.pathname / URL.toString() runs through the WHATWG
  // serializer, which normalizes and re-encodes.
  const trimmedPath = parsedBase.pathname.replace(/\/$/, "");
  const built = new URL(parsedBase.origin);
  const expectedSegment = `/ink/v1/${encodeURIComponent(agentId)}/agent.json`;
  built.pathname = `${trimmedPath}${expectedSegment}`;
  // Belt-and-braces: confirm the WHATWG serializer didn't normalise away
  // any segment we intended to be present (e.g. via attacker-supplied
  // unicode that decomposes to "..").
  if (!built.pathname.endsWith(expectedSegment)) {
    return null;
  }
  const url = built.toString();
  // Strict mode: reject before any network work if the caller asked for a
  // safe fetch but didn't supply one. The default global fetch cannot do
  // connect-time IP filtering, which is what closes the DNS-rebinding
  // window. Fail closed.
  if (options?.requireSafeFetch && !options.fetch) {
    return null;
  }
  const fetchImpl = options?.fetch ?? fetch;
  try {
    const res = await fetchImpl(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(5000),
      // Refuse to follow redirects. Without this, a validated https://
      // baseUrl could redirect to http://internal/, http://169.254.169.254/,
      // or any other origin — bypassing the protocol/userinfo checks above.
      // The INK convention serves the card at a fixed path, so any redirect
      // is treated as an SSRF attempt.
      redirect: "manual",
    });
    // Fail closed on an over-cap declared length BEFORE doing any stream work,
    // so a huge Content-Length can't make us read until the cap aborts. The
    // evaluator re-checks this; the early guard is the fetch-path optimisation.
    if (contentLengthExceedsCap(res.headers.get("Content-Length"))) return null;
    // Cap card body size with a STREAM-READ before the contract check.
    // res.text() would buffer the entire body first; a chunked response
    // without Content-Length could exhaust memory pre-validation.
    const text = await readResponseBodyWithCap(res, MAX_AGENT_CARD_BYTES);
    if (text === null) return null;
    // The response contract (status 200, application/json, size cap, JSON
    // parse, AgentCardSchema, protocol literal, identity binding) is the pinned
    // agent-card-fetch conformance decision, shared with the second
    // implementation so retrieval cannot diverge across runtimes.
    const evaluated = evaluateAgentCardFetch({
      status: res.status,
      contentType: res.headers.get("Content-Type"),
      contentLength: res.headers.get("Content-Length"),
      bodyRaw: text,
      requestedAgentId: agentId,
    });
    if (!evaluated.accepted || !evaluated.card) return null;
    const card = evaluated.card;
    // Endpoint hardening: any URL field inside the card that a downstream
    // caller might pass to fetch must pass the same SSRF gate as baseUrl
    // (https-only, no userinfo, no literal private/loopback/IANA-special).
    // Without this, a compromised registry could return
    // `endpoint: "http://169.254.169.254/..."` (or stash the same in
    // `capabilities.thirdPartyAudit.services[].endpoint`) and SSRF
    // anyone who reads the field.
    const allowPrivate = options?.allowPrivateHosts === true;
    if (!isSafePublicUrl(card.endpoint, allowPrivate)) return null;
    const auditSvcs = card.capabilities?.thirdPartyAudit?.services;
    if (auditSvcs) {
      for (const svc of auditSvcs) {
        if (!isSafePublicUrl(svc.endpoint, allowPrivate)) return null;
      }
    }
    return card;
  } catch {
    return null;
  }
}

/**
 * Extract candidate signing keys from an Agent Card.
 *
 * Authority rule: presence of `keys.signing` (even when empty) is
 * authoritative. Callers MUST treat the returned set as the complete list
 * of acceptable signers — including the empty set, which means "key set
 * published, no usable keys" and forbids any legacy bootstrap fallback.
 *
 *   - `keys.signing` absent  → fall back to legacy `publicKeyMultibase`
 *   - `keys.signing: []`     → return [] (authoritative empty)
 *   - `keys.signing: [k..]`  → parse each entry independently; malformed
 *                              entries are skipped so a single bad entry
 *                              cannot collapse the whole set to "legacy"
 *                              and let a rotated-away bootstrap key pass.
 */
export function extractCandidateKeys(card: AgentCard): CandidateKey[] {
  if (card === null || typeof card !== "object" || Array.isArray(card)) {
    return [];
  }
  const signing = card.keys?.signing as unknown;
  if (signing !== undefined) {
    // Runtime type guard: a malformed card where `signing` is an object/
    // string would otherwise throw on `.slice()` and collapse to the
    // legacy bootstrap fallback at the caller — defeating key rotation.
    // Present-but-invalid → authoritative empty.
    if (!Array.isArray(signing)) return [];
    // Cap to MAX_PARSE_KEYS BEFORE the decode loop — base58 decode on
    // poisoned cards with thousands of entries would otherwise burn CPU
    // even though only the first 20 are ever used at verification time.
    const limited = signing.slice(0, MAX_PARSE_KEYS) as unknown[];
    const out: CandidateKey[] = [];
    for (const rawEntry of limited) {
      // Each entry must be a plain object with string keyId/publicKeyMultibase
      // and an allowlisted status. Anything else is skipped — never thrown —
      // so a single malformed entry can't collapse the whole set.
      if (rawEntry === null || typeof rawEntry !== "object" || Array.isArray(rawEntry)) continue;
      const entry = rawEntry as {
        keyId?: unknown;
        publicKeyMultibase?: unknown;
        status?: unknown;
        validFrom?: unknown;
        validUntil?: unknown;
        revokedAt?: unknown;
      };
      if (typeof entry.keyId !== "string" || typeof entry.publicKeyMultibase !== "string") continue;
      if (entry.status !== "active" && entry.status !== "retired" && entry.status !== "revoked") {
        continue;
      }
      // Carry validity-window fields through to the verifier so it can
      // reject messages whose timestamp is outside the window. Each
      // window field is OPTIONAL but if present it must be a non-empty
      // parseable ISO 8601 datetime string. A present-but-malformed
      // window field on the card is suspicious — it could be a
      // deliberate attempt to "blank out" an expiry — so we skip the
      // WHOLE entry instead of dropping just the field. The verifier's
      // own defense-in-depth check would also refuse it, but rejecting
      // here means downstream consumers never see a degraded key.
      const accept = (x: unknown): boolean => {
        if (x === undefined) return true;
        // INK's strict RFC 3339 profile, the same grammar the verifier
        // applies, so a card window field is read identically everywhere
        // (the parser also caps length and rejects an empty string).
        return typeof x === "string" && isInkTimestamp(x);
      };
      if (!accept(entry.validFrom) || !accept(entry.validUntil) || !accept(entry.revokedAt)) {
        continue;
      }
      try {
        out.push({
          keyId: entry.keyId,
          publicKey: decodePublicKeyMultibase(entry.publicKeyMultibase),
          status: entry.status,
          validFrom: typeof entry.validFrom === "string" ? entry.validFrom : undefined,
          validUntil: typeof entry.validUntil === "string" ? entry.validUntil : undefined,
          revokedAt: typeof entry.revokedAt === "string" ? entry.revokedAt : undefined,
        });
      } catch {
        // Skip malformed entry; do not collapse the whole set to legacy.
      }
    }
    return out;
  }

  // Legacy card (no `keys.signing` block at all): single key.
  // Wrap the decode so a malformed legacy `publicKeyMultibase` returns []
  // instead of throwing — callers processing an untrusted card would
  // otherwise crash. [] is the correct "no usable keys" signal here
  // because the card itself was observed (presence of `card`); callers
  // treat that as authoritative and won't fall back to bootstrap.
  if (typeof card.publicKeyMultibase !== "string") return [];
  try {
    return [
      {
        keyId: "legacy",
        publicKey: decodePublicKeyMultibase(card.publicKeyMultibase),
        status: "active" as const,
      },
    ];
  } catch {
    return [];
  }
}

/**
 * Resolve a well-known discovery base URL for an agent handle.
 *
 * INK does not mandate a single discovery origin — handle → base URL
 * resolution is integrator-specific. Implementations typically use one of:
 *
 *   - DNS TXT record at `_ink.<handle>` (planned)
 *   - HTTPS .well-known lookup at `https://<handle>/.well-known/ink/agent.json`
 *   - A platform-specific registry maintained by a host service
 *
 * Pass a `resolveBase` callback at integration time. Returning null defers
 * to the caller's fallback (e.g. an explicit endpoint in the Agent Card
 * itself).
 */
export function resolveBaseUrl(
  handle: string,
  resolveBase?: (handle: string) => string | null,
): string | null {
  return resolveBase ? resolveBase(handle) : null;
}
