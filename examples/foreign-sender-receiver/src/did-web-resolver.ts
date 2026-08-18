/**
 * `did:web:` document URL derivation, host validation, and SSRF
 * defenses for outbound resolver fetches.
 *
 * The point of this module is to refuse before issuing a fetch. A
 * `did:web:` host is by definition attacker-controllable, so the
 * resolver fetches arbitrary URLs based on what the sender claims.
 * The defenses here are the receiver's structural backstop against
 * the resolver being used as an SSRF gadget.
 *
 * Companion guide: https://ink.tulpa.network/guides/accepting-foreign-senders/
 */

// did:web hostnames are DNS names. RFC 1035 + UTS 46 + practical
// caps: 253 chars total, each label 1-63 chars, allowed chars
// a-z 0-9 - . Underscores are allowed in some real-world TLDs but
// did:web specs require lowercase a-z 0-9 only.
const DID_WEB_HOST_RE =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

/**
 * Returns true when the hostname is any literal IP address (IPv4
 * dotted-quad, decimal-numeric, or bracketed/bare IPv6). Outbound
 * endpoints in this example never accept IP literals; legitimate
 * peers are reachable by hostname and enumerating every reserved
 * IPv6 range is error-prone (the previous reviewer caught
 * `::ffff:127.0.0.1` slipping past an IPv4-only check).
 */
export function isIpLiteralHost(hostname: string): boolean {
  if (!hostname) return false;
  const bare = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bare)) return true;
  if (/^\d+$/.test(bare)) return true;
  // IPv6: contains `:` and only hex / `:` / `.` (mapped IPv4 tail) /
  // `%` (zone id). URL.hostname always strips the brackets.
  if (bare.includes(":") && /^[0-9a-fA-F:%.]+$/.test(bare)) return true;
  return false;
}

/**
 * Returns true when the hostname names a private, reserved,
 * loopback, or cloud-metadata address. The outbound URL validator
 * rejects any host that matches.
 */
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
    if (a === 169 && b === 254) return true; // link-local incl. cloud metadata 169.254.169.254
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true; // multicast + reserved
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

/**
 * Translate a did:web identifier to its document URL.
 *
 * Forms supported (per did:web 1.0 spec):
 *   - `did:web:example.com` → `https://example.com/.well-known/did.json`
 *   - `did:web:example.com:user:alice` → `https://example.com/user/alice/did.json`
 *
 * Returns null when the DID is malformed, the host is not a valid
 * public DNS name, or any path segment fails the safe-character check.
 */
export function didWebToDocUrl(did: string): string | null {
  if (!did.startsWith("did:web:")) return null;
  const id = did.slice("did:web:".length);
  if (id.length === 0 || id.length > 1024) return null;
  // Path segments are colon-separated in did:web. A percent-encoded colon in
  // the host part is a port, and it is carried into the resolved URL: dropping
  // it would resolve a different origin than the identifier names. A port we
  // cannot carry faithfully rejects the whole identifier.
  const parts = id.split(":");
  if (parts.some((p) => p.length === 0)) return null;
  const host = parts[0]!;
  const authority = parseDidWebAuthority(host);
  if (!authority) return null;
  const hostBare = authority.host;
  const hostPort = authority.port === undefined ? hostBare : `${hostBare}:${authority.port}`;
  if (!isValidDidWebHost(hostBare) || isPrivateHost(hostBare)) return null;
  // Build from the SERIALIZED origin: an explicit `:443` is the default port,
  // so it serializes away and the identifier resolves at the origin it names.
  // Any other port is carried verbatim.
  let origin: string;
  try {
    origin = new URL(`https://${hostPort}`).origin;
  } catch {
    return null;
  }
  const safePath = /^[A-Za-z0-9._~\-]+$/;
  if (parts.length === 1) {
    return `${origin}/.well-known/did.json`;
  }
  const rest = parts.slice(1);
  for (const seg of rest) {
    // Reject "." and ".." segments explicitly. They satisfy the
    // safe-char regex but a literal dot-segment in the resolved URL
    // is a traversal vector even after URL normalization elsewhere.
    if (seg === "." || seg === "..") return null;
    if (!safePath.test(seg)) return null;
  }
  return `${origin}/${rest.join("/")}/did.json`;
}

/**
 * Extract a `did:web:` authority through the canonical `didWebToDocUrl`
 * parser. Returns `host` for a portless identifier and `host:port` for one
 * that names a port. Returns null when the DID is malformed (private IP host,
 * bad shape, ill-formed segments, unusable port).
 *
 * The port is part of the identity: `did:web:example.com%3A8443` is not
 * `did:web:example.com`, so a binding check that compared host alone would
 * admit delivery to the wrong origin.
 *
 * Reusing the canonical parser keeps every identity-binding check
 * aligned with the resolver's notion of "valid host". Inline
 * host-extraction logic drifts.
 */
export function extractDidWebHost(did: string): string | null {
  const docUrl = didWebToDocUrl(did);
  if (!docUrl) return null;
  try {
    return new URL(docUrl).host;
  } catch {
    return null;
  }
}
