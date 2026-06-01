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
  // Path segments are colon-separated in did:web. Percent-encoded
  // colons in the host part may legitimately appear for ports, but
  // we refuse them here — a published did:web endpoint should not
  // depend on a port.
  const parts = id.split(":");
  if (parts.some((p) => p.length === 0)) return null;
  const host = parts[0]!;
  const hostBare = host.split("%3A")[0]!;
  if (!isValidDidWebHost(hostBare) || isPrivateHost(hostBare)) return null;
  const safePath = /^[A-Za-z0-9._~\-]+$/;
  if (parts.length === 1) {
    return `https://${hostBare}/.well-known/did.json`;
  }
  const rest = parts.slice(1);
  for (const seg of rest) {
    if (!safePath.test(seg)) return null;
  }
  return `https://${hostBare}/${rest.join("/")}/did.json`;
}

/**
 * Extract a `did:web:` host through the canonical
 * `didWebToDocUrl` parser. Returns null when the DID is malformed
 * (private IP host, bad shape, ill-formed segments).
 *
 * Reusing the canonical parser keeps every identity-binding check
 * aligned with the resolver's notion of "valid host". Inline
 * host-extraction logic drifts.
 */
export function extractDidWebHost(did: string): string | null {
  const docUrl = didWebToDocUrl(did);
  if (!docUrl) return null;
  try {
    return new URL(docUrl).hostname;
  } catch {
    return null;
  }
}
