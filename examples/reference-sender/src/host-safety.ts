/**
 * Static-literal host safety classifier.
 *
 * The outbound URL validator rejects any IP-literal or private /
 * reserved / loopback / cloud-metadata host before a signed request is
 * sent. This is the same compact classifier used by the
 * `foreign-sender-receiver` example so a sender built on either reads the
 * same way; it depends on nothing outside this file.
 *
 * It is a literal-host gate only. It does NOT resolve DNS, so a public
 * hostname that resolves to a private IP at connect time still needs
 * connect-time IP pinning at the platform layer (a custom fetch).
 */

/**
 * True when the hostname is any literal IP address (IPv4 dotted-quad,
 * decimal-numeric, or bracketed/bare IPv6). Legitimate INK endpoints are
 * reachable by hostname; an IP literal is never one, and enumerating every
 * reserved IPv6 range by hand is error-prone (`::ffff:127.0.0.1` slips past
 * an IPv4-only check), so any IP-shaped host is refused outright.
 */
export function isIpLiteralHost(hostname: string): boolean {
  if (!hostname) return false;
  const bare =
    hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bare)) return true;
  if (/^\d+$/.test(bare)) return true;
  // IPv6: contains `:` and only hex / `:` / `.` (mapped IPv4 tail) / `%`
  // (zone id). URL.hostname always strips the brackets.
  if (bare.includes(":") && /^[0-9a-fA-F:%.]+$/.test(bare)) return true;
  return false;
}

/**
 * True when the hostname names a private, reserved, loopback, or
 * cloud-metadata address. The outbound URL validator rejects any match.
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
    if (a === 169 && b === 254) return true; // link-local incl. 169.254.169.254 metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true; // multicast + reserved
  }
  if (/^\d+$/.test(bare)) return true;
  return false;
}

/**
 * A did:web port is a decimal 1 to 65535 with no leading zeros.
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
 * Serialize a did:web host component to its https origin, or null when the
 * identifier is unusable. The WHATWG serializer drops an explicit default
 * port, so `example.com%3A443` and `example.com` produce the same origin —
 * which is what they mean — while any other port survives verbatim.
 */
export function didWebOrigin(hostComponent: string): string | null {
  const authority = parseDidWebAuthority(hostComponent);
  if (!authority) return null;
  const hostPort = authority.port === undefined
    ? authority.host
    : `${authority.host}:${authority.port}`;
  let url: URL;
  try {
    url = new URL(`https://${hostPort}`);
  } catch {
    return null;
  }
  // The serializer normalizes shorthand IPv4 (`127.1` → `127.0.0.1`) and
  // re-cases; if what it produced isn't the host we parsed, refuse rather than
  // resolve somewhere else. `:443` legitimately serializes to the empty port.
  const expectedPort = authority.port === undefined || authority.port === "443"
    ? ""
    : authority.port;
  if (url.hostname !== authority.host || url.port !== expectedPort) return null;
  return url.origin;
}
