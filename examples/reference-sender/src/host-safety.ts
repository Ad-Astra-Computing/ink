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
