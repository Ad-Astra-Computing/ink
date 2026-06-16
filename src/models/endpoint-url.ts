// INK Agent Card endpoint URL grammar (1.0).
//
// Agent Card endpoint fields (endpoint, inboxEndpoint, thirdPartyAudit.endpoint)
// are validated against a deliberately narrow, deterministic grammar rather than
// the broad, runtime-dependent `z.string().url()` (which accepts javascript:,
// mailto:, ftp:, control-character-tainted strings, etc.). Pinning the grammar
// keeps the wire contract identical across implementations and keeps endpoint
// identifiers to fetchable https URLs. See specs/ink-agent-card.md.
//
// An endpoint URL is a non-empty string of at most 2048 UTF-8 bytes, containing
// no ASCII control character or whitespace, with scheme https (lowercase), a
// non-empty host (DNS name, IPv4, or bracketed IPv6), no userinfo, an optional
// 1..65535 port, an optional path and query, and no fragment.
// The grammar is validated by explicit string rules, NOT a runtime URL parser:
// `new URL()` and Go's net/url disagree on backslashes, malformed percent
// escapes, percent-encoded hosts, and IPv6 zone ids, so relying on either would
// reintroduce a cross-implementation split. Both implementations run this same
// logic instead.
export function isInkEndpointUrl(value: unknown): boolean {
  if (typeof value !== "string" || value.length === 0) return false;
  if (new TextEncoder().encode(value).length > 2048) return false;
  // No ASCII control chars (<= U+001F), no ASCII whitespace including space
  // (U+0020), no DEL (U+007F). Do not trim first.
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) return false;
  }
  // A backslash is normalized to a slash by WHATWG but kept by other parsers.
  if (value.includes("\\")) return false;
  // Every percent escape must be %XX with two hex digits.
  if (/%(?![0-9A-Fa-f]{2})/.test(value)) return false;
  // Scheme must be lowercase https with an authority; a fragment is a
  // client-side identifier, not part of an endpoint.
  if (!value.startsWith("https://")) return false;
  if (value.includes("#")) return false;
  const authority = value.slice("https://".length).split(/[/?]/, 1)[0] ?? "";
  if (authority.length === 0) return false;
  // No userinfo, and no percent-encoding in the host (which a permissive parser
  // would decode, diverging across implementations).
  if (authority.includes("@") || authority.includes("%")) return false;
  let host: string;
  let port: string | undefined;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end === -1) return false;
    host = authority.slice(1, end);
    const after = authority.slice(end + 1);
    if (after !== "") {
      if (!after.startsWith(":")) return false;
      port = after.slice(1);
    }
    // Bracketed IPv6 literal: hex digits, colons, and dots only.
    if (host.length === 0 || !/^[0-9A-Fa-f:.]+$/.test(host)) return false;
  } else {
    const colon = authority.indexOf(":");
    if (colon === -1) {
      host = authority;
    } else {
      host = authority.slice(0, colon);
      port = authority.slice(colon + 1);
    }
    // Reg-name or IPv4 host: letters, digits, dot, hyphen.
    if (host.length === 0 || !/^[A-Za-z0-9.-]+$/.test(host)) return false;
  }
  if (port !== undefined) {
    if (!/^[0-9]+$/.test(port)) return false;
    const n = Number(port);
    if (n < 1 || n > 65535) return false;
  }
  return true;
}
