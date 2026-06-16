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
export function isInkEndpointUrl(value: unknown): boolean {
  if (typeof value !== "string" || value.length === 0) return false;
  if (new TextEncoder().encode(value).length > 2048) return false;
  // No ASCII control chars (<= U+001F), no ASCII whitespace including space
  // (U+0020), no DEL (U+007F). Do not trim first.
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) return false;
  }
  // Scheme must be lowercase https with an authority.
  if (!value.startsWith("https://")) return false;
  // A fragment is a client-side identifier, not part of an endpoint.
  if (value.includes("#")) return false;
  const authority = value.slice("https://".length).split(/[/?]/, 1)[0] ?? "";
  if (authority.length === 0) return false;
  // No userinfo.
  if (authority.includes("@")) return false;
  // Validate an explicit port: decimal digits, 1..65535. Strip a bracketed
  // IPv6 host so its inner colons are not read as a port separator.
  const hostPort = authority.startsWith("[")
    ? authority.slice(authority.indexOf("]") + 1)
    : authority;
  const colon = hostPort.indexOf(":");
  if (colon !== -1) {
    const port = hostPort.slice(colon + 1);
    if (!/^[0-9]+$/.test(port)) return false;
    const n = Number(port);
    if (n < 1 || n > 65535) return false;
  }
  // Final parseability and host validation.
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return false;
  }
  if (u.protocol !== "https:" || u.hostname === "" || u.username !== "" || u.password !== "" || u.hash !== "") {
    return false;
  }
  return true;
}
