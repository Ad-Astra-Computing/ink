/**
 * Outbound INK delivery to foreign DIDs.
 *
 * This is the companion to the receive-side gates: when your service
 * also needs to send INK envelopes to peers on other platforms, the
 * caller supplies the recipient's endpoint URL explicitly.
 *
 * INK 0.1 specifies endpoint discovery via a DID-Document service
 * entry (see the Discovery & Transport spec on ink.tulpa.network);
 * implementing that lookup is straightforward but outside the scope
 * of this minimal sender. `did:key:` cannot publish a service entry
 * at all, so even a fully-conformant resolver still needs an
 * explicit-URL path for that method. Adopters who do implement DID
 * Document discovery should layer it on top of the validator below
 * — the SSRF and identity-binding checks here are the same defenses
 * needed regardless of how the URL was obtained.
 *
 * The function below enforces:
 *
 *   - HTTPS only.
 *   - No URL fragments.
 *   - No IP literal hosts (IPv4 dotted-quad, single-numeric, every
 *     bracketed IPv6 form including mapped/reserved literals).
 *   - No hostnames resolving to private/loopback/link-local/cloud
 *     metadata ranges.
 *   - Identity binding for `did:web:` recipients: the URL hostname
 *     must equal the host extracted by `extractDidWebHost`. A
 *     malformed `did:web:` whose canonical host cannot be extracted
 *     is rejected outright; the binding is never disabled by
 *     fallthrough.
 *   - INK §3.3 Authorization signed over `url.pathname` (query
 *     params are intentionally outside the signature base —
 *     receivers must not put authorization-relevant routing in
 *     query).
 *   - 5s timeout, `redirect: "manual"`, 64 KB response cap.
 *
 * Signing is done via `@adastracomputing/ink`'s `signInkMessage` and
 * `buildAuthHeader`. The example imports them by name so a consumer
 * can replace them with their own implementations if needed.
 */

import { signInkMessage, buildAuthHeader } from "@adastracomputing/ink";
import {
  didWebToDocUrl,
  extractDidWebHost,
  isIpLiteralHost,
  isPrivateHost,
} from "./did-web-resolver.js";

const MAX_RESPONSE_BYTES = 64 * 1024;
const TIMEOUT_MS = 5_000;

export type ForeignDeliveryResult =
  | { ok: true; status: number; bodyPreview: string }
  | { ok: false; reason: ForeignDeliveryError; status?: number };

export type ForeignDeliveryError =
  | "invalid_target_url"
  | "host_mismatch"
  | "https_required"
  | "private_host_blocked"
  | "fragment_not_allowed"
  | "network_error"
  | "timeout"
  | "non_2xx"
  | "response_too_large";

export interface ForeignDeliveryInput {
  /** Caller-supplied recipient endpoint URL. */
  targetUrl: string;
  /** Recipient's DID. For `did:web:` recipients the URL host must
   *  equal the DID host. Other methods do not impose a host check. */
  recipientDid: string;
  /** Signed INK envelope ready to POST. */
  envelope: Record<string, unknown>;
  /** Sender's Ed25519 private key for the HTTP auth signature. */
  signingPrivateKey: Uint8Array;
  /** Optional key id to include in the Authorization header. */
  signingKeyId?: string;
}

/**
 * Validate a caller-supplied URL for outbound foreign INK delivery.
 * Returns the parsed URL on success or a stable error code on
 * failure. The error codes feed back into the delivery result so a
 * caller can audit *why* a delivery was refused.
 */
export function validateOutboundDeliveryUrl(
  raw: string,
  options: { requiredDidWebHost?: string } = {},
): { ok: true; url: URL } | { ok: false; reason: ForeignDeliveryError } {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 2048) {
    return { ok: false, reason: "invalid_target_url" };
  }
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, reason: "invalid_target_url" };
  }
  if (parsed.protocol !== "https:") return { ok: false, reason: "https_required" };
  if (parsed.hash.length > 0) return { ok: false, reason: "fragment_not_allowed" };
  const host = parsed.hostname;
  if (!host) return { ok: false, reason: "invalid_target_url" };
  if (isIpLiteralHost(host)) return { ok: false, reason: "private_host_blocked" };
  if (isPrivateHost(host)) return { ok: false, reason: "private_host_blocked" };
  if (options.requiredDidWebHost) {
    const expected = options.requiredDidWebHost.toLowerCase().replace(/\.+$/, "");
    const actual = host.toLowerCase().replace(/\.+$/, "");
    if (expected !== actual) return { ok: false, reason: "host_mismatch" };
  }
  return { ok: true, url: parsed };
}

/**
 * Deliver a signed INK envelope to a foreign INK endpoint.
 *
 * Performs SSRF validation, identity binding (URL host == DID host
 * for did:web), HTTP signing per INK §3.3 over the target URL's
 * pathname, then POSTs with bounded timeout, body cap, and no
 * redirect-following.
 */
export async function deliverInkEnvelopeToForeign(
  input: ForeignDeliveryInput,
): Promise<ForeignDeliveryResult> {
  // Bind URL → DID host for did:web. Other foreign methods (did:key)
  // have no host concept so the binding does not apply. A malformed
  // did:web whose canonical host cannot be extracted must NOT silently
  // disable the binding by falling through to `undefined` — that
  // would let a bad did:web recipient deliver to any validated
  // public target.
  let requiredDidWebHost: string | undefined;
  if (input.recipientDid.startsWith("did:web:")) {
    const host = extractDidWebHost(input.recipientDid);
    if (!host) return { ok: false, reason: "invalid_target_url" };
    requiredDidWebHost = host;
  }
  const validated = validateOutboundDeliveryUrl(input.targetUrl, {
    requiredDidWebHost,
  });
  if (!validated.ok) {
    return { ok: false, reason: validated.reason };
  }
  const url = validated.url;

  const timestamp = new Date().toISOString();
  const sig = await signInkMessage(
    {
      method: "POST",
      path: url.pathname,
      recipientDid: input.recipientDid,
      body: input.envelope,
      timestamp,
    },
    input.signingPrivateKey,
  );
  const authHeader = buildAuthHeader(sig, input.signingKeyId);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": authHeader,
        "Ink-Timestamp": timestamp,
      },
      body: JSON.stringify(input.envelope),
      signal: controller.signal,
      redirect: "manual",
    });
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof Error && err.name === "AbortError") {
      return { ok: false, reason: "timeout" };
    }
    return { ok: false, reason: "network_error" };
  }
  clearTimeout(timer);

  if (!response.ok) {
    return { ok: false, reason: "non_2xx", status: response.status };
  }

  const reader = response.body?.getReader();
  let preview = "";
  if (reader) {
    let received = 0;
    const decoder = new TextDecoder();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        try { await reader.cancel(); } catch { /* */ }
        return { ok: false, reason: "response_too_large", status: response.status };
      }
      preview += decoder.decode(value, { stream: true });
      if (preview.length > 2048) preview = preview.slice(0, 2048);
    }
  }

  return { ok: true, status: response.status, bodyPreview: preview };
}

// Re-exports so consumers can grab the helpers without reaching into
// did-web-resolver directly.
export { didWebToDocUrl, extractDidWebHost };
