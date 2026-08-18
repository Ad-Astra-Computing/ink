/**
 * Transport: SSRF-safe delivery of a signed envelope.
 *
 * Sending a signed message to an attacker-influenced URL is an SSRF
 * sink, so the URL is validated before anything is signed or sent:
 *
 *   - https only (no cleartext, no other schemes).
 *   - No embedded userinfo (it confuses host parsing downstream).
 *   - No fragment (never sent on the wire; its presence signals a
 *     malformed or hostile URL).
 *   - Host is not an IP literal or a loopback / private / link-local /
 *     cloud-metadata address, decided by the static-literal classifier in
 *     `host-safety.ts`. A literal host is never a legitimate INK endpoint.
 *   - For `did:web:` recipients the URL host must equal the DID host
 *     (identity binding), so a signed envelope for one identity cannot be
 *     delivered to an unrelated endpoint.
 *
 * This is a static-literal gate. It does NOT defend against DNS
 * rebinding: a public hostname that resolves to a private IP at connect
 * time still needs connect-time IP pinning at the platform layer.
 *
 * The transport signature (INK §3.3) is signed over the URL's pathname,
 * never its query — receivers must not put authorization-relevant routing
 * in the query string.
 */

import { signInkMessage, buildAuthHeader } from "@adastracomputing/ink";
import type { SenderIdentity } from "./identity.ts";
import { isIpLiteralHost, isPrivateHost, didWebOrigin } from "./host-safety.ts";

const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_PREVIEW_CHARS = 2048;
const TIMEOUT_MS = 5_000;

export type DeliveryError =
  | "invalid_target_url"
  | "https_required"
  | "userinfo_not_allowed"
  | "fragment_not_allowed"
  | "private_host_blocked"
  | "host_mismatch"
  | "timeout"
  | "network_error"
  | "non_2xx"
  | "response_too_large";

export type UrlValidation =
  | { ok: true; url: URL }
  | { ok: false; reason: DeliveryError };

/**
 * Extract the canonical AUTHORITY from a `did:web:` identifier, or null.
 *
 * did:web encodes the host (and optional path segments) colon-separated, with
 * a port percent-encoded as `%3A` inside the first segment. The port is part
 * of the identity — `did:web:example.com%3A8443` is not
 * `did:web:example.com` — so it is carried into the returned authority and
 * compared by the delivery binding. An explicit `:443` serializes away,
 * because it names the default origin. This is the same grammar discovery
 * uses (`didWebTargets`), so the two stay on one authority.
 */
export function didWebHost(did: string): string | null {
  if (!did.startsWith("did:web:")) return null;
  const rest = did.slice("did:web:".length);
  if (rest.length === 0) return null;
  const firstSegment = rest.split(":")[0]!;
  const origin = didWebOrigin(firstSegment);
  if (origin === null) return null;
  const host = new URL(origin).host.toLowerCase().replace(/\.+$/, "");
  return host.length > 0 ? host : null;
}

export function validateTargetUrl(
  raw: string,
  options: { requiredDidWebHost?: string; allowPrivateHosts?: boolean } = {},
): UrlValidation {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 2048) {
    return { ok: false, reason: "invalid_target_url" };
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: "invalid_target_url" };
  }
  if (url.protocol !== "https:") return { ok: false, reason: "https_required" };
  if (url.username || url.password) return { ok: false, reason: "userinfo_not_allowed" };
  if (url.hash.length > 0) return { ok: false, reason: "fragment_not_allowed" };
  const host = url.hostname;
  if (!host) return { ok: false, reason: "invalid_target_url" };
  // The private/loopback/IP-literal refusal is the one check `allowPrivateHosts`
  // relaxes, for local-dev targets. https, userinfo, fragment, and the did:web
  // host binding below are never relaxed.
  if (!options.allowPrivateHosts) {
    if (isIpLiteralHost(host)) return { ok: false, reason: "private_host_blocked" };
    if (isPrivateHost(host)) return { ok: false, reason: "private_host_blocked" };
  }
  if (options.requiredDidWebHost) {
    // Compare the AUTHORITY, not the bare hostname: a did:web that names a
    // port binds to that port, and comparing hostnames alone would let an
    // endpoint on a different port satisfy the binding.
    const expected = options.requiredDidWebHost.toLowerCase().replace(/\.+$/, "");
    const actual = url.host.toLowerCase().replace(/\.+$/, "");
    if (expected !== actual) return { ok: false, reason: "host_mismatch" };
  }
  return { ok: true, url };
}

export interface DeliverInput {
  identity: SenderIdentity;
  /** Absolute https URL to POST to. */
  targetUrl: string;
  /** Recipient DID. For did:web the URL host must equal the DID host. */
  recipientDid: string;
  /** Fully signed, schema-valid envelope. */
  envelope: Record<string, unknown>;
  /** Injectable fetch (tests, or a connect-time-IP-pinning wrapper). */
  fetchImpl?: typeof fetch;
  /** Injectable clock for deterministic tests. */
  now?: () => Date;
  /** Overall request budget covering connect AND body read. Default 5s. */
  timeoutMs?: number;
  /** Permit a private/loopback delivery host (local dev only). The did:web
   *  host binding is still enforced. */
  allowPrivateHosts?: boolean;
}

export type DeliverResult =
  | { ok: true; status: number; bodyPreview: string }
  | { ok: false; reason: DeliveryError; status?: number };

/**
 * Validate, sign, and POST a signed envelope to a foreign INK endpoint.
 * Returns a stable error code on any refusal so a caller can audit why a
 * delivery did not happen.
 */
export async function deliverEnvelope(input: DeliverInput): Promise<DeliverResult> {
  let requiredDidWebHost: string | undefined;
  if (input.recipientDid.startsWith("did:web:")) {
    const host = didWebHost(input.recipientDid);
    // A malformed did:web whose host cannot be extracted must NOT fall
    // through with an undefined binding — that would let a bad recipient
    // deliver to any validated public target.
    if (!host) return { ok: false, reason: "invalid_target_url" };
    requiredDidWebHost = host;
  }

  const validated = validateTargetUrl(input.targetUrl, {
    requiredDidWebHost,
    allowPrivateHosts: input.allowPrivateHosts,
  });
  if (!validated.ok) return { ok: false, reason: validated.reason };
  const url = validated.url;

  // The §3.3 signature base timestamp MUST equal the envelope's own
  // `timestamp` field: the receiver's `verifyInkAuth` reconstructs the
  // base from `body.timestamp`, so signing over any other value yields a
  // base the receiver cannot reproduce. Fall back to a fresh timestamp
  // only if the envelope carries none.
  const timestamp =
    typeof input.envelope.timestamp === "string"
      ? input.envelope.timestamp
      : (input.now ? input.now() : new Date()).toISOString();
  const sig = await signInkMessage(
    {
      method: "POST",
      path: url.pathname,
      recipientDid: input.recipientDid,
      body: input.envelope,
      timestamp,
    },
    input.identity.privateKey,
  );
  // No keyId hint: a did:key sender carries its single verification key
  // inline in the DID, so there is nothing for the receiver to select.
  const authHeader = buildAuthHeader(sig);

  const doFetch = input.fetchImpl ?? fetch;
  const timeoutMs = input.timeoutMs ?? TIMEOUT_MS;
  const controller = new AbortController();
  // The timer stays armed through the body read, not just the header
  // exchange: a hostile endpoint can return headers then stall the body
  // forever, and the byte cap only fires once bytes arrive. Aborting the
  // shared controller cancels an in-flight body read too. Cleared once in
  // `finally`.
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response: Response;
    try {
      response = await doFetch(url.toString(), {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: authHeader,
        },
        body: JSON.stringify(input.envelope),
        signal: controller.signal,
        redirect: "manual",
      });
    } catch (err) {
      return abortOrNetwork(err);
    }

    if (!response.ok) {
      return { ok: false, reason: "non_2xx", status: response.status };
    }

    let preview: string | null;
    try {
      preview = await readCappedText(response);
    } catch (err) {
      return abortOrNetwork(err);
    }
    if (preview === null) {
      return { ok: false, reason: "response_too_large", status: response.status };
    }
    return { ok: true, status: response.status, bodyPreview: preview };
  } finally {
    clearTimeout(timer);
  }
}

/** Map a fetch/read rejection to a timeout (on abort) or a network error. */
function abortOrNetwork(err: unknown): { ok: false; reason: DeliveryError } {
  if (err instanceof Error && err.name === "AbortError") {
    return { ok: false, reason: "timeout" };
  }
  return { ok: false, reason: "network_error" };
}

/** Read at most MAX_RESPONSE_BYTES, returning null if the body exceeds it. */
async function readCappedText(response: Response): Promise<string | null> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const decoder = new TextDecoder();
  let received = 0;
  let preview = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      received += value.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        try {
          await reader.cancel();
        } catch {
          /* ignore */
        }
        return null;
      }
      preview += decoder.decode(value, { stream: true });
      if (preview.length > MAX_PREVIEW_CHARS) preview = preview.slice(0, MAX_PREVIEW_CHARS);
    }
  }
  return preview;
}
