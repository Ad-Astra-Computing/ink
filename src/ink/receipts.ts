import { computeMessageHash, signInkMessage, buildAuthHeader } from "../crypto/ink.js";
import { signMessage } from "../crypto/sign.js";
import { isPrivateHostname } from "../discovery/agent-card.js";
import type { InkReceipt } from "../models/ink-audit.js";

export interface BuildReceiptInput {
  from: string;
  to: string;
  messageId: string;
  messageBody: Record<string, unknown>;
  disposition: "received" | "delivered" | "acted" | "rejected";
  note?: string;
  privateKey: Uint8Array;
}

/** Build a signed INK receipt envelope. */
export async function buildReceipt(input: BuildReceiptInput): Promise<InkReceipt> {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("input must be a non-null object");
  }
  if (!(input.privateKey instanceof Uint8Array) || input.privateKey.length !== 32) {
    throw new Error("input.privateKey must be a 32-byte Uint8Array");
  }
  const now = new Date().toISOString();
  const messageHash = await computeMessageHash(input.messageBody);
  const nonce = crypto.randomUUID().replace(/-/g, "");

  const unsigned = {
    protocol: "ink/0.1" as const,
    type: "network.tulpa.receipt" as const,
    from: input.from,
    to: input.to,
    messageId: input.messageId,
    disposition: input.disposition,
    dispositionAt: now,
    messageHash,
    nonce,
    timestamp: now,
    ...(input.note ? { note: input.note } : {}),
  };

  const signature = await signMessage(unsigned as unknown as Record<string, unknown>, input.privateKey);

  return { ...unsigned, signature };
}

/** Loop prevention: don't send receipts for receipts or audit messages. */
const NO_RECEIPT_TYPES = new Set([
  "network.tulpa.receipt",
  "network.tulpa.audit_query",
  "network.tulpa.audit_response",
  "network.tulpa.audit_submit",
  "network.tulpa.audit_inclusion",
]);

export function shouldSendReceipt(intentOrType: string): boolean {
  return !NO_RECEIPT_TYPES.has(intentOrType);
}

export interface SendReceiptOptions {
  /** Allow endpoints whose hostname is loopback / private / link-local /
   *  IANA special-use. Off by default — flip on only for tests or for
   *  intentional intranet deployments where peer endpoints are trusted. */
  allowPrivateHosts?: boolean;
}

/** Fire-and-forget POST of a receipt with INK request signature. Never throws.
 *
 *  Endpoint MUST be an absolute `https://` URL. Other schemes (file://, data:,
 *  blob:, http://) are rejected silently to prevent SSRF and local-file
 *  exfiltration when integrators pass peer-supplied URLs without sanitising.
 *
 *  Mirrors the SSRF defenses in fetchAgentCard: https-only, no userinfo,
 *  literal-hostname allowlist excluding private/loopback/special-use, no
 *  redirect following, request timeout. DNS rebinding is still the
 *  integrator's responsibility — pass a connect-time-pinning `fetchFn`
 *  when the endpoint is not fully trusted. */
export async function sendReceiptFireAndForget(
  endpoint: string,
  receipt: InkReceipt,
  privateKey: Uint8Array,
  fetchFn: typeof fetch = globalThis.fetch,
  signingKeyId?: string,
  options?: SendReceiptOptions,
): Promise<void> {
  try {
    let url: URL;
    try { url = new URL(endpoint); } catch { return; }
    if (url.protocol !== "https:") return;
    if (url.username || url.password) return;
    if (!options?.allowPrivateHosts && isPrivateHostname(url.hostname)) return;

    const sig = await signInkMessage({
      method: "POST",
      path: url.pathname,
      recipientDid: receipt.to,
      body: receipt as unknown as Record<string, unknown>,
      timestamp: receipt.timestamp,
    }, privateKey);

    await fetchFn(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": buildAuthHeader(sig, signingKeyId),
      },
      body: JSON.stringify(receipt),
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    // Fire-and-forget — swallow errors
  }
}
