import { computeMessageHash, signInkMessage, buildAuthHeader } from "../crypto/ink.js";
import { signMessage, verifyMessage } from "../crypto/sign.js";
import { isPrivateHostname } from "../discovery/agent-card.js";
import { InkReceiptSchema, type InkReceipt } from "../models/ink-audit.js";
import { wireTypeAliases } from "../models/wire-type.js";

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

export interface VerifyReceiptResult {
  valid: boolean;
  /** Machine-readable reason when `valid` is false. */
  reason?: string;
}

/**
 * Verify an INK receipt against the message it claims to acknowledge.
 *
 * Checks all the bindings a hand-rolled verifier commonly forgets: the
 * receipt's Ed25519 signature against the issuer's (`from`) key, that `from`,
 * `to` and `messageId` equal the expected values, and that `messageHash`
 * equals the hash of the exact message body that was sent (recomputed here,
 * not trusted from the receipt). A receipt that passes proves the named
 * counterparty acknowledged that specific message; nothing weaker should be
 * treated as proof of delivery.
 */
export async function verifyReceipt(opts: {
  receipt: unknown;
  /** Raw 32-byte Ed25519 public key of the issuer (the receipt's `from`). */
  senderPublicKey: Uint8Array;
  expected: {
    from: string;
    to: string;
    messageId: string;
    messageBody: Record<string, unknown>;
    /** When set, require the receipt to acknowledge this specific disposition
     *  (e.g. "delivered"). The disposition is covered by the signature, but
     *  without this a signed receipt for a different state would still pass, so
     *  callers proving a specific delivery state MUST pin it. */
    disposition?: InkReceipt["disposition"];
  };
}): Promise<VerifyReceiptResult> {
  const parsed = InkReceiptSchema.safeParse(opts.receipt);
  if (!parsed.success) return { valid: false, reason: "malformed_receipt" };
  const receipt = parsed.data;
  const { senderPublicKey, expected } = opts;
  if (!(senderPublicKey instanceof Uint8Array) || senderPublicKey.length !== 32) {
    return { valid: false, reason: "invalid_public_key" };
  }
  if (receipt.from !== expected.from) return { valid: false, reason: "from_mismatch" };
  if (receipt.to !== expected.to) return { valid: false, reason: "to_mismatch" };
  if (receipt.messageId !== expected.messageId) return { valid: false, reason: "message_id_mismatch" };
  if (expected.disposition !== undefined && receipt.disposition !== expected.disposition) {
    return { valid: false, reason: "disposition_mismatch" };
  }
  let expectedHash: string;
  try {
    expectedHash = await computeMessageHash(expected.messageBody);
  } catch {
    return { valid: false, reason: "message_hash_error" };
  }
  if (receipt.messageHash !== expectedHash) return { valid: false, reason: "message_hash_mismatch" };
  const sigOk = await verifyMessage(receipt as unknown as Record<string, unknown>, senderPublicKey);
  if (!sigOk) return { valid: false, reason: "invalid_signature" };
  return { valid: true };
}

/** Loop prevention: don't send receipts for receipts or audit messages.
 *  Both the legacy `network.tulpa.*` and vendor-neutral `network.ink.*`
 *  spellings are suppressed, so a peer on the new namespace cannot induce a
 *  receipt loop. */
const NO_RECEIPT_TYPES = new Set<string>([
  ...wireTypeAliases("receipt"),
  ...wireTypeAliases("audit_query"),
  ...wireTypeAliases("audit_response"),
  ...wireTypeAliases("audit_submit"),
  ...wireTypeAliases("audit_inclusion"),
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
