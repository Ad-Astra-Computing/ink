/**
 * Lightweight audit log of inbound envelopes.
 *
 * Each entry holds ONLY non-sensitive metadata: when, who claimed to
 * send it (sender DID from the envelope, NOT verified at log time),
 * intent type, verdict, error code if any. No payload bodies, no
 * signatures, no IPs. Intended for operator inspection via
 * `wrangler kv key list` or a one-off probe; not surfaced over HTTP.
 *
 * Bounded: KV entries auto-expire after AUDIT_TTL_SEC so the namespace
 * never grows without limit. There is no fan-in path that would let
 * a single sender wipe other senders' entries.
 */

export const AUDIT_TTL_SEC = 7 * 86400;

export interface AuditEntryInput {
  kv: KVNamespace;
  sender: string;
  intent: string;
  verdict: "accepted" | "rejected_rate_limit" | "rejected_schema" | "rejected_signature" | "rejected_unsupported_intent" | "rejected_oversize" | "rejected_utf8" | "error";
  errorCode?: string;
  now?: () => number;
}

const KV_PREFIX = "audit:";

function clamp(s: string, max = 200): string {
  return s.replace(/[^a-zA-Z0-9._:-]/g, "_").slice(0, max);
}

export async function recordAudit(input: AuditEntryInput): Promise<void> {
  const now = input.now ?? (() => Date.now());
  // Reverse-timestamp prefix so a `kv key list` returns newest first.
  const reverseTs = (Number.MAX_SAFE_INTEGER - now()).toString().padStart(16, "0");
  const rand = crypto.getRandomValues(new Uint8Array(8));
  const randHex = Array.from(rand, (b) => b.toString(16).padStart(2, "0")).join("");
  const key = `${KV_PREFIX}${reverseTs}:${randHex}`;
  const value = JSON.stringify({
    ts: new Date(now()).toISOString(),
    sender: clamp(input.sender),
    intent: clamp(input.intent, 32),
    verdict: input.verdict,
    errorCode: input.errorCode ? clamp(input.errorCode, 64) : null,
  });
  try {
    await input.kv.put(key, value, { expirationTtl: AUDIT_TTL_SEC });
  } catch { /* best-effort, never break the response path */ }
}
