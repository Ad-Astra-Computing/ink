/**
 * Per-sender rate limit, KV-backed.
 *
 * The receiver is a public test target so it MUST be resilient to a
 * single sender flooding it. The cheap version: 30 inbound envelopes
 * per sender DID per 60s, enforced via a sliding-window counter in KV.
 *
 * Race notes: KV is eventually consistent and read-modify-write is
 * not transactional. Two parallel requests CAN both pass the limit
 * window in a tight burst. That's OK for a test receiver: the goal
 * is to stop a stuck client from running the worker into the ground,
 * not to be a financial-grade rate limiter.
 */

export interface RateLimitInput {
  kv: KVNamespace;
  /** Sender identifier — already canonicalized by the caller. */
  senderKey: string;
  /** Calls allowed per window. */
  limit: number;
  /** Window length in seconds. */
  windowSec: number;
  /** `Date.now()` injected for tests. */
  now?: () => number;
}

export interface RateLimitVerdict {
  allowed: boolean;
  remaining: number;
  resetSec: number;
}

const KV_PREFIX = "rl:";

function clamp(s: string): string {
  return s.replace(/[^a-zA-Z0-9._:-]/g, "_").slice(0, 200);
}

export async function checkRateLimit(input: RateLimitInput): Promise<RateLimitVerdict> {
  const now = input.now ?? (() => Date.now());
  const nowSec = Math.floor(now() / 1000);
  const bucket = Math.floor(nowSec / input.windowSec);
  const key = `${KV_PREFIX}${clamp(input.senderKey)}:${bucket}`;
  let count = 0;
  try {
    const raw = await input.kv.get(key);
    if (raw) {
      const parsed = parseInt(raw, 10);
      if (Number.isFinite(parsed) && parsed >= 0) count = parsed;
    }
  } catch { /* KV transient failure — fall through with count=0 */ }
  if (count >= input.limit) {
    return {
      allowed: false,
      remaining: 0,
      resetSec: (bucket + 1) * input.windowSec - nowSec,
    };
  }
  try {
    // expirationTtl: a hair more than two windows so a request landing
    // just at the boundary still sees its own write before the bucket
    // rolls over.
    await input.kv.put(key, String(count + 1), {
      expirationTtl: input.windowSec * 2 + 30,
    });
  } catch { /* best-effort */ }
  return {
    allowed: true,
    remaining: Math.max(0, input.limit - (count + 1)),
    resetSec: (bucket + 1) * input.windowSec - nowSec,
  };
}
