/**
 * Sketch: dual rate limiter, per source IP and per sender DID (decision 3).
 *
 * Two independent fixed windows. did:key is free to mint, so the per-DID cap is
 * weak on its own (an attacker rotates DIDs); per-IP is the backstop against
 * that rotation, and per-DID catches one identity spread across many IPs.
 * First-contact (connection_request) gets a tighter per-DID cap.
 *
 * Illustrative, not a tested service. Mirrors the KV/D1 shape of the nonce store.
 */

type Store = {
  get(k: string): Promise<string | null>;
  put(k: string, v: string, o?: { expirationTtl?: number }): Promise<void>;
};

const WINDOW_SEC = 60;
const IP_CAP = 30;
const DID_CAP_FIRST_CONTACT = 5;
const DID_CAP_ESTABLISHED = 20;

async function bump(store: Store, key: string, cap: number): Promise<{ ok: boolean; retryAfter: number }> {
  // Approximate fixed-window counter. KV is not atomic, so a few requests may
  // slip over the cap under contention — acceptable for a coarse limiter.
  const used = parseInt((await store.get(key)) ?? "0", 10) || 0;
  if (used >= cap) return { ok: false, retryAfter: WINDOW_SEC };
  await store.put(key, String(used + 1), { expirationTtl: WINDOW_SEC });
  return { ok: true, retryAfter: 0 };
}

async function hashIp(ip: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ip));
  return [...new Uint8Array(digest)].slice(0, 8).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Pass `did: null` for the pre-parse per-IP check, then call again with the
 * authenticated DID for the per-DID check. Returns the first scope that trips.
 */
export async function checkRateLimits(
  store: Store,
  { ip, did, firstContact }: { ip: string; did: string | null; firstContact: boolean },
): Promise<{ ok: true } | { ok: false; scope: "ip" | "did"; retryAfter: number }> {
  if (did === null) {
    const r = await bump(store, `rl:ip:${await hashIp(ip)}`, IP_CAP);
    return r.ok ? { ok: true } : { ok: false, scope: "ip", retryAfter: r.retryAfter };
  }
  const cap = firstContact ? DID_CAP_FIRST_CONTACT : DID_CAP_ESTABLISHED;
  const r = await bump(store, `rl:did:${did}`, cap);
  return r.ok ? { ok: true } : { ok: false, scope: "did", retryAfter: r.retryAfter };
}
