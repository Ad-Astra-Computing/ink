/**
 * Per-user inbound-foreign INK acceptance policy.
 *
 * A "foreign sender" is any DID whose method is not native to the
 * receiving service. The example treats `did:tulpa:` and `did:plc:`
 * as native; every other `did:*` is foreign. Adjust `NATIVE_PREFIXES`
 * for your own deployment.
 *
 * The decision function `evaluateInboundForeign` consolidates the
 * precedence rules into a single pure function so call sites cannot
 * accidentally apply the gates in the wrong order:
 *
 *   1. block-list (always wins)
 *   2. native sender (always pass at this layer)
 *   3. master `acceptForeignAgents` opt-in (default OFF)
 *   4. explicit DID allow-list (when non-empty, allow-list-only)
 *   5. method allow-list (e.g. ["did:web:"])
 *   6. host suffix allow-list for `did:web:` senders
 *   7. default: allow
 *
 * Every reject returns a stable reason code so audit logs are
 * grep-able. Storage of the policy is the integrator's choice; this
 * module is pure logic plus normalization helpers.
 */

export interface InkInboundPolicy {
  userId: string;
  /** Master toggle. When false, every foreign-DID sender is rejected
   *  regardless of any allow-list contents. Default: false. */
  acceptForeignAgents: boolean;
  /** When non-empty AND acceptForeignAgents is true, restrict accepted
   *  senders to these DID methods (e.g. ["did:web:", "did:key:"]). */
  allowedMethods: string[];
  /** Host suffix allow-list for did:web: specifically. Trailing-label
   *  semantics — `partner.example` matches `a.partner.example` but
   *  NOT `evilpartner.example`. */
  allowedHosts: string[];
  /** Explicit DID allow-list. When non-empty, ONLY these exact DIDs
   *  are accepted, regardless of method or host. */
  allowedDids: string[];
  /** Explicit DID deny-list. Always enforced — overrides every other
   *  allow rule. */
  blockedDids: string[];
  updatedAt: string;
}

/** Methods that the example treats as "native" — these share the
 *  service's primary key resolution path and are NOT subject to the
 *  foreign-agent gate. Every other did:* (including future methods
 *  this service learns to resolve) is treated as foreign so the
 *  default-deny posture survives a method-family expansion. */
const NATIVE_PREFIXES = ["did:tulpa:", "did:plc:"];

export function isForeignDid(did: string): boolean {
  if (!did.startsWith("did:")) return false;
  return !NATIVE_PREFIXES.some((p) => did.startsWith(p));
}

/**
 * Canonicalize a DID for case-insensitive policy comparison.
 *
 * `did:web:` hosts MUST be lowercase per spec; some senders may not
 * conform, so we lowercase the host portion before matching the
 * recipient's allow/deny lists. We do NOT lowercase did:key: multibase
 * (base58btc is case-sensitive) or path segments (which are
 * %-encoded). Unknown methods are returned unchanged.
 */
export function canonicalizeDid(did: string): string {
  if (did.startsWith("did:web:")) {
    const rest = did.slice("did:web:".length);
    const [host, ...pathParts] = rest.split(":");
    const lowerHost = (host ?? "").toLowerCase().replace(/\.+$/, "");
    return pathParts.length === 0
      ? `did:web:${lowerHost}`
      : `did:web:${lowerHost}:${pathParts.join(":")}`;
  }
  return did;
}

export interface InboundDecision {
  /** True when the sender is allowed to deliver to this recipient. */
  allowed: boolean;
  /** Stable reason code suitable for telemetry/logs. The 403
   *  response body should expose only this code; never the envelope
   *  content. */
  reason:
    | "ok_native"
    | "ok_foreign_user_opt_in"
    | "block_recipient_not_accepting_foreign"
    | "block_method_not_in_user_allow_list"
    | "block_host_not_in_user_allow_list"
    | "block_did_not_in_user_allow_list"
    | "block_did_in_user_block_list";
}

/**
 * Compute whether `senderDid` may deliver an INK message to the user
 * who owns `policy`. Native senders are always accepted at this
 * layer — the upstream worker-level auth chain (signature, freshness,
 * nonce) still applies. Foreign senders are only accepted when
 * `acceptForeignAgents` is true and every applicable allow-list is
 * satisfied.
 */
export function evaluateInboundForeign(
  policy: InkInboundPolicy,
  senderDid: string,
): InboundDecision {
  // Canonicalize the sender DID and every policy list entry before
  // comparing. This ensures a case-shifted or trailing-dot variant of
  // a known DID is treated identically to its canonical form.
  const sender = canonicalizeDid(senderDid);
  const blockedDids = policy.blockedDids.map(canonicalizeDid);
  const allowedDids = policy.allowedDids.map(canonicalizeDid);
  const allowedHosts = policy.allowedHosts.map((h) =>
    h.toLowerCase().replace(/\.+$/, ""),
  );
  // Defense-in-depth: drop any stored method prefix that lost its
  // trailing colon. A `startsWith` match against `did:key` (no colon)
  // would let `did:keyevil-attacker:...` through. Strict shape:
  // `did:<lower-alnum>:`.
  const allowedMethods = policy.allowedMethods.filter((p) =>
    /^did:[a-z0-9]+:$/.test(p),
  );

  // Block-list always wins regardless of any allow rules.
  if (blockedDids.includes(sender)) {
    return { allowed: false, reason: "block_did_in_user_block_list" };
  }
  // Native senders pass through this gate; downstream auth still applies.
  if (!isForeignDid(sender)) {
    return { allowed: true, reason: "ok_native" };
  }
  if (!policy.acceptForeignAgents) {
    return { allowed: false, reason: "block_recipient_not_accepting_foreign" };
  }
  // Explicit DID allow-list — when set, only these DIDs are accepted.
  if (allowedDids.length > 0) {
    if (allowedDids.includes(sender)) {
      return { allowed: true, reason: "ok_foreign_user_opt_in" };
    }
    return { allowed: false, reason: "block_did_not_in_user_allow_list" };
  }
  // Method allow-list.
  if (allowedMethods.length > 0) {
    const matchesMethod = allowedMethods.some((p) => sender.startsWith(p));
    if (!matchesMethod) {
      return { allowed: false, reason: "block_method_not_in_user_allow_list" };
    }
  }
  // Host allow-list — only meaningful for did:web:.
  if (sender.startsWith("did:web:") && allowedHosts.length > 0) {
    const host = (sender
      .slice("did:web:".length)
      .split(":")[0] ?? "")
      .replace(/%3A.*/i, "");
    const matches = allowedHosts.some(
      (suffix) => host === suffix || host.endsWith("." + suffix),
    );
    if (!matches) {
      return { allowed: false, reason: "block_host_not_in_user_allow_list" };
    }
  }
  return { allowed: true, reason: "ok_foreign_user_opt_in" };
}

/**
 * Normalize a list of host suffix entries for the policy's
 * `allowedHosts` field. Rejects ports, schemes, IP literals,
 * wildcards, bare labels, and any value that can't be a valid public
 * authority. Apply on write; re-validate on read so a row that
 * bypassed the writer cannot widen acceptance later.
 */
export function normalizeHostSuffixes(values: string[]): string[] {
  const seen = new Set<string>();
  for (const v of values) {
    if (typeof v !== "string") continue;
    const t = v.trim().toLowerCase().replace(/\.+$/, "");
    if (t.length === 0) continue;
    if (t.includes("/") || t.includes(":") || t.includes("@")) continue;
    if (t.includes("*") || t.includes("?") || t.includes("#")) continue;
    if (t.startsWith(".") || !t.includes(".")) continue;
    if (/^\d{1,3}(\.\d{1,3}){0,3}$/.test(t)) continue;
    if (t.includes("::") || /^[a-f0-9:]+$/i.test(t)) continue;
    if (t.split(".").some((label) => label.length === 0)) continue;
    seen.add(t);
  }
  return Array.from(seen);
}
