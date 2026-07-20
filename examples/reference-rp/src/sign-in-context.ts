/**
 * The RP's outstanding sign-in state.
 *
 * Two pieces of receiver state carry the flow's non-cryptographic bindings. The
 * first is the sign-in context: when the RP issues a challenge it associates the
 * challenge's nonce with the context that initiated it (a browser session or the
 * carrier's equivalent), and it accepts the answering grant only in that same
 * context. Over a browser redirect there is no authenticated presenter, so the
 * grant verifier's presentation binding never fires; the context binding is what
 * stops a grant minted for one sign-in from completing another. The context has
 * a lifetime of its own: the RP expires it at the challenge's `expiresAt`, so a
 * completion that arrives late finds no context that owns the derived id,
 * whatever the grant's own window says.
 *
 * The second is the seen set of accepted `(issuer, grantId)` pairs. The RP
 * records an accepted pair atomically with acceptance and rejects a second
 * presentation of the same pair, so even an issuer that lost its own mint-once
 * record cannot buy a second sign-in. The two defenses layer: neither depends on
 * the other.
 */

import {
  deriveChallengeGrantId,
  parseInkTimestampMs,
  type AuthorizationChallenge,
  type GrantKey,
} from "@adastracomputing/ink";

export interface SignInContext {
  /** The context that initiated the challenge, e.g. a browser session id. */
  sessionId: string;
  challenge: AuthorizationChallenge;
  /** The grant id derived from the challenge, the derived-id binding key. */
  derivedGrantId: string;
  /** The instant the context expires, equal to the challenge's `expiresAt`. */
  expiresAtMs: number;
}

/**
 * The outcome of looking a session up. `expired` is distinguished from `absent`
 * so the completion endpoint can log a late completion separately from a stray
 * one; both refuse the sign-in.
 */
export type ContextLookup =
  | { status: "live"; context: SignInContext }
  | { status: "expired" }
  | { status: "absent" };

export class SignInContextStore {
  private readonly contexts = new Map<string, SignInContext>();
  private readonly seen = new Set<string>();

  /**
   * Open a sign-in context for a freshly issued challenge, keyed by the session
   * that initiated it. The derived grant id is computed once here and pinned to
   * the context, so completion is a derived-id equality check against it.
   */
  async open(sessionId: string, challenge: AuthorizationChallenge): Promise<SignInContext> {
    const derivedGrantId = await deriveChallengeGrantId(challenge);
    const expiresAtMs = parseInkTimestampMs(challenge.expiresAt);
    if (expiresAtMs === null) {
      // Unreachable: a built challenge carries a strict timestamp. Fail closed.
      throw new Error("challenge expiresAt is not a strict INK timestamp");
    }
    const context: SignInContext = { sessionId, challenge, derivedGrantId, expiresAtMs };
    this.contexts.set(sessionId, context);
    return context;
  }

  /**
   * Look a session up. A context at or after its expiry instant is dropped and
   * reported as `expired`, so a late completion cannot find a context that owns
   * its nonce. A session with no context is `absent`.
   */
  lookup(sessionId: string, nowMs: number): ContextLookup {
    const context = this.contexts.get(sessionId);
    if (context === undefined) return { status: "absent" };
    if (nowMs >= context.expiresAtMs) {
      this.contexts.delete(sessionId);
      return { status: "expired" };
    }
    return { status: "live", context };
  }

  /** The accepted `(issuer, grantId)` pairs, the replay seen set the verifier reads. */
  seenGrants(): Iterable<GrantKey> {
    return [...this.seen].map((entry) => {
      const [issuer, grantId] = splitKey(entry);
      return { issuer, grantId };
    });
  }

  /**
   * Record an accepted pair as a single check-and-insert under one guard, and
   * report whether it was new. Returns false when the pair is already recorded, so
   * the caller refuses a replay. This is the atomicity the spec requires: the
   * check and the insert are one synchronous step, so two concurrent completions
   * of the same pair cannot both be admitted, even though the earlier grant
   * verification is async and only reads the seen set. This in-memory store is
   * single threaded; a real store performs the same check-and-insert against its
   * own concurrency, for example a unique-key insert whose conflict is the replay.
   */
  tryAccept(key: GrantKey): boolean {
    const entry = joinKey(key);
    if (this.seen.has(entry)) return false;
    this.seen.add(entry);
    return true;
  }
}

// The seen set is keyed by the (issuer, grantId) pair. It is stored as a single
// string with a length-prefixed issuer so no issuer or grantId value can be
// crafted to collide with another pair through the separator.
function joinKey(key: GrantKey): string {
  return `${key.issuer.length}:${key.issuer}:${key.grantId}`;
}

function splitKey(entry: string): [string, string] {
  const firstColon = entry.indexOf(":");
  const issuerLen = Number(entry.slice(0, firstColon));
  const issuer = entry.slice(firstColon + 1, firstColon + 1 + issuerLen);
  const grantId = entry.slice(firstColon + 1 + issuerLen + 1);
  return [issuer, grantId];
}
