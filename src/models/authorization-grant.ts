import { z } from "zod";
import { dualWireType } from "./wire-type.js";
import { isInkTimestamp, parseInkTimestampMs } from "../crypto/timestamp.js";
import { isWithinBounds, signMessage, verifyMessage } from "../crypto/sign.js";
import { hasUnpairedSurrogate } from "../crypto/surrogate.js";

// A minimal scoped authorization grant, the "Sign in with INK" primitive. An
// issuer signs a bounded capability for a subject to present to one named
// audience, valid for a fixed window. It is deliberately not a permissions
// framework: there is no delegation chain, no capability algebra, and no policy
// language. Scope strings are opaque tokens the audience interprets by its own
// policy. The verifier makes only the security decisions two implementations
// must agree on: signature, audience, expiry, replay, revocation, and an
// optional owner-verification requirement.

// Caps mirror the DID/agent-id bound used across INK payloads. The scope caps
// bound the parser so an overbroad or pathological scope array cannot expand a
// grant beyond what a verifier will walk.
const ID_MAX = 512;
const GRANT_ID_MIN = 16;
const GRANT_ID_MAX = 256;
const SCOPE_ENTRY_MAX = 128;
const SCOPE_MAX = 64;

// Maximum grant lifetime. The validity window (expiresAt minus issuedAt) must
// not exceed this. A grant is a short-lived bootstrap credential and its window
// is the primary revocation control, so a long window undermines the whole
// short-TTL stance. Ten minutes is the login/bootstrap ceiling: long enough to
// absorb clock skew and a slow sign-in, short enough that every grant expires on
// its own before a receiver denylist would matter. It is a fixed profile bound,
// larger than the 5 minute freshness age used for single messages because a
// grant covers a whole sign-in rather than one request. A verifier caller may
// tighten this per check but never loosen it. A grant whose window exceeds the
// cap is out of profile and rejects structurally, the same as a grantId or scope
// bound, independent of the verifier clock.
export const MAX_GRANT_LIFETIME_MS = 10 * 60 * 1000;

/**
 * Byte-length ceiling on a raw grant body, the byte-layer counterpart to the
 * structural schema bounds. A receiver holding raw grant bytes MUST reject a body
 * longer than this as `schema` before it decodes the bytes, per the *Byte bound*
 * rule in the spec: the largest well-formed grant is around 12 KiB, so a body
 * padded past 65536 bytes is not a legitimate presentation and need not be
 * decoded. This reference `verifyAuthorizationGrant` takes an already-decoded
 * object and applies the structural bounds instead, so this constant is the
 * contract for whatever layer received the bytes, the same rule the Go
 * `MaxGrantBodyBytes` enforces on its bytes API. See
 * [`specs/ink-authorization-grant.md`](../../specs/ink-authorization-grant.md).
 */
export const MAX_GRANT_BODY_BYTES = 65536;

// A scope is a non-empty array of distinct opaque tokens. Distinctness is
// enforced so a grant cannot smuggle a larger apparent scope through repetition,
// and so two implementations count the same set. The tokens are not parsed here:
// their meaning is the audience's policy.
const ScopeSchema = z
  .array(z.string().min(1).max(SCOPE_ENTRY_MAX))
  .min(1)
  .max(SCOPE_MAX)
  .refine((s) => new Set(s).size === s.length, { message: "scope entries must be distinct" });

// The validity window must be strictly positive and no longer than the maximum
// grant lifetime. A zero or negative window is a malformed grant, not one that
// expires the instant it is issued. A window longer than MAX_GRANT_LIFETIME_MS
// is out of profile: the short-window control only holds if the window is short.
function isWindowInProfile(g: { issuedAt: string; expiresAt: string }): boolean {
  const start = parseInkTimestampMs(g.issuedAt);
  const end = parseInkTimestampMs(g.expiresAt);
  if (start === null || end === null) return false;
  if (end <= start) return false;
  return end - start <= MAX_GRANT_LIFETIME_MS;
}

// The signed grant. The signature covers every field except `signature` itself,
// so a verifier can bind the grant to the issuer key and reject any tampering of
// the subject, audience, scope, or validity window. The wire `type` accepts the
// vendor-neutral network.ink spelling alongside the legacy network.tulpa one;
// the spelling is signed, never normalized.
export const AuthorizationGrantSchema = z
  .object({
    protocol: z.literal("ink/0.1"),
    type: dualWireType("authorization_grant"),
    issuer: z.string().min(1).max(ID_MAX),
    subject: z.string().min(1).max(ID_MAX),
    audience: z.string().min(1).max(ID_MAX),
    scope: ScopeSchema,
    grantId: z.string().min(GRANT_ID_MIN).max(GRANT_ID_MAX),
    issuedAt: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
    expiresAt: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
    // Optional owner-verification requirement. When true the verifier requires
    // the caller to supply a verified owner status; the check itself is the
    // caller's owner-verification pipeline. Absent means the grant does not
    // require owner verification.
    requireVerifiedOwner: z.boolean().optional(),
    // The signature is 64 raw bytes, 86 base64url characters with no padding. A
    // string that is not that exact shape is a structural failure, rejected as
    // "schema" before any signature work, so both implementations agree on the
    // reason for a malformed signature.
    signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  })
  .strict()
  // The window must be strictly positive and within the maximum grant lifetime.
  .refine(isWindowInProfile, {
    message: "validity window must be positive and within the maximum grant lifetime",
  });

export type AuthorizationGrant = z.infer<typeof AuthorizationGrantSchema>;

const UnsignedAuthorizationGrantSchema = z
  .object({
    protocol: z.literal("ink/0.1"),
    type: dualWireType("authorization_grant"),
    issuer: z.string().min(1).max(ID_MAX),
    subject: z.string().min(1).max(ID_MAX),
    audience: z.string().min(1).max(ID_MAX),
    scope: ScopeSchema,
    grantId: z.string().min(GRANT_ID_MIN).max(GRANT_ID_MAX),
    issuedAt: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
    expiresAt: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
    requireVerifiedOwner: z.boolean().optional(),
  })
  .strict()
  .refine(isWindowInProfile, {
    message: "validity window must be positive and within the maximum grant lifetime",
  });

export interface AuthorizationGrantInput {
  /** Defaults to the legacy `network.tulpa.authorization_grant` spelling. */
  type?: "network.tulpa.authorization_grant" | "network.ink.authorization_grant";
  issuer: string;
  subject: string;
  audience: string;
  scope: string[];
  grantId: string;
  issuedAt: string;
  expiresAt: string;
  requireVerifiedOwner?: boolean;
}

/**
 * Which check rejected a grant. Callers discriminate on this stable field rather
 * than any message prose. `schema` covers every structural, byte-safety, or
 * profile-bound failure, including a window that exceeds the maximum grant
 * lifetime and a verifier clock that is not a strict INK timestamp; the rest are
 * the individual security decisions.
 */
export type AuthorizationGrantReason =
  | "schema"
  | "signature"
  | "audience"
  | "subject"
  | "expired"
  | "not_yet_valid"
  | "replay"
  | "revoked"
  | "owner_unverified";

/**
 * Thrown by callers that prefer an exception over the result object. `reason` is
 * the same stable discriminator the verify result carries. The verifier itself
 * never throws; it returns a rejection result.
 */
export class AuthorizationGrantError extends Error {
  readonly reason: AuthorizationGrantReason;

  constructor(reason: AuthorizationGrantReason, message: string) {
    super(message);
    this.name = "AuthorizationGrantError";
    this.reason = reason;
  }
}

/**
 * The self-asserted human-ownership signal the caller's owner-verification
 * pipeline produces. This module does not compute it. When a grant sets
 * `requireVerifiedOwner`, the verifier requires `status === "verified"` here.
 */
export interface VerifiedOwnerStatus {
  status: "verified" | "unverified";
}

/**
 * A grant identity for replay and revocation. Both keys are the pair of the
 * signed `issuer` and the issuer-chosen `grantId`. `grantId` is chosen by the
 * issuer, so two issuers can pick the same string; keying replay and revocation
 * on the pair keeps one issuer's seen or revoked ids from colliding with
 * another's, which would otherwise let a hostile or careless issuer deny or
 * confuse a grant it never minted.
 */
export interface GrantKey {
  issuer: string;
  grantId: string;
}

/**
 * Everything a verifier needs beyond the issuer key. `audience` is the service
 * checking the grant, compared against the signed `audience` to reject a grant
 * minted for a different service (confused deputy). `now` is the verifier clock,
 * a strict INK timestamp. `presenter` is the authenticated identity of the
 * principal presenting the grant, as the transport established it (for INK, the
 * signed envelope sender); a presenter is a non-empty string, and when it is
 * supplied it must equal the signed `subject`, so a stolen grant is not
 * presentable by another principal inside its window. An empty or absent
 * presenter means no authenticated presenter was established: the binding check
 * is skipped and the grant is a bearer artifact whose presentation the audience
 * must bind out of band. Treating `""` as absent matches Go's `Presenter != ""`
 * gate, since Go cannot distinguish an unset string field from `""`; a service
 * MUST NOT pass an empty string as an authenticated identity.
 * `seenGrants` and `isRevoked` are the two receiver policy hooks for replay and
 * revocation; both are keyed by the `(issuer, grantId)` pair, both optional, and
 * default to "not seen" and "not revoked". `seenGrants` only reports what a prior
 * acceptance recorded: a service MUST record the accepted `(issuer, grantId)`
 * pair atomically with acceptance (check-and-insert under one guard) so two
 * concurrent presentations of the same pair cannot both be accepted; this
 * verifier reads the set but does not record into it. `verifiedOwner` is the
 * owner-verification composition hook, consulted only when the grant requires it.
 * `maxLifetimeMs` optionally tightens the maximum grant lifetime for this check.
 * A value of exactly 0 means unset and uses the profile default, matching the Go
 * `MaxLifetimeMs == 0` gate; a negative or non-finite value is a verifier input
 * error and fails closed as `schema`, like a malformed clock (non-finite is
 * TS-only, since a Go integer cannot express it). A supplied positive value is
 * clamped to at most `MAX_GRANT_LIFETIME_MS`, so a caller can only shorten the
 * ceiling, never raise it.
 */
export interface AuthorizationGrantVerifyContext {
  audience: string;
  now: string;
  presenter?: string;
  seenGrants?: Iterable<GrantKey>;
  isRevoked?: (key: GrantKey) => boolean;
  verifiedOwner?: VerifiedOwnerStatus;
  maxLifetimeMs?: number;
}

export type AuthorizationGrantVerifyResult =
  | { ok: true; grant: AuthorizationGrant }
  | { ok: false; reason: AuthorizationGrantReason };

/**
 * Build a signed authorization grant. The unsigned grant is validated before
 * signing, so a malformed scope or an inverted validity window is rejected at
 * build time rather than producing a signature over an out-of-profile grant.
 */
export async function buildAuthorizationGrant(
  input: AuthorizationGrantInput,
  issuerPrivateKey: Uint8Array,
): Promise<AuthorizationGrant> {
  const unsigned = {
    protocol: "ink/0.1" as const,
    type: input.type ?? ("network.tulpa.authorization_grant" as const),
    issuer: input.issuer,
    subject: input.subject,
    audience: input.audience,
    scope: input.scope,
    grantId: input.grantId,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    ...(input.requireVerifiedOwner === undefined ? {} : { requireVerifiedOwner: input.requireVerifiedOwner }),
  };
  UnsignedAuthorizationGrantSchema.parse(unsigned);
  const signature = await signMessage(unsigned, issuerPrivateKey);
  return { ...unsigned, signature } as AuthorizationGrant;
}

/**
 * Verify an authorization grant against the issuer's public key and a
 * verification context. Fails closed: every structural, byte-safety, or security
 * failure returns a typed rejection, and the function never throws. The
 * signature is checked before any context decision, so a grant with a bad
 * signature never reveals whether its audience or window would have passed.
 *
 * Check order (each returns its own reason on the first failure):
 *   1. structural schema + byte safety + lifetime cap    -> "schema"
 *   2. issuer signature over the canonical grant         -> "signature"
 *   3. audience binding (confused-deputy defense)         -> "audience"
 *   4. presentation binding (presenter equals subject)    -> "subject"
 *   5. caller-tightened lifetime cap                      -> "schema"
 *   6. validity window (not_yet_valid / expired)          -> "not_yet_valid" | "expired"
 *   7. replay (issuer + grantId already seen)             -> "replay"
 *   8. revocation (issuer + grantId on the denylist)      -> "revoked"
 *   9. owner verification, only when the grant requires   -> "owner_unverified"
 *
 * The default maximum lifetime is enforced in step 1, before the signature, so a
 * grant whose window exceeds the profile ceiling is rejected structurally on the
 * signed bytes alone. A caller-tightened `maxLifetimeMs` is enforced in step 5,
 * after the signature and the presentation binding, so a verifier-local policy
 * value is never observable on an unauthenticated grant. A `now` that is not a strict INK timestamp is a verifier
 * input error and rejects as "schema", not a window verdict the verifier never
 * computed.
 */
export async function verifyAuthorizationGrant(
  raw: unknown,
  issuerPublicKey: Uint8Array,
  context: AuthorizationGrantVerifyContext,
): Promise<AuthorizationGrantVerifyResult> {
  try {
    // Bounds first: a hostile object that blows past the node/char caps is
    // rejected before Zod or canonicalization walks it.
    if (!isWithinBounds(raw)) {
      return { ok: false, reason: "schema" };
    }
    const parsed = AuthorizationGrantSchema.safeParse(raw);
    if (!parsed.success) {
      return { ok: false, reason: "schema" };
    }
    const grant = parsed.data;

    // String safety is structural: a grant carrying a lone UTF-16 surrogate is
    // not portable across implementations, so it is rejected as "schema" before
    // the signature check rather than surfacing as a signature failure. verifyMessage
    // also rejects it defensively, but here the reason is the structural one the
    // spec names.
    if (hasUnpairedSurrogate(grant)) {
      return { ok: false, reason: "schema" };
    }

    // Signature before any context decision, so a rejection never leaks whether
    // the audience or window would have matched.
    if (!(await verifyMessage(grant, issuerPublicKey))) {
      return { ok: false, reason: "signature" };
    }

    // Confused-deputy defense: a grant minted for one service must not be
    // replayed against another. The signed audience must equal the verifying
    // service's own identity.
    if (grant.audience !== context.audience) {
      return { ok: false, reason: "audience" };
    }

    // Presentation binding. The grant is a bearer artifact within its window, so
    // a caller that authenticated the presenting principal supplies it here to
    // bind the presentation to the signed subject: a presenter that is not the
    // subject is rejected before the window even opens, so a stolen grant is not
    // presentable by another principal. An empty or absent presenter means no
    // authenticated presenter was established, so the check is skipped and the
    // audience is responsible for binding presentation out of band. The empty
    // guard matches Go's `Presenter != ""` gate, since Go cannot tell an unset
    // field from "": the cross-implementation contract is that an empty presenter
    // is no presenter. This runs after the audience check and before the lifetime
    // and window checks so a stolen grant rejects on the binding rather than on
    // its clock.
    if (context.presenter !== undefined && context.presenter !== "" && context.presenter !== grant.subject) {
      return { ok: false, reason: "subject" };
    }

    const start = parseInkTimestampMs(grant.issuedAt);
    const end = parseInkTimestampMs(grant.expiresAt);
    if (start === null || end === null) {
      // Unreachable after schema validation, but fail closed rather than trust it.
      return { ok: false, reason: "schema" };
    }

    // Caller-tightened lifetime. The schema already enforced the profile ceiling
    // before the signature; here a caller may shorten it further for this check.
    // The value is clamped so it can only tighten, never loosen, the ceiling. A
    // window past the tightened cap is out of the caller's policy and rejects as
    // "schema", checked after the signature so the policy value is not observable
    // on an unauthenticated grant.
    //
    // A value of exactly 0 means unset: use the profile default, no tightening.
    // This matches Go's `MaxLifetimeMs == 0` gate, since a Go zero-value integer
    // is indistinguishable from an unset one, so the cross-implementation contract
    // is that 0 is "no caller cap". Only a negative or non-finite value is a
    // verifier input error: a NaN would make Math.min return NaN and silently
    // disable the comparison, and a negative cap admits no window at all, so both
    // fail closed as "schema", the same as a malformed clock (non-finite is
    // TS-only, since a Go integer cannot express it).
    if (context.maxLifetimeMs !== undefined && context.maxLifetimeMs !== 0) {
      if (!(Number.isFinite(context.maxLifetimeMs) && context.maxLifetimeMs > 0)) {
        return { ok: false, reason: "schema" };
      }
      const cap = Math.min(context.maxLifetimeMs, MAX_GRANT_LIFETIME_MS);
      if (end - start > cap) {
        return { ok: false, reason: "schema" };
      }
    }

    // Validity window. The verifier clock must itself be a strict INK timestamp;
    // a caller that supplies a malformed clock fails closed as a verifier input
    // error rather than a window verdict the verifier never computed. The lower
    // bound is inclusive (a grant is valid at its issue instant) and the upper
    // bound is exclusive (a grant is not valid at its expiry instant).
    const now = parseInkTimestampMs(context.now);
    if (now === null) {
      return { ok: false, reason: "schema" };
    }
    if (now < start) {
      return { ok: false, reason: "not_yet_valid" };
    }
    if (now >= end) {
      return { ok: false, reason: "expired" };
    }

    // Replay: an (issuer, grantId) pair already seen at this receiver is a
    // replay. The seen set is receiver state, not part of the grant. Keying on
    // the pair keeps one issuer's ids from colliding with another's.
    if (context.seenGrants) {
      for (const key of context.seenGrants) {
        if (key.issuer === grant.issuer && key.grantId === grant.grantId) {
          return { ok: false, reason: "replay" };
        }
      }
    }

    // Revocation: the receiver's denylist predicate, keyed by the same
    // (issuer, grantId) pair. A revoked grant is rejected even inside its window.
    if (context.isRevoked && context.isRevoked({ issuer: grant.issuer, grantId: grant.grantId })) {
      return { ok: false, reason: "revoked" };
    }

    // Owner-verification composition hook. Only consulted when the grant asks
    // for it. The status is produced by the caller's owner-verification
    // pipeline; this module never computes it. Absent status is unverified.
    if (grant.requireVerifiedOwner === true) {
      if (context.verifiedOwner?.status !== "verified") {
        return { ok: false, reason: "owner_unverified" };
      }
    }

    return { ok: true, grant };
  } catch {
    // Fail closed on a hostile object whose getters or proxy traps throw during
    // bounds checking, parsing, or canonicalization.
    return { ok: false, reason: "schema" };
  }
}
