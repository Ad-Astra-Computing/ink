import { z } from "zod";
import { dualWireType } from "./wire-type.js";
import { isInkTimestamp, parseInkTimestampMs } from "../crypto/timestamp.js";
import { isWithinBounds, signMessage, verifyMessage } from "../crypto/sign.js";

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

// A scope is a non-empty array of distinct opaque tokens. Distinctness is
// enforced so a grant cannot smuggle a larger apparent scope through repetition,
// and so two implementations count the same set. The tokens are not parsed here:
// their meaning is the audience's policy.
const ScopeSchema = z
  .array(z.string().min(1).max(SCOPE_ENTRY_MAX))
  .min(1)
  .max(SCOPE_MAX)
  .refine((s) => new Set(s).size === s.length, { message: "scope entries must be distinct" });

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
    signature: z.string().min(1),
  })
  .strict()
  // expiresAt must be strictly after issuedAt: a zero or negative window is a
  // malformed grant, not a grant that expires the instant it is issued.
  .refine(
    (g) => {
      const start = parseInkTimestampMs(g.issuedAt);
      const end = parseInkTimestampMs(g.expiresAt);
      return start !== null && end !== null && end > start;
    },
    { message: "expiresAt must be after issuedAt" },
  );

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
  .refine(
    (g) => {
      const start = parseInkTimestampMs(g.issuedAt);
      const end = parseInkTimestampMs(g.expiresAt);
      return start !== null && end !== null && end > start;
    },
    { message: "expiresAt must be after issuedAt" },
  );

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
 * than any message prose. `schema` covers every structural or byte-safety
 * failure; the rest are the individual security decisions.
 */
export type AuthorizationGrantReason =
  | "schema"
  | "signature"
  | "audience"
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
 * Everything a verifier needs beyond the issuer key. `audience` is the service
 * checking the grant, compared against the signed `audience` to reject a grant
 * minted for a different service (confused deputy). `now` is the verifier clock,
 * a strict INK timestamp. `seenGrantIds` and `isRevoked` are the two receiver
 * policy hooks for replay and revocation; both are optional and default to
 * "not seen" and "not revoked". `verifiedOwner` is the owner-verification
 * composition hook, consulted only when the grant requires it.
 */
export interface AuthorizationGrantVerifyContext {
  audience: string;
  now: string;
  seenGrantIds?: Iterable<string>;
  isRevoked?: (grantId: string) => boolean;
  verifiedOwner?: VerifiedOwnerStatus;
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
 *   1. structural schema + byte safety                  -> "schema"
 *   2. issuer signature over the canonical grant        -> "signature"
 *   3. audience binding (confused-deputy defense)        -> "audience"
 *   4. validity window (not_yet_valid / expired)         -> "not_yet_valid" | "expired"
 *   5. replay (grantId already seen)                     -> "replay"
 *   6. revocation (grantId on the receiver denylist)     -> "revoked"
 *   7. owner verification, only when the grant requires  -> "owner_unverified"
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

    // Validity window. The verifier clock must itself be a strict INK timestamp;
    // a caller that supplies a malformed clock fails closed. The lower bound is
    // inclusive (a grant is valid at its issue instant) and the upper bound is
    // exclusive (a grant is not valid at its expiry instant).
    const now = parseInkTimestampMs(context.now);
    if (now === null) {
      return { ok: false, reason: "expired" };
    }
    const start = parseInkTimestampMs(grant.issuedAt);
    const end = parseInkTimestampMs(grant.expiresAt);
    if (start === null || end === null) {
      // Unreachable after schema validation, but fail closed rather than trust it.
      return { ok: false, reason: "schema" };
    }
    if (now < start) {
      return { ok: false, reason: "not_yet_valid" };
    }
    if (now >= end) {
      return { ok: false, reason: "expired" };
    }

    // Replay: a grantId already seen at this receiver is a replay. The seen set
    // is receiver state, not part of the grant.
    if (context.seenGrantIds) {
      for (const id of context.seenGrantIds) {
        if (id === grant.grantId) {
          return { ok: false, reason: "replay" };
        }
      }
    }

    // Revocation: the receiver's denylist predicate. A grant whose id is revoked
    // is rejected even inside its validity window.
    if (context.isRevoked && context.isRevoked(grant.grantId)) {
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
