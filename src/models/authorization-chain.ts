import { z } from "zod";
import { isInkTimestamp, parseInkTimestampMs } from "../crypto/timestamp.js";
import { isWithinBounds, signMessage, verifyMessage } from "../crypto/sign.js";
import { hasUnpairedSurrogate } from "../crypto/surrogate.js";
import { jcsCanonicalize, base64urlEncode } from "../crypto/ink.js";
import { parseSignedBodyBytes } from "../crypto/parse-signed-body.js";
import type { GrantKey, VerifiedOwnerStatus } from "./authorization-grant.js";

// A linear authorization chain: 2 to 4 delegation links, each the grant field
// model with two changes (a network.ink.delegation_link type and a parent hash),
// each hop narrowing the last. The chain is a post-1.0 extension on top of the
// authorization-grant primitive. Every link reuses the grant's schema, its JCS
// canonicalization and its Ed25519 body-signature discipline unchanged; the
// extension adds a parent hash binding each link to the one above it, an
// issuer-subject continuity rule across each seam, a monotonic attenuation rule
// decided on signed bytes and a three-pass fail-closed verify order. See
// specs/ink-authorization-chain.md.

// Field caps mirror the grant: the same DID/agent-id and scope bounds, because a
// link IS the grant field model.
const ID_MAX = 512;
const GRANT_ID_MIN = 16;
const GRANT_ID_MAX = 256;
const SCOPE_ENTRY_MAX = 128;
const SCOPE_MAX = 64;

// Chain depth: at least 2 links (a one-link chain is a plain grant, verified by
// the grant verifier, not this one) and at most 4 (the origin plus three
// re-delegations), so a presented chain forces at most four card resolutions.
const MIN_LINKS = 2;
const MAX_LINKS = 4;

/**
 * Lifetime ceiling for an intermediate (non-final) link, including the root when
 * the chain is longer than two links: 24 hours. An intermediate link only
 * authorizes further delegation within a day-scale window, so it carries the
 * looser bound while the final link carries the tight login-and-bootstrap one.
 * Checked structurally in pass 1 on the signed issuedAt and expiresAt,
 * clock-independent like the rest of the window constraints.
 */
export const INTERMEDIATE_LINK_MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;

/**
 * Lifetime ceiling for the final link, the head the presenter holds: 10 minutes,
 * the same short bootstrap ceiling the grant applies to a single grant. The final
 * link is the credential actually exercised at the audience, so it carries the
 * tight bound. Checked structurally in pass 1.
 */
export const FINAL_LINK_MAX_LIFETIME_MS = 10 * 60 * 1000;

/**
 * Byte-length ceiling on a raw chain body, enforced before the body is decoded.
 * The largest well-formed four-link chain is far under it, so a presentation
 * padded past the cap is not legitimate and need not be decoded at all.
 * `verifyAuthorizationChain` enforces it on the bytes it is handed, the same
 * figure the Go `MaxChainBodyBytes` enforces, and the same figure the grant
 * rounds to, because a link IS the grant field model.
 *
 * The cap is not redundant with the structural bounds walk: JSON permits unbounded
 * whitespace between tokens, and whitespace vanishes at canonicalization, so a
 * schema-valid chain padded with megabytes of spaces carries per-link signatures
 * that still verify. Without a byte cap that body is admitted. See
 * [`specs/ink-authorization-chain.md`](../../specs/ink-authorization-chain.md).
 */
export const MAX_CHAIN_BODY_BYTES = 65536;

/**
 * The reserved delegability token. Its presence in a link's `scope` authorizes
 * exactly one further re-delegation below it. It confers no service capability of
 * its own and attenuates like any other token under the subset rule, so the
 * ability to re-delegate can only narrow down a chain, never appear from nowhere.
 */
export const DELEGATION_EXTEND_SCOPE = "delegation.extend";

// The domain string the parent digest covers, followed by a single newline and
// the JCS of the full parent link. The same domain-then-newline pattern the
// body-signature scheme uses.
const PARENT_HASH_DOMAIN = "ink/delegation-link";

const ScopeSchema = z
  .array(z.string().min(1).max(SCOPE_ENTRY_MAX))
  .min(1)
  .max(SCOPE_MAX)
  .refine((s) => new Set(s).size === s.length, { message: "scope entries must be distinct" });

// A delegation link is the grant field model with the two changes: the
// network.ink.delegation_link type and an optional parent hash (present on every
// non-root link, absent on the root, enforced by position in the verifier). The
// window must be strictly positive here; the per-position lifetime ceiling is
// enforced in the verifier because it depends on the link's index.
const DelegationLinkSchema = z
  .object({
    protocol: z.literal("ink/0.1"),
    type: z.literal("network.ink.delegation_link"),
    issuer: z.string().min(1).max(ID_MAX),
    subject: z.string().min(1).max(ID_MAX),
    audience: z.string().min(1).max(ID_MAX),
    scope: ScopeSchema,
    grantId: z.string().min(GRANT_ID_MIN).max(GRANT_ID_MAX),
    issuedAt: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
    expiresAt: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
    requireVerifiedOwner: z.boolean().optional(),
    // 43 base64url characters, the encoding of a 32-byte SHA-256 digest. Present
    // on non-root links, absent on the root; the position rule is enforced in the
    // verifier because zod cannot key it to the array index.
    parent: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional(),
    signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  })
  .strict()
  .refine((l) => {
    const start = parseInkTimestampMs(l.issuedAt);
    const end = parseInkTimestampMs(l.expiresAt);
    return start !== null && end !== null && end > start;
  }, { message: "validity window must be strictly positive" });

export type DelegationLink = z.infer<typeof DelegationLinkSchema>;

// The presentation wrapper is unsigned: integrity comes from the per-link
// signatures and the parent hash chain, and presentation binding and replay are
// decided by the final-link rules.
export const AuthorizationChainSchema = z
  .object({
    protocol: z.literal("ink/0.1"),
    type: z.literal("network.ink.authorization_chain"),
    links: z.array(DelegationLinkSchema).min(MIN_LINKS).max(MAX_LINKS),
  })
  .strict();

export type AuthorizationChain = z.infer<typeof AuthorizationChainSchema>;

export interface DelegationLinkInput {
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
 * Which check rejected a chain. Callers discriminate on this stable field. The
 * set is exactly eleven reasons: nine are reused verbatim from the grant, and
 * only `chain` (continuity or parent-hash mismatch) and `attenuation` (a widening
 * at some seam) are new. `schema` covers every structural, byte-safety, or
 * position-ceiling failure and a verifier clock that is not a strict INK
 * timestamp; the rest are the individual security decisions.
 */
export type AuthorizationChainReason =
  | "schema"
  | "chain"
  | "attenuation"
  | "signature"
  | "audience"
  | "subject"
  | "not_yet_valid"
  | "expired"
  | "replay"
  | "revoked"
  | "owner_unverified";

/**
 * Thrown by callers that prefer an exception over the result object. `reason` is
 * the same stable discriminator the verify result carries. The verifier itself
 * never throws; it returns a rejection result.
 */
export class AuthorizationChainError extends Error {
  readonly reason: AuthorizationChainReason;

  constructor(reason: AuthorizationChainReason, message: string) {
    super(message);
    this.name = "AuthorizationChainError";
    this.reason = reason;
  }
}

/**
 * A resolved signing key for one link's issuer, the output of the Agent Card
 * machinery pass 2 runs per issuer. `status` is the key's rotation status at the
 * verifier clock: only an `active` key verifies a link, so a retired or a revoked
 * key never does, which is the chain's fastest revocation lever for a compromised
 * delegate. A verifier that cannot resolve an issuer to a usable active key
 * supplies no entry (or a non-active one) and the link rejects as `signature`.
 */
export interface ChainIssuerKey {
  publicKey: Uint8Array;
  status: "active" | "retired" | "revoked";
}

/**
 * Everything a verifier needs beyond the per-link issuer keys. `audience` is the
 * verifying service, compared against every link's signed `audience` (the
 * confused-deputy defense carried across the whole chain). `now` is the verifier
 * clock, a strict INK timestamp; a malformed clock fails closed as `schema`
 * wherever it is consulted. `issuerKeys` resolves each link's issuer to a signing
 * key, aligned to `links` root-first. `presenter` is the authenticated presenting
 * principal; when supplied (non-empty) it must equal the FINAL link's `subject`,
 * and an empty or absent presenter skips the binding, the same empty-string
 * equivalence the grant pins. `seenGrants` is the replay seen set, READ against
 * the final link's `(issuer, grantId)` pair only; this verifier never records.
 * `isRevoked` is the revocation predicate, consulted for EVERY link's pair.
 * `verifiedOwner` is the owner-verification hook, consulted when any link requires
 * it (a conjunction over the chain).
 */
export interface AuthorizationChainVerifyContext {
  audience: string;
  now: string;
  issuerKeys: ChainIssuerKey[];
  presenter?: string;
  seenGrants?: Iterable<GrantKey>;
  isRevoked?: (key: GrantKey) => boolean;
  verifiedOwner?: VerifiedOwnerStatus;
}

export type AuthorizationChainVerifyResult =
  | { ok: true; chain: AuthorizationChain }
  | { ok: false; reason: AuthorizationChainReason };

/**
 * Compute the `parent` hash binding a link to the exact bytes of its parent: the
 * base64url-no-padding SHA-256 digest of the UTF-8 bytes of the domain string
 * `ink/delegation-link`, a single newline, and the JCS (RFC 8785) canonicalization
 * of the FULL parent link INCLUDING its `signature`. The 43-character result is
 * the child's `parent` field. The parent is canonicalized with every member
 * present, `signature` included, because the child commits to the parent as it was
 * actually signed and presented.
 */
export async function deriveDelegationParentHash(parentLink: Record<string, unknown>): Promise<string> {
  const canonical = jcsCanonicalize(parentLink);
  const bytes = new TextEncoder().encode(`${PARENT_HASH_DOMAIN}\n${canonical}`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return base64urlEncode(digest);
}

/**
 * Build a signed delegation link. When `parentLink` is supplied its `parent`
 * hash is derived and bound into the signed bytes; the root link passes `null`
 * and carries no `parent`. The link is signed the grant's way, over
 * `tulpa/sign\n` + JCS(link without `signature`), so the signature covers every
 * field including `parent` and `type`.
 */
export async function buildDelegationLink(
  input: DelegationLinkInput,
  parentLink: Record<string, unknown> | null,
  issuerPrivateKey: Uint8Array,
): Promise<DelegationLink> {
  const unsigned = {
    protocol: "ink/0.1" as const,
    type: "network.ink.delegation_link" as const,
    issuer: input.issuer,
    subject: input.subject,
    audience: input.audience,
    scope: input.scope,
    grantId: input.grantId,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    ...(input.requireVerifiedOwner === undefined ? {} : { requireVerifiedOwner: input.requireVerifiedOwner }),
    ...(parentLink === null ? {} : { parent: await deriveDelegationParentHash(parentLink) }),
  };
  const signature = await signMessage(unsigned, issuerPrivateKey);
  return { ...unsigned, signature } as DelegationLink;
}

/**
 * Wrap a root-first array of signed delegation links in the unsigned presentation
 * wrapper. The wrapper carries no signature of its own.
 */
export function buildAuthorizationChain(links: DelegationLink[]): AuthorizationChain {
  return { protocol: "ink/0.1", type: "network.ink.authorization_chain", links } as AuthorizationChain;
}

// A scope array as a set, for the subset test.
function scopeSet(scope: string[]): Set<string> {
  return new Set(scope);
}

/**
 * Verify a presented authorization chain against a verification context. Fails
 * closed: every structural, continuity, attenuation, signature, or context
 * failure returns a typed rejection, and the function never throws. Verification
 * runs three passes in order and returns the first failure's reason.
 *
 * The input is the **raw body bytes**, not a parsed value. Every link is a signed
 * body, so the presentation is subject to the raw-body gate of
 * [`specs/ink-signed-string-safety.md`](../../specs/ink-signed-string-safety.md)
 * §"Enforcement order": invalid UTF-8, a lone UTF-16 surrogate escape and a number
 * literal outside the IEEE-754 double range are all rules about the bytes that no
 * longer exist once the body is parsed. A verifier that took a parsed value could
 * not run them: a duplicate member shadows an out-of-range literal (JSON member
 * semantics are last-wins), so the value layer never sees it, every link
 * canonicalizes cleanly and every signature verifies, while an implementation that
 * gates the bytes refuses the same presentation outright. That is an
 * accept-versus-reject split in a signed path, choosable by anyone who can write
 * the bytes, so the bytes are the input.
 *
 *   Pass 0 (bytes): byte cap, raw-body gate, JSON parse -> schema
 *   Pass 1 (structure, on signed bytes, clock-independent):
 *     schema      -> field set, types, 2..4 link count, distinct/positive-window
 *                    per link, per-position lifetime ceiling, parent shape and
 *                    by-position presence, byte-safety
 *     chain       -> issuer-subject continuity and parent-hash match at each seam
 *     attenuation -> scope subset, window nesting, delegability at each seam
 *   Pass 2 (signatures, root to head):
 *     signature   -> each link verifies against a resolved active issuer key; a
 *                    retired or revoked key never verifies. A malformed `now`
 *                    consulted here fails as schema, not signature.
 *   Pass 3 (context, against the verifier clock):
 *     audience -> every link equals the verifying service
 *     subject  -> supplied presenter equals the FINAL link's subject
 *     window   -> now in [issuedAt, expiresAt) for every link
 *     replay   -> the FINAL link's (issuer, grantId) is not already seen (read only)
 *     revoked  -> no link's (issuer, grantId) is revoked
 *     owner    -> if any link requires it, the supplied owner status is verified
 */
export async function verifyAuthorizationChain(
  raw: Uint8Array,
  context: AuthorizationChainVerifyContext,
): Promise<AuthorizationChainVerifyResult> {
  try {
    // A caller on an untyped boundary can still hand over something that is not
    // bytes; that is a verifier input error, not a chain this function can rule
    // on, and it fails closed rather than being coerced.
    if (!ArrayBuffer.isView(raw) || !(raw instanceof Uint8Array)) {
      return { ok: false, reason: "schema" };
    }
    // The byte cap runs before the decoder: an oversized blob is refused without
    // being decoded at all.
    if (raw.length > MAX_CHAIN_BODY_BYTES) {
      return { ok: false, reason: "schema" };
    }
    // The raw-body gate, then the parse. ParseSignedBodyError and the native
    // SyntaxError from a malformed body are both structural rejections.
    let value: unknown;
    try {
      value = parseSignedBodyBytes(raw);
    } catch {
      return { ok: false, reason: "schema" };
    }
    // Bounds next: a hostile object past the node/char caps is rejected before
    // zod or canonicalization walks it.
    if (!isWithinBounds(value)) {
      return { ok: false, reason: "schema" };
    }
    // String safety is structural: a lone UTF-16 surrogate is not portable, so it
    // rejects as schema before any signature work, not as a signature failure.
    if (hasUnpairedSurrogate(value)) {
      return { ok: false, reason: "schema" };
    }
    const parsed = AuthorizationChainSchema.safeParse(value);
    if (!parsed.success) {
      return { ok: false, reason: "schema" };
    }
    const chain = parsed.data;
    const links = chain.links;
    const n = links.length;

    // Per-position schema rules zod cannot key to the array index: the root link
    // carries no parent and every non-root link carries one, and each link's
    // lifetime is within the ceiling for its position (final 10 minutes, every
    // other link 24 hours).
    for (let i = 0; i < n; i++) {
      const link = links[i]!;
      const isRoot = i === 0;
      const isFinal = i === n - 1;
      if (isRoot && link.parent !== undefined) {
        return { ok: false, reason: "schema" };
      }
      if (!isRoot && link.parent === undefined) {
        return { ok: false, reason: "schema" };
      }
      const start = parseInkTimestampMs(link.issuedAt);
      const end = parseInkTimestampMs(link.expiresAt);
      if (start === null || end === null) {
        return { ok: false, reason: "schema" };
      }
      const ceiling = isFinal ? FINAL_LINK_MAX_LIFETIME_MS : INTERMEDIATE_LINK_MAX_LIFETIME_MS;
      if (end - start > ceiling) {
        return { ok: false, reason: "schema" };
      }
    }

    // Continuity: for every non-root link its issuer byte-equals the parent's
    // subject, and its parent field equals the SHA-256 digest of the parent link.
    for (let i = 1; i < n; i++) {
      const parent = links[i - 1]!;
      const child = links[i]!;
      if (child.issuer !== parent.subject) {
        return { ok: false, reason: "chain" };
      }
      const expected = await deriveDelegationParentHash(parent as unknown as Record<string, unknown>);
      if (child.parent !== expected) {
        return { ok: false, reason: "chain" };
      }
    }

    // Attenuation: at every seam the child scope is a subset of the parent scope,
    // the child window nests inside the parent window, and the parent carries the
    // delegability token that seats the child.
    for (let i = 1; i < n; i++) {
      const parent = links[i - 1]!;
      const child = links[i]!;
      const parentScope = scopeSet(parent.scope);
      for (const token of child.scope) {
        if (!parentScope.has(token)) {
          return { ok: false, reason: "attenuation" };
        }
      }
      const parentStart = parseInkTimestampMs(parent.issuedAt)!;
      const parentEnd = parseInkTimestampMs(parent.expiresAt)!;
      const childStart = parseInkTimestampMs(child.issuedAt)!;
      const childEnd = parseInkTimestampMs(child.expiresAt)!;
      if (!(parentStart <= childStart && childEnd <= parentEnd)) {
        return { ok: false, reason: "attenuation" };
      }
      if (!parentScope.has(DELEGATION_EXTEND_SCOPE)) {
        return { ok: false, reason: "attenuation" };
      }
    }

    // Pass 2: signatures, root to head. The verifier clock is consulted here first
    // (key activity), so a malformed clock fails closed as schema before any
    // signature check, not as signature. Each link verifies against a resolved
    // active issuer key; a retired or revoked key, or a missing one, never verifies.
    const now = parseInkTimestampMs(context.now);
    if (now === null) {
      return { ok: false, reason: "schema" };
    }
    for (let i = 0; i < n; i++) {
      const key = context.issuerKeys[i];
      if (key === undefined || key.status !== "active") {
        return { ok: false, reason: "signature" };
      }
      if (!(await verifyMessage(links[i] as unknown as Record<string, unknown>, key.publicKey))) {
        return { ok: false, reason: "signature" };
      }
    }

    // Pass 3: context. Audience across every link (confused-deputy defense).
    for (const link of links) {
      if (link.audience !== context.audience) {
        return { ok: false, reason: "audience" };
      }
    }

    // Presentation binding: a supplied presenter must equal the final link's
    // subject. An empty or absent presenter skips the binding, the same
    // empty-string equivalence the grant pins.
    const finalLink = links[n - 1]!;
    if (context.presenter !== undefined && context.presenter !== "" && context.presenter !== finalLink.subject) {
      return { ok: false, reason: "subject" };
    }

    // Validity window: now in [issuedAt, expiresAt) for every link.
    for (const link of links) {
      const start = parseInkTimestampMs(link.issuedAt)!;
      const end = parseInkTimestampMs(link.expiresAt)!;
      if (now < start) {
        return { ok: false, reason: "not_yet_valid" };
      }
      if (now >= end) {
        return { ok: false, reason: "expired" };
      }
    }

    // Replay: READ the seen set on the final link only. Intermediate links are not
    // replay-checked, because one parent prefix can seat many distinct child
    // chains. The verifier never records; the service inserts atomically on full
    // acceptance.
    if (context.seenGrants) {
      for (const key of context.seenGrants) {
        if (key.issuer === finalLink.issuer && key.grantId === finalLink.grantId) {
          return { ok: false, reason: "replay" };
        }
      }
    }

    // Revocation: every link's (issuer, grantId) pair. A revoked pair anywhere in
    // the chain rejects the whole chain, even inside its window.
    if (context.isRevoked) {
      for (const link of links) {
        if (context.isRevoked({ issuer: link.issuer, grantId: link.grantId })) {
          return { ok: false, reason: "revoked" };
        }
      }
    }

    // Owner verification is a conjunction: if any link requires a verified owner
    // the whole chain does, and the supplied status must be verified. Absent is
    // unverified.
    if (links.some((l) => l.requireVerifiedOwner === true)) {
      if (context.verifiedOwner?.status !== "verified") {
        return { ok: false, reason: "owner_unverified" };
      }
    }

    return { ok: true, chain };
  } catch {
    // Fail closed on a hostile object whose getters or proxy traps throw during
    // bounds checking, parsing, or canonicalization.
    return { ok: false, reason: "schema" };
  }
}
