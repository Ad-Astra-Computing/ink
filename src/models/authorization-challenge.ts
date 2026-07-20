import { z } from "zod";
import { isInkTimestamp, parseInkTimestampMs } from "../crypto/timestamp.js";
import { isWithinBounds, signMessage, verifyMessage } from "../crypto/sign.js";
import { hasUnpairedSurrogate } from "../crypto/surrogate.js";
import { jcsCanonicalize, base64urlEncode } from "../crypto/ink.js";
import type { CandidateKey } from "./key-entry.js";

// The "INK Agent Authorization" sign-in challenge, the one artifact the flow
// profile adds on top of the authorization grant primitive
// (specs/ink-agent-authorization.md). A relying party (RP) signs a challenge to
// request sign-in; the user's agent verifies it before minting the grant that
// answers it. This module pins the challenge artifact and its verification plus
// the derived grantId the answering identity assertion adopts; the grant itself
// is verified by the existing authorization-grant verifier. The challenge
// composes the grant, it does not reinterpret it.

// Bounds. rp mirrors the grant principal bound; nonce, scope, and redirectUri
// match the profile's Challenge section. Everything is measured in UTF-16 code
// units so two implementations count the same length.
const RP_MAX = 512;
const NONCE_MIN = 16;
const NONCE_MAX = 256;
const SCOPE_ENTRY_MAX = 128;
const SCOPE_MAX = 64;
const REDIRECT_MAX = 2048;

// Maximum challenge lifetime. Identical to the grant ceiling and for the same
// reason: a challenge is a short-lived bootstrap request, so its window is short
// enough to expire on its own well before any denylist matters and long enough to
// absorb clock skew and a slow user consent.
export const MAX_CHALLENGE_LIFETIME_MS = 10 * 60 * 1000;

/**
 * Byte-length ceiling on a raw challenge body, the byte-layer counterpart to the
 * structural schema bounds. A receiver holding raw challenge bytes MUST reject a
 * body longer than this as `schema` before it decodes, per the *Byte bound* rule
 * in the spec. This reference `verifyAuthorizationChallenge` takes an
 * already-decoded object and applies the structural bounds instead, so this
 * constant is the contract for whatever layer received the bytes, the same rule
 * the Go `MaxChallengeBodyBytes` enforces on its bytes API. See
 * [`specs/ink-agent-authorization.md`](../../specs/ink-agent-authorization.md).
 */
export const MAX_CHALLENGE_BODY_BYTES = 65536;

// The domain string for the derived grantId. The digest covers the bytes of this
// string, a single newline, then the JCS canonicalization of the four binding
// fields, the same domain-then-newline pattern the body-signature scheme uses.
const CHALLENGE_ID_DOMAIN = "ink/challenge-id";

// The profile's closed scope registry. Every requestedScope entry MUST be one of
// these tokens, and identity.assert MUST be present. Tokens outside the registry
// reject as schema on the request side; the profile assigns them no meaning.
export const CHALLENGE_SCOPE_REGISTRY = ["identity.assert", "profile.read", "agent.message.send"] as const;
const REGISTRY = new Set<string>(CHALLENGE_SCOPE_REGISTRY);
const IDENTITY_ASSERT = "identity.assert";

// Cap on candidate keys tried during signature verification, matching the
// multi-key verifier: a poisoned Agent Card cannot force an unbounded number of
// Ed25519 operations.
const MAX_CANDIDATE_KEYS = 20;

/**
 * Derive the RP origin from a bare-host `did:web` identifier by explicit string
 * rules, never a URL parser. Returns the derived origin (`https://` + host +
 * optional `:port`) or null when `rp` is not a bare-host `did:web` under the
 * profile grammar. The grammar is exact because the origin it yields gates redirect
 * acceptance before the signature, so two implementations must never disagree on
 * it: an internationalized name is pre-encoded as punycode (bytewise comparison),
 * a final all-digit label is excluded (which rules out every dotted-quad IPv4
 * literal and matches the hostname rule that a TLD is never all-numeric), a
 * bracketed IPv6 literal already fails the label grammar, the port marker is an
 * uppercase `%3A` so a lowercase `%3a` leaves a `%` in the host and rejects, and an
 * explicit port 443 is out of profile because its derived origin would collide
 * with the default and origin equality must stay exact string comparison.
 */
export function deriveRpOrigin(rp: unknown): string | null {
  if (typeof rp !== "string") return null;
  const prefix = "did:web:";
  if (!rp.startsWith(prefix)) return null;
  const rest = rp.slice(prefix.length);
  if (rest.length === 0) return null;
  let host: string;
  let port: string | undefined;
  const idx = rest.indexOf("%3A");
  if (idx === -1) {
    host = rest;
  } else {
    host = rest.slice(0, idx);
    port = rest.slice(idx + 3);
    // Exactly one port marker: a second %3A is a malformed identifier.
    if (port.includes("%3A")) return null;
  }
  // The host carries no percent-encoding: an A-label host is already ASCII, and a
  // leftover `%` (for example a lowercase `%3a` that the uppercase marker missed)
  // is malformed rather than a port separator.
  if (host.includes("%")) return null;
  if (!isBareHost(host)) return null;
  if (port !== undefined && !isRpPort(port)) return null;
  return "https://" + host + (port !== undefined ? ":" + port : "");
}

// A bare host is one or more dot-separated LDH labels, each 1 to 63 characters of
// lowercase a-z, digits, and hyphens, not starting or ending with a hyphen, with
// no trailing or empty label, and a final label that is not all-numeric.
function isBareHost(host: string): boolean {
  if (host.length === 0) return false;
  const labels = host.split(".");
  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return false;
    if (!/^[a-z0-9-]+$/.test(label)) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }
  const last = labels[labels.length - 1] ?? "";
  if (/^[0-9]+$/.test(last)) return false;
  return true;
}

// A port is a decimal 1 to 65535 with no leading zeros. An explicit 443 is out of
// profile because the derived origin would collide with the default.
function isRpPort(port: string): boolean {
  if (!/^[1-9][0-9]{0,4}$/.test(port)) return false;
  const n = Number(port);
  if (n < 1 || n > 65535) return false;
  if (n === 443) return false;
  return true;
}

/**
 * Whether `redirectUri` is admissible for a challenge whose RP origin is
 * `origin`, by explicit string rules with no URL parsing: it MUST be the derived
 * origin followed immediately by `/` and an optional path and query under a
 * literal prefix match, and MUST NOT contain `#`, `\`, any ASCII control
 * character (U+0000-U+001F, U+007F) or ASCII whitespace (the string is not
 * trimmed first). The trailing `/` in the prefix makes userinfo, host-case
 * tricks, percent-encoded host confusion, default-port aliasing, and
 * suffix-extension of the host structurally impossible.
 */
export function isChallengeRedirect(redirectUri: unknown, origin: string): boolean {
  if (typeof redirectUri !== "string") return false;
  for (let i = 0; i < redirectUri.length; i++) {
    const c = redirectUri.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) return false;
  }
  if (redirectUri.includes("#")) return false;
  if (redirectUri.includes("\\")) return false;
  return redirectUri.startsWith(origin + "/");
}

// The window must be strictly positive and no longer than the maximum challenge
// lifetime. A zero or negative window is malformed; an over-long window is out of
// profile. Independent of the verifier clock.
function isWindowInProfile(c: { issuedAt: string; expiresAt: string }): boolean {
  const start = parseInkTimestampMs(c.issuedAt);
  const end = parseInkTimestampMs(c.expiresAt);
  if (start === null || end === null) return false;
  if (end <= start) return false;
  return end - start <= MAX_CHALLENGE_LIFETIME_MS;
}

// The requestedScope is 1 to 64 distinct registry tokens including identity.assert.
const RequestedScopeSchema = z
  .array(z.string().min(1).max(SCOPE_ENTRY_MAX))
  .min(1)
  .max(SCOPE_MAX)
  .refine((s) => new Set(s).size === s.length, { message: "requestedScope entries must be distinct" })
  .refine((s) => s.every((t) => REGISTRY.has(t)), { message: "every requestedScope entry must be a registry token" })
  .refine((s) => s.includes(IDENTITY_ASSERT), { message: "requestedScope must include identity.assert" });

// The cross-field rule: rp derives a bare-host origin and redirectUri is a literal
// prefix of that origin plus "/". Both reject as schema on the signed bytes alone.
function refineRpRedirect(
  obj: { rp: string; redirectUri: string },
  ctx: z.RefinementCtx,
): void {
  const origin = deriveRpOrigin(obj.rp);
  if (origin === null) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "rp must be a bare-host did:web identifier", path: ["rp"] });
    return;
  }
  if (!isChallengeRedirect(obj.redirectUri, origin)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "redirectUri must be the derived RP origin followed by /", path: ["redirectUri"] });
  }
}

const challengeShape = {
  protocol: z.literal("ink/0.1"),
  // A single spelling: the challenge is a new type with no legacy dual-accept.
  type: z.literal("network.ink.authorization_challenge"),
  rp: z.string().min(1).max(RP_MAX),
  nonce: z.string().min(NONCE_MIN).max(NONCE_MAX),
  requestedScope: RequestedScopeSchema,
  redirectUri: z.string().min(1).max(REDIRECT_MAX),
  issuedAt: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
  expiresAt: z.string().refine(isInkTimestamp, { message: "invalid INK timestamp" }),
};

/**
 * The signed challenge. The signature covers every field except `signature`
 * itself, over the domain-separated JCS canonicalization of the unsigned object
 * (`ink/0.1` keeps the `tulpa/sign` domain), the same body-signature scheme the
 * grant uses.
 */
export const AuthorizationChallengeSchema = z
  .object({
    ...challengeShape,
    // 64 raw bytes, 86 base64url characters, no padding. A malformed shape rejects
    // as schema before any signature work.
    signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  })
  .strict()
  .refine(isWindowInProfile, { message: "validity window must be positive and within the maximum challenge lifetime" })
  .superRefine(refineRpRedirect);

export type AuthorizationChallenge = z.infer<typeof AuthorizationChallengeSchema>;

const UnsignedAuthorizationChallengeSchema = z
  .object(challengeShape)
  .strict()
  .refine(isWindowInProfile, { message: "validity window must be positive and within the maximum challenge lifetime" })
  .superRefine(refineRpRedirect);

export interface AuthorizationChallengeInput {
  rp: string;
  nonce: string;
  requestedScope: string[];
  redirectUri: string;
  issuedAt: string;
  expiresAt: string;
}

/**
 * Which check rejected a challenge. `schema` covers every structural,
 * byte-safety, or profile-bound failure, including a non-bare-host rp, an
 * out-of-profile redirectUri or requestedScope, a window past the ceiling, and a
 * verifier clock that is not a strict INK timestamp; `signature` is an actual
 * signature or active-key-usability failure; the window verdicts are the rest.
 */
export type AuthorizationChallengeReason = "schema" | "signature" | "not_yet_valid" | "expired";

/**
 * Thrown by callers that prefer an exception over the result object. The verifier
 * itself never throws; it returns a rejection result.
 */
export class AuthorizationChallengeError extends Error {
  readonly reason: AuthorizationChallengeReason;

  constructor(reason: AuthorizationChallengeReason, message: string) {
    super(message);
    this.name = "AuthorizationChallengeError";
    this.reason = reason;
  }
}

/**
 * Everything the verifier needs beyond the candidate key set. `now` is the
 * verifier clock, a strict INK timestamp; it is consulted both for the key
 * validity window in the signature step and for the challenge validity window,
 * never at the challenge's RP-chosen `issuedAt`. A malformed `now` is a verifier
 * input error and fails closed as `schema` wherever it is consulted.
 */
export interface AuthorizationChallengeVerifyContext {
  now: string;
}

export type AuthorizationChallengeVerifyResult =
  | { ok: true; challenge: AuthorizationChallenge }
  | { ok: false; reason: AuthorizationChallengeReason };

/**
 * Build a signed challenge. The unsigned challenge is validated before signing,
 * so a non-bare-host rp, an out-of-profile redirectUri or requestedScope, or an
 * inverted window is rejected at build time rather than producing a signature over
 * an out-of-profile challenge.
 */
export async function buildAuthorizationChallenge(
  input: AuthorizationChallengeInput,
  rpPrivateKey: Uint8Array,
): Promise<AuthorizationChallenge> {
  const unsigned = {
    protocol: "ink/0.1" as const,
    type: "network.ink.authorization_challenge" as const,
    rp: input.rp,
    nonce: input.nonce,
    requestedScope: input.requestedScope,
    redirectUri: input.redirectUri,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
  };
  UnsignedAuthorizationChallengeSchema.parse(unsigned);
  const signature = await signMessage(unsigned, rpPrivateKey);
  return { ...unsigned, signature } as AuthorizationChallenge;
}

/**
 * Derive the identity assertion's `grantId` from a verified challenge. It is the
 * base64url encoding without padding of the SHA-256 digest of the bytes of the
 * domain string `ink/challenge-id`, a single newline, then the JCS
 * canonicalization of the object with exactly the members `rp`, `nonce`,
 * `issuedAt`, and `expiresAt` copied from the challenge. NOT the raw nonce: a raw
 * nonce is not issuer-unique, so two RPs sharing a nonce or one RP reusing one in
 * a fresh window would collide. The derivation is deterministic and RP-verifiable,
 * and challenges that differ in any of the four binding fields derive distinct
 * ids. The 43-character result is inside the grant's grantId bound, so the grant
 * schema does not change.
 */
export async function deriveChallengeGrantId(challenge: {
  rp: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}): Promise<string> {
  const binding = {
    rp: challenge.rp,
    nonce: challenge.nonce,
    issuedAt: challenge.issuedAt,
    expiresAt: challenge.expiresAt,
  };
  const canonical = jcsCanonicalize(binding);
  const bytes = new TextEncoder().encode(`${CHALLENGE_ID_DOMAIN}\n${canonical}`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return base64urlEncode(digest);
}

// Whether a candidate key is usable at the verifier clock. Presence is semantic,
// matching the multi-key verifier and Go's OptionalTimestamp: a present revokedAt
// of any value marks the key unusable; a present validFrom/validUntil that is not
// a strict RFC 3339 timestamp fails closed; an absent field is unconstrained.
function isActiveKeyUsableAt(key: CandidateKey, nowMs: number): boolean {
  if (key.revokedAt !== undefined) return false;
  if (key.validFrom !== undefined) {
    const from = parseInkTimestampMs(key.validFrom);
    if (from === null || nowMs < from) return false;
  }
  if (key.validUntil !== undefined) {
    const until = parseInkTimestampMs(key.validUntil);
    if (until === null || nowMs > until) return false;
  }
  return true;
}

// Verify the challenge body signature against an active signing key of the RP
// card, evaluated at the verifier clock. Only active keys are tried: a live
// challenge is never historical, so a retired key MUST NOT verify one, and a
// revoked key never verifies. The window is evaluated at `now`, not the
// RP-chosen issuedAt, so an RP cannot backdate a challenge into an old key's
// window. A card that yields no usable active key fails the signature step.
async function verifyChallengeSignature(
  challenge: AuthorizationChallenge,
  keys: CandidateKey[],
  nowMs: number,
): Promise<boolean> {
  if (!Array.isArray(keys) || keys.length === 0) return false;
  const bounded = keys.slice(0, MAX_CANDIDATE_KEYS);
  for (const key of bounded) {
    if (key.status !== "active") continue;
    if (!isActiveKeyUsableAt(key, nowMs)) continue;
    if (!(key.publicKey instanceof Uint8Array)) continue;
    try {
      if (await verifyMessage(challenge, key.publicKey)) return true;
    } catch {
      // Try the next candidate.
    }
  }
  return false;
}

/**
 * Verify an authorization challenge against the RP card's candidate signing keys
 * and a verification context. Fails closed: every structural, byte-safety, or
 * security failure returns a typed rejection, and the function never throws.
 *
 * Check order (each returns its own reason on the first failure):
 *   1. structural schema + byte safety + rp/redirect/scope/window rules -> "schema"
 *   2. RP signature against an active, in-window signing key            -> "signature"
 *   3. validity window (not_yet_valid / expired)                        -> "not_yet_valid" | "expired"
 *
 * The rp grammar, redirect prefix rule, scope registry rule, and window ceiling
 * are all enforced in step 1 on the signed bytes alone, before the signature, so
 * two implementations reject a malformed challenge identically regardless of who
 * signed it. The signature is checked before the window, so a rejected challenge
 * never reveals whether its window would have passed. A `now` that is not a strict
 * INK timestamp is a verifier input error and rejects as "schema" wherever it is
 * consulted, including the key-window evaluation in step 2.
 */
export async function verifyAuthorizationChallenge(
  raw: unknown,
  keys: CandidateKey[],
  context: AuthorizationChallengeVerifyContext,
): Promise<AuthorizationChallengeVerifyResult> {
  try {
    if (!isWithinBounds(raw)) {
      return { ok: false, reason: "schema" };
    }
    const parsed = AuthorizationChallengeSchema.safeParse(raw);
    if (!parsed.success) {
      return { ok: false, reason: "schema" };
    }
    const challenge = parsed.data;

    // String safety is structural: a lone UTF-16 surrogate is not portable, so it
    // rejects as schema before the signature, not as a signature failure.
    if (hasUnpairedSurrogate(challenge)) {
      return { ok: false, reason: "schema" };
    }

    // The verifier clock feeds both the key window in the signature step and the
    // validity window below. A malformed clock is a verifier input error and
    // fails closed as schema, not a window verdict the verifier never computed.
    const nowMs = parseInkTimestampMs(context.now);
    if (nowMs === null) {
      return { ok: false, reason: "schema" };
    }

    // Signature before the window, so a rejection never leaks whether the window
    // would have passed.
    if (!(await verifyChallengeSignature(challenge, keys, nowMs))) {
      return { ok: false, reason: "signature" };
    }

    const start = parseInkTimestampMs(challenge.issuedAt);
    const end = parseInkTimestampMs(challenge.expiresAt);
    if (start === null || end === null) {
      // Unreachable after schema validation, but fail closed rather than trust it.
      return { ok: false, reason: "schema" };
    }
    if (nowMs < start) {
      return { ok: false, reason: "not_yet_valid" };
    }
    if (nowMs >= end) {
      return { ok: false, reason: "expired" };
    }

    return { ok: true, challenge };
  } catch {
    return { ok: false, reason: "schema" };
  }
}
