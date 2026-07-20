/**
 * The RP completion endpoint: consume the answering identity assertion and
 * decide whether a sign-in happened.
 *
 * This is where the RP upholds the profile's security properties. The base grant
 * verifier from `@adastracomputing/ink` makes the decisions two implementations
 * must agree on over the grant bytes: signature, audience, window, replay. It
 * does not know this profile's shape, so the RP runs a profile acceptance
 * checklist on top of it. Everything fails closed: any structural, cryptographic,
 * or binding failure returns a typed reason and no sign-in.
 *
 * The endpoint that runs this MUST itself consume the grant. It must not be or
 * chain a redirect and must not forward the grant bytes cross-origin in any form.
 * The literal-prefix rule already narrows delivery to the RP's own origin; the
 * consumption rule closes what remains, because an open redirect or a forwarding
 * endpoint inside that origin would hand the grant to wherever it points.
 */

import {
  verifyAuthorizationGrant,
  parseInkTimestampMs,
  type AuthorizationGrant,
  type AuthorizationGrantReason,
} from "@adastracomputing/ink";
import type { Identity, Directory } from "./identity.ts";
import type { SignInContextStore } from "./sign-in-context.ts";
import { IDENTITY_ASSERT, isIdentityAssertionToken } from "./scope.ts";

/**
 * Why a completion was refused. `grant:<reason>` wraps a rejection the base grant
 * verifier returned (signature, audience, expired, replay and the rest); the
 * others are the RP-local profile checks. There is no success reason: a sign-in
 * is the `ok: true` branch.
 */
export type CompletionReason =
  | `grant:${AuthorizationGrantReason}`
  | "no_context"
  | "context_expired"
  | "redirect_mismatch"
  | "issuer_unresolved"
  | "issuer_not_subject"
  | "grant_id_not_derived"
  | "mint_window"
  | "owner_field_present"
  | "scope_missing_identity_assert"
  | "scope_not_identity_assertion_token"
  | "scope_not_requested";

export type CompletionResult =
  | { ok: true; subject: string; scope: string[] }
  | { ok: false; reason: CompletionReason };

export interface CompletionRequest {
  rp: Identity;
  /** Resolves an assertion's issuer to a signing key, or null when it cannot. */
  directory: Directory;
  store: SignInContextStore;
  /** The session the completion arrived in, the context-binding key. */
  sessionId: string;
  /** The URL the grant was delivered to, checked against the challenge redirect. */
  completionUri: string;
  grant: AuthorizationGrant;
  /** The RP clock. Defaults to now. */
  now?: number;
}

/**
 * Verify an identity assertion delivered to the RP's completion endpoint and, if
 * it holds under every rule, return the signed-in subject.
 *
 * Order, each failing closed with its own reason:
 *   1. Context binding: a live context owns this session, else `no_context` /
 *      `context_expired`. Runs first so a stray completion never reaches the key
 *      resolver or the verifier.
 *   2. Completion binding: the grant arrived at the exact URL the challenge named,
 *      else `redirect_mismatch`. The endpoint consumes the grant here and forwards
 *      nothing, so there is nowhere else for it to have arrived.
 *   3. Issuer resolution: the assertion's issuer resolves to a signing key, else
 *      `issuer_unresolved`. Resolution failure fails closed; the RP never skips
 *      signature verification.
 *   4. Base grant verification bound to the RP audience and the seen set. No
 *      presenter is supplied, because a browser redirect authenticates none; the
 *      context binding above is the presentation control. A rejection surfaces as
 *      `grant:<reason>`.
 *   5. Profile acceptance checklist: issuer equals subject; the grant id equals
 *      the id derived from this context's challenge; the mint window; the omitted
 *      owner field; and the scope rules.
 *   6. Record the accepted pair and return the subject as the signed-in identity.
 */
export async function completeSignIn(request: CompletionRequest): Promise<CompletionResult> {
  const nowMs = request.now ?? Date.now();
  const { grant } = request;

  // 1. Context binding. A completion that owns no live context is refused before
  // any signature work: the context expiring at the challenge's `expiresAt` is
  // what bounds a late completion independent of the grant's own window. An
  // expired context is reported separately from an absent one; both refuse.
  const lookup = request.store.lookup(request.sessionId, nowMs);
  if (lookup.status === "expired") {
    return { ok: false, reason: "context_expired" };
  }
  if (lookup.status === "absent") {
    return { ok: false, reason: "no_context" };
  }
  const context = lookup.context;

  // 2. Completion binding. The grant must arrive at the exact URL the challenge
  // named. Because this endpoint consumes the grant rather than forwarding it,
  // the delivered URL is the challenge's own `redirectUri`; a mismatch means the
  // bytes travelled a path the RP did not sanction.
  if (request.completionUri !== context.challenge.redirectUri) {
    return { ok: false, reason: "redirect_mismatch" };
  }

  // 3. Issuer resolution. In production the RP fetches the issuer's Agent Card at
  // its derived origin under the private-hostname gate; here the directory stands
  // in. Either way an issuer the RP cannot resolve to a usable key is rejected.
  const issuerKey = request.directory.resolve(grant.issuer);
  if (issuerKey === null) {
    return { ok: false, reason: "issuer_unresolved" };
  }

  // 4. Base grant verification. Bound to the RP's own identity as the audience
  // (the confused-deputy defense) and to the seen set (replay). No presenter is
  // passed: over a browser redirect none is authenticated, so the grant is a
  // bearer artifact whose presentation the context binding in step 1 governs.
  const verified = await verifyAuthorizationGrant(grant, issuerKey, {
    audience: request.rp.did,
    now: new Date(nowMs).toISOString(),
    seenGrants: request.store.seenGrants(),
  });
  if (!verified.ok) {
    return { ok: false, reason: `grant:${verified.reason}` };
  }

  // 5. Profile acceptance checklist. These are RP-local rules the base verifier
  // does not know; each refuses the sign-in without a new wire reason.

  // An identity assertion's issuer and subject are both the user's agent.
  if (grant.issuer !== grant.subject) {
    return { ok: false, reason: "issuer_not_subject" };
  }

  // Derived-id binding. The grant id must equal the id the RP derived from the
  // challenge whose context received this completion. This is the context
  // binding stated as an equality check: a grant minted for any other challenge,
  // even a valid one, carries a different derived id and is refused here.
  if (grant.grantId !== context.derivedGrantId) {
    return { ok: false, reason: "grant_id_not_derived" };
  }

  // Mint window. The assertion's `issuedAt` must fall within the challenge's own
  // `[issuedAt, expiresAt)` window, so a grant minted for an earlier sign-in
  // whose window has closed cannot be presented in a later completion.
  const issuedAtMs = parseInkTimestampMs(grant.issuedAt);
  const windowStartMs = parseInkTimestampMs(context.challenge.issuedAt);
  const windowEndMs = parseInkTimestampMs(context.challenge.expiresAt);
  if (issuedAtMs === null || windowStartMs === null || windowEndMs === null) {
    return { ok: false, reason: "mint_window" };
  }
  if (issuedAtMs < windowStartMs || issuedAtMs >= windowEndMs) {
    return { ok: false, reason: "mint_window" };
  }

  // A grant minted under this profile omits `requireVerifiedOwner`; a grant that
  // carries it, whatever its value, is not a grant under this profile.
  if (grant.requireVerifiedOwner !== undefined) {
    return { ok: false, reason: "owner_field_present" };
  }

  // Scope. The assertion MUST contain `identity.assert`, and every entry MUST be
  // an identity-assertion registry token that appeared in the challenge's
  // `requestedScope`. A delegated-capability token such as `agent.message.send`
  // is not an identity-assertion token and is refused here even if it verified.
  if (!grant.scope.includes(IDENTITY_ASSERT)) {
    return { ok: false, reason: "scope_missing_identity_assert" };
  }
  const requested = new Set(context.challenge.requestedScope);
  for (const token of grant.scope) {
    if (!isIdentityAssertionToken(token)) {
      return { ok: false, reason: "scope_not_identity_assertion_token" };
    }
    if (!requested.has(token)) {
      return { ok: false, reason: "scope_not_requested" };
    }
  }

  // 6. Accept. Record the pair as a single check-and-insert under one guard. The
  // seen-set read in step 4 rejects a pair a prior completion already committed;
  // this check-and-insert closes the concurrency window between that async read
  // and the record, so two simultaneous completions of the same pair cannot both
  // be admitted. If the pair was recorded between step 4 and here, the sign-in is
  // a replay. Otherwise the subject is the signed-in identity.
  if (!request.store.tryAccept({ issuer: grant.issuer, grantId: grant.grantId })) {
    return { ok: false, reason: "grant:replay" };
  }
  return { ok: true, subject: grant.subject, scope: [...grant.scope] };
}
