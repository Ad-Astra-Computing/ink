/**
 * A simulated user's agent, the counterparty the RP flow answers to.
 *
 * This is NOT RP code. It exists so the example can drive an end-to-end sign-in:
 * the RP signs a challenge, this agent verifies it and mints the answering
 * identity assertion, and the RP consumes that assertion. It is deliberately
 * minimal. It verifies the challenge with the reference verifier, gates minting
 * behind a consent decision, mints the assertion with the derived grant id, and
 * enforces mint-once. The consent UX itself is product surface and is stubbed to
 * a caller-supplied set of consented tokens.
 */

import {
  verifyAuthorizationChallenge,
  deriveChallengeGrantId,
  buildAuthorizationGrant,
  type AuthorizationChallengeReason,
  type AuthorizationGrant,
  type CandidateKey,
} from "@adastracomputing/ink";
import type { Identity } from "./identity.ts";
import { IDENTITY_ASSERT, isIdentityAssertionToken } from "./scope.ts";

/**
 * Why the agent refused to mint. `challenge:<reason>` wraps a challenge that did
 * not verify; the rest are the agent's own minting rules.
 */
export type MintRefusal =
  | `challenge:${AuthorizationChallengeReason}`
  | "consent_not_requested"
  | "consent_not_identity_assertion_token"
  | "mint_once";

export type MintResult =
  | { ok: true; grant: AuthorizationGrant }
  | { ok: false; reason: MintRefusal };

export class UserAgent {
  /** The derived ids this agent has already minted, its mint-once record. */
  private readonly minted = new Set<string>();
  private readonly identity: Identity;

  constructor(identity: Identity) {
    this.identity = identity;
  }

  /**
   * Verify a challenge and, on a consent decision, mint the answering identity
   * assertion. `consentedScope` is the identity-assertion tokens the user agreed
   * to beyond the mandatory `identity.assert`; each must have been requested and
   * must be an identity-assertion token. The minted assertion's issuer and
   * subject are both this agent, its audience is the challenge `rp`, its grant id
   * is derived from the verified challenge, and its window is the challenge's own
   * window, so it always falls inside the mint window the RP checks.
   */
  async respond(
    challengeRaw: Uint8Array,
    rpCandidateKeys: CandidateKey[],
    options: { consentedScope?: string[]; now?: number } = {},
  ): Promise<MintResult> {
    const nowMs = options.now ?? Date.now();

    // The agent verifies the challenge before minting anything. A tampered,
    // wrongly signed, not-yet-valid, or expired challenge is refused here.
    const verified = await verifyAuthorizationChallenge(challengeRaw, rpCandidateKeys, {
      now: new Date(nowMs).toISOString(),
    });
    if (!verified.ok) {
      return { ok: false, reason: `challenge:${verified.reason}` };
    }

    // Consent gate. The user names the RP identity and the requested scope before
    // any grant exists, including a bare sign-in. Each consented token must be an
    // identity-assertion token the challenge actually requested.
    const requested = new Set(verified.challenge.requestedScope);
    const consented = options.consentedScope ?? [];
    for (const token of consented) {
      if (!requested.has(token)) {
        return { ok: false, reason: "consent_not_requested" };
      }
      if (!isIdentityAssertionToken(token)) {
        return { ok: false, reason: "consent_not_identity_assertion_token" };
      }
    }

    // Derived-id binding and mint-once. The grant id is derived from the verified
    // challenge, never the raw nonce, and the agent mints at most one assertion
    // per derived id.
    const grantId = await deriveChallengeGrantId(verified.challenge);
    if (this.minted.has(grantId)) {
      return { ok: false, reason: "mint_once" };
    }
    this.minted.add(grantId);

    const scope = [IDENTITY_ASSERT, ...consented.filter((t) => t !== IDENTITY_ASSERT)];
    const grant = await buildAuthorizationGrant(
      {
        type: "network.ink.authorization_grant",
        issuer: this.identity.did,
        subject: this.identity.did,
        audience: verified.challenge.rp,
        scope,
        grantId,
        // The challenge's own window: `issuedAt` sits at the inclusive lower
        // bound of the mint window and the span never exceeds the ten-minute
        // ceiling, so the assertion always passes the RP's mint-window check.
        issuedAt: verified.challenge.issuedAt,
        expiresAt: verified.challenge.expiresAt,
      },
      this.identity.privateKey,
    );
    return { ok: true, grant };
  }
}
