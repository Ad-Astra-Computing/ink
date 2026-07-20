/**
 * The RP side of the challenge: mint a nonce, build a completion URL that
 * satisfies the literal-prefix rule, and sign the challenge.
 *
 * The challenge is the one artifact this flow adds on top of the authorization
 * grant. The RP signs it so the user's agent learns who is asking and for what
 * before it mints anything. Everything below is a thin wrapper over
 * `buildAuthorizationChallenge`: the reference validates and signs the challenge,
 * so an out-of-profile `rp`, `redirectUri`, `requestedScope`, or window is
 * rejected at build time rather than producing a signature over a bad challenge.
 */

import {
  buildAuthorizationChallenge,
  deriveRpOrigin,
  type AuthorizationChallenge,
} from "@adastracomputing/ink";
import type { Identity } from "./identity.ts";
import { IDENTITY_ASSERT } from "./scope.ts";

/**
 * The default challenge window. Ten minutes is the profile ceiling; the RP picks
 * a shorter window so a sign-in that stalls past it expires on its own well
 * before any denylist would matter.
 */
export const DEFAULT_CHALLENGE_WINDOW_MS = 2 * 60 * 1000;

/**
 * Mint a nonce with at least 128 bits of entropy, as the profile requires: the
 * nonce is the entropy source of the derived grant id and of the RP's
 * outstanding-context mapping, so a guessable nonce would let an attacker
 * predict or pre-seed ids. Sixteen random bytes rendered as hex is 32 code
 * units, inside the 16 to 256 bound.
 */
export function mintNonce(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("hex");
}

/**
 * Build a completion URL for the RP. It is the RP origin derived from its
 * `did:web` principal, followed immediately by `/` and an optional path. The
 * profile checks this as a literal string prefix with no URL parsing, so the
 * URL is assembled from the derived origin rather than parsed back from a
 * free-form string. The completion endpoint this names MUST itself consume the
 * grant: it must not redirect or forward the grant bytes anywhere else.
 */
export function completionUri(rp: Identity, path: string): string {
  const origin = deriveRpOrigin(rp.did);
  if (origin === null) {
    throw new Error(`rp is not a bare-host did:web: ${rp.did}`);
  }
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return origin + suffix;
}

export interface ChallengeRequest {
  rp: Identity;
  /** The completion URL the answering grant is delivered to. */
  redirectUri: string;
  /** The scope tokens the RP asks the user to grant. `identity.assert` is added. */
  requestedScope?: string[];
  nonce?: string;
  /** The instant the challenge is minted. Defaults to now. */
  now?: number;
  windowMs?: number;
}

/**
 * Build and sign an authorization challenge for the RP. `identity.assert` is
 * always requested, since a challenge that does not request it is not a sign-in
 * request under the profile.
 */
export async function buildChallenge(request: ChallengeRequest): Promise<AuthorizationChallenge> {
  const nowMs = request.now ?? Date.now();
  const windowMs = request.windowMs ?? DEFAULT_CHALLENGE_WINDOW_MS;
  const requested = new Set<string>([IDENTITY_ASSERT, ...(request.requestedScope ?? [])]);
  return buildAuthorizationChallenge(
    {
      rp: request.rp.did,
      nonce: request.nonce ?? mintNonce(),
      requestedScope: [...requested],
      redirectUri: request.redirectUri,
      issuedAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + windowMs).toISOString(),
    },
    request.rp.privateKey,
  );
}
