/**
 * The profile's closed scope registry, split by grant shape.
 *
 * `@adastracomputing/ink` exports the flat registry as `CHALLENGE_SCOPE_REGISTRY`
 * and rejects any `requestedScope` entry outside it as `schema`. The profile also
 * assigns each token a shape, because an identity assertion and a delegated
 * capability point in opposite directions: an assertion's audience is the RP, so
 * it can only carry authority the RP exercises for itself, and a token exercised
 * against the user's agent can ride only in a delegated-capability grant whose
 * audience is the agent. The registry does not carry that split, so the RP
 * encodes it here as acceptance policy: an assertion may only carry
 * identity-assertion tokens.
 */

import { CHALLENGE_SCOPE_REGISTRY } from "@adastracomputing/ink";

/** Always present in an identity assertion and always requested in a challenge. */
export const IDENTITY_ASSERT = "identity.assert";

/**
 * The identity-assertion tokens: the subset of the registry an identity
 * assertion may carry. `agent.message.send` is a delegated-capability token and
 * never appears in an assertion, so it is deliberately absent.
 */
export const IDENTITY_ASSERTION_TOKENS: readonly string[] = ["identity.assert", "profile.read"];

/** Whether a token is a registry token this profile knows at all. */
export function isRegistryToken(token: string): boolean {
  return (CHALLENGE_SCOPE_REGISTRY as readonly string[]).includes(token);
}

/** Whether a token is valid inside an identity assertion. */
export function isIdentityAssertionToken(token: string): boolean {
  return IDENTITY_ASSERTION_TOKENS.includes(token);
}
