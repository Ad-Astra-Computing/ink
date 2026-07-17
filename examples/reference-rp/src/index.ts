/**
 * The relying-party half of the Sign in with INK flow, built solely on the
 * public surface of `@adastracomputing/ink`.
 *
 * The RP signs an authorization challenge (`challenge.ts`), tracks the sign-in
 * context and the accepted-grant seen set (`sign-in-context.ts`), and consumes
 * the answering identity assertion at a completion endpoint that upholds the
 * profile's fail-closed acceptance rules (`completion.ts`). `user-agent.ts` is a
 * simulated counterparty that mints the assertion, so the example can drive the
 * flow end to end. `identity.ts` and `scope.ts` are the principals, key
 * resolution, and the profile's scope registry split by grant shape.
 */

export { createIdentity, activeSigningKeys, Directory, type Identity } from "./identity.ts";
export {
  IDENTITY_ASSERT,
  IDENTITY_ASSERTION_TOKENS,
  isRegistryToken,
  isIdentityAssertionToken,
} from "./scope.ts";
export {
  buildChallenge,
  completionUri,
  mintNonce,
  DEFAULT_CHALLENGE_WINDOW_MS,
  type ChallengeRequest,
} from "./challenge.ts";
export {
  SignInContextStore,
  type SignInContext,
} from "./sign-in-context.ts";
export {
  completeSignIn,
  type CompletionRequest,
  type CompletionResult,
  type CompletionReason,
} from "./completion.ts";
export { UserAgent, type MintResult, type MintRefusal } from "./user-agent.ts";
