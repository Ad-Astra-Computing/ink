/**
 * Shared test fixtures. Not a test file: it builds a small world (an RP, a user
 * agent, a directory, a context store) and a raw grant minter the negative tests
 * use to forge assertions the honest agent would never produce.
 */

import {
  buildAuthorizationGrant,
  deriveChallengeGrantId,
  type AuthorizationChallenge,
  type AuthorizationGrant,
} from "@adastracomputing/ink";
import {
  createIdentity,
  activeSigningKeys,
  Directory,
  buildChallenge,
  completionUri,
  SignInContextStore,
  UserAgent,
  type Identity,
} from "../src/index.ts";

export interface World {
  rp: Identity;
  agentIdentity: Identity;
  agent: UserAgent;
  directory: Directory;
  store: SignInContextStore;
  sessionId: string;
  redirectUri: string;
}

/** A fresh world with the agent's key published to the RP directory. */
export async function makeWorld(): Promise<World> {
  const rp = await createIdentity("rp.example");
  const agentIdentity = await createIdentity("agent.example");
  const directory = new Directory();
  directory.publish(agentIdentity);
  return {
    rp,
    agentIdentity,
    agent: new UserAgent(agentIdentity),
    directory,
    store: new SignInContextStore(),
    sessionId: "session-1",
    redirectUri: completionUri(rp, "/auth/ink/callback"),
  };
}

export { activeSigningKeys, buildChallenge };

/**
 * Mint a raw identity assertion with field overrides, signed by `signerKey`
 * (the agent's key by default). `grantId` defaults to the id derived from the
 * challenge, so a test that wants the honest binding omits it and a test that
 * wants a broken binding overrides it.
 */
export async function mintGrant(
  challenge: AuthorizationChallenge,
  signerKey: Uint8Array,
  issuer: string,
  overrides: Partial<{
    subject: string;
    audience: string;
    scope: string[];
    grantId: string;
    issuedAt: string;
    expiresAt: string;
    requireVerifiedOwner: boolean;
  }> = {},
): Promise<AuthorizationGrant> {
  const grantId = overrides.grantId ?? (await deriveChallengeGrantId(challenge));
  return buildAuthorizationGrant(
    {
      type: "network.ink.authorization_grant",
      issuer,
      subject: overrides.subject ?? issuer,
      audience: overrides.audience ?? challenge.rp,
      scope: overrides.scope ?? ["identity.assert"],
      grantId,
      issuedAt: overrides.issuedAt ?? challenge.issuedAt,
      expiresAt: overrides.expiresAt ?? challenge.expiresAt,
      ...(overrides.requireVerifiedOwner === undefined
        ? {}
        : { requireVerifiedOwner: overrides.requireVerifiedOwner }),
    },
    signerKey,
  );
}
