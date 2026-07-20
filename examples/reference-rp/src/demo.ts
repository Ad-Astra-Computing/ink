/**
 * An end-to-end walk-through of the RP flow, printed to the console.
 *
 * It runs the whole flow in process: the RP signs a challenge, a simulated user
 * agent verifies it and mints the answering identity assertion, and the RP
 * completion endpoint consumes the assertion and signs the user in. Then it
 * shows two fail-closed paths so the security properties are visible, not just
 * asserted: a grant replayed into the same context, and a forged grant whose id
 * is not derived from the challenge.
 */

import {
  createIdentity,
  activeSigningKeys,
  Directory,
  buildChallenge,
  completionUri,
  SignInContextStore,
  completeSignIn,
  UserAgent,
} from "./index.ts";
import { buildAuthorizationGrant, deriveChallengeGrantId } from "@adastracomputing/ink";

function line(label: string, value: string): void {
  console.log(`  ${label.padEnd(16)} ${value}`);
}

export async function runDemo(): Promise<void> {
  // Principals. The RP is a bare-host did:web; the agent is one too, so the RP
  // resolves its issuer the same way it resolves any card.
  const rp = await createIdentity("rp.example");
  const agentIdentity = await createIdentity("agent.example");
  const agent = new UserAgent(agentIdentity);

  // The RP resolves the agent's issuer key from its directory. In production this
  // is an Agent Card fetch at the derived origin under the private-hostname gate.
  const directory = new Directory();
  directory.publish(agentIdentity);

  const store = new SignInContextStore();
  const sessionId = "browser-session-42";

  console.log("Sign in with INK, relying-party flow\n");

  // 1. The RP signs a challenge and opens a sign-in context for the session.
  const redirectUri = completionUri(rp, "/auth/ink/callback");
  const challenge = await buildChallenge({
    rp,
    redirectUri,
    requestedScope: ["profile.read"],
  });
  const context = await store.open(sessionId, challenge);
  console.log("1. RP issues a signed challenge");
  line("rp", challenge.rp);
  line("requestedScope", challenge.requestedScope.join(", "));
  line("redirectUri", challenge.redirectUri);
  line("derived id", context.derivedGrantId);

  // 2. The user's agent verifies the challenge and mints the identity assertion.
  const minted = await agent.respond(challenge, activeSigningKeys(rp), {
    consentedScope: ["profile.read"],
  });
  if (!minted.ok) {
    throw new Error(`agent refused to mint: ${minted.reason}`);
  }
  console.log("\n2. User agent verifies the challenge and mints an identity assertion");
  line("issuer", minted.grant.issuer);
  line("subject", minted.grant.subject);
  line("audience", minted.grant.audience);
  line("grantId", minted.grant.grantId);
  line("scope", minted.grant.scope.join(", "));

  // 3. The RP completion endpoint consumes the assertion and signs the user in.
  const result = await completeSignIn({
    rp,
    directory,
    store,
    sessionId,
    completionUri: redirectUri,
    grant: minted.grant,
  });
  console.log("\n3. RP completion endpoint consumes the assertion");
  if (result.ok) {
    line("signed in as", result.subject);
    line("scope", result.scope.join(", "));
  } else {
    throw new Error(`completion failed: ${result.reason}`);
  }

  // 4. Fail closed: the same grant replayed into the same context is refused by
  // the seen-set check, even though every signature and binding still holds.
  const replay = await completeSignIn({
    rp,
    directory,
    store,
    sessionId,
    completionUri: redirectUri,
    grant: minted.grant,
  });
  console.log("\n4. Replay of the accepted grant");
  line("refused", replay.ok ? "NO (bug)" : replay.reason);

  // 5. Fail closed: a forged grant whose id is not derived from the challenge.
  // Every other field is well formed and the signature verifies, but the grant
  // id does not match the derived-id binding, so the RP refuses it.
  const forgedId = await deriveChallengeGrantId({
    rp: challenge.rp,
    nonce: "0".repeat(32),
    issuedAt: challenge.issuedAt,
    expiresAt: challenge.expiresAt,
  });
  const forged = await buildAuthorizationGrant(
    {
      type: "network.ink.authorization_grant",
      issuer: agentIdentity.did,
      subject: agentIdentity.did,
      audience: rp.did,
      scope: ["identity.assert"],
      grantId: forgedId,
      issuedAt: challenge.issuedAt,
      expiresAt: challenge.expiresAt,
    },
    agentIdentity.privateKey,
  );
  const forgedResult = await completeSignIn({
    rp,
    directory,
    store,
    sessionId,
    completionUri: redirectUri,
    grant: forged,
  });
  console.log("\n5. Grant id not derived from the challenge");
  line("refused", forgedResult.ok ? "NO (bug)" : forgedResult.reason);

  console.log("\nDone.");
}
