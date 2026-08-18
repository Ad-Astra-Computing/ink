/**
 * The showcase: a challenge the RP signs is answered by an assertion the RP
 * accepts, driven through the simulated user agent. It also pins the agent-side
 * refusals the flow depends on and the cross-context binding that stops an
 * assertion minted for one sign-in from completing another.
 */

import { describe, it, expect } from "vitest";
import { completeSignIn, buildChallenge, completionUri } from "../src/index.ts";
import { makeWorld, activeSigningKeys } from "./harness.ts";

/**
 * Serialize an artifact to the bytes a verifier checks. The wire form is bytes
 * and the signature covers those bytes, so every verifier takes them rather
 * than a parsed object.
 */
function artifactBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}


const AT = Date.parse("2026-07-17T12:00:00Z");

describe("RP and user agent round trip", () => {
  it("a signed challenge is answered and accepted end to end", async () => {
    const world = await makeWorld();
    const challenge = await buildChallenge({
      rp: world.rp,
      redirectUri: world.redirectUri,
      requestedScope: ["profile.read"],
      now: AT,
    });
    await world.store.open(world.sessionId, challenge);

    const minted = await world.agent.respond(artifactBytes(challenge), activeSigningKeys(world.rp), {
      consentedScope: ["profile.read"],
      now: AT,
    });
    expect(minted.ok).toBe(true);
    if (!minted.ok) return;

    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grantRaw: artifactBytes(minted.grant),
      now: AT + 1000,
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.subject).toBe(world.agentIdentity.did);
  });

  it("the agent refuses to mint against a tampered challenge", async () => {
    const world = await makeWorld();
    const challenge = await buildChallenge({
      rp: world.rp,
      redirectUri: world.redirectUri,
      now: AT,
    });
    const tampered = { ...challenge, redirectUri: completionUri(world.rp, "/elsewhere") };
    const minted = await world.agent.respond(artifactBytes(tampered), activeSigningKeys(world.rp), { now: AT });
    expect(minted.ok).toBe(false);
    if (!minted.ok) expect(minted.reason).toBe("challenge:signature");
  });

  it("the agent mints at most one assertion per derived id", async () => {
    const world = await makeWorld();
    const challenge = await buildChallenge({
      rp: world.rp,
      redirectUri: world.redirectUri,
      now: AT,
    });
    const first = await world.agent.respond(artifactBytes(challenge), activeSigningKeys(world.rp), { now: AT });
    expect(first.ok).toBe(true);
    const second = await world.agent.respond(artifactBytes(challenge), activeSigningKeys(world.rp), { now: AT });
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.reason).toBe("mint_once");
  });

  it("the agent refuses consent to a token the challenge did not request", async () => {
    const world = await makeWorld();
    const challenge = await buildChallenge({
      rp: world.rp,
      redirectUri: world.redirectUri,
      requestedScope: [],
      now: AT,
    });
    const minted = await world.agent.respond(artifactBytes(challenge), activeSigningKeys(world.rp), {
      consentedScope: ["profile.read"],
      now: AT,
    });
    expect(minted.ok).toBe(false);
    if (!minted.ok) expect(minted.reason).toBe("consent_not_requested");
  });

  it("an assertion minted for one context does not complete another", async () => {
    const world = await makeWorld();

    // Two concurrent sign-ins, each with its own challenge and derived id.
    const challengeA = await buildChallenge({ rp: world.rp, redirectUri: world.redirectUri, now: AT });
    const challengeB = await buildChallenge({ rp: world.rp, redirectUri: world.redirectUri, now: AT });
    await world.store.open("session-A", challengeA);
    await world.store.open("session-B", challengeB);

    const mintedA = await world.agent.respond(artifactBytes(challengeA), activeSigningKeys(world.rp), { now: AT });
    expect(mintedA.ok).toBe(true);
    if (!mintedA.ok) return;

    // Present A's assertion into B's context. It verifies, but its derived id is
    // not the id B's challenge derives, so the derived-id binding refuses it.
    const crossed = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: "session-B",
      completionUri: world.redirectUri,
      grantRaw: artifactBytes(mintedA.grant),
      now: AT + 1000,
    });
    expect(crossed).toEqual({ ok: false, reason: "grant_id_not_derived" });

    // And it still completes its own context.
    const ownResult = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: "session-A",
      completionUri: world.redirectUri,
      grantRaw: artifactBytes(mintedA.grant),
      now: AT + 1000,
    });
    expect(ownResult.ok).toBe(true);
  });
});
