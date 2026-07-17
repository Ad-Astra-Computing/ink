/**
 * The RP completion endpoint upholds every acceptance rule the profile pins.
 * The happy path signs the user in; each negative test forces one rule to fail
 * and asserts the typed reason, so a regression in any single check is visible.
 */

import { describe, it, expect } from "vitest";
import { completeSignIn, createIdentity } from "../src/index.ts";
import { makeWorld, activeSigningKeys, buildChallenge, mintGrant, type World } from "./harness.ts";

const AT = Date.parse("2026-07-17T12:00:00Z");

/** Open a sign-in context in `world` for a challenge with the given options. */
async function openContext(
  world: World,
  options: { requestedScope?: string[]; now?: number; windowMs?: number } = {},
) {
  const challenge = await buildChallenge({
    rp: world.rp,
    redirectUri: world.redirectUri,
    requestedScope: options.requestedScope ?? ["profile.read"],
    now: options.now ?? AT,
    windowMs: options.windowMs,
  });
  await world.store.open(world.sessionId, challenge);
  return challenge;
}

describe("RP completion, happy path", () => {
  it("signs the user in when the assertion is honest", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world);
    const minted = await world.agent.respond(challenge, activeSigningKeys(world.rp), {
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
      grant: minted.grant,
      now: AT + 1000,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.subject).toBe(world.agentIdentity.did);
      expect(result.scope).toEqual(["identity.assert", "profile.read"]);
    }
  });

  it("signs in a bare identity.assert when the user declines every capability", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world, { requestedScope: [] });
    const minted = await world.agent.respond(challenge, activeSigningKeys(world.rp), { now: AT });
    expect(minted.ok).toBe(true);
    if (!minted.ok) return;
    expect(minted.grant.scope).toEqual(["identity.assert"]);

    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant: minted.grant,
      now: AT + 1000,
    });
    expect(result.ok).toBe(true);
  });
});

describe("RP completion, fail closed", () => {
  it("refuses a completion in a session with no context", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world);
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did);
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: "unknown-session",
      completionUri: world.redirectUri,
      grant,
      now: AT + 1000,
    });
    expect(result).toEqual({ ok: false, reason: "no_context" });
  });

  it("refuses a completion after the context has expired", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world, { windowMs: 60_000 });
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did);
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 120_000,
    });
    expect(result).toEqual({ ok: false, reason: "context_expired" });
  });

  it("refuses a grant delivered to a URL other than the challenge redirect", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world);
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did);
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: "https://rp.example/some/other/path",
      grant,
      now: AT + 1000,
    });
    expect(result).toEqual({ ok: false, reason: "redirect_mismatch" });
  });

  it("refuses an assertion whose issuer the RP cannot resolve", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world);
    const stranger = await createIdentity("stranger.example");
    // The stranger signs a well-formed assertion, but the RP's directory has no
    // key for it, so resolution fails closed rather than skipping verification.
    const grant = await mintGrant(challenge, stranger.privateKey, stranger.did);
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 1000,
    });
    expect(result).toEqual({ ok: false, reason: "issuer_unresolved" });
  });

  it("refuses a grant with a bad signature", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world);
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did);
    // Flip the last signature character to a different base64url symbol.
    const last = grant.signature.slice(-1);
    const tampered = { ...grant, signature: grant.signature.slice(0, -1) + (last === "A" ? "B" : "A") };
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant: tampered,
      now: AT + 1000,
    });
    expect(result).toEqual({ ok: false, reason: "grant:signature" });
  });

  it("refuses a grant minted for a different audience", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world);
    // A grant whose signed audience is another service: the confused-deputy
    // defense in the base verifier rejects it against the RP.
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did, {
      audience: "did:web:other.example",
    });
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 1000,
    });
    expect(result).toEqual({ ok: false, reason: "grant:audience" });
  });

  it("refuses an expired grant", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world, { windowMs: 300_000 });
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did, {
      // A grant window that closes before the context does, so the grant is
      // expired while the context is still live.
      issuedAt: new Date(AT).toISOString(),
      expiresAt: new Date(AT + 30_000).toISOString(),
    });
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 60_000,
    });
    expect(result).toEqual({ ok: false, reason: "grant:expired" });
  });

  it("refuses a replay of an already-accepted grant", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world);
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did, {
      scope: ["identity.assert", "profile.read"],
    });
    const first = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 1000,
    });
    expect(first.ok).toBe(true);
    const replay = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 2000,
    });
    expect(replay).toEqual({ ok: false, reason: "grant:replay" });
  });

  it("admits exactly one of two concurrent completions of the same grant", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world);
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did);
    // Both calls read the seen set (empty) before either records, so only the
    // synchronous check-and-insert at acceptance can keep them from both winning.
    const call = () =>
      completeSignIn({
        rp: world.rp,
        directory: world.directory,
        store: world.store,
        sessionId: world.sessionId,
        completionUri: world.redirectUri,
        grant,
        now: AT + 1000,
      });
    const [a, b] = await Promise.all([call(), call()]);
    const accepted = [a, b].filter((r) => r.ok).length;
    const replayed = [a, b].filter((r) => !r.ok && r.reason === "grant:replay").length;
    expect(accepted).toBe(1);
    expect(replayed).toBe(1);
  });

  it("refuses an assertion whose issuer is not its subject", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world);
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did, {
      subject: "did:web:someone-else.example",
    });
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 1000,
    });
    expect(result).toEqual({ ok: false, reason: "issuer_not_subject" });
  });

  it("refuses a grant whose id is not derived from the challenge", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world);
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did, {
      grantId: "not-a-derived-grant-id-0000",
    });
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 1000,
    });
    expect(result).toEqual({ ok: false, reason: "grant_id_not_derived" });
  });

  it("refuses an assertion minted outside the challenge window", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world, { windowMs: 120_000 });
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did, {
      // A valid grant window, but its issue instant predates the challenge's own
      // window, so the mint-window rule refuses it even though it verifies.
      issuedAt: new Date(AT - 60_000).toISOString(),
      expiresAt: new Date(AT + 30_000).toISOString(),
    });
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 1000,
    });
    expect(result).toEqual({ ok: false, reason: "mint_window" });
  });

  it("refuses a sign-in grant that carries requireVerifiedOwner", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world);
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did, {
      requireVerifiedOwner: false,
    });
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 1000,
    });
    expect(result).toEqual({ ok: false, reason: "owner_field_present" });
  });

  it("refuses an assertion whose scope omits identity.assert", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world);
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did, {
      scope: ["profile.read"],
    });
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 1000,
    });
    expect(result).toEqual({ ok: false, reason: "scope_missing_identity_assert" });
  });

  it("refuses an assertion carrying a delegated-capability token", async () => {
    const world = await makeWorld();
    const challenge = await openContext(world, { requestedScope: ["agent.message.send"] });
    // agent.message.send belongs to a delegated capability, never an assertion.
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did, {
      scope: ["identity.assert", "agent.message.send"],
    });
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 1000,
    });
    expect(result).toEqual({ ok: false, reason: "scope_not_identity_assertion_token" });
  });

  it("refuses an assertion carrying a token the challenge did not request", async () => {
    const world = await makeWorld();
    // The challenge requests only identity.assert; the grant adds profile.read.
    const challenge = await openContext(world, { requestedScope: [] });
    const grant = await mintGrant(challenge, world.agentIdentity.privateKey, world.agentIdentity.did, {
      scope: ["identity.assert", "profile.read"],
    });
    const result = await completeSignIn({
      rp: world.rp,
      directory: world.directory,
      store: world.store,
      sessionId: world.sessionId,
      completionUri: world.redirectUri,
      grant,
      now: AT + 1000,
    });
    expect(result).toEqual({ ok: false, reason: "scope_not_requested" });
  });
});
