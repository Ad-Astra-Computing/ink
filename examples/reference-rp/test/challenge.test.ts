/**
 * The RP challenge: it is well formed, it verifies against the RP's own card,
 * and it fails closed under tampering, a wrong key, and a stale window. The
 * literal-prefix redirect rule and the registry rule reject at build time.
 */

import { describe, it, expect } from "vitest";
import { verifyAuthorizationChallenge } from "@adastracomputing/ink";
import { createIdentity, activeSigningKeys, buildChallenge, completionUri } from "../src/index.ts";

/**
 * Serialize an artifact to the bytes a verifier checks. The wire form is bytes
 * and the signature covers those bytes, so every verifier takes them rather
 * than a parsed object.
 */
function artifactBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}


describe("RP challenge", () => {
  it("verifies against the RP's active signing key", async () => {
    const rp = await createIdentity("rp.example");
    const now = Date.parse("2026-07-17T12:00:00Z");
    const challenge = await buildChallenge({
      rp,
      redirectUri: completionUri(rp, "/callback"),
      requestedScope: ["profile.read"],
      now,
    });
    const result = await verifyAuthorizationChallenge(artifactBytes(challenge), activeSigningKeys(rp), {
      now: new Date(now + 1000).toISOString(),
    });
    expect(result.ok).toBe(true);
    expect(challenge.requestedScope).toContain("identity.assert");
  });

  it("rejects a tampered challenge as a signature failure", async () => {
    const rp = await createIdentity("rp.example");
    const challenge = await buildChallenge({ rp, redirectUri: completionUri(rp, "/callback") });
    const flipped = challenge.nonce[0] === "0" ? "1" : "0";
    const tampered = { ...challenge, nonce: flipped + challenge.nonce.slice(1) };
    const result = await verifyAuthorizationChallenge(artifactBytes(tampered), activeSigningKeys(rp), {
      now: new Date().toISOString(),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("rejects a challenge signed by a key the card does not carry", async () => {
    const rp = await createIdentity("rp.example");
    const impostor = await createIdentity("rp.example");
    const challenge = await buildChallenge({ rp, redirectUri: completionUri(rp, "/callback") });
    // The card resolves the honest RP key, but the challenge below carries the
    // real RP's fields; verifying it against the impostor's card fails the
    // signature, since the impostor did not sign it.
    const result = await verifyAuthorizationChallenge(artifactBytes(challenge), activeSigningKeys(impostor), {
      now: new Date().toISOString(),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("rejects an expired challenge", async () => {
    const rp = await createIdentity("rp.example");
    const now = Date.parse("2026-07-17T12:00:00Z");
    const challenge = await buildChallenge({
      rp,
      redirectUri: completionUri(rp, "/callback"),
      now,
      windowMs: 60_000,
    });
    const result = await verifyAuthorizationChallenge(artifactBytes(challenge), activeSigningKeys(rp), {
      now: new Date(now + 120_000).toISOString(),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("expired");
  });

  it("refuses to build a challenge whose redirect is not the RP origin plus /", async () => {
    const rp = await createIdentity("rp.example");
    await expect(
      buildChallenge({ rp, redirectUri: "https://attacker.example/callback" }),
    ).rejects.toThrow();
  });

  it("refuses to build a challenge requesting an unregistered scope token", async () => {
    const rp = await createIdentity("rp.example");
    await expect(
      buildChallenge({
        rp,
        redirectUri: completionUri(rp, "/callback"),
        requestedScope: ["not.a.registry.token"],
      }),
    ).rejects.toThrow();
  });
});
