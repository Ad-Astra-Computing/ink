import { describe, it, expect } from "vitest";
import { generateKeypair, type Keypair } from "../src/crypto/keys.js";
import {
  buildAuthorizationChallenge,
  verifyAuthorizationChallenge,
  deriveChallengeGrantId,
  deriveRpOrigin,
  isChallengeRedirect,
  AuthorizationChallengeSchema,
  MAX_CHALLENGE_LIFETIME_MS,
  MAX_CHALLENGE_BODY_BYTES,
  CHALLENGE_SCOPE_REGISTRY,
  type AuthorizationChallengeInput,
} from "../src/models/authorization-challenge.js";
import { MAX_CHALLENGE_BODY_BYTES as MAX_CHALLENGE_BODY_BYTES_ROOT } from "../src/index.js";
import type { CandidateKey } from "../src/models/key-entry.js";

const issuedAt = "2026-07-16T12:00:00.000Z";
const expiresAt = "2026-07-16T12:05:00.000Z";
const clockInWindow = "2026-07-16T12:02:00.000Z";

function baseInput(overrides: Partial<AuthorizationChallengeInput> = {}): AuthorizationChallengeInput {
  return {
    rp: "did:web:rp.example",
    nonce: "nonce-challenge-000000001",
    requestedScope: ["identity.assert", "profile.read"],
    redirectUri: "https://rp.example/callback",
    issuedAt,
    expiresAt,
    ...overrides,
  };
}

function activeKeys(kp: Keypair): CandidateKey[] {
  return [{ keyId: "rp-active", publicKey: kp.publicKey, status: "active" }];
}

const utf8 = (text: string) => new TextEncoder().encode(text);

/** The verifier takes the raw body bytes, because the raw-body gate is about
 *  bytes a parsed value has already lost. Most cases here are written as values,
 *  so serialize them the way an RP would; the raw-text cases below hand the
 *  verifier bytes no serializer could produce. */
function verifyChallenge(challenge: unknown, keys: CandidateKey[], context: { now: string }) {
  return verifyAuthorizationChallenge(utf8(JSON.stringify(challenge)), keys, context);
}

describe("authorization challenge build and verify", () => {
  it("builds and verifies a challenge against an active RP key", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    expect(AuthorizationChallengeSchema.safeParse(challenge).success).toBe(true);
    expect(challenge.type).toBe("network.ink.authorization_challenge");
    const result = await verifyChallenge(challenge, activeKeys(kp), { now: clockInWindow });
    expect(result.ok).toBe(true);
  });

  it("rejects a retired key on a live challenge (active-key-only)", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    const keys: CandidateKey[] = [{ keyId: "rp-retired", publicKey: kp.publicKey, status: "retired" }];
    const result = await verifyChallenge(challenge, keys, { now: clockInWindow });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("treats the active-key validity window as inclusive at both ends (evaluated at now)", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    const atUpper: CandidateKey[] = [{ keyId: "rp-active", publicKey: kp.publicKey, status: "active", validUntil: clockInWindow }];
    const atLower: CandidateKey[] = [{ keyId: "rp-active", publicKey: kp.publicKey, status: "active", validFrom: clockInWindow }];
    expect((await verifyChallenge(challenge, atUpper, { now: clockInWindow })).ok).toBe(true);
    expect((await verifyChallenge(challenge, atLower, { now: clockInWindow })).ok).toBe(true);
  });

  it("checks the signature before the window (bad signature outranks expiry)", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    const tampered = { ...challenge, nonce: "nonce-challenge-999999999" };
    const result = await verifyChallenge(tampered, activeKeys(kp), { now: "2026-07-16T12:06:00.000Z" });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("evaluates the key window at now, not at issuedAt", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    // Key expired before the verifier clock: not usable even though the challenge
    // window is open.
    const keys: CandidateKey[] = [{ keyId: "rp-active", publicKey: kp.publicKey, status: "active", validUntil: "2026-07-16T11:00:00.000Z" }];
    const result = await verifyChallenge(challenge, keys, { now: clockInWindow });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("refuses to build an out-of-profile challenge (non-bare-host rp)", async () => {
    const kp = await generateKeypair();
    await expect(buildAuthorizationChallenge(baseInput({ rp: "did:web:rp.example:path" }), kp.privateKey)).rejects.toThrow();
  });

  it("refuses to build a challenge whose redirectUri is not under the rp origin", async () => {
    const kp = await generateKeypair();
    await expect(buildAuthorizationChallenge(baseInput({ redirectUri: "https://evil.example/callback" }), kp.privateKey)).rejects.toThrow();
  });
});

describe("challenge byte bound", () => {
  it("pins the 65536-byte ceiling and re-exports it from the root", () => {
    expect(MAX_CHALLENGE_BODY_BYTES).toBe(65536);
    expect(MAX_CHALLENGE_BODY_BYTES_ROOT).toBe(MAX_CHALLENGE_BODY_BYTES);
  });

  it("rejects a body past the byte cap even when it canonicalizes to a valid challenge", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    // Whitespace between tokens is legal JSON and vanishes at canonicalization,
    // so the signature over this body still verifies. The byte cap is the only
    // thing that refuses it.
    const padded = `{${" ".repeat(MAX_CHALLENGE_BODY_BYTES)}${JSON.stringify(challenge).slice(1)}`;
    expect(padded.length).toBeGreaterThan(MAX_CHALLENGE_BODY_BYTES);
    expect(await verifyAuthorizationChallenge(utf8(padded), activeKeys(kp), { now: clockInWindow })).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("accepts a body padded with whitespace under the byte cap", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    const padded = `{${" ".repeat(64)}${JSON.stringify(challenge).slice(1)}`;
    expect((await verifyAuthorizationChallenge(utf8(padded), activeKeys(kp), { now: clockInWindow })).ok).toBe(true);
  });
});

describe("challenge raw-body gate", () => {
  it("fails closed when handed something that is not bytes", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    // A caller on an untyped boundary (a JSON body a framework already parsed)
    // gets a typed rejection rather than a coercion.
    await expect(
      verifyAuthorizationChallenge(challenge as unknown as Uint8Array, activeKeys(kp), { now: clockInWindow }),
    ).resolves.toEqual({ ok: false, reason: "schema" });
  });

  it("fails closed on a body that is not JSON at all", async () => {
    const kp = await generateKeypair();
    await expect(
      verifyAuthorizationChallenge(utf8("{not json"), activeKeys(kp), { now: clockInWindow }),
    ).resolves.toEqual({ ok: false, reason: "schema" });
  });

  it("rejects an out-of-range number literal shadowed by a later duplicate member", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    // The challenge is untouched as a value: JSON member semantics are last-wins,
    // so the shadowed literal never reaches the parsed object and the signature
    // over the canonical form still verifies. Only a gate on the raw text can see
    // it, and without one this body is accepted here and refused by an
    // implementation that gates its bytes.
    const shadowed = `{"protocol":1e309,${JSON.stringify(challenge).slice(1)}`;
    expect(JSON.parse(shadowed)).toEqual(challenge);
    expect(await verifyAuthorizationChallenge(utf8(shadowed), activeKeys(kp), { now: clockInWindow })).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("accepts a shadowed underflowing exponent, which is in range", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    // The negative control: every IEEE-754 parser decodes 1e-400 to 0, so the
    // gate is a range test rather than a ban on exponents.
    const shadowed = `{"protocol":1e-400,${JSON.stringify(challenge).slice(1)}`;
    expect((await verifyAuthorizationChallenge(utf8(shadowed), activeKeys(kp), { now: clockInWindow })).ok).toBe(true);
  });

  it("rejects a lone UTF-16 surrogate escape in the raw text", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    const raw = JSON.stringify(challenge).replace(`"nonce":"${challenge.nonce}"`, `"nonce":"\\ud800${challenge.nonce}"`);
    expect(await verifyAuthorizationChallenge(utf8(raw), activeKeys(kp), { now: clockInWindow })).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("rejects raw bytes that are not valid UTF-8", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    const bytes = utf8(JSON.stringify(challenge));
    // Splice a lone continuation byte into the body. A JS string cannot hold it,
    // so this rule is unreachable from a parsed value.
    const broken = new Uint8Array(bytes.length + 1);
    broken.set(bytes.subarray(0, 1), 0);
    broken[1] = 0x80;
    broken.set(bytes.subarray(1), 2);
    expect(await verifyAuthorizationChallenge(broken, activeKeys(kp), { now: clockInWindow })).toEqual({
      ok: false,
      reason: "schema",
    });
  });
});

describe("derived challenge grantId", () => {
  it("is deterministic and 43 base64url characters", async () => {
    const c = baseInput();
    const id1 = await deriveChallengeGrantId(c);
    const id2 = await deriveChallengeGrantId(c);
    expect(id1).toBe(id2);
    expect(id1).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("ignores fields outside the four binding fields", async () => {
    const id1 = await deriveChallengeGrantId(baseInput());
    const id2 = await deriveChallengeGrantId(baseInput({ requestedScope: ["identity.assert"], redirectUri: "https://rp.example/other" }));
    expect(id1).toBe(id2);
  });

  it("differs when rp, nonce, or window differs", async () => {
    const id = await deriveChallengeGrantId(baseInput());
    expect(await deriveChallengeGrantId(baseInput({ rp: "did:web:rp2.example" }))).not.toBe(id);
    expect(await deriveChallengeGrantId(baseInput({ nonce: "nonce-challenge-000000002" }))).not.toBe(id);
    expect(await deriveChallengeGrantId(baseInput({ expiresAt: "2026-07-16T12:06:00.000Z" }))).not.toBe(id);
  });
});

describe("rp origin derivation (parser-independent)", () => {
  it("derives the origin for a bare host and an explicit non-default port", () => {
    expect(deriveRpOrigin("did:web:rp.example")).toBe("https://rp.example");
    expect(deriveRpOrigin("did:web:rp.example%3A8443")).toBe("https://rp.example:8443");
  });

  it("rejects path-bearing, uppercase, all-digit-final-label, IPv4, explicit-443, and lowercase-marker forms", () => {
    expect(deriveRpOrigin("did:web:rp.example:path")).toBeNull();
    expect(deriveRpOrigin("did:web:RP.example")).toBeNull();
    expect(deriveRpOrigin("did:web:rp.123")).toBeNull();
    expect(deriveRpOrigin("did:web:192.168.0.1")).toBeNull();
    expect(deriveRpOrigin("did:web:rp.example%3A443")).toBeNull();
    expect(deriveRpOrigin("did:web:rp.example%3a8443")).toBeNull();
    expect(deriveRpOrigin("did:web:rp.example%3A08443")).toBeNull();
  });

  it("rejects the parser-edge forms (trailing dot, repeated marker, port 0/65536, IPv6 bracket, percent host)", () => {
    expect(deriveRpOrigin("did:web:rp.example.")).toBeNull();
    expect(deriveRpOrigin("did:web:rp.example%3A8443%3A9000")).toBeNull();
    expect(deriveRpOrigin("did:web:rp.example%3A0")).toBeNull();
    expect(deriveRpOrigin("did:web:rp.example%3A65536")).toBeNull();
    expect(deriveRpOrigin("did:web:[2001:db8::1]")).toBeNull();
    expect(deriveRpOrigin("did:web:rp%2Eexample")).toBeNull();
    // The maximum in-range port is accepted.
    expect(deriveRpOrigin("did:web:rp.example%3A65535")).toBe("https://rp.example:65535");
  });
});

describe("challenge redirect rule (parser-independent)", () => {
  const origin = "https://rp.example";
  it("accepts the origin followed immediately by / and a path", () => {
    expect(isChallengeRedirect("https://rp.example/callback", origin)).toBe(true);
    expect(isChallengeRedirect("https://rp.example/", origin)).toBe(true);
  });
  it("rejects a non-prefix, host-suffix extension, missing slash, fragment, backslash, control, and whitespace", () => {
    expect(isChallengeRedirect("https://evil.example/callback", origin)).toBe(false);
    expect(isChallengeRedirect("https://rp.example.evil.com/callback", origin)).toBe(false);
    expect(isChallengeRedirect("https://rp.example", origin)).toBe(false);
    expect(isChallengeRedirect("https://rp.example/callback#frag", origin)).toBe(false);
    expect(isChallengeRedirect("https://rp.example/call\\back", origin)).toBe(false);
    expect(isChallengeRedirect("https://rp.example/call"+String.fromCharCode(1)+"back", origin)).toBe(false);
    expect(isChallengeRedirect("https://rp.example/call back", origin)).toBe(false);
  });
});

describe("scope registry", () => {
  it("pins the initial registry and the ten-minute ceiling", () => {
    expect(CHALLENGE_SCOPE_REGISTRY).toEqual(["identity.assert", "profile.read", "agent.message.send"]);
    expect(MAX_CHALLENGE_LIFETIME_MS).toBe(10 * 60 * 1000);
  });
});
