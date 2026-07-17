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

describe("authorization challenge build and verify", () => {
  it("builds and verifies a challenge against an active RP key", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    expect(AuthorizationChallengeSchema.safeParse(challenge).success).toBe(true);
    expect(challenge.type).toBe("network.ink.authorization_challenge");
    const result = await verifyAuthorizationChallenge(challenge, activeKeys(kp), { now: clockInWindow });
    expect(result.ok).toBe(true);
  });

  it("rejects a retired key on a live challenge (active-key-only)", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    const keys: CandidateKey[] = [{ keyId: "rp-retired", publicKey: kp.publicKey, status: "retired" }];
    const result = await verifyAuthorizationChallenge(challenge, keys, { now: clockInWindow });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("treats the active-key validity window as inclusive at both ends (evaluated at now)", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    const atUpper: CandidateKey[] = [{ keyId: "rp-active", publicKey: kp.publicKey, status: "active", validUntil: clockInWindow }];
    const atLower: CandidateKey[] = [{ keyId: "rp-active", publicKey: kp.publicKey, status: "active", validFrom: clockInWindow }];
    expect((await verifyAuthorizationChallenge(challenge, atUpper, { now: clockInWindow })).ok).toBe(true);
    expect((await verifyAuthorizationChallenge(challenge, atLower, { now: clockInWindow })).ok).toBe(true);
  });

  it("checks the signature before the window (bad signature outranks expiry)", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    const tampered = { ...challenge, nonce: "nonce-challenge-999999999" };
    const result = await verifyAuthorizationChallenge(tampered, activeKeys(kp), { now: "2026-07-16T12:06:00.000Z" });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("evaluates the key window at now, not at issuedAt", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    // Key expired before the verifier clock: not usable even though the challenge
    // window is open.
    const keys: CandidateKey[] = [{ keyId: "rp-active", publicKey: kp.publicKey, status: "active", validUntil: "2026-07-16T11:00:00.000Z" }];
    const result = await verifyAuthorizationChallenge(challenge, keys, { now: clockInWindow });
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

  it("rejects an oversized decoded object as schema", async () => {
    const kp = await generateKeypair();
    const challenge = await buildAuthorizationChallenge(baseInput(), kp.privateKey);
    // An extra top-level field padded past the byte ceiling: the strict schema
    // rejects the unknown key as schema, and the byte-boundary contract is that a
    // raw body this large is refused before decode by whatever received the bytes.
    const oversized = { ...challenge, pad: "a".repeat(MAX_CHALLENGE_BODY_BYTES + 1) };
    const result = await verifyAuthorizationChallenge(oversized, activeKeys(kp), { now: clockInWindow });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
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
