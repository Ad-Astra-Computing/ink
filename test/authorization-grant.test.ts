import { describe, it, expect } from "vitest";
import { generateKeypair, type Keypair } from "../src/crypto/keys.js";
import {
  buildAuthorizationGrant,
  verifyAuthorizationGrant,
  AuthorizationGrantError,
  AuthorizationGrantSchema,
  MAX_GRANT_LIFETIME_MS,
  type AuthorizationGrantInput,
  type AuthorizationGrantVerifyContext,
} from "../src/models/authorization-grant.js";

// A fixed issue time and a matching clock keep every case inside the default
// freshness window unless a case moves the clock deliberately.
const issuedAt = "2026-07-11T12:00:00.000Z";
const expiresAt = "2026-07-11T12:05:00.000Z";
const clockInWindow = "2026-07-11T12:02:00.000Z";
const grantId = "grant-0123456789abcdef";
const issuer = "did:web:issuer.example";

function baseInput(overrides: Partial<AuthorizationGrantInput> = {}): AuthorizationGrantInput {
  return {
    issuer,
    subject: "did:web:subject.example",
    audience: "did:web:service.example",
    scope: ["profile:read", "messages:send"],
    grantId,
    issuedAt,
    expiresAt,
    ...overrides,
  };
}

function baseContext(overrides: Partial<AuthorizationGrantVerifyContext> = {}): AuthorizationGrantVerifyContext {
  return {
    audience: "did:web:service.example",
    now: clockInWindow,
    ...overrides,
  };
}

async function makeGrant(kp: Keypair, overrides: Partial<AuthorizationGrantInput> = {}) {
  return buildAuthorizationGrant(baseInput(overrides), kp.privateKey);
}

describe("authorization grant build", () => {
  it("builds and verifies a scoped grant (happy path)", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    expect(AuthorizationGrantSchema.safeParse(grant).success).toBe(true);
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext());
    expect(result.ok).toBe(true);
  });

  it("defaults to the legacy network.tulpa spelling", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    expect(grant.type).toBe("network.tulpa.authorization_grant");
  });

  it("emits the vendor-neutral network.ink spelling on request", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp, { type: "network.ink.authorization_grant" });
    expect(grant.type).toBe("network.ink.authorization_grant");
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext());
    expect(result.ok).toBe(true);
  });

  it("verifies a grant that requires a verified owner when the owner is verified", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp, { requireVerifiedOwner: true });
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext({ verifiedOwner: { status: "verified" } }));
    expect(result.ok).toBe(true);
  });

  it("rejects a malformed scope at build time", async () => {
    const kp = await generateKeypair();
    await expect(buildAuthorizationGrant(baseInput({ scope: [] }), kp.privateKey)).rejects.toThrow();
  });

  it("rejects an expiresAt at or before issuedAt at build time", async () => {
    const kp = await generateKeypair();
    await expect(
      buildAuthorizationGrant(baseInput({ expiresAt: issuedAt }), kp.privateKey),
    ).rejects.toThrow();
  });
});

describe("authorization grant verify: happy structure", () => {
  it("accepts a grant with a single scope entry", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp, { scope: ["profile:read"] });
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext());
    expect(result.ok).toBe(true);
  });

  it("reports the verified grant so a caller can read its scope", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.grant.scope).toEqual(["profile:read", "messages:send"]);
      expect(result.grant.grantId).toBe(grantId);
    }
  });
});

describe("authorization grant verify: fail closed with typed reasons", () => {
  it("rejects a bad signature with reason signature", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const tampered = { ...grant, scope: ["profile:read", "admin:all"] };
    const result = await verifyAuthorizationGrant(tampered, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("rejects the wrong issuer key with reason signature", async () => {
    const kp = await generateKeypair();
    const other = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(grant, other.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("rejects a grant addressed to a different audience with reason audience (confused deputy)", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp, { audience: "did:web:other-service.example" });
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("audience");
  });

  it("rejects an expired grant with reason expired", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext({ now: "2026-07-11T12:06:00.000Z" }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("expired");
  });

  it("rejects a grant presented before issuedAt with reason not_yet_valid", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext({ now: "2026-07-11T11:59:00.000Z" }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("not_yet_valid");
  });

  it("rejects a replayed (issuer, grantId) with reason replay", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext({ seenGrants: [{ issuer, grantId }] }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("replay");
  });

  it("rejects a revoked (issuer, grantId) with reason revoked", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(
      grant,
      kp.publicKey,
      baseContext({ isRevoked: (key) => key.issuer === issuer && key.grantId === grantId }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("revoked");
  });

  it("rejects a malformed grant with reason schema", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant({ ...grant, extra: 1 }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects a grant with no scope entries with reason schema", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant({ ...grant, scope: [] }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects a missing signature with reason schema", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const { signature: _sig, ...unsigned } = grant;
    const result = await verifyAuthorizationGrant(unsigned, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });
});

describe("authorization grant verify: owner verification composition hook", () => {
  it("rejects a grant that requires a verified owner when no owner status is supplied", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp, { requireVerifiedOwner: true });
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("owner_unverified");
  });

  it("rejects a grant that requires a verified owner when the owner is unverified", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp, { requireVerifiedOwner: true });
    const result = await verifyAuthorizationGrant(
      grant,
      kp.publicKey,
      baseContext({ verifiedOwner: { status: "unverified" } }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("owner_unverified");
  });

  it("ignores owner status when the grant does not require a verified owner", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp, { requireVerifiedOwner: false });
    const result = await verifyAuthorizationGrant(
      grant,
      kp.publicKey,
      baseContext({ verifiedOwner: { status: "unverified" } }),
    );
    expect(result.ok).toBe(true);
  });
});

describe("authorization grant verify: fail closed on hostile and edge inputs", () => {
  it("fails closed on a hostile object whose getter throws", async () => {
    const kp = await generateKeypair();
    const hostile = {
      get issuer(): string {
        throw new Error("boom");
      },
    };
    const result = await verifyAuthorizationGrant(hostile, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
  });

  it("rejects a non-object grant", async () => {
    const kp = await generateKeypair();
    const result = await verifyAuthorizationGrant("not an object", kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
  });

  it("rejects a tampered audience even when the context audience matches the tampered value (signature binds audience)", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    // Re-point both the grant and the checked audience: the signature still fails
    // because the signed bytes bound the original audience.
    const tampered = { ...grant, audience: "did:web:evil.example" };
    const result = await verifyAuthorizationGrant(tampered, kp.publicKey, baseContext({ audience: "did:web:evil.example" }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("rejects an issuedAt that is not a strict INK timestamp with reason schema", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant({ ...grant, issuedAt: "2026-07-11 12:00" }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects a context clock that is not a strict INK timestamp with reason schema", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext({ now: "nonsense" }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("accepts a grant presented exactly at issuedAt (inclusive lower bound)", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext({ now: issuedAt }));
    expect(result.ok).toBe(true);
  });

  it("rejects a grant presented exactly at expiresAt (exclusive upper bound)", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext({ now: expiresAt }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("expired");
  });

  it("exposes AuthorizationGrantError with a reason for callers that prefer throwing", () => {
    const err = new AuthorizationGrantError("audience", "wrong audience");
    expect(err).toBeInstanceOf(Error);
    expect(err.reason).toBe("audience");
    expect(err.name).toBe("AuthorizationGrantError");
  });
});

describe("authorization grant scope fuzzing", () => {
  it("rejects an overbroad scope array (too many entries)", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const scope = Array.from({ length: 65 }, (_, i) => `s${i}`);
    const result = await verifyAuthorizationGrant({ ...grant, scope }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects a scope entry that is not a string", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant({ ...grant, scope: ["ok", 1] }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects an empty-string scope entry", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant({ ...grant, scope: [""] }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects an over-length scope entry", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant({ ...grant, scope: ["x".repeat(129)] }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects a duplicate scope entry (build refuses to sign one)", async () => {
    const kp = await generateKeypair();
    await expect(makeGrant(kp, { scope: ["profile:read", "profile:read"] })).rejects.toThrow();
  });

  it("rejects a grant tampered to carry a duplicate scope entry with reason schema", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(
      { ...grant, scope: ["profile:read", "profile:read"] },
      kp.publicKey,
      baseContext(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });
});

describe("authorization grant maximum lifetime", () => {
  it("exposes a ten-minute maximum grant lifetime", () => {
    expect(MAX_GRANT_LIFETIME_MS).toBe(10 * 60 * 1000);
  });

  it("accepts a window exactly at the maximum lifetime", async () => {
    const kp = await generateKeypair();
    const start = "2026-07-11T12:00:00.000Z";
    const end = new Date(Date.parse(start) + MAX_GRANT_LIFETIME_MS).toISOString();
    const grant = await makeGrant(kp, { issuedAt: start, expiresAt: end });
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext({ now: start }));
    expect(result.ok).toBe(true);
  });

  it("refuses to build a grant whose window exceeds the maximum lifetime", async () => {
    const kp = await generateKeypair();
    const start = "2026-07-11T12:00:00.000Z";
    const end = new Date(Date.parse(start) + MAX_GRANT_LIFETIME_MS + 1000).toISOString();
    await expect(buildAuthorizationGrant(baseInput({ issuedAt: start, expiresAt: end }), kp.privateKey)).rejects.toThrow();
  });

  it("rejects a grant whose window exceeds the maximum lifetime with reason schema", async () => {
    const kp = await generateKeypair();
    const start = "2026-07-11T12:00:00.000Z";
    const end = new Date(Date.parse(start) + MAX_GRANT_LIFETIME_MS + 1000).toISOString();
    // Sign a short in-profile grant, then relabel expiresAt past the ceiling: the
    // over-long window is rejected structurally before the signature is even checked.
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(
      { ...grant, issuedAt: start, expiresAt: end },
      kp.publicKey,
      baseContext({ now: start }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects the over-long window before the signature (structural, on signed bytes)", async () => {
    const kp = await generateKeypair();
    const other = await generateKeypair();
    const start = "2026-07-11T12:00:00.000Z";
    const end = new Date(Date.parse(start) + MAX_GRANT_LIFETIME_MS + 1000).toISOString();
    const grant = await makeGrant(kp);
    // Wrong verifying key would fail signature, but the window cap fails first.
    const result = await verifyAuthorizationGrant(
      { ...grant, issuedAt: start, expiresAt: end },
      other.publicKey,
      baseContext({ now: start }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("lets a caller tighten the lifetime for a check but the tightened cap is applied after the signature", async () => {
    const kp = await generateKeypair();
    // A full five-minute grant, in profile, but the caller only accepts windows
    // up to one minute for this check.
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(grant, kp.publicKey, baseContext({ maxLifetimeMs: 60 * 1000 }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("a caller-tightened window failure is checked after the signature", async () => {
    const kp = await generateKeypair();
    const other = await generateKeypair();
    const grant = await makeGrant(kp);
    // Both the signature (wrong key) and the tightened window would fail; the
    // signature must be reported first.
    const result = await verifyAuthorizationGrant(grant, other.publicKey, baseContext({ maxLifetimeMs: 60 * 1000 }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("does not let a caller loosen the lifetime beyond the profile ceiling", async () => {
    const kp = await generateKeypair();
    const start = "2026-07-11T12:00:00.000Z";
    const end = new Date(Date.parse(start) + MAX_GRANT_LIFETIME_MS + 1000).toISOString();
    const grant = await makeGrant(kp);
    // A caller asking for a two-hour cap cannot admit an over-ceiling grant: the
    // schema layer already rejected it before any context value applied.
    const result = await verifyAuthorizationGrant(
      { ...grant, issuedAt: start, expiresAt: end },
      kp.publicKey,
      baseContext({ now: start, maxLifetimeMs: 2 * 60 * 60 * 1000 }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });
});

describe("authorization grant replay and revocation key on (issuer, grantId)", () => {
  it("does not treat a different issuer's same grantId as a replay", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    // Another issuer has used the same grantId string. Our seen set records that
    // other issuer's key, which must not affect this grant.
    const result = await verifyAuthorizationGrant(
      grant,
      kp.publicKey,
      baseContext({ seenGrants: [{ issuer: "did:web:other-issuer.example", grantId }] }),
    );
    expect(result.ok).toBe(true);
  });

  it("does not treat a different issuer's same grantId as revoked", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(
      grant,
      kp.publicKey,
      baseContext({ isRevoked: (key) => key.grantId === grantId && key.issuer === "did:web:other-issuer.example" }),
    );
    expect(result.ok).toBe(true);
  });

  it("still rejects a replay of the same issuer and grantId", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyAuthorizationGrant(
      grant,
      kp.publicKey,
      baseContext({ seenGrants: [{ issuer: "did:web:other-issuer.example", grantId }, { issuer, grantId }] }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("replay");
  });
});

describe("authorization grant signature-first ordering with hostile context", () => {
  const cases: Array<[string, Partial<AuthorizationGrantVerifyContext>]> = [
    ["wrong audience", { audience: "did:web:other-service.example" }],
    ["expired clock", { now: "2026-07-11T12:06:00.000Z" }],
    ["replay set", { seenGrants: [{ issuer, grantId }] }],
    ["revoked predicate", { isRevoked: () => true }],
    ["owner unverified", { verifiedOwner: { status: "unverified" } }],
  ];
  for (const [label, ctx] of cases) {
    it(`reports signature first even with ${label}`, async () => {
      const kp = await generateKeypair();
      const grant = await makeGrant(kp, { requireVerifiedOwner: true });
      const tampered = { ...grant, scope: ["profile:read", "admin:all"] };
      const result = await verifyAuthorizationGrant(tampered, kp.publicKey, baseContext(ctx));
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe("signature");
    });
  }
});

describe("authorization grant string safety is structural", () => {
  it("rejects a lone UTF-16 surrogate in a string field with reason schema", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    // A lone high surrogate in the subject is not portable, so it rejects as a
    // structural failure before the signature check.
    const result = await verifyAuthorizationGrant(
      { ...grant, subject: "sub\uD800" },
      kp.publicKey,
      baseContext(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });
});
