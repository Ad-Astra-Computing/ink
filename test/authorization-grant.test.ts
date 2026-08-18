import { describe, it, expect } from "vitest";
import { generateKeypair, type Keypair } from "../src/crypto/keys.js";
import {
  buildAuthorizationGrant,
  verifyAuthorizationGrant,
  AuthorizationGrantError,
  AuthorizationGrantSchema,
  MAX_GRANT_LIFETIME_MS,
  MAX_GRANT_BODY_BYTES,
  type AuthorizationGrantInput,
  type AuthorizationGrantVerifyContext,
} from "../src/models/authorization-grant.js";
import { MAX_GRANT_BODY_BYTES as MAX_GRANT_BODY_BYTES_ROOT } from "../src/index.js";

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

const utf8 = (text: string) => new TextEncoder().encode(text);

/** The verifier takes the raw body bytes, because the raw-body gate is about
 *  bytes a parsed value has already lost. Most cases here are written as values,
 *  so serialize them the way a presenter would; the raw-text cases below hand the
 *  verifier bytes no serializer could produce. */
function verifyGrant(grant: unknown, key: Uint8Array, context: AuthorizationGrantVerifyContext) {
  return verifyAuthorizationGrant(utf8(JSON.stringify(grant)), key, context);
}

describe("authorization grant build", () => {
  it("builds and verifies a scoped grant (happy path)", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    expect(AuthorizationGrantSchema.safeParse(grant).success).toBe(true);
    const result = await verifyGrant(grant, kp.publicKey, baseContext());
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
    const result = await verifyGrant(grant, kp.publicKey, baseContext());
    expect(result.ok).toBe(true);
  });

  it("verifies a grant that requires a verified owner when the owner is verified", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp, { requireVerifiedOwner: true });
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ verifiedOwner: { status: "verified" } }));
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
    const result = await verifyGrant(grant, kp.publicKey, baseContext());
    expect(result.ok).toBe(true);
  });

  it("reports the verified grant so a caller can read its scope", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext());
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
    const result = await verifyGrant(tampered, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("rejects the wrong issuer key with reason signature", async () => {
    const kp = await generateKeypair();
    const other = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, other.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("rejects a grant addressed to a different audience with reason audience (confused deputy)", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp, { audience: "did:web:other-service.example" });
    const result = await verifyGrant(grant, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("audience");
  });

  it("rejects an expired grant with reason expired", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ now: "2026-07-11T12:06:00.000Z" }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("expired");
  });

  it("rejects a grant presented before issuedAt with reason not_yet_valid", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ now: "2026-07-11T11:59:00.000Z" }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("not_yet_valid");
  });

  it("rejects a replayed (issuer, grantId) with reason replay", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ seenGrants: [{ issuer, grantId }] }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("replay");
  });

  it("rejects a revoked (issuer, grantId) with reason revoked", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(
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
    const result = await verifyGrant({ ...grant, extra: 1 }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects a grant with no scope entries with reason schema", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant({ ...grant, scope: [] }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects a missing signature with reason schema", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const { signature: _sig, ...unsigned } = grant;
    const result = await verifyGrant(unsigned, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });
});

describe("authorization grant verify: owner verification composition hook", () => {
  it("rejects a grant that requires a verified owner when no owner status is supplied", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp, { requireVerifiedOwner: true });
    const result = await verifyGrant(grant, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("owner_unverified");
  });

  it("rejects a grant that requires a verified owner when the owner is unverified", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp, { requireVerifiedOwner: true });
    const result = await verifyGrant(
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
    const result = await verifyGrant(
      grant,
      kp.publicKey,
      baseContext({ verifiedOwner: { status: "unverified" } }),
    );
    expect(result.ok).toBe(true);
  });
});

describe("authorization grant verify: fail closed on hostile and edge inputs", () => {
  it("fails closed on a hostile object whose getter throws, without ever invoking it", async () => {
    const kp = await generateKeypair();
    let touched = false;
    const hostile = {
      get issuer(): string {
        touched = true;
        throw new Error("boom");
      },
    };
    // The verifier takes bytes, so a hostile object is refused at the input
    // guard before any getter or proxy trap can run.
    const result = await verifyAuthorizationGrant(hostile as unknown as Uint8Array, kp.publicKey, baseContext());
    expect(result).toEqual({ ok: false, reason: "schema" });
    expect(touched).toBe(false);
  });

  it("rejects a non-object grant", async () => {
    const kp = await generateKeypair();
    const result = await verifyGrant("not an object", kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
  });

  it("rejects a tampered audience even when the context audience matches the tampered value (signature binds audience)", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    // Re-point both the grant and the checked audience: the signature still fails
    // because the signed bytes bound the original audience.
    const tampered = { ...grant, audience: "did:web:evil.example" };
    const result = await verifyGrant(tampered, kp.publicKey, baseContext({ audience: "did:web:evil.example" }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });

  it("rejects an issuedAt that is not a strict INK timestamp with reason schema", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant({ ...grant, issuedAt: "2026-07-11 12:00" }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects a context clock that is not a strict INK timestamp with reason schema", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ now: "nonsense" }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("accepts a grant presented exactly at issuedAt (inclusive lower bound)", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ now: issuedAt }));
    expect(result.ok).toBe(true);
  });

  it("rejects a grant presented exactly at expiresAt (exclusive upper bound)", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ now: expiresAt }));
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
    const result = await verifyGrant({ ...grant, scope }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects a scope entry that is not a string", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant({ ...grant, scope: ["ok", 1] }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects an empty-string scope entry", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant({ ...grant, scope: [""] }, kp.publicKey, baseContext());
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("rejects an over-length scope entry", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant({ ...grant, scope: ["x".repeat(129)] }, kp.publicKey, baseContext());
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
    const result = await verifyGrant(
      { ...grant, scope: ["profile:read", "profile:read"] },
      kp.publicKey,
      baseContext(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });
});

describe("authorization grant byte bound", () => {
  it("exposes a 65536-byte maximum grant body, the spec byte bound", () => {
    expect(MAX_GRANT_BODY_BYTES).toBe(65536);
  });

  it("re-exports the byte bound from the package root", () => {
    expect(MAX_GRANT_BODY_BYTES_ROOT).toBe(MAX_GRANT_BODY_BYTES);
  });

  it("rejects a body past the byte cap even when it canonicalizes to a valid grant", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    // Whitespace between tokens is legal JSON and vanishes at canonicalization,
    // so the signature over this body still verifies. The byte cap is the only
    // thing that refuses it.
    const padded = `{${" ".repeat(MAX_GRANT_BODY_BYTES)}${JSON.stringify(grant).slice(1)}`;
    expect(padded.length).toBeGreaterThan(MAX_GRANT_BODY_BYTES);
    expect(await verifyAuthorizationGrant(utf8(padded), kp.publicKey, baseContext())).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("accepts a body padded with whitespace under the byte cap", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const padded = `{${" ".repeat(64)}${JSON.stringify(grant).slice(1)}`;
    expect((await verifyAuthorizationGrant(utf8(padded), kp.publicKey, baseContext())).ok).toBe(true);
  });
});

describe("authorization grant raw-body gate", () => {
  it("fails closed when handed something that is not bytes", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    // A caller on an untyped boundary (a JSON body a framework already parsed)
    // gets a typed rejection rather than a coercion.
    await expect(
      verifyAuthorizationGrant(grant as unknown as Uint8Array, kp.publicKey, baseContext()),
    ).resolves.toEqual({ ok: false, reason: "schema" });
  });

  it("fails closed on a body that is not JSON at all", async () => {
    const kp = await generateKeypair();
    await expect(verifyAuthorizationGrant(utf8("{not json"), kp.publicKey, baseContext())).resolves.toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("rejects an out-of-range number literal shadowed by a later duplicate member", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    // The grant is untouched as a value: JSON member semantics are last-wins, so
    // the shadowed literal never reaches the parsed object and the signature over
    // the canonical form still verifies. Only a gate on the raw text can see it,
    // and without one this body is accepted here and refused by an implementation
    // that gates its bytes.
    const shadowed = `{"protocol":1e309,${JSON.stringify(grant).slice(1)}`;
    expect(JSON.parse(shadowed)).toEqual(grant);
    expect(await verifyAuthorizationGrant(utf8(shadowed), kp.publicKey, baseContext())).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("rejects an out-of-range number literal in a live member", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp, { requireVerifiedOwner: true });
    const raw = JSON.stringify(grant).replace(`"requireVerifiedOwner":true`, `"requireVerifiedOwner":1e309`);
    expect(
      await verifyAuthorizationGrant(utf8(raw), kp.publicKey, baseContext({ verifiedOwner: { status: "verified" } })),
    ).toEqual({ ok: false, reason: "schema" });
  });

  it("accepts a shadowed underflowing exponent, which is in range", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    // The negative control: every IEEE-754 parser decodes 1e-400 to 0, so the
    // gate is a range test rather than a ban on exponents.
    const shadowed = `{"protocol":1e-400,${JSON.stringify(grant).slice(1)}`;
    expect((await verifyAuthorizationGrant(utf8(shadowed), kp.publicKey, baseContext())).ok).toBe(true);
  });

  it("rejects a lone UTF-16 surrogate escape in the raw text", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const raw = JSON.stringify(grant).replace(`"subject":"${grant.subject}"`, `"subject":"\\ud800${grant.subject}"`);
    expect(await verifyAuthorizationGrant(utf8(raw), kp.publicKey, baseContext())).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("rejects raw bytes that are not valid UTF-8", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const bytes = utf8(JSON.stringify(grant));
    // Splice a lone continuation byte into the body. A JS string cannot hold it,
    // so this rule is unreachable from a parsed value.
    const broken = new Uint8Array(bytes.length + 1);
    broken.set(bytes.subarray(0, 1), 0);
    broken[1] = 0x80;
    broken.set(bytes.subarray(1), 2);
    expect(await verifyAuthorizationGrant(broken, kp.publicKey, baseContext())).toEqual({
      ok: false,
      reason: "schema",
    });
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
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ now: start }));
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
    const result = await verifyGrant(
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
    const result = await verifyGrant(
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
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ maxLifetimeMs: 60 * 1000 }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });

  it("a caller-tightened window failure is checked after the signature", async () => {
    const kp = await generateKeypair();
    const other = await generateKeypair();
    const grant = await makeGrant(kp);
    // Both the signature (wrong key) and the tightened window would fail; the
    // signature must be reported first.
    const result = await verifyGrant(grant, other.publicKey, baseContext({ maxLifetimeMs: 60 * 1000 }));
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
    const result = await verifyGrant(
      { ...grant, issuedAt: start, expiresAt: end },
      kp.publicKey,
      baseContext({ now: start, maxLifetimeMs: 2 * 60 * 60 * 1000 }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });
});

describe("authorization grant caller-tightened lifetime input validation", () => {
  const badValues: Array<[string, number]> = [
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["-Infinity", Number.NEGATIVE_INFINITY],
    ["negative", -1],
  ];
  for (const [label, value] of badValues) {
    it(`rejects a ${label} maxLifetimeMs as schema (fails closed like a malformed clock)`, async () => {
      const kp = await generateKeypair();
      const grant = await makeGrant(kp);
      const result = await verifyGrant(grant, kp.publicKey, baseContext({ maxLifetimeMs: value }));
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe("schema");
    });
  }

  it("treats a zero maxLifetimeMs as unset and uses the profile default (accepts)", async () => {
    // Zero means unset, matching Go's MaxLifetimeMs == 0 gate: a Go zero-value
    // integer is indistinguishable from an unset one, so 0 is no caller cap.
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ maxLifetimeMs: 0 }));
    expect(result.ok).toBe(true);
  });

  it("still accepts a finite positive maxLifetimeMs that admits the window", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ maxLifetimeMs: 5 * 60 * 1000 }));
    expect(result.ok).toBe(true);
  });
});

describe("authorization grant presentation binding", () => {
  const subject = "did:web:subject.example";

  it("accepts when the presenter equals the signed subject", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ presenter: subject }));
    expect(result.ok).toBe(true);
  });

  it("rejects when the presenter is not the signed subject with reason subject", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ presenter: "did:web:thief.example" }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("subject");
  });

  it("skips the check when no presenter is supplied (bearer artifact)", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext());
    expect(result.ok).toBe(true);
  });

  it("skips the check when the presenter is an empty string (empty means absent)", async () => {
    // An empty presenter is no presenter, matching Go's Presenter != "" gate:
    // Go cannot tell an unset field from an empty one, so the two are equivalent.
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ presenter: "" }));
    expect(result.ok).toBe(true);
  });

  it("checks the presenter after the audience check, before the window", async () => {
    const kp = await generateKeypair();
    // Wrong audience and a stolen presenter both fail; the audience check runs
    // first, so the reason is audience, not subject.
    const grant = await makeGrant(kp, { audience: "did:web:other-service.example" });
    const result = await verifyGrant(grant, kp.publicKey, baseContext({ presenter: "did:web:thief.example" }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("audience");
  });

  it("checks the presenter before the window, so a stolen expired grant rejects on subject", async () => {
    const kp = await generateKeypair();
    // The grant is expired and stolen; the subject binding is checked before the
    // window, so the reason is subject rather than expired.
    const grant = await makeGrant(kp);
    const result = await verifyGrant(
      grant,
      kp.publicKey,
      baseContext({ presenter: "did:web:thief.example", now: "2026-07-11T12:06:00.000Z" }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("subject");
  });

  it("reports signature first even when the presenter does not match", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const tampered = { ...grant, scope: ["profile:read", "admin:all"] };
    const result = await verifyGrant(tampered, kp.publicKey, baseContext({ presenter: "did:web:thief.example" }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature");
  });
});

describe("authorization grant replay and revocation key on (issuer, grantId)", () => {
  it("does not treat a different issuer's same grantId as a replay", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    // Another issuer has used the same grantId string. Our seen set records that
    // other issuer's key, which must not affect this grant.
    const result = await verifyGrant(
      grant,
      kp.publicKey,
      baseContext({ seenGrants: [{ issuer: "did:web:other-issuer.example", grantId }] }),
    );
    expect(result.ok).toBe(true);
  });

  it("does not treat a different issuer's same grantId as revoked", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(
      grant,
      kp.publicKey,
      baseContext({ isRevoked: (key) => key.grantId === grantId && key.issuer === "did:web:other-issuer.example" }),
    );
    expect(result.ok).toBe(true);
  });

  it("still rejects a replay of the same issuer and grantId", async () => {
    const kp = await generateKeypair();
    const grant = await makeGrant(kp);
    const result = await verifyGrant(
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
      const result = await verifyGrant(tampered, kp.publicKey, baseContext(ctx));
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
    const result = await verifyGrant(
      { ...grant, subject: "sub\uD800" },
      kp.publicKey,
      baseContext(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("schema");
  });
});
