import { describe, it, expect } from "vitest";
import { generateKeypair, type Keypair } from "../src/crypto/keys.js";
import {
  buildDiscoveryQueryEnvelope,
  verifyDiscoveryQueryEnvelope,
  DiscoveryQueryEnvelopeSchema,
  MAX_DISCOVERY_QUERY_AGE_MS,
  MAX_DISCOVERY_QUERY_SKEW_MS,
  MAX_DISCOVERY_QUERY_BODY_BYTES,
  type DiscoveryQueryInput,
  type DiscoveryQueryVerifyContext,
} from "../src/models/discovery-query.js";

const validTimestamp = "2026-07-09T12:00:00.000Z";
const validNonce = "0123456789abcdef"; // exactly 16 chars
const directory = "did:web:directory.example";

/** A verifier clock `offsetMs` past the signed timestamp. */
function clock(offsetMs: number): string {
  return new Date(Date.parse(validTimestamp) + offsetMs).toISOString();
}

function baseInput(overrides: Partial<DiscoveryQueryInput> = {}): DiscoveryQueryInput {
  return {
    from: "did:web:requester.example",
    to: directory,
    nonce: validNonce,
    timestamp: validTimestamp,
    query: { tags: ["go", "typescript"], scope: "public", limit: 10 },
    ...overrides,
  };
}

function makeEnvelope(kp: Keypair, overrides: Partial<DiscoveryQueryInput> = {}) {
  return buildDiscoveryQueryEnvelope(baseInput(overrides), kp.privateKey);
}

/** The context a well-behaved directory supplies: itself, a clock inside the
 *  freshness window and an empty seen-nonce set. */
function ctx(overrides: Partial<DiscoveryQueryVerifyContext> = {}): DiscoveryQueryVerifyContext {
  return { audience: directory, now: clock(1000), ...overrides };
}

const utf8 = (text: string) => new TextEncoder().encode(text);

/** The verifier takes the raw body bytes, because the raw-body gate is about
 *  bytes a parsed value has already lost. Most cases here are written as values,
 *  so serialize them the way a sender would; the raw-text cases below hand the
 *  verifier bytes no serializer could produce. */
function verify(envelope: unknown, key: Uint8Array, context: DiscoveryQueryVerifyContext) {
  return verifyDiscoveryQueryEnvelope(utf8(JSON.stringify(envelope)), key, context);
}

describe("discovery query envelope", () => {
  it("builds and verifies a valid signed query", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(DiscoveryQueryEnvelopeSchema.safeParse(env).success).toBe(true);
    const result = await verify(env, kp.publicKey, ctx());
    expect(result).toEqual({ ok: true, envelope: env });
  });

  it("verifies a minimal query with an empty query object", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp, { query: {} });
    expect((await verify(env, kp.publicKey, ctx())).ok).toBe(true);
  });

  it("accepts the vendor-neutral network.ink spelling", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp, { type: "network.ink.discovery_query" });
    expect(env.type).toBe("network.ink.discovery_query");
    expect((await verify(env, kp.publicKey, ctx())).ok).toBe(true);
  });

  it("fails when `to` is tampered after signing", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tampered = { ...env, to: "did:web:evil.example" };
    expect(await verify(tampered, kp.publicKey, ctx({ audience: "did:web:evil.example" }))).toEqual(
      { ok: false, reason: "signature" },
    );
  });

  it("fails when `type` is tampered after signing", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp); // signed as network.tulpa.*
    const tampered = { ...env, type: "network.ink.discovery_query" };
    expect(await verify(tampered, kp.publicKey, ctx())).toEqual({
      ok: false,
      reason: "signature",
    });
  });

  it("fails when a query tag is tampered after signing", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tampered = { ...env, query: { ...env.query, tags: ["rust", "typescript"] } };
    expect(await verify(tampered, kp.publicKey, ctx())).toEqual({
      ok: false,
      reason: "signature",
    });
  });

  it("fails against the wrong public key", async () => {
    const kp = await generateKeypair();
    const other = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verify(env, other.publicKey, ctx())).toEqual({
      ok: false,
      reason: "signature",
    });
  });

  it("rejects an invalid timestamp", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verify({ ...env, timestamp: "2026-07-09 12:00" }, kp.publicKey, ctx())).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("rejects a short nonce", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verify({ ...env, nonce: "short" }, kp.publicKey, ctx())).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("rejects an unknown top-level key", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verify({ ...env, extra: 1 }, kp.publicKey, ctx())).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("rejects an unknown key inside query", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tampered = { ...env, query: { ...env.query, rank: "best" } };
    expect(await verify(tampered, kp.publicKey, ctx())).toEqual({ ok: false, reason: "schema" });
  });

  it("rejects more than 32 tags", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tags = Array.from({ length: 33 }, (_, i) => `t${i}`);
    const tampered = { ...env, query: { ...env.query, tags } };
    expect(await verify(tampered, kp.publicKey, ctx())).toEqual({ ok: false, reason: "schema" });
  });

  it("rejects a limit over 100", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tampered = { ...env, query: { ...env.query, limit: 101 } };
    expect(await verify(tampered, kp.publicKey, ctx())).toEqual({ ok: false, reason: "schema" });
  });

  it("rejects a missing signature", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const { signature: _sig, ...unsigned } = env;
    expect(await verify(unsigned, kp.publicKey, ctx())).toEqual({ ok: false, reason: "schema" });
  });

  it("fails closed on a body that is not JSON at all", async () => {
    const kp = await generateKeypair();
    await expect(verifyDiscoveryQueryEnvelope(utf8("{not json"), kp.publicKey, ctx())).resolves.toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("fails closed when handed something that is not bytes", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    // A caller on an untyped boundary (a JSON body a framework already parsed)
    // gets a typed rejection rather than a coercion.
    await expect(
      verifyDiscoveryQueryEnvelope(env as unknown as Uint8Array, kp.publicKey, ctx()),
    ).resolves.toEqual({ ok: false, reason: "schema" });
  });

  describe("raw-body gate", () => {
    it("rejects an out-of-range number literal shadowed by a later duplicate member", async () => {
      const kp = await generateKeypair();
      const env = await makeEnvelope(kp);
      // The envelope is untouched as a value: JSON member semantics are
      // last-wins, so the shadowed literal never reaches the parsed object and
      // the signature over the canonical form still verifies. Only a gate on the
      // raw text can see it, and without one this body is accepted here and
      // refused by an implementation that gates its bytes.
      const shadowed = `{"protocol":1e309,${JSON.stringify(env).slice(1)}`;
      expect(JSON.parse(shadowed)).toEqual(env);
      expect(await verifyDiscoveryQueryEnvelope(utf8(shadowed), kp.publicKey, ctx())).toEqual({
        ok: false,
        reason: "schema",
      });
    });

    it("rejects an out-of-range number literal in a live member", async () => {
      const kp = await generateKeypair();
      const env = await makeEnvelope(kp);
      const raw = JSON.stringify({ ...env, query: { ...env.query, limit: 10 } }).replace(`"limit":10`, `"limit":1e309`);
      expect(await verifyDiscoveryQueryEnvelope(utf8(raw), kp.publicKey, ctx())).toEqual({
        ok: false,
        reason: "schema",
      });
    });

    it("rejects a lone UTF-16 surrogate escape in the raw text", async () => {
      const kp = await generateKeypair();
      const env = await makeEnvelope(kp);
      const raw = JSON.stringify(env).replace(`"nonce":"${env.nonce}"`, `"nonce":"\\ud800${env.nonce}"`);
      expect(await verifyDiscoveryQueryEnvelope(utf8(raw), kp.publicKey, ctx())).toEqual({
        ok: false,
        reason: "schema",
      });
    });

    it("rejects raw bytes that are not valid UTF-8", async () => {
      const kp = await generateKeypair();
      const env = await makeEnvelope(kp);
      const bytes = utf8(JSON.stringify(env));
      // Splice a lone continuation byte into the body. A JS string cannot hold
      // it, so this rule is unreachable from a parsed value.
      const broken = new Uint8Array(bytes.length + 1);
      broken.set(bytes.subarray(0, 1), 0);
      broken[1] = 0x80;
      broken.set(bytes.subarray(1), 2);
      expect(await verifyDiscoveryQueryEnvelope(broken, kp.publicKey, ctx())).toEqual({
        ok: false,
        reason: "schema",
      });
    });

    it("rejects a body past the byte cap even when it canonicalizes to a valid envelope", async () => {
      const kp = await generateKeypair();
      const env = await makeEnvelope(kp);
      // Whitespace between tokens is legal JSON and vanishes at
      // canonicalization, so the signature over this body still verifies. The
      // byte cap is the only thing that refuses it.
      const padded = `{${" ".repeat(MAX_DISCOVERY_QUERY_BODY_BYTES)}${JSON.stringify(env).slice(1)}`;
      expect(padded.length).toBeGreaterThan(MAX_DISCOVERY_QUERY_BODY_BYTES);
      expect(await verifyDiscoveryQueryEnvelope(utf8(padded), kp.publicKey, ctx())).toEqual({
        ok: false,
        reason: "schema",
      });
    });

    it("accepts a body padded with whitespace under the byte cap", async () => {
      const kp = await generateKeypair();
      const env = await makeEnvelope(kp);
      const padded = `{${" ".repeat(64)}${JSON.stringify(env).slice(1)}`;
      expect((await verifyDiscoveryQueryEnvelope(utf8(padded), kp.publicKey, ctx())).ok).toBe(true);
    });
  });

  it("build rejects a malformed query at sign time", async () => {
    const kp = await generateKeypair();
    await expect(buildDiscoveryQueryEnvelope(baseInput({ query: { limit: 0 } }), kp.privateKey)).rejects.toThrow();
  });
});

describe("discovery query audience binding", () => {
  it("rejects a query addressed to another directory", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verify(env, kp.publicKey, ctx({ audience: "did:web:other.example" }))).toEqual({
      ok: false,
      reason: "audience",
    });
  });

  it("accepts when the signed `to` matches one of several self-identifiers", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const audience = ["https://directory.example", "directory.example", directory];
    expect((await verify(env, kp.publicKey, ctx({ audience }))).ok).toBe(true);
  });

  it("compares the audience exactly, with no case folding", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verify(env, kp.publicKey, ctx({ audience: "DID:WEB:DIRECTORY.EXAMPLE" }))).toEqual(
      { ok: false, reason: "audience" },
    );
  });

  it("fails closed on an empty audience set rather than admitting every audience", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verify(env, kp.publicKey, ctx({ audience: [] }))).toEqual({
      ok: false,
      reason: "schema",
    });
    expect(await verify(env, kp.publicKey, ctx({ audience: "" }))).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("checks the signature before the audience", async () => {
    const kp = await generateKeypair();
    const other = await generateKeypair();
    const env = await makeEnvelope(kp);
    // Both the key and the audience are wrong; the signature verdict wins, so a
    // rejection never reveals whether the audience would have matched.
    expect(await verify(env, other.publicKey, ctx({ audience: "did:web:other.example" }))).toEqual(
      { ok: false, reason: "signature" },
    );
  });
});

describe("discovery query freshness window", () => {
  it("rejects a query older than the freshness window", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const now = clock(MAX_DISCOVERY_QUERY_AGE_MS + 1);
    expect(await verify(env, kp.publicKey, ctx({ now }))).toEqual({
      ok: false,
      reason: "expired",
    });
  });

  it("accepts a query exactly at the age bound", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const now = clock(MAX_DISCOVERY_QUERY_AGE_MS);
    expect((await verify(env, kp.publicKey, ctx({ now }))).ok).toBe(true);
  });

  it("rejects a query timestamped past the skew allowance", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const now = clock(-(MAX_DISCOVERY_QUERY_SKEW_MS + 1));
    expect(await verify(env, kp.publicKey, ctx({ now }))).toEqual({
      ok: false,
      reason: "not_yet_valid",
    });
  });

  it("accepts a query exactly at the skew bound", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const now = clock(-MAX_DISCOVERY_QUERY_SKEW_MS);
    expect((await verify(env, kp.publicKey, ctx({ now }))).ok).toBe(true);
  });

  it("fails closed on a verifier clock that is not a strict INK timestamp", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verify(env, kp.publicKey, ctx({ now: "2026-07-09 12:00" }))).toEqual({
      ok: false,
      reason: "schema",
    });
  });
});

describe("discovery query replay", () => {
  it("rejects a nonce this directory already burned", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const seenNonces = [{ from: env.from, nonce: env.nonce }];
    expect(await verify(env, kp.publicKey, ctx({ seenNonces }))).toEqual({
      ok: false,
      reason: "replay",
    });
  });

  it("makes no replay decision when the directory supplies no seen-nonce state", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect((await verify(env, kp.publicKey, ctx({ seenNonces: undefined }))).ok).toBe(true);
  });

  it("keys replay on the (from, nonce) pair, so one requester cannot burn another's nonce", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const seenNonces = [{ from: "did:web:someone-else.example", nonce: env.nonce }];
    expect((await verify(env, kp.publicKey, ctx({ seenNonces }))).ok).toBe(true);
  });

  it("checks replay after the window, so a stale replay reports the window", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const seenNonces = [{ from: env.from, nonce: env.nonce }];
    const now = clock(MAX_DISCOVERY_QUERY_AGE_MS + 1);
    expect(await verify(env, kp.publicKey, ctx({ seenNonces, now }))).toEqual({
      ok: false,
      reason: "expired",
    });
  });
});
