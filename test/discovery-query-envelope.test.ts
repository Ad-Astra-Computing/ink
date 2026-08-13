import { describe, it, expect } from "vitest";
import { generateKeypair, type Keypair } from "../src/crypto/keys.js";
import {
  buildDiscoveryQueryEnvelope,
  verifyDiscoveryQueryEnvelope,
  DiscoveryQueryEnvelopeSchema,
  MAX_DISCOVERY_QUERY_AGE_MS,
  MAX_DISCOVERY_QUERY_SKEW_MS,
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

describe("discovery query envelope", () => {
  it("builds and verifies a valid signed query", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(DiscoveryQueryEnvelopeSchema.safeParse(env).success).toBe(true);
    const result = await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx());
    expect(result).toEqual({ ok: true, envelope: env });
  });

  it("verifies a minimal query with an empty query object", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp, { query: {} });
    expect((await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx())).ok).toBe(true);
  });

  it("accepts the vendor-neutral network.ink spelling", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp, { type: "network.ink.discovery_query" });
    expect(env.type).toBe("network.ink.discovery_query");
    expect((await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx())).ok).toBe(true);
  });

  it("fails when `to` is tampered after signing", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tampered = { ...env, to: "did:web:evil.example" };
    expect(await verifyDiscoveryQueryEnvelope(tampered, kp.publicKey, ctx({ audience: "did:web:evil.example" }))).toEqual(
      { ok: false, reason: "signature" },
    );
  });

  it("fails when `type` is tampered after signing", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp); // signed as network.tulpa.*
    const tampered = { ...env, type: "network.ink.discovery_query" };
    expect(await verifyDiscoveryQueryEnvelope(tampered, kp.publicKey, ctx())).toEqual({
      ok: false,
      reason: "signature",
    });
  });

  it("fails when a query tag is tampered after signing", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tampered = { ...env, query: { ...env.query, tags: ["rust", "typescript"] } };
    expect(await verifyDiscoveryQueryEnvelope(tampered, kp.publicKey, ctx())).toEqual({
      ok: false,
      reason: "signature",
    });
  });

  it("fails against the wrong public key", async () => {
    const kp = await generateKeypair();
    const other = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verifyDiscoveryQueryEnvelope(env, other.publicKey, ctx())).toEqual({
      ok: false,
      reason: "signature",
    });
  });

  it("rejects an invalid timestamp", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verifyDiscoveryQueryEnvelope({ ...env, timestamp: "2026-07-09 12:00" }, kp.publicKey, ctx())).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("rejects a short nonce", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verifyDiscoveryQueryEnvelope({ ...env, nonce: "short" }, kp.publicKey, ctx())).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("rejects an unknown top-level key", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verifyDiscoveryQueryEnvelope({ ...env, extra: 1 }, kp.publicKey, ctx())).toEqual({
      ok: false,
      reason: "schema",
    });
  });

  it("rejects an unknown key inside query", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tampered = { ...env, query: { ...env.query, rank: "best" } };
    expect(await verifyDiscoveryQueryEnvelope(tampered, kp.publicKey, ctx())).toEqual({ ok: false, reason: "schema" });
  });

  it("rejects more than 32 tags", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tags = Array.from({ length: 33 }, (_, i) => `t${i}`);
    const tampered = { ...env, query: { ...env.query, tags } };
    expect(await verifyDiscoveryQueryEnvelope(tampered, kp.publicKey, ctx())).toEqual({ ok: false, reason: "schema" });
  });

  it("rejects a limit over 100", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tampered = { ...env, query: { ...env.query, limit: 101 } };
    expect(await verifyDiscoveryQueryEnvelope(tampered, kp.publicKey, ctx())).toEqual({ ok: false, reason: "schema" });
  });

  it("rejects a missing signature", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const { signature: _sig, ...unsigned } = env;
    expect(await verifyDiscoveryQueryEnvelope(unsigned, kp.publicKey, ctx())).toEqual({ ok: false, reason: "schema" });
  });

  it("fails closed on a hostile object whose getter throws", async () => {
    const kp = await generateKeypair();
    const hostile = {
      get protocol(): string {
        throw new Error("boom");
      },
    };
    await expect(verifyDiscoveryQueryEnvelope(hostile, kp.publicKey, ctx())).resolves.toEqual({
      ok: false,
      reason: "schema",
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
    expect(await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ audience: "did:web:other.example" }))).toEqual({
      ok: false,
      reason: "audience",
    });
  });

  it("accepts when the signed `to` matches one of several self-identifiers", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const audience = ["https://directory.example", "directory.example", directory];
    expect((await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ audience }))).ok).toBe(true);
  });

  it("compares the audience exactly, with no case folding", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ audience: "DID:WEB:DIRECTORY.EXAMPLE" }))).toEqual(
      { ok: false, reason: "audience" },
    );
  });

  it("fails closed on an empty audience set rather than admitting every audience", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ audience: [] }))).toEqual({
      ok: false,
      reason: "schema",
    });
    expect(await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ audience: "" }))).toEqual({
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
    expect(await verifyDiscoveryQueryEnvelope(env, other.publicKey, ctx({ audience: "did:web:other.example" }))).toEqual(
      { ok: false, reason: "signature" },
    );
  });
});

describe("discovery query freshness window", () => {
  it("rejects a query older than the freshness window", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const now = clock(MAX_DISCOVERY_QUERY_AGE_MS + 1);
    expect(await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ now }))).toEqual({
      ok: false,
      reason: "expired",
    });
  });

  it("accepts a query exactly at the age bound", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const now = clock(MAX_DISCOVERY_QUERY_AGE_MS);
    expect((await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ now }))).ok).toBe(true);
  });

  it("rejects a query timestamped past the skew allowance", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const now = clock(-(MAX_DISCOVERY_QUERY_SKEW_MS + 1));
    expect(await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ now }))).toEqual({
      ok: false,
      reason: "not_yet_valid",
    });
  });

  it("accepts a query exactly at the skew bound", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const now = clock(-MAX_DISCOVERY_QUERY_SKEW_MS);
    expect((await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ now }))).ok).toBe(true);
  });

  it("fails closed on a verifier clock that is not a strict INK timestamp", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ now: "2026-07-09 12:00" }))).toEqual({
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
    expect(await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ seenNonces }))).toEqual({
      ok: false,
      reason: "replay",
    });
  });

  it("makes no replay decision when the directory supplies no seen-nonce state", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect((await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ seenNonces: undefined }))).ok).toBe(true);
  });

  it("keys replay on the (from, nonce) pair, so one requester cannot burn another's nonce", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const seenNonces = [{ from: "did:web:someone-else.example", nonce: env.nonce }];
    expect((await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ seenNonces }))).ok).toBe(true);
  });

  it("checks replay after the window, so a stale replay reports the window", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const seenNonces = [{ from: env.from, nonce: env.nonce }];
    const now = clock(MAX_DISCOVERY_QUERY_AGE_MS + 1);
    expect(await verifyDiscoveryQueryEnvelope(env, kp.publicKey, ctx({ seenNonces, now }))).toEqual({
      ok: false,
      reason: "expired",
    });
  });
});
