import { describe, it, expect } from "vitest";
import { generateKeypair, type Keypair } from "../src/crypto/keys.js";
import {
  buildDiscoveryQueryEnvelope,
  verifyDiscoveryQueryEnvelope,
  DiscoveryQueryEnvelopeSchema,
  type DiscoveryQueryInput,
} from "../src/models/discovery-query.js";

const validTimestamp = "2026-07-09T12:00:00.000Z";
const validNonce = "0123456789abcdef"; // exactly 16 chars

function baseInput(overrides: Partial<DiscoveryQueryInput> = {}): DiscoveryQueryInput {
  return {
    from: "did:web:requester.example",
    to: "did:web:directory.example",
    nonce: validNonce,
    timestamp: validTimestamp,
    query: { tags: ["go", "typescript"], scope: "public", limit: 10 },
    ...overrides,
  };
}

function makeEnvelope(kp: Keypair, overrides: Partial<DiscoveryQueryInput> = {}) {
  return buildDiscoveryQueryEnvelope(baseInput(overrides), kp.privateKey);
}

describe("discovery query envelope", () => {
  it("builds and verifies a valid signed query", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(DiscoveryQueryEnvelopeSchema.safeParse(env).success).toBe(true);
    expect(await verifyDiscoveryQueryEnvelope(env, kp.publicKey)).toBe(true);
  });

  it("verifies a minimal query with an empty query object", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp, { query: {} });
    expect(await verifyDiscoveryQueryEnvelope(env, kp.publicKey)).toBe(true);
  });

  it("accepts the vendor-neutral network.ink spelling", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp, { type: "network.ink.discovery_query" });
    expect(env.type).toBe("network.ink.discovery_query");
    expect(await verifyDiscoveryQueryEnvelope(env, kp.publicKey)).toBe(true);
  });

  it("fails when `to` is tampered after signing", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verifyDiscoveryQueryEnvelope({ ...env, to: "did:web:evil.example" }, kp.publicKey)).toBe(false);
  });

  it("fails when `type` is tampered after signing", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp); // signed as network.tulpa.*
    expect(await verifyDiscoveryQueryEnvelope({ ...env, type: "network.ink.discovery_query" }, kp.publicKey)).toBe(
      false,
    );
  });

  it("fails when a query tag is tampered after signing", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tampered = { ...env, query: { ...env.query, tags: ["rust", "typescript"] } };
    expect(await verifyDiscoveryQueryEnvelope(tampered, kp.publicKey)).toBe(false);
  });

  it("fails against the wrong public key", async () => {
    const kp = await generateKeypair();
    const other = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verifyDiscoveryQueryEnvelope(env, other.publicKey)).toBe(false);
  });

  it("rejects an invalid timestamp", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verifyDiscoveryQueryEnvelope({ ...env, timestamp: "2026-07-09 12:00" }, kp.publicKey)).toBe(false);
  });

  it("rejects a short nonce", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verifyDiscoveryQueryEnvelope({ ...env, nonce: "short" }, kp.publicKey)).toBe(false);
  });

  it("rejects an unknown top-level key", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    expect(await verifyDiscoveryQueryEnvelope({ ...env, extra: 1 }, kp.publicKey)).toBe(false);
  });

  it("rejects an unknown key inside query", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tampered = { ...env, query: { ...env.query, rank: "best" } };
    expect(await verifyDiscoveryQueryEnvelope(tampered, kp.publicKey)).toBe(false);
  });

  it("rejects more than 32 tags", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tags = Array.from({ length: 33 }, (_, i) => `t${i}`);
    expect(await verifyDiscoveryQueryEnvelope({ ...env, query: { ...env.query, tags } }, kp.publicKey)).toBe(false);
  });

  it("rejects a limit over 100", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const tampered = { ...env, query: { ...env.query, limit: 101 } };
    expect(await verifyDiscoveryQueryEnvelope(tampered, kp.publicKey)).toBe(false);
  });

  it("rejects a missing signature", async () => {
    const kp = await generateKeypair();
    const env = await makeEnvelope(kp);
    const { signature: _sig, ...unsigned } = env;
    expect(await verifyDiscoveryQueryEnvelope(unsigned, kp.publicKey)).toBe(false);
  });

  it("fails closed on a hostile object whose getter throws", async () => {
    const kp = await generateKeypair();
    const hostile = {
      get protocol(): string {
        throw new Error("boom");
      },
    };
    await expect(verifyDiscoveryQueryEnvelope(hostile, kp.publicKey)).resolves.toBe(false);
  });

  it("build rejects a malformed query at sign time", async () => {
    const kp = await generateKeypair();
    await expect(buildDiscoveryQueryEnvelope(baseInput({ query: { limit: 0 } }), kp.privateKey)).rejects.toThrow();
  });
});
