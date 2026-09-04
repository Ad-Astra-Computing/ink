import { describe, it, expect } from "vitest";
import { generateKeypair } from "../src/crypto/keys.js";
import {
  buildAttestation,
  verifyAttestation,
  AttestationSchema,
  MAX_ATTESTATION_BODY_BYTES,
  type AttestationInput,
} from "../src/models/attestation.js";

const issuedAt = "2026-08-01T00:00:00.000Z";
const expiresAt = "2027-08-01T00:00:00.000Z";
const now = "2026-09-01T00:00:00.000Z";
const attestationId = "att-0123456789abcdef";

function baseInput(overrides: Partial<AttestationInput> = {}): AttestationInput {
  return {
    issuer: "did:web:issuer.example",
    subject: "ink:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    claimType: "example.owner.verified_human",
    claim: { method: "in_person" },
    attestationId,
    issuedAt,
    expiresAt,
    ...overrides,
  };
}

async function signedBytes(overrides: Partial<AttestationInput> = {}) {
  const kp = await generateKeypair();
  const att = await buildAttestation(baseInput(overrides), kp.privateKey);
  return { kp, att, bytes: new TextEncoder().encode(JSON.stringify(att)) };
}

describe("buildAttestation", () => {
  it("round-trips through verification", async () => {
    const { kp, bytes } = await signedBytes();
    const v = await verifyAttestation(bytes, kp.publicKey, { now });
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.attestation.claimType).toBe("example.owner.verified_human");
  });

  it("emits the single vendor-neutral wire type", async () => {
    const { att } = await signedBytes();
    expect(att.type).toBe("network.ink.attestation");
  });

  it("accepts an empty claim object", async () => {
    const { kp, bytes } = await signedBytes({ claim: {} });
    const v = await verifyAttestation(bytes, kp.publicKey, { now });
    expect(v.ok).toBe(true);
  });

  it("accepts self-attestation", async () => {
    const kp = await generateKeypair();
    const att = await buildAttestation(
      baseInput({ issuer: "did:web:self.example", subject: "did:web:self.example" }),
      kp.privateKey,
    );
    const v = await verifyAttestation(new TextEncoder().encode(JSON.stringify(att)), kp.publicKey, { now });
    expect(v.ok).toBe(true);
  });

  it("refuses to build an out-of-grammar claimType", async () => {
    const kp = await generateKeypair();
    for (const bad of ["nodots", "Upper.case", "trailing.", ".leading", "sp ace.x", "a"]) {
      await expect(buildAttestation(baseInput({ claimType: bad }), kp.privateKey)).rejects.toThrow();
    }
  });

  it("refuses an inverted or empty window at build time", async () => {
    const kp = await generateKeypair();
    await expect(
      buildAttestation(baseInput({ expiresAt: issuedAt }), kp.privateKey),
    ).rejects.toThrow();
    await expect(
      buildAttestation(baseInput({ expiresAt: "2026-07-31T23:59:59.000Z" }), kp.privateKey),
    ).rejects.toThrow();
  });

  it("allows a multi-year window; no lifetime cap applies", async () => {
    const { kp, bytes } = await signedBytes({ expiresAt: "2030-01-01T00:00:00.000Z" });
    const v = await verifyAttestation(bytes, kp.publicKey, { now });
    expect(v.ok).toBe(true);
  });
});

describe("verifyAttestation structural rejections", () => {
  it("rejects a non-bytes input as schema", async () => {
    const { kp, att } = await signedBytes();
    const v = await verifyAttestation(att as unknown as Uint8Array, kp.publicKey, { now });
    expect(v).toEqual({ ok: false, reason: "schema" });
  });

  it("rejects a body over the byte cap without decoding it", async () => {
    const { kp } = await signedBytes();
    const big = new Uint8Array(MAX_ATTESTATION_BODY_BYTES + 1).fill(0x20);
    const v = await verifyAttestation(big, kp.publicKey, { now });
    expect(v).toEqual({ ok: false, reason: "schema" });
  });

  it("rejects the legacy namespace spelling", async () => {
    const { kp, att } = await signedBytes();
    const relabeled = { ...att, type: "network.tulpa.attestation" };
    const v = await verifyAttestation(
      new TextEncoder().encode(JSON.stringify(relabeled)),
      kp.publicKey,
      { now },
    );
    expect(v).toEqual({ ok: false, reason: "schema" });
  });

  it("rejects an unknown top-level member", async () => {
    const { kp, att } = await signedBytes();
    const extended = { ...att, note: "extra" };
    const v = await verifyAttestation(
      new TextEncoder().encode(JSON.stringify(extended)),
      kp.publicKey,
      { now },
    );
    expect(v).toEqual({ ok: false, reason: "schema" });
  });

  it("rejects an attestationId outside the nonce grammar or bounds", async () => {
    const { kp, att } = await signedBytes();
    for (const bad of ["short", "has space padding..", "x".repeat(257), "bad!chars#here!!"]) {
      const doc = { ...att, attestationId: bad };
      const v = await verifyAttestation(
        new TextEncoder().encode(JSON.stringify(doc)),
        kp.publicKey,
        { now },
      );
      expect(v).toEqual({ ok: false, reason: "schema" });
    }
  });

  it("rejects a non-object claim", async () => {
    const { kp, att } = await signedBytes();
    for (const bad of ["string", 7, null, ["array"]]) {
      const doc = { ...att, claim: bad };
      const v = await verifyAttestation(
        new TextEncoder().encode(JSON.stringify(doc)),
        kp.publicKey,
        { now },
      );
      expect(v).toEqual({ ok: false, reason: "schema" });
    }
  });
});

describe("verifyAttestation signature and window", () => {
  it("rejects a tampered field as signature, not schema", async () => {
    const { kp, att } = await signedBytes();
    const tampered = { ...att, subject: "did:web:other.example" };
    const v = await verifyAttestation(
      new TextEncoder().encode(JSON.stringify(tampered)),
      kp.publicKey,
      { now },
    );
    expect(v).toEqual({ ok: false, reason: "signature" });
  });

  it("rejects the wrong issuer key as signature", async () => {
    const { bytes } = await signedBytes();
    const other = await generateKeypair();
    const v = await verifyAttestation(bytes, other.publicKey, { now });
    expect(v).toEqual({ ok: false, reason: "signature" });
  });

  it("is valid at the issue instant and invalid at the expiry instant", async () => {
    const { kp, bytes } = await signedBytes();
    expect((await verifyAttestation(bytes, kp.publicKey, { now: issuedAt })).ok).toBe(true);
    expect(await verifyAttestation(bytes, kp.publicKey, { now: expiresAt })).toEqual({
      ok: false,
      reason: "expired",
    });
  });

  it("rejects before the window opens as not_yet_valid", async () => {
    const { kp, bytes } = await signedBytes();
    const v = await verifyAttestation(bytes, kp.publicKey, { now: "2026-07-31T23:59:59.000Z" });
    expect(v).toEqual({ ok: false, reason: "not_yet_valid" });
  });

  it("rejects a malformed verifier clock as schema", async () => {
    const { kp, bytes } = await signedBytes();
    const v = await verifyAttestation(bytes, kp.publicKey, { now: "yesterday" });
    expect(v).toEqual({ ok: false, reason: "schema" });
  });
});

describe("AttestationSchema", () => {
  it("parses a built attestation", async () => {
    const { att } = await signedBytes();
    expect(AttestationSchema.safeParse(att).success).toBe(true);
  });
});
