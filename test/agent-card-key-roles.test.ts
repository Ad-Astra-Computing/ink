import { describe, it, expect } from "vitest";
import { AgentCardSchema } from "../src/models/agent-card.js";
import { encodePublicKeyMultibase, encodeEncryptionKeyMultibase } from "../src/crypto/keys.js";

// Identity model §4.1: the roles are disjoint and the multicodec enforces it.
// A signing-key slot MUST decode to 0xed01 plus 32 bytes and an encryption-key
// slot to 0xec01 plus 32 bytes; anything else rejects at card validation.
const ed = encodePublicKeyMultibase(new Uint8Array(32).fill(3));
const enc = encodeEncryptionKeyMultibase(new Uint8Array(32).fill(7));

const entry = (publicKeyMultibase: string, algorithm: "Ed25519" | "X25519") => ({
  keyId: "k1",
  algorithm,
  publicKeyMultibase,
  status: "active" as const,
  validFrom: "2026-01-01T00:00:00Z",
});

const card = (keys: object) => ({
  protocol: "ink/0.1",
  agentId: "did:web:a.example",
  handle: "alice",
  displayName: "Alice",
  endpoint: "https://a.example/ink/inbox",
  publicKeyMultibase: ed,
  capabilities: { intentsAccepted: ["ping"], intentsSent: ["ask"] },
  availability: { timezone: "UTC" },
  keys,
});

describe("agent card key-role multicodec binding (§4.1)", () => {
  it("accepts an Ed25519 signing key and an X25519 encryption key", () => {
    const r = AgentCardSchema.safeParse(
      card({ signing: [entry(ed, "Ed25519")], encryption: [entry(enc, "X25519")] }),
    );
    expect(r.success).toBe(true);
  });

  it("rejects an Ed25519 key in the encryption slot", () => {
    const r = AgentCardSchema.safeParse(
      card({ signing: [entry(ed, "Ed25519")], encryption: [entry(ed, "X25519")] }),
    );
    expect(r.success).toBe(false);
  });

  it("rejects an X25519 key in the signing slot", () => {
    const r = AgentCardSchema.safeParse(
      card({ signing: [entry(enc, "Ed25519")], encryption: [entry(enc, "X25519")] }),
    );
    expect(r.success).toBe(false);
  });

  it("rejects an undecodable key in the signing slot", () => {
    const r = AgentCardSchema.safeParse(
      card({ signing: [entry("zJUNK", "Ed25519")], encryption: [entry(enc, "X25519")] }),
    );
    expect(r.success).toBe(false);
  });

  it("rejects an undecodable key in the encryption slot", () => {
    const r = AgentCardSchema.safeParse(
      card({ signing: [entry(ed, "Ed25519")], encryption: [entry("zJUNK", "X25519")] }),
    );
    expect(r.success).toBe(false);
  });

  it("rejects an algorithm label that contradicts the slot", () => {
    const r = AgentCardSchema.safeParse(
      card({ signing: [entry(ed, "X25519")], encryption: [entry(enc, "X25519")] }),
    );
    expect(r.success).toBe(false);
  });

  it("still accepts a card with no keys block", () => {
    const { keys: _keys, ...noKeys } = card({});
    const r = AgentCardSchema.safeParse(noKeys);
    expect(r.success).toBe(true);
  });
});
