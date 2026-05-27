/**
 * Security regression tests — round 16.
 *
 * Findings (Codex final pass, 2026-05):
 *   1. verifyMessage() in sign.ts canonicalized attacker-controlled
 *      objects before any complexity cap. The sibling guard added to
 *      ink.ts in round 14 was never propagated.
 *   2. validity-window fields on CandidateKey (validFrom/validUntil/
 *      revokedAt) were checked via truthiness, so an empty string
 *      bypassed the check entirely. extractCandidateKeys now coerces
 *      empty strings to undefined at the boundary.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { signMessage, verifyMessage } from "../src/crypto/sign.js";
import { extractCandidateKeys } from "../src/discovery/agent-card.js";
import { encodePublicKeyMultibase } from "../src/crypto/keys.js";
import type { AgentCard } from "../src/models/agent-card.js";

async function makeKey() {
  const { secretKey: priv, publicKey: pub } = await ed.keygenAsync();
  return { priv, pub };
}

describe("sign.ts: pre-canonicalize bounds in verifyMessage and signMessage", () => {
  it("verifyMessage returns false on huge bodies without canonicalizing them", async () => {
    const key = await makeKey();
    const huge: Record<string, string> = {};
    for (let i = 0; i < 20_000; i++) huge[`k${i}`] = "v";
    const message = { ...huge, signature: "A".repeat(86) };
    const ok = await verifyMessage(message, key.pub);
    expect(ok).toBe(false);
  });

  it("verifyMessage returns false on excessively-deep bodies", async () => {
    const key = await makeKey();
    let cur: Record<string, unknown> = {};
    const root = cur;
    for (let i = 0; i < 200; i++) {
      const next: Record<string, unknown> = {};
      cur.next = next;
      cur = next;
    }
    const message = { ...root, signature: "A".repeat(86) };
    const ok = await verifyMessage(message, key.pub);
    expect(ok).toBe(false);
  });

  it("signMessage rejects oversize input rather than minting an over-cap signature", async () => {
    const key = await makeKey();
    const huge: Record<string, string> = {};
    for (let i = 0; i < 20_000; i++) huge[`k${i}`] = "v";
    await expect(signMessage(huge, key.priv)).rejects.toThrow();
  });

  it("still round-trips a normal message", async () => {
    const key = await makeKey();
    const msg = { hello: "world", n: 42, nested: { ok: true } };
    const sig = await signMessage(msg, key.priv);
    expect(await verifyMessage({ ...msg, signature: sig }, key.pub)).toBe(true);
  });
});

describe("extractCandidateKeys: empty-string window fields are coerced to undefined", () => {
  function makeCard(
    pubKeyMultibase: string,
    entry: Record<string, unknown>,
  ): AgentCard {
    return {
      protocol: "ink/0.1",
      agentId: "tulpa:test",
      handle: "test",
      displayName: "Test",
      endpoint: "https://example.com",
      publicKeyMultibase: pubKeyMultibase,
      capabilities: { intentsAccepted: [], intentsSent: [] },
      availability: { timezone: "UTC" },
      keys: {
        signing: [entry],
        encryption: [],
      },
    } as unknown as AgentCard;
  }

  it("rejects entries with empty-string window fields entirely (round 18 hardening)", async () => {
    const key = await makeKey();
    const mb = encodePublicKeyMultibase(key.pub);
    const card = makeCard(mb, {
      keyId: "k1",
      publicKeyMultibase: mb,
      status: "active",
      validFrom: "",
      validUntil: "",
      revokedAt: "",
    });
    // Round 18 tightened extractCandidateKeys: any present-but-malformed
    // window field skips the WHOLE entry, not just the field. An empty
    // string is suspicious enough to discard the whole key.
    const out = extractCandidateKeys(card);
    expect(out.length).toBe(0);
  });

  it("preserves real ISO timestamps in window fields", async () => {
    const key = await makeKey();
    const mb = encodePublicKeyMultibase(key.pub);
    const card = makeCard(mb, {
      keyId: "k1",
      publicKeyMultibase: mb,
      status: "active",
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2026-12-31T23:59:59Z",
    });
    const out = extractCandidateKeys(card);
    expect(out.length).toBe(1);
    expect(out[0]!.validFrom).toBe("2026-01-01T00:00:00Z");
    expect(out[0]!.validUntil).toBe("2026-12-31T23:59:59Z");
  });

  it("rejects entries with non-string window values (round 18 hardening)", async () => {
    const key = await makeKey();
    const mb = encodePublicKeyMultibase(key.pub);
    const card = makeCard(mb, {
      keyId: "k1",
      publicKeyMultibase: mb,
      status: "active",
      validFrom: 1234,
      validUntil: null,
      revokedAt: {},
    });
    // Non-string window values look like a deserialisation bug or a
    // poisoned card. The whole entry is dropped.
    const out = extractCandidateKeys(card);
    expect(out.length).toBe(0);
  });
});
