import { describe, it, expect } from "vitest";
import * as ed25519 from "@noble/ed25519";
import { AgentCardSchema } from "../src/models/agent-card.js";
import { generateKeypair, encodePublicKeyMultibase, deriveAgentId } from "../src/crypto/keys.js";
import { buildAttestation } from "../src/models/attestation.js";
import { signAgentCard, verifyAgentCardSignature } from "../src/crypto/agent-card-signature.js";
import { evaluateAgentCardFetch } from "../src/discovery/agent-card-fetch.js";

const ed = encodePublicKeyMultibase(new Uint8Array(32).fill(3));

function baseCard(extra: Record<string, unknown> = {}) {
  return {
    protocol: "ink/0.1",
    agentId: "did:web:a.example",
    handle: "alice",
    displayName: "Alice",
    endpoint: "https://a.example/ink/inbox",
    publicKeyMultibase: ed,
    capabilities: { intentsAccepted: ["ping"], intentsSent: ["ask"] },
    availability: { timezone: "UTC" },
    ...extra,
  };
}

async function someAttestation() {
  const kp = await generateKeypair();
  return buildAttestation(
    {
      issuer: "did:web:issuer.example",
      subject: "did:web:a.example",
      claimType: "example.owner.verified_human",
      claim: {},
      attestationId: "att-0123456789abcdef",
      issuedAt: "2026-08-01T00:00:00.000Z",
      expiresAt: "2027-08-01T00:00:00.000Z",
    },
    kp.privateKey,
  );
}

describe("card evidence members", () => {
  it("accepts a card carrying a valid attestations array", async () => {
    const att = await someAttestation();
    const r = AgentCardSchema.safeParse(baseCard({ attestations: [att] }));
    expect(r.success).toBe(true);
    if (r.success) expect((r.data as Record<string, unknown>).attestations).toHaveLength(1);
  });

  it("rejects an empty or oversized attestations array", async () => {
    const att = await someAttestation();
    expect(AgentCardSchema.safeParse(baseCard({ attestations: [] })).success).toBe(false);
    expect(
      AgentCardSchema.safeParse(baseCard({ attestations: Array(17).fill(att) })).success,
    ).toBe(false);
  });

  it("rejects an attestations entry that is not a well-formed attestation", () => {
    const r = AgentCardSchema.safeParse(baseCard({ attestations: [{ type: "wrong" }] }));
    expect(r.success).toBe(false);
  });

  it("accepts an evidencePolicy with required and preferred sets", () => {
    const r = AgentCardSchema.safeParse(
      baseCard({
        evidencePolicy: {
          required: ["example.owner.verified_human"],
          preferred: ["example.org.member"],
        },
      }),
    );
    expect(r.success).toBe(true);
  });

  it("rejects duplicate claim types in a policy array", () => {
    const r = AgentCardSchema.safeParse(
      baseCard({
        evidencePolicy: { required: ["example.a.b", "example.a.b"] },
      }),
    );
    expect(r.success).toBe(false);
  });

  it("rejects out-of-grammar claim types in a policy array", () => {
    const r = AgentCardSchema.safeParse(
      baseCard({ evidencePolicy: { required: ["NotLower.case"] } }),
    );
    expect(r.success).toBe(false);
  });

  it("keeps unknown members inside evidencePolicy for the proof", () => {
    const r = AgentCardSchema.safeParse(
      baseCard({ evidencePolicy: { required: ["example.a.b"], futureKnob: true } }),
    );
    expect(r.success).toBe(true);
    if (r.success) {
      const policy = (r.data as Record<string, unknown>).evidencePolicy as Record<string, unknown>;
      expect(policy.futureKnob).toBe(true);
    }
  });
});

describe("unknown members survive parsing for proof verification", () => {
  it("preserves an unknown top-level member through the schema", () => {
    const r = AgentCardSchema.safeParse(baseCard({ futureMember: { a: 1 } }));
    expect(r.success).toBe(true);
    if (r.success) expect((r.data as Record<string, unknown>).futureMember).toEqual({ a: 1 });
  });

  it("verifies a signed card carrying evidence members after the fetch contract", async () => {
    const priv = new Uint8Array(32).fill(9);
    const pub = await ed25519.getPublicKeyAsync(priv);
    const agentId = deriveAgentId(pub);
    const att = await someAttestation();
    const unsigned = {
      ...baseCard({
        agentId,
        publicKeyMultibase: encodePublicKeyMultibase(pub),
        attestations: [att],
        evidencePolicy: { required: ["example.owner.verified_human"] },
      }),
      keys: {
        signing: [
          {
            keyId: "g1",
            algorithm: "Ed25519",
            publicKeyMultibase: encodePublicKeyMultibase(pub),
            status: "active",
            validFrom: "2026-01-01T00:00:00Z",
          },
        ],
        encryption: [],
      },
      currentSigningKeyId: "g1",
      keySetVersion: 1,
    };
    const signature = await signAgentCard(unsigned as Record<string, unknown>, priv);
    const served = { ...unsigned, cardSignature: { keyId: "g1", signature } };

    const fetched = evaluateAgentCardFetch({
      status: 200,
      contentLength: null,
      contentType: "application/json",
      bodyRaw: JSON.stringify(served),
      requestedAgentId: agentId,
      resolutionDid: null,
    });
    expect(fetched.accepted).toBe(true);
    if (!fetched.accepted || fetched.card === null) return;

    const verdict = await verifyAgentCardSignature(fetched.card, agentId, { profile: "1.0" });
    expect(verdict.authenticated).toBe(true);
    expect(verdict.reason).toBe("signed_authenticated");
  });
});
