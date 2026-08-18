import { describe, it, expect } from "vitest";
import {
  buildAgentCard,
  resolveCardUpdatedAt,
  DEFAULT_CARD_UPDATED_AT,
  SUPPORTED_INTENTS,
} from "../src/agent-card.js";
import { buildDidDocument } from "../src/did-web.js";
import { loadReceiverIdentity } from "../src/keys.js";
import {
  generateKeypair,
  encodePublicKeyMultibase,
  base64urlEncode,
  AgentCardSchema,
  verifyAgentCardSignature,
  isInkTimestamp,
  type AgentCard,
} from "@adastracomputing/ink";

const UPDATED_AT = "2026-01-01T00:00:00Z";

async function freshIdentity() {
  const kp = await generateKeypair();
  return loadReceiverIdentity({
    INK_RECEIVER_SIGNING_SEED: base64urlEncode(kp.privateKey),
    INK_RECEIVER_PUBLIC_KEY_MULTIBASE: encodePublicKeyMultibase(kp.publicKey),
  });
}

describe("buildAgentCard", () => {
  it("returns a card that parses cleanly against AgentCardSchema", async () => {
    const id = await freshIdentity();
    const card = await buildAgentCard({ did: "did:web:r.example", host: "r.example", identity: id, updatedAt: UPDATED_AT });
    const parsed = AgentCardSchema.safeParse(card);
    expect(parsed.success).toBe(true);
  });

  it("announces only the supported intents", async () => {
    const id = await freshIdentity();
    const card = await buildAgentCard({ did: "did:web:r.example", host: "r.example", identity: id, updatedAt: UPDATED_AT }) as {
      capabilities: { intentsAccepted: string[] };
    };
    expect(card.capabilities.intentsAccepted.sort()).toEqual([...SUPPORTED_INTENTS].sort());
  });

  it("uses the configured host for the endpoint URL", async () => {
    const id = await freshIdentity();
    const card = await buildAgentCard({ did: "did:web:r.example", host: "r.example", identity: id, updatedAt: UPDATED_AT }) as {
      endpoint: string; inboxEndpoint: string;
    };
    expect(card.endpoint).toBe("https://r.example/ink/v1/inbound");
    expect(card.inboxEndpoint).toBe(card.endpoint);
  });

  it("signs the card (Phase B) so it verifies as authenticated when anchored", async () => {
    const id = await freshIdentity();
    const card = await buildAgentCard({ did: "did:web:r.example", host: "r.example", identity: id, updatedAt: UPDATED_AT }) as AgentCard & {
      cardSignature?: { keyId: string; signature: string };
    };
    // Legacy single-key card: signer keyId is the literal `bootstrap` (§3.3).
    expect(card.cardSignature?.keyId).toBe("bootstrap");
    expect(card.cardSignature?.signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
    // A did:web card roots on its DID-document key; supply the anchor the
    // receiver publishes at /.well-known/did.json.
    const result = await verifyAgentCardSignature(card, "did:web:r.example", {
      profile: "pre-1.0",
      didVerificationKeys: [id.publicKeyMultibase],
    });
    expect(result.authenticated).toBe(true);
    expect(result.rejected).toBe(false);
  });

  it("produces a signature over the served body (tamper is rejected)", async () => {
    const id = await freshIdentity();
    const card = await buildAgentCard({ did: "did:web:r.example", host: "r.example", identity: id, updatedAt: UPDATED_AT }) as AgentCard;
    const tampered = { ...card, endpoint: "https://evil.example/ink/v1/inbound" } as AgentCard;
    const result = await verifyAgentCardSignature(tampered, "did:web:r.example", {
      profile: "pre-1.0",
      didVerificationKeys: [id.publicKeyMultibase],
    });
    expect(result.authenticated).toBe(false);
    expect(result.reason).toBe("invalid_signature");
  });
});

describe("resolveCardUpdatedAt", () => {
  it("falls back to the source default when the var is unset or blank", () => {
    expect(resolveCardUpdatedAt({})).toBe(DEFAULT_CARD_UPDATED_AT);
    expect(resolveCardUpdatedAt({ INK_RECEIVER_CARD_UPDATED_AT: "   " })).toBe(DEFAULT_CARD_UPDATED_AT);
  });

  it("ships a default that is itself a valid strict RFC 3339 timestamp", () => {
    expect(isInkTimestamp(DEFAULT_CARD_UPDATED_AT)).toBe(true);
  });

  it("uses the configured override", () => {
    expect(resolveCardUpdatedAt({ INK_RECEIVER_CARD_UPDATED_AT: " 2030-05-06T07:08:09Z " }))
      .toBe("2030-05-06T07:08:09Z");
  });

  it("rejects a value that is not a strict RFC 3339 timestamp", () => {
    // A loose spelling the Date constructor would happily accept. It must fail
    // loudly at load, naming the var, rather than surfacing as a card-invalid
    // 500 with a schema issue dump.
    expect(() => resolveCardUpdatedAt({ INK_RECEIVER_CARD_UPDATED_AT: "2026-08-18" }))
      .toThrow(/invalid_card_updated_at/);
    expect(() => resolveCardUpdatedAt({ INK_RECEIVER_CARD_UPDATED_AT: "not a date" }))
      .toThrow(/invalid_card_updated_at/);
  });

  it("puts the resolved value on the card verbatim", async () => {
    const id = await freshIdentity();
    const card = await buildAgentCard({
      did: "did:web:r.example", host: "r.example", identity: id, updatedAt: UPDATED_AT,
    }) as AgentCard;
    expect(card.updatedAt).toBe(UPDATED_AT);
  });
});

describe("buildDidDocument", () => {
  it("includes the verification method and service entries", async () => {
    const id = await freshIdentity();
    const doc = buildDidDocument({ did: "did:web:r.example", host: "r.example", identity: id }) as {
      id: string;
      verificationMethod: Array<{ id: string; type: string; publicKeyMultibase: string }>;
      service: Array<{ id: string; type: string; serviceEndpoint: string }>;
    };
    expect(doc.id).toBe("did:web:r.example");
    expect(doc.verificationMethod[0]!.type).toBe("Ed25519VerificationKey2020");
    expect(doc.verificationMethod[0]!.publicKeyMultibase).toBe(id.publicKeyMultibase);
    const services = doc.service.map((s) => s.type);
    expect(services).toContain("InkAgentEndpoint");
    expect(services).toContain("InkAgentCard");
  });
});
