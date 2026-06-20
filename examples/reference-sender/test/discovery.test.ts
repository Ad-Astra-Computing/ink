import { describe, it, expect } from "vitest";
import { generateKeypair, encodePublicKeyMultibase } from "@adastracomputing/ink";
import { resolveInboxEndpoint, didWebCardUrl } from "../src/discovery.ts";

describe("didWebCardUrl", () => {
  it("derives the well-known card URL for a host-only did:web", () => {
    expect(didWebCardUrl("did:web:r.example")).toBe(
      "https://r.example/.well-known/ink/agent.json",
    );
  });
  it("derives a path-form card URL for a multi-segment did:web", () => {
    expect(didWebCardUrl("did:web:r.example:agents:bot")).toBe(
      "https://r.example/agents/bot/ink/agent.json",
    );
  });
  it("returns null for non-did:web", () => {
    expect(didWebCardUrl("did:key:z6Mk")).toBeNull();
  });
  it("rejects a port-bearing did:web so discovery and delivery stay aligned", () => {
    expect(didWebCardUrl("did:web:example.com%3A8443")).toBeNull();
  });
});

describe("resolveInboxEndpoint", () => {
  it("uses an explicit endpoint when provided", async () => {
    const r = await resolveInboxEndpoint({
      recipientDid: "did:key:z6Mkwhatever",
      explicitEndpoint: "https://host.example/ink/v1/inbound",
    });
    expect(r).toEqual({ ok: true, endpoint: "https://host.example/ink/v1/inbound", source: "explicit" });
  });

  it("requires an explicit endpoint for did:key", async () => {
    const r = await resolveInboxEndpoint({ recipientDid: "did:key:z6Mkwhatever" });
    expect(r).toEqual({ ok: false, reason: "endpoint_required_for_did_key" });
  });

  it("rejects unsupported DID methods", async () => {
    const r = await resolveInboxEndpoint({ recipientDid: "did:example:123" });
    expect(r).toEqual({ ok: false, reason: "unsupported_did_method" });
  });

  it("resolves a did:web inbox from a fetched Agent Card", async () => {
    const kp = await generateKeypair();
    const did = "did:web:card.example";
    const endpoint = "https://card.example/ink/v1/inbound";
    const card = {
      protocol: "ink/0.1",
      supportedProtocolVersions: ["ink/0.1", "ink/0.2"],
      agentId: did,
      handle: "card.example",
      displayName: "Card Example",
      endpoint,
      inboxEndpoint: endpoint,
      publicKeyMultibase: encodePublicKeyMultibase(kp.publicKey),
      capabilities: {
        intentsAccepted: ["ping"],
        intentsSent: [],
        receipts: { send: false, dispositions: [] },
      },
      availability: { timezone: "UTC", responseSla: "best_effort" },
    };
    const fetchImpl = (async () =>
      new Response(JSON.stringify(card), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })) as typeof fetch;

    const r = await resolveInboxEndpoint({ recipientDid: did, fetchImpl, allowPrivateHosts: true });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.endpoint).toBe("https://card.example/ink/v1/inbound");
      expect(r.source).toBe("did-web-card");
    }
  });
});
