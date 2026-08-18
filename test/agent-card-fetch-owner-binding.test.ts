/**
 * Owner anti-substitution: step 9 of the Agent Card discovery fetch contract
 * (specs/ink-agent-card-discovery-fetch.md).
 *
 * A host that legitimately publishes a card for one DID must not be able to
 * serve that card in answer to resolution of another. When the fetch was
 * reached through a DID document the caller names the DID under resolution,
 * and a card carrying an `ownerDid` must name the same one, byte for byte.
 *
 * The step is deliberately narrow: it is NOT owner authentication (`ownerDid`
 * is self-asserted), and both "card carries no ownerDid" and "fetch names no
 * DID" pass unchanged.
 */

import { describe, it, expect } from "vitest";
import { evaluateAgentCardFetch, fetchAgentCard } from "../src/index.js";

const AGENT_ID = "did:web:a.example";
const OWNER_DID = "did:web:owner.example";

function card(extra: Record<string, unknown> = {}) {
  return {
    protocol: "ink/0.1",
    agentId: AGENT_ID,
    handle: "alice",
    displayName: "Alice",
    endpoint: "https://a.example/ink/inbox",
    publicKeyMultibase: "z6MkgosDnsjFCTf73Ms7S4Nzwe78GD7Bzn94hTU462M4GirX",
    capabilities: { intentsAccepted: ["ask"], intentsSent: ["ask"] },
    availability: { timezone: "UTC" },
    ...extra,
  };
}

function evaluate(body: unknown, resolutionDid?: string | null) {
  return evaluateAgentCardFetch({
    status: 200,
    contentType: "application/json",
    contentLength: null,
    bodyRaw: JSON.stringify(body),
    requestedAgentId: AGENT_ID,
    resolutionDid: resolutionDid ?? null,
  });
}

describe("evaluateAgentCardFetch step 9: owner anti-substitution", () => {
  it("rejects a DID-mediated fetch whose card names a different ownerDid", () => {
    const r = evaluate(card({ ownerDid: OWNER_DID }), "did:web:someone-else.example");
    expect(r.accepted).toBe(false);
    expect(r.card).toBeNull();
  });

  it("accepts when the card's ownerDid equals the DID under resolution", () => {
    const r = evaluate(card({ ownerDid: OWNER_DID }), OWNER_DID);
    expect(r.accepted).toBe(true);
    expect(r.card?.ownerDid).toBe(OWNER_DID);
  });

  it("compares byte for byte, with no case folding", () => {
    expect(evaluate(card({ ownerDid: OWNER_DID }), "did:web:Owner.example").accepted).toBe(false);
  });

  it("accepts a card that carries no ownerDid under a DID-mediated fetch", () => {
    expect(evaluate(card(), OWNER_DID).accepted).toBe(true);
  });

  it("accepts a card carrying an ownerDid when the fetch names no DID", () => {
    expect(evaluate(card({ ownerDid: OWNER_DID }), null).accepted).toBe(true);
    // An absent field behaves identically to an explicit null.
    expect(evaluateAgentCardFetch({
      status: 200,
      contentType: "application/json",
      contentLength: null,
      bodyRaw: JSON.stringify(card({ ownerDid: OWNER_DID })),
      requestedAgentId: AGENT_ID,
    }).accepted).toBe(true);
  });

  it("runs after identity binding: a mismatched agentId still rejects first", () => {
    const r = evaluateAgentCardFetch({
      status: 200,
      contentType: "application/json",
      contentLength: null,
      bodyRaw: JSON.stringify(card({ agentId: "did:web:other.example", ownerDid: OWNER_DID })),
      requestedAgentId: AGENT_ID,
      resolutionDid: OWNER_DID,
    });
    expect(r.accepted).toBe(false);
  });
});

describe("fetchAgentCard threads resolutionDid into the contract", () => {
  const serve = (body: unknown): typeof fetch =>
    (async () => new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })) as unknown as typeof fetch;

  it("refuses a card whose ownerDid is not the DID under resolution", async () => {
    const got = await fetchAgentCard(AGENT_ID, "https://a.example", {
      fetch: serve(card({ ownerDid: OWNER_DID })),
      resolutionDid: "did:web:someone-else.example",
    });
    expect(got).toBeNull();
  });

  it("returns the card when the ownerDid matches", async () => {
    const got = await fetchAgentCard(AGENT_ID, "https://a.example", {
      fetch: serve(card({ ownerDid: OWNER_DID })),
      resolutionDid: OWNER_DID,
    });
    expect(got?.ownerDid).toBe(OWNER_DID);
  });

  it("leaves a fetch that names no DID unchanged", async () => {
    const got = await fetchAgentCard(AGENT_ID, "https://a.example", {
      fetch: serve(card({ ownerDid: OWNER_DID })),
    });
    expect(got?.agentId).toBe(AGENT_ID);
  });
});
