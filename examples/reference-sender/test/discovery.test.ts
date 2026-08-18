import { describe, it, expect } from "vitest";
import { generateKeypair, encodePublicKeyMultibase } from "@adastracomputing/ink";
import { resolveInboxEndpoint, didWebTargets } from "../src/discovery.ts";

const cardPath = (did: string) => `/ink/v1/${encodeURIComponent(did)}/agent.json`;

describe("didWebTargets", () => {
  // The versioned path is the sole normative discovery surface
  // (specs/ink-resolver.md §3.2). No /.well-known/ink/agent.json alias URL is
  // derived, so a peer publishing only the alias is not discoverable here.
  it("derives the versioned card URL for a host-only did:web", () => {
    const t = didWebTargets("did:web:r.example");
    expect(t!.host).toBe("r.example");
    expect(t!.didDocUrl).toBe("https://r.example/.well-known/did.json");
    expect(t!.versionedCardUrl).toBe(
      `https://r.example${cardPath("did:web:r.example")}`,
    );
  });

  it("derives the path-form DID document URL, card still at the versioned path", () => {
    const did = "did:web:r.example:agents:bot";
    const t = didWebTargets(did);
    expect(t!.didDocUrl).toBe("https://r.example/agents/bot/did.json");
    expect(t!.versionedCardUrl).toBe(`https://r.example${cardPath(did)}`);
  });

  it("returns null for non-did:web", () => {
    expect(didWebTargets("did:key:z6Mk")).toBeNull();
  });

  // Ruling 4: a %3A port is carried, never dropped. Resolving at the default
  // port would silently target a different origin than the identifier names.
  it("carries a %3A port into every derived URL", () => {
    const did = "did:web:r.example%3A8443";
    const t = didWebTargets(did);
    expect(t!.host).toBe("r.example:8443");
    expect(t!.didDocUrl).toBe("https://r.example:8443/.well-known/did.json");
    expect(t!.versionedCardUrl).toBe(`https://r.example:8443${cardPath(did)}`);
  });

  // The W3C did:web method allows an optional percent-encoded port and bans no
  // value, so %3A443 is legal and refusing it would be an interop bug. It names
  // the default https origin, which is where it resolves. The sign-in profile's
  // extra ban on an explicit 443 is profile-local (`deriveRpOrigin`).
  it("accepts an explicit 443 and resolves it at the default origin", () => {
    const did = "did:web:r.example%3A443";
    const t = didWebTargets(did);
    expect(t!.host).toBe("r.example");
    expect(t!.didDocUrl).toBe("https://r.example/.well-known/did.json");
    expect(t!.versionedCardUrl).toBe(`https://r.example${cardPath(did)}`);
  });

  it("rejects rather than drops a port it cannot carry", () => {
    expect(didWebTargets("did:web:r.example%3A")).toBeNull();
    expect(didWebTargets("did:web:r.example%3Aabc")).toBeNull();
    expect(didWebTargets("did:web:r.example%3A0")).toBeNull();
    expect(didWebTargets("did:web:r.example%3A08443")).toBeNull();
    expect(didWebTargets("did:web:r.example%3A65536")).toBeNull();
    expect(didWebTargets("did:web:r.example%3A8443%3A9")).toBeNull();
    expect(didWebTargets("did:web:r.example%3a8443")).toBeNull();
    expect(didWebTargets("did:web:r.example%3A8443:.")).toBeNull();
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

  // --- discovery path: versioned only, DID-document service entry honoured ---

  const DID = "did:web:card.example";
  const VERSIONED = `https://card.example${cardPath(DID)}`;
  const WELL_KNOWN = "https://card.example/.well-known/ink/agent.json";
  const DID_DOC = "https://card.example/.well-known/did.json";

  async function buildCard() {
    const kp = await generateKeypair();
    const endpoint = "https://card.example/ink/v1/inbound";
    return {
      protocol: "ink/0.1",
      agentId: DID,
      handle: "card.example",
      displayName: "Card Example",
      endpoint,
      inboxEndpoint: endpoint,
      publicKeyMultibase: encodePublicKeyMultibase(kp.publicKey),
      capabilities: { intentsAccepted: ["ping"], intentsSent: [] },
      availability: { timezone: "UTC" },
    };
  }

  function router(routes: Record<string, unknown>, seen?: string[]) {
    return (async (url: string | URL) => {
      const u = String(url);
      seen?.push(u);
      if (u in routes) {
        return new Response(JSON.stringify(routes[u]), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("not found", { status: 404 });
    }) as typeof fetch;
  }

  it("fetches the versioned discovery path when the DID document names no service", async () => {
    const card = await buildCard();
    const seen: string[] = [];
    const r = await resolveInboxEndpoint({
      recipientDid: DID,
      fetchImpl: router({ [DID_DOC]: { id: DID, service: [] }, [VERSIONED]: card }, seen),
      allowPrivateHosts: true,
    });
    expect(r).toEqual({ ok: true, endpoint: "https://card.example/ink/v1/inbound", source: "did-web-card" });
    expect(seen).toContain(VERSIONED);
  });

  // ink-resolver.md §3.2: a resolver MUST NOT depend on the /.well-known alias
  // or fall back to it. A peer serving only the alias is not discoverable, and
  // the alias is never even requested.
  it("does not discover a peer that serves only the well-known alias", async () => {
    const card = await buildCard();
    const seen: string[] = [];
    const r = await resolveInboxEndpoint({
      recipientDid: DID,
      fetchImpl: router({ [DID_DOC]: { id: DID, service: [] }, [WELL_KNOWN]: card }, seen),
      allowPrivateHosts: true,
    });
    expect(r).toEqual({ ok: false, reason: "card_rejected" });
    expect(seen).not.toContain(WELL_KNOWN);
  });

  it("honours an InkAgentCard service entry on the DID's own authority", async () => {
    const card = await buildCard();
    const custom = "https://card.example/custom/agent.json";
    const seen: string[] = [];
    const r = await resolveInboxEndpoint({
      recipientDid: DID,
      fetchImpl: router({
        [DID_DOC]: { id: DID, service: [{ type: "InkAgentCard", serviceEndpoint: custom }] },
        [custom]: card,
      }, seen),
      allowPrivateHosts: true,
    });
    expect(r.ok).toBe(true);
    expect(seen).toContain(custom);
    expect(seen).not.toContain(VERSIONED);
  });

  it("ignores a service entry that points at another authority or downgrades to http", async () => {
    const card = await buildCard();
    for (const bad of ["https://attacker.example/agent.json", "http://card.example/agent.json"]) {
      const seen: string[] = [];
      const r = await resolveInboxEndpoint({
        recipientDid: DID,
        fetchImpl: router({
          [DID_DOC]: { id: DID, service: [{ type: "InkAgentCard", serviceEndpoint: bad }] },
          [VERSIONED]: card,
        }, seen),
        allowPrivateHosts: true,
      });
      expect(r.ok).toBe(true);
      expect(seen).not.toContain(bad);
    }
  });

  it("still resolves when the DID document is unreachable", async () => {
    const card = await buildCard();
    const r = await resolveInboxEndpoint({
      recipientDid: DID,
      fetchImpl: router({ [VERSIONED]: card }),
      allowPrivateHosts: true,
    });
    expect(r.ok).toBe(true);
  });

  it("discovers a peer whose did:web names a non-default port", async () => {
    const kp = await generateKeypair();
    const did = "did:web:card.example%3A8443";
    const endpoint = "https://card.example:8443/ink/v1/inbound";
    const card = {
      protocol: "ink/0.1",
      agentId: did,
      handle: "card.example",
      displayName: "Card Example",
      endpoint,
      inboxEndpoint: endpoint,
      publicKeyMultibase: encodePublicKeyMultibase(kp.publicKey),
      capabilities: { intentsAccepted: ["ping"], intentsSent: [] },
      availability: { timezone: "UTC" },
    };
    const r = await resolveInboxEndpoint({
      recipientDid: did,
      fetchImpl: router({ [`https://card.example:8443${cardPath(did)}`]: card }),
      allowPrivateHosts: true,
    });
    expect(r).toEqual({ ok: true, endpoint, source: "did-web-card" });
  });
});
