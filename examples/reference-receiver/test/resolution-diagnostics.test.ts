/**
 * Actionable rejection reasons for unresolvable senders.
 *
 * This receiver is a public test target, so a rejection is a support message.
 * `sender_key_unresolved` on its own does not tell an adopter whether their
 * DID document is missing, their card is at the wrong URL, or their card is
 * malformed. The resolver reports WHICH step failed and the worker hands that
 * back, without weakening the resolver: it still refuses to look at the
 * `/.well-known/ink/agent.json` alias, and it does not probe it to confirm a
 * diagnosis either (`specs/ink-resolver.md` §3.2 plus one fewer
 * attacker-triggerable outbound fetch on an unauthenticated path).
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import {
  resolveAgentCardForDidWebDetailed,
  CARD_RESOLUTION_HINTS,
} from "../src/did-web-resolver.js";
import {
  processInbound,
  resolveSenderKeysDetailed,
  senderKeyHint,
} from "../src/inbound.js";
import { InMemoryNonceStore } from "../src/nonce-store.js";
import { loadReceiverIdentity } from "../src/keys.js";
import worker from "../src/index.js";
import {
  generateKeypair,
  encodePublicKeyMultibase,
  base64urlEncode,
} from "@adastracomputing/ink";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

const RECEIVER_HOST = "receiver.example";
const RECEIVER_DID = `did:web:${RECEIVER_HOST}`;
const SENDER_HOST = "sender.example";
const SENDER_DID = `did:web:${SENDER_HOST}`;
const SENDER_DID_DOC = `https://${SENDER_HOST}/.well-known/did.json`;
const SENDER_CARD_URL =
  `https://${SENDER_HOST}/ink/v1/${encodeURIComponent(SENDER_DID)}/agent.json`;
const SENDER_ALIAS_URL = `https://${SENDER_HOST}/.well-known/ink/agent.json`;

const ctx = {
  waitUntil() { /* audit writes are fire-and-forget in tests */ },
  passThroughOnException() { /* not used */ },
} as unknown as ExecutionContext;

function memoryKv() {
  const store = new Map<string, string>();
  return {
    async get(key: string) { return store.get(key) ?? null; },
    async put(key: string, value: string) { store.set(key, String(value)); },
  };
}

async function makeReceiver() {
  const kp = await generateKeypair();
  const id = loadReceiverIdentity({
    INK_RECEIVER_SIGNING_SEED: base64urlEncode(kp.privateKey),
    INK_RECEIVER_PUBLIC_KEY_MULTIBASE: encodePublicKeyMultibase(kp.publicKey),
  });
  return { id, did: RECEIVER_DID };
}

async function senderCard(agentId = SENDER_DID) {
  const kp = await generateKeypair();
  const endpoint = `https://${SENDER_HOST}/ink/v1/inbound`;
  return {
    protocol: "ink/0.1",
    agentId,
    handle: SENDER_HOST,
    displayName: "Test Sender",
    endpoint,
    inboxEndpoint: endpoint,
    publicKeyMultibase: encodePublicKeyMultibase(kp.publicKey),
    capabilities: { intentsAccepted: ["ping"], intentsSent: ["ping"] },
    availability: { timezone: "UTC" },
  };
}

/** Serves only the URLs in `map`; every other URL 404s and is recorded. */
function trackingFetcher(map: Record<string, unknown>) {
  const requested: string[] = [];
  const fetcher = (async (url: string | URL) => {
    const u = String(url);
    requested.push(u);
    const value = map[u];
    if (value === undefined) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify(value), {
      status: 200, headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { fetcher, requested };
}

function pingEnvelope(to: string, from = SENDER_DID) {
  const createdAt = new Date().toISOString();
  return {
    protocol: "ink/0.1" as const,
    id: `msg-${crypto.randomUUID()}`,
    correlationId: `corr-${crypto.randomUUID()}`,
    createdAt,
    from,
    to,
    intent: "ping" as const,
    payload: {},
    signature: "A".repeat(86),
    timestamp: createdAt,
    nonce: crypto.randomUUID(),
  };
}

afterEach(() => { vi.restoreAllMocks(); });

describe("resolveAgentCardForDidWebDetailed", () => {
  it("names the alias-only case and still refuses to fetch the alias", async () => {
    const card = await senderCard();
    const { fetcher, requested } = trackingFetcher({
      [SENDER_DID_DOC]: { id: SENDER_DID, service: [] },
      // The peer publishes ONLY at the legacy alias.
      [SENDER_ALIAS_URL]: card,
    });
    const res = await resolveAgentCardForDidWebDetailed(SENDER_DID, { fetcher });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.reason).toBe("card_absent_from_discovery_path");
      // The hint has to actually name the alias, otherwise it is not a fix.
      expect(res.hint).toContain("/.well-known/ink/agent.json");
      expect(res.hint).toContain("/ink/v1/<agentId>/agent.json");
    }
    // No probe: the alias must not be requested even to confirm the diagnosis.
    expect(requested).not.toContain(SENDER_ALIAS_URL);
    expect(requested).toEqual([SENDER_DID_DOC, SENDER_CARD_URL]);
  });

  it("reports an unreachable DID document", async () => {
    const { fetcher, requested } = trackingFetcher({});
    const res = await resolveAgentCardForDidWebDetailed(SENDER_DID, { fetcher });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("did_document_unreachable");
    // Fails at step one: the card URL is never fetched.
    expect(requested).toEqual([SENDER_DID_DOC]);
  });

  it("reports a did:web identifier the SSRF guards refuse, with no fetch at all", async () => {
    const { fetcher, requested } = trackingFetcher({});
    const res = await resolveAgentCardForDidWebDetailed("did:web:localhost", { fetcher });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("did_unresolvable");
    expect(requested).toEqual([]);
  });

  it("distinguishes a declared service endpoint that serves nothing", async () => {
    const { fetcher } = trackingFetcher({
      [SENDER_DID_DOC]: {
        id: SENDER_DID,
        service: [{ type: "InkAgentCard", serviceEndpoint: `https://${SENDER_HOST}/cards/me.json` }],
      },
    });
    const res = await resolveAgentCardForDidWebDetailed(SENDER_DID, { fetcher });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("card_absent_from_service_endpoint");
  });

  it("reports a served document that is not a valid agent card", async () => {
    const { fetcher } = trackingFetcher({
      [SENDER_DID_DOC]: { id: SENDER_DID, service: [] },
      [SENDER_CARD_URL]: { protocol: "ink/0.1", agentId: SENDER_DID },
    });
    const res = await resolveAgentCardForDidWebDetailed(SENDER_DID, { fetcher });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("card_schema_invalid");
  });

  it("reports a card that binds to a different DID", async () => {
    const { fetcher } = trackingFetcher({
      [SENDER_DID_DOC]: { id: SENDER_DID, service: [] },
      [SENDER_CARD_URL]: await senderCard("did:web:someone-else.example"),
    });
    const res = await resolveAgentCardForDidWebDetailed(SENDER_DID, { fetcher });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("card_agent_id_mismatch");
  });

  it("still resolves a well-published peer", async () => {
    const card = await senderCard();
    const { fetcher } = trackingFetcher({
      [SENDER_DID_DOC]: { id: SENDER_DID, service: [] },
      [SENDER_CARD_URL]: card,
    });
    const res = await resolveAgentCardForDidWebDetailed(SENDER_DID, { fetcher });
    expect(res.ok).toBe(true);
  });

  it("gives every reason a non-empty hint", () => {
    for (const [reason, hint] of Object.entries(CARD_RESOLUTION_HINTS)) {
      expect(hint.length, reason).toBeGreaterThan(20);
    }
  });
});

describe("resolveSenderKeysDetailed", () => {
  it("reports an unsupported DID method", async () => {
    const out = await resolveSenderKeysDetailed("did:plc:abc123");
    expect(out.keys).toEqual([]);
    expect(out.reason).toBe("unsupported_did_method");
    expect(senderKeyHint("unsupported_did_method")).toContain("did:key");
  });

  it("reports an undecodable did:key", async () => {
    const out = await resolveSenderKeysDetailed("did:key:znotvalidbase58!!!");
    expect(out.reason).toBe("did_key_undecodable");
  });

  it("carries the resolver's reason through for did:web", async () => {
    const { fetcher } = trackingFetcher({
      [SENDER_DID_DOC]: { id: SENDER_DID, service: [] },
      [SENDER_ALIAS_URL]: await senderCard(),
    });
    const out = await resolveSenderKeysDetailed(SENDER_DID, { fetcher });
    expect(out.reason).toBe("card_absent_from_discovery_path");
  });

  it("reports no reason on success", async () => {
    const { fetcher } = trackingFetcher({
      [SENDER_DID_DOC]: { id: SENDER_DID, service: [] },
      [SENDER_CARD_URL]: await senderCard(),
    });
    const out = await resolveSenderKeysDetailed(SENDER_DID, { fetcher });
    expect(out.keys.length).toBeGreaterThan(0);
    expect(out.reason).toBeUndefined();
  });
});

describe("processInbound rejection carries the reason", () => {
  it("explains an alias-only sender without changing the verdict", async () => {
    const { id, did } = await makeReceiver();
    const { fetcher } = trackingFetcher({
      [SENDER_DID_DOC]: { id: SENDER_DID, service: [] },
      [SENDER_ALIAS_URL]: await senderCard(),
    });
    const out = await processInbound(
      enc(JSON.stringify(pingEnvelope(did))),
      "INK-Ed25519 " + "A".repeat(86),
      { identity: id, receiverDid: did, fetcher, nonceStore: new InMemoryNonceStore() },
    );
    expect(out.kind).toBe("rejected");
    if (out.kind === "rejected") {
      // Unchanged: the outcome is still a signature rejection with the same
      // errorCode. Only the explanation is new.
      expect(out.verdict).toBe("signature");
      expect(out.errorCode).toBe("sender_key_unresolved");
      expect(out.reason).toBe("card_absent_from_discovery_path");
      expect(out.hint).toContain("/.well-known/ink/agent.json");
    }
  });
});

describe("worker surfaces the reason on /ink/v1/inbound", () => {
  it("returns reason + hint in the 400 body and logs one structured line", async () => {
    const kp = await generateKeypair();
    const env = {
      INK_RECEIVER_SIGNING_SEED: base64urlEncode(kp.privateKey),
      INK_RECEIVER_PUBLIC_KEY_MULTIBASE: encodePublicKeyMultibase(kp.publicKey),
      INK_RECEIVER_HOST: RECEIVER_HOST,
      INK_RECEIVER: memoryKv(),
    };
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    // The worker's inbound path resolves the sender over the real `fetch`, so
    // point the envelope at a DID whose host is refused by the SSRF guards:
    // no network, and a reason the sender can act on.
    const envelope = pingEnvelope(RECEIVER_DID, "did:web:127.0.0.1");
    const res = await worker.fetch(
      new Request(`https://${RECEIVER_HOST}/ink/v1/inbound`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "INK-Ed25519 " + "A".repeat(86) },
        body: JSON.stringify(envelope),
      }),
      env as never,
      ctx,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { code: string; reason: string; hint: string };
    expect(body.code).toBe("sender_key_unresolved");
    expect(body.reason).toBe("did_unresolvable");
    expect(body.hint.length).toBeGreaterThan(20);
    expect(warn).toHaveBeenCalledTimes(1);
    const logged = JSON.parse(warn.mock.calls[0]![0] as string) as Record<string, string>;
    expect(logged.event).toBe("sender_key_unresolved");
    expect(logged.reason).toBe("did_unresolvable");
    expect(logged.sender).toBe("did:web:127.0.0.1");
  });

  it("adds no reason field to rejections that are not resolution failures", async () => {
    const kp = await generateKeypair();
    const env = {
      INK_RECEIVER_SIGNING_SEED: base64urlEncode(kp.privateKey),
      INK_RECEIVER_PUBLIC_KEY_MULTIBASE: encodePublicKeyMultibase(kp.publicKey),
      INK_RECEIVER_HOST: RECEIVER_HOST,
      INK_RECEIVER: memoryKv(),
    };
    const res = await worker.fetch(
      new Request(`https://${RECEIVER_HOST}/ink/v1/inbound`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{not json",
      }),
      env as never,
      ctx,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect(body.reason).toBeUndefined();
    expect(body.hint).toBeUndefined();
  });
});
