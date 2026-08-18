/**
 * Discovery round trip: the reference library resolves the reference
 * receiver's card.
 *
 * `fetchAgentCard` builds `GET <base>/ink/v1/<agentId>/agent.json`. Until the
 * worker served that path there was no way for the library to fetch this
 * receiver's card at all — the two halves of the reference implementation
 * could not talk to each other about discovery. These tests hold the round
 * trip closed, and hold the well-known path as a byte-identical alias.
 *
 * The alias assertion here shares one warm process, so on its own it proves
 * only that the two routes agree within a process. What makes the claim true
 * in a multi-isolate deployment is that the card build is deterministic;
 * `card-determinism.test.ts` is what proves that, including across processes.
 */

import { describe, it, expect, beforeAll } from "vitest";
import worker, { matchVersionedCardPath } from "../src/index.js";
import { resolveAgentCardForDidWeb } from "../src/did-web-resolver.js";
import {
  generateKeypair,
  encodePublicKeyMultibase,
  base64urlEncode,
  fetchAgentCard,
  verifyAgentCardSignature,
  type AgentCard,
} from "@adastracomputing/ink";

const HOST = "r.example";
const DID = `did:web:${HOST}`;
const VERSIONED_PATH = `/ink/v1/${encodeURIComponent(DID)}/agent.json`;
const WELL_KNOWN_PATH = "/.well-known/ink/agent.json";

function memoryKv() {
  const store = new Map<string, string>();
  return {
    async get(key: string) { return store.get(key) ?? null; },
    async put(key: string, value: string) { store.set(key, String(value)); },
  };
}

let env: Record<string, unknown>;
let publicKeyMultibase: string;

const ctx = {
  waitUntil() { /* audit writes are fire-and-forget in tests */ },
  passThroughOnException() { /* not used */ },
} as unknown as ExecutionContext;

/** Route a library fetch straight into the worker, no network involved. */
const workerFetch = (async (input: RequestInfo | URL, init?: RequestInit) =>
  worker.fetch(new Request(input as RequestInfo, init), env as never, ctx)) as typeof fetch;

beforeAll(async () => {
  const kp = await generateKeypair();
  publicKeyMultibase = encodePublicKeyMultibase(kp.publicKey);
  env = {
    INK_RECEIVER_SIGNING_SEED: base64urlEncode(kp.privateKey),
    INK_RECEIVER_PUBLIC_KEY_MULTIBASE: publicKeyMultibase,
    INK_RECEIVER_HOST: HOST,
    INK_RECEIVER: memoryKv(),
  };
});

describe("matchVersionedCardPath", () => {
  it("decodes the agentId segment", () => {
    expect(matchVersionedCardPath(VERSIONED_PATH)).toBe(DID);
  });

  it("returns null for anything that is not a versioned card path", () => {
    expect(matchVersionedCardPath("/ink/v1/inbound")).toBeNull();
    expect(matchVersionedCardPath("/ink/v1//agent.json")).toBeNull();
    expect(matchVersionedCardPath("/ink/v1/a/b/agent.json")).toBeNull();
    expect(matchVersionedCardPath("/ink/v2/x/agent.json")).toBeNull();
    // Invalid percent-encoding is not a card path, and must not throw.
    expect(matchVersionedCardPath("/ink/v1/%zz/agent.json")).toBeNull();
  });
});

describe("versioned card path", () => {
  it("serves the card the library asks for", async () => {
    const res = await workerFetch(`https://${HOST}${VERSIONED_PATH}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json");
    const card = await res.json() as { agentId: string };
    expect(card.agentId).toBe(DID);
  });

  it("serves the well-known alias byte-for-byte identically", async () => {
    const versioned = await (await workerFetch(`https://${HOST}${VERSIONED_PATH}`)).text();
    const wellKnown = await (await workerFetch(`https://${HOST}${WELL_KNOWN_PATH}`)).text();
    expect(wellKnown).toBe(versioned);
  });

  it("accepts the unescaped-colon spelling of the same segment", async () => {
    // A colon is legal unescaped in a path segment, and clients differ on
    // whether they escape it (Go's url.PathEscape does not). Both spellings
    // name the same agentId, so both must resolve.
    const res = await workerFetch(`https://${HOST}/ink/v1/${DID}/agent.json`);
    expect(res.status).toBe(200);
    expect((await res.json() as { agentId: string }).agentId).toBe(DID);
  });

  it("404s a versioned path for some other agentId", async () => {
    const res = await workerFetch(
      `https://${HOST}/ink/v1/${encodeURIComponent("did:web:someone-else.example")}/agent.json`,
    );
    expect(res.status).toBe(404);
  });
});

describe("fetchAgentCard against the reference receiver", () => {
  it("resolves the receiver's card from the DID and the origin alone", async () => {
    const card = await fetchAgentCard(DID, `https://${HOST}`, { fetch: workerFetch });
    expect(card).not.toBeNull();
    expect(card!.agentId).toBe(DID);
    expect(card!.endpoint).toBe(`https://${HOST}/ink/v1/inbound`);
  });

  it("resolves a card whose signature verifies against the published DID key", async () => {
    const res = await workerFetch(`https://${HOST}${VERSIONED_PATH}`);
    const served = await res.json() as AgentCard & { cardSignature?: { keyId: string } };
    // The bytes the library fetches are the bytes that carry the signature.
    const fetched = await fetchAgentCard(DID, `https://${HOST}`, { fetch: workerFetch });
    expect(fetched).not.toBeNull();
    expect(served.cardSignature?.keyId).toBe("bootstrap");
    const result = await verifyAgentCardSignature(served, DID, {
      profile: "pre-1.0",
      didVerificationKeys: [publicKeyMultibase],
    });
    expect(result.authenticated).toBe(true);
  });
});

describe("did:web resolution of the receiver by the receiver's own resolver", () => {
  it("walks the DID document's InkAgentCard service entry to the versioned path", async () => {
    const didDoc = await (await workerFetch(`https://${HOST}/.well-known/did.json`)).json() as {
      service: Array<{ type: string; serviceEndpoint: string }>;
    };
    const entry = didDoc.service.find((s) => s.type === "InkAgentCard");
    expect(entry?.serviceEndpoint).toBe(`https://${HOST}${VERSIONED_PATH}`);
    const card = await resolveAgentCardForDidWeb(DID, { fetcher: workerFetch }) as { agentId: string } | null;
    expect(card).not.toBeNull();
    expect(card!.agentId).toBe(DID);
  });
});
