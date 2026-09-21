/**
 * Byte fidelity of the Agent Card discovery fetch contract
 * (specs/ink-agent-card-discovery-fetch.md step 4-5).
 *
 * `AgentCardFetchInput.bodyRaw` is the response body exactly as received, not
 * transcoded. A caller that hands over a JS string has already crossed the
 * UTF-8 boundary: a lenient decode substitutes U+FFFD for an invalid byte and
 * strips a leading BOM, so a card with a raw invalid byte or a leading BOM
 * would be accepted here even though the shared byte-level signed-body gate
 * (parseSignedBodyBytes) refuses both. `evaluateAgentCardFetch` must decide on
 * the bytes themselves, and must reject rather than throw when handed
 * anything else.
 */

import { describe, it, expect } from "vitest";
import { evaluateAgentCardFetch } from "../src/index.js";

const AGENT_ID = "did:web:a.example";

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

function baseInput(bodyRaw: unknown): Parameters<typeof evaluateAgentCardFetch>[0] {
  return {
    status: 200,
    contentType: "application/json",
    contentLength: null,
    bodyRaw,
    requestedAgentId: AGENT_ID,
    resolutionDid: null,
  } as Parameters<typeof evaluateAgentCardFetch>[0];
}

describe("evaluateAgentCardFetch: bodyRaw must be raw bytes", () => {
  it("rejects, without throwing, when bodyRaw is a string rather than Uint8Array", () => {
    const bodyText = JSON.stringify(card());
    const r = evaluateAgentCardFetch(baseInput(bodyText));
    expect(r.accepted).toBe(false);
    expect(r.card).toBeNull();
  });

  it("rejects, without throwing, when bodyRaw only looks like a Uint8Array", () => {
    // Both pass instanceof and neither has a backing buffer, so reading
    // byteLength off one throws. A decision function rejects instead.
    const forged = Object.create(Uint8Array.prototype) as Uint8Array;
    expect(evaluateAgentCardFetch(baseInput(forged)).accepted).toBe(false);
    const proxied = new Proxy(new TextEncoder().encode("{}"), {}) as Uint8Array;
    expect(evaluateAgentCardFetch(baseInput(proxied)).accepted).toBe(false);
  });

  it("rejects, without throwing, when bodyRaw is null", () => {
    const r = evaluateAgentCardFetch(baseInput(null));
    expect(r.accepted).toBe(false);
    expect(r.card).toBeNull();
  });

  it("rejects, without throwing, when bodyRaw is a plain object", () => {
    const r = evaluateAgentCardFetch(baseInput({}));
    expect(r.accepted).toBe(false);
    expect(r.card).toBeNull();
  });

  it("rejects, without throwing, when bodyRaw is a number", () => {
    const r = evaluateAgentCardFetch(baseInput(42));
    expect(r.accepted).toBe(false);
    expect(r.card).toBeNull();
  });

  it("rejects a raw invalid UTF-8 byte inside a field that would otherwise be a valid bound card", () => {
    const text = JSON.stringify(card());
    const bytes = new TextEncoder().encode(text);
    // Corrupt the 'A' of "Alice" into an invalid lone continuation byte.
    const idx = text.indexOf("Alice");
    expect(idx).toBeGreaterThan(-1);
    bytes[idx] = 0xff;
    const r = evaluateAgentCardFetch(baseInput(bytes));
    expect(r.accepted).toBe(false);
    expect(r.card).toBeNull();
  });

  it("rejects a body carrying a leading UTF-8 byte-order mark", () => {
    const text = JSON.stringify(card());
    const body = new TextEncoder().encode(text);
    const bom = new Uint8Array([0xef, 0xbb, 0xbf, ...body]);
    const r = evaluateAgentCardFetch(baseInput(bom));
    expect(r.accepted).toBe(false);
    expect(r.card).toBeNull();
  });

  it("accepts a valid card whose fields carry 2-, 3- and 4-byte UTF-8 sequences", () => {
    const bytes = new TextEncoder().encode(JSON.stringify(card({ displayName: "héllo 中 😀" })));
    const r = evaluateAgentCardFetch(baseInput(bytes));
    expect(r.accepted).toBe(true);
    expect(r.card).not.toBeNull();
  });
});
