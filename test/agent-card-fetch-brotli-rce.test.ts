// CVE-2026-111497: fetch() decodes Brotli lazily on body read, and a
// compromised agent-card host picks Content-Encoding on its own regardless of
// what the request asked for. fetchAgentCard must refuse before any read.
import { describe, it, expect } from "vitest";
import { fetchAgentCard } from "../src/discovery/agent-card.js";

describe("fetchAgentCard refuses a compressed response before decoding it", () => {
  it("rejects a card whose Content-Encoding is br without ever reading the body", async () => {
    // A null return alone proves nothing here: an unrelated downstream check
    // (schema, size cap) also returns null, so a body that merely decodes to
    // something invalid would pass this test even without the CVE guard, the
    // same false-pass the published fix for this repo's CLI had to avoid.
    // getReader() is spied rather than the stream's own pull(), which the
    // runtime can invoke on its own shortly after construction to prime the
    // queue, independent of whether any consumer ever reads from it.
    let bodyWasRead = false;
    const body = new ReadableStream<Uint8Array>({ pull() {} });
    const originalGetReader = body.getReader.bind(body);
    body.getReader = ((...args: Parameters<typeof originalGetReader>) => {
      bodyWasRead = true;
      return originalGetReader(...args);
    }) as typeof body.getReader;
    const fakeFetch: typeof fetch = async () =>
      new Response(body, {
        status: 200,
        headers: { "content-type": "application/json", "content-encoding": "br" },
      });

    const card = await fetchAgentCard("did:plc:victim", "https://agent.example.com", { fetch: fakeFetch });
    expect(bodyWasRead).toBe(false);
    expect(card).toBeNull();
  });
});
