import { describe, it, expect } from "vitest";
import {
  isIpLiteralHost,
  isPrivateHost,
  resolveDidWebTargets,
  resolveAgentCardForDidWeb,
} from "../src/did-web-resolver.js";

describe("isIpLiteralHost", () => {
  it("flags dotted-quad", () => {
    expect(isIpLiteralHost("10.0.0.1")).toBe(true);
    expect(isIpLiteralHost("127.0.0.1")).toBe(true);
  });

  it("flags bracketed and bare IPv6", () => {
    expect(isIpLiteralHost("[::1]")).toBe(true);
    expect(isIpLiteralHost("::1")).toBe(true);
    expect(isIpLiteralHost("fe80::1")).toBe(true);
  });

  it("flags decimal-numeric IPv4 packed form", () => {
    expect(isIpLiteralHost("2130706433")).toBe(true);
  });

  it("does not flag DNS hosts", () => {
    expect(isIpLiteralHost("example.com")).toBe(false);
    expect(isIpLiteralHost("did-host.tld")).toBe(false);
  });
});

describe("isPrivateHost", () => {
  it("flags loopback variants", () => {
    expect(isPrivateHost("localhost")).toBe(true);
    expect(isPrivateHost("sub.localhost")).toBe(true);
    expect(isPrivateHost("127.0.0.1")).toBe(true);
    expect(isPrivateHost("::1")).toBe(true);
  });

  it("flags private IPv4 ranges", () => {
    expect(isPrivateHost("10.0.0.5")).toBe(true);
    expect(isPrivateHost("172.16.0.1")).toBe(true);
    expect(isPrivateHost("172.31.255.255")).toBe(true);
    expect(isPrivateHost("192.168.1.1")).toBe(true);
  });

  it("flags 169.254.169.254 (cloud metadata)", () => {
    expect(isPrivateHost("169.254.169.254")).toBe(true);
  });

  it("flags IPv6 ULA + link-local", () => {
    expect(isPrivateHost("fc00::1")).toBe(true);
    expect(isPrivateHost("fd12::1")).toBe(true);
    expect(isPrivateHost("fe80::1")).toBe(true);
  });

  it("does not flag normal public hosts", () => {
    expect(isPrivateHost("example.com")).toBe(false);
    expect(isPrivateHost("api.tulpa.network")).toBe(false);
  });
});

describe("resolveDidWebTargets", () => {
  it("returns canonical urls for a bare host did:web", () => {
    const t = resolveDidWebTargets("did:web:example.com");
    expect(t).not.toBeNull();
    expect(t!.host).toBe("example.com");
    expect(t!.didDocUrl).toBe("https://example.com/.well-known/did.json");
    expect(t!.versionedCardUrl).toBe(
      `https://example.com/ink/v1/${encodeURIComponent("did:web:example.com")}/agent.json`,
    );
  });

  it("returns null on non-did:web", () => {
    expect(resolveDidWebTargets("did:key:z6MkXXX")).toBeNull();
  });

  it("returns null on private host", () => {
    expect(resolveDidWebTargets("did:web:localhost")).toBeNull();
    expect(resolveDidWebTargets("did:web:127.0.0.1")).toBeNull();
  });

  it("returns null on IP literal", () => {
    expect(resolveDidWebTargets("did:web:8.8.8.8")).toBeNull();
  });

  it("returns null on IPv4 shorthand that resolves to loopback", () => {
    // URL parser normalizes 127.1 -> 127.0.0.1, 0177.1 -> octal, etc.
    expect(resolveDidWebTargets("did:web:127.1")).toBeNull();
    expect(resolveDidWebTargets("did:web:127.0.1")).toBeNull();
    expect(resolveDidWebTargets("did:web:10.1")).toBeNull();
  });

  it("supports path-form did:web", () => {
    const t = resolveDidWebTargets("did:web:example.com:user:alice");
    expect(t!.didDocUrl).toBe("https://example.com/user/alice/did.json");
  });

  it("rejects path segments with disallowed chars", () => {
    expect(resolveDidWebTargets("did:web:example.com:..")).toBeNull();
    expect(resolveDidWebTargets("did:web:example.com:foo/bar")).toBeNull();
  });
});

// A `%3A` in the host part of a did:web identifier is a port. Dropping it and
// resolving at the default port silently retargets a different origin, so the
// rule is: carry the port, or reject the identifier. Never drop it.
describe("resolveDidWebTargets carries the %3A port", () => {
  it("carries the port into every derived URL", () => {
    const t = resolveDidWebTargets("did:web:example.com%3A8443");
    expect(t).not.toBeNull();
    expect(t!.host).toBe("example.com:8443");
    expect(t!.didDocUrl).toBe("https://example.com:8443/.well-known/did.json");
    expect(t!.versionedCardUrl).toBe(
      `https://example.com:8443/ink/v1/${encodeURIComponent("did:web:example.com%3A8443")}/agent.json`,
    );
  });

  it("carries the port on path-form identifiers", () => {
    const t = resolveDidWebTargets("did:web:example.com%3A8443:user:alice");
    expect(t!.didDocUrl).toBe("https://example.com:8443/user/alice/did.json");
    expect(t!.host).toBe("example.com:8443");
  });

  it("rejects rather than drops a malformed port", () => {
    expect(resolveDidWebTargets("did:web:example.com%3A")).toBeNull();       // empty
    expect(resolveDidWebTargets("did:web:example.com%3Aabc")).toBeNull();    // not numeric
    expect(resolveDidWebTargets("did:web:example.com%3A0")).toBeNull();      // out of range
    expect(resolveDidWebTargets("did:web:example.com%3A08443")).toBeNull();  // leading zero
    expect(resolveDidWebTargets("did:web:example.com%3A65536")).toBeNull();  // out of range
    expect(resolveDidWebTargets("did:web:example.com%3A8443%3A9")).toBeNull(); // two markers
    expect(resolveDidWebTargets("did:web:example.com%3a8443")).toBeNull();   // lowercase marker
    expect(resolveDidWebTargets("did:web:example.com%3A8443:.")).toBeNull(); // dot segment
  });

  // The W3C did:web method allows an optional percent-encoded port and bans no
  // value, so `%3A443` is a legal identifier and refusing it is an interop bug.
  // It names the default https origin, which is exactly where it resolves. The
  // sign-in profile's extra ban on an explicit 443 is profile-local
  // (`deriveRpOrigin`) and does not reach this path.
  it("accepts an explicit 443 and resolves it at the default origin", () => {
    const t = resolveDidWebTargets("did:web:example.com%3A443");
    expect(t).not.toBeNull();
    expect(t!.host).toBe("example.com");
    expect(t!.didDocUrl).toBe("https://example.com/.well-known/did.json");
    // The identity is still the ported spelling: it is carried in the path.
    expect(t!.versionedCardUrl).toBe(
      `https://example.com/ink/v1/${encodeURIComponent("did:web:example.com%3A443")}/agent.json`,
    );
  });

  it("still rejects a private or IP-literal host that carries a port", () => {
    expect(resolveDidWebTargets("did:web:localhost%3A8443")).toBeNull();
    expect(resolveDidWebTargets("did:web:127.0.0.1%3A8443")).toBeNull();
    expect(resolveDidWebTargets("did:web:10.1%3A8443")).toBeNull();
  });
});

describe("resolveAgentCardForDidWeb", () => {
  const DID = "did:web:example.com";
  const VERSIONED = `https://example.com/ink/v1/${encodeURIComponent(DID)}/agent.json`;
  const WELL_KNOWN = "https://example.com/.well-known/ink/agent.json";

  function buildCard(agentId: string) {
    const endpoint = "https://example.com/ink/v1/inbound";
    return {
      protocol: "ink/0.1",
      agentId,
      handle: "example.com",
      displayName: "Example",
      endpoint,
      inboxEndpoint: endpoint,
      publicKeyMultibase: "z6MkpTHR8VNsBxYAAWHut2Geadd9jSshBHRNNbnuHYNNNNNN",
      capabilities: {
        intentsAccepted: ["ping"],
        intentsSent: [],
      },
      availability: { timezone: "UTC" },
    };
  }

  it("returns null when did doc fetch fails", async () => {
    const fetcher = (async () => new Response("nope", { status: 500 })) as typeof fetch;
    const result = await resolveAgentCardForDidWeb("did:web:example.com", { fetcher });
    expect(result).toBeNull();
  });

  it("uses the versioned discovery path when the did doc lacks an InkAgentCard service", async () => {
    const card = buildCard(DID);
    const fetcher = (async (url: string | URL) => {
      const u = String(url);
      if (u === "https://example.com/.well-known/did.json") {
        return new Response(JSON.stringify({ id: DID, service: [] }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      if (u === VERSIONED) {
        return new Response(JSON.stringify(card), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      return new Response("not found", { status: 404 });
    }) as typeof fetch;
    const result = await resolveAgentCardForDidWeb(DID, { fetcher });
    expect(result).not.toBeNull();
    expect((result as { agentId: string }).agentId).toBe(DID);
  });

  // ink-resolver.md §3.2: the versioned path is the sole normative discovery
  // surface. A resolver MUST NOT depend on the /.well-known alias or fall back
  // to it, so a peer that serves ONLY the alias is not discoverable here — and
  // the alias must not even be requested.
  it("does not discover a peer that serves only the well-known alias", async () => {
    const card = buildCard(DID);
    const requested: string[] = [];
    const fetcher = (async (url: string | URL) => {
      const u = String(url);
      requested.push(u);
      if (u === "https://example.com/.well-known/did.json") {
        return new Response(JSON.stringify({ id: DID, service: [] }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      if (u === WELL_KNOWN) {
        return new Response(JSON.stringify(card), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      return new Response("not found", { status: 404 });
    }) as typeof fetch;
    const result = await resolveAgentCardForDidWeb(DID, { fetcher });
    expect(result).toBeNull();
    expect(requested).not.toContain(WELL_KNOWN);
  });

  it("ignores InkAgentCard service entries that point at a different host (identity binding)", async () => {
    const card = buildCard("did:web:example.com");
    const fetcher = (async (url: string | URL) => {
      const u = String(url);
      if (u === "https://example.com/.well-known/did.json") {
        return new Response(JSON.stringify({
          id: "did:web:example.com",
          service: [{ type: "InkAgentCard", serviceEndpoint: "https://attacker.example/agent.json" }],
        }), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (u === VERSIONED) {
        return new Response(JSON.stringify(card), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      return new Response("nope", { status: 404 });
    }) as typeof fetch;
    const result = await resolveAgentCardForDidWeb(DID, { fetcher });
    expect(result).not.toBeNull();
    // The attacker.example URL was rejected; we fell through to the versioned path.
  });

  it("rejects a card whose agentId doesn't match the DID we resolved", async () => {
    const card = buildCard("did:web:other.example");  // claims a different DID
    const fetcher = (async () => new Response(JSON.stringify(card), {
      status: 200, headers: { "content-type": "application/json" },
    })) as typeof fetch;
    const result = await resolveAgentCardForDidWeb("did:web:example.com", { fetcher });
    expect(result).toBeNull();
  });

  it("ignores InkAgentCard service entries that use http:// (no protocol downgrade)", async () => {
    const card = buildCard("did:web:example.com");
    const fetcher = (async (url: string | URL) => {
      const u = String(url);
      if (u === "https://example.com/.well-known/did.json") {
        return new Response(JSON.stringify({
          id: "did:web:example.com",
          // Same host, but http:// — should be ignored.
          service: [{ type: "InkAgentCard", serviceEndpoint: "http://example.com/agent.json" }],
        }), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (u === VERSIONED) {
        return new Response(JSON.stringify(card), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      if (u === "http://example.com/agent.json") {
        throw new Error("http:// endpoint should NOT have been fetched");
      }
      return new Response("nope", { status: 404 });
    }) as typeof fetch;
    const result = await resolveAgentCardForDidWeb("did:web:example.com", { fetcher });
    expect(result).not.toBeNull();
  });

  it("aborts a response body that exceeds the fetch byte cap", async () => {
    const oversize = new Uint8Array(2 * 1024 * 1024);
    const fetcher = (async (url: string | URL) => {
      const u = String(url);
      if (u === "https://example.com/.well-known/did.json") {
        // Stream the oversize body so the cap kicks in mid-read.
        const stream = new ReadableStream({
          start(controller) {
            controller.enqueue(oversize);
            controller.close();
          },
        });
        return new Response(stream, { status: 200, headers: { "content-type": "application/json" } });
      }
      return new Response("nope", { status: 404 });
    }) as typeof fetch;
    const result = await resolveAgentCardForDidWeb("did:web:example.com", { fetcher });
    expect(result).toBeNull();
  });
});
