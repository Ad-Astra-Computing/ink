import { describe, it, expect } from "vitest";
import { generateSenderIdentity } from "../src/identity.ts";
import { buildSignedEnvelope, pingPayload } from "../src/envelope.ts";
import { validateTargetUrl, didWebHost, deliverEnvelope } from "../src/transport.ts";

describe("validateTargetUrl", () => {
  it("accepts a plain public https URL", () => {
    const r = validateTargetUrl("https://ink-echo.tulpa.network/ink/v1/inbound");
    expect(r.ok).toBe(true);
  });

  it("rejects non-https schemes", () => {
    expect(validateTargetUrl("http://example.com/x")).toEqual({ ok: false, reason: "https_required" });
    expect(validateTargetUrl("ftp://example.com/x")).toEqual({ ok: false, reason: "https_required" });
  });

  it("rejects embedded userinfo", () => {
    expect(validateTargetUrl("https://user:pass@example.com/x")).toEqual({
      ok: false,
      reason: "userinfo_not_allowed",
    });
  });

  it("rejects a fragment", () => {
    expect(validateTargetUrl("https://example.com/x#frag")).toEqual({
      ok: false,
      reason: "fragment_not_allowed",
    });
  });

  it("rejects IP-literal and private hosts", () => {
    expect(validateTargetUrl("https://127.0.0.1/x").ok).toBe(false);
    expect(validateTargetUrl("https://10.0.0.5/x").ok).toBe(false);
    expect(validateTargetUrl("https://[::1]/x").ok).toBe(false);
    expect(validateTargetUrl("https://localhost/x").ok).toBe(false);
  });

  it("enforces did:web host binding", () => {
    expect(
      validateTargetUrl("https://evil.example/x", { requiredDidWebHost: "good.example" }),
    ).toEqual({ ok: false, reason: "host_mismatch" });
    expect(
      validateTargetUrl("https://good.example/x", { requiredDidWebHost: "good.example" }).ok,
    ).toBe(true);
  });

  it("allowPrivateHosts relaxes only the private-host refusal", () => {
    // The private/loopback host is now permitted...
    expect(validateTargetUrl("https://127.0.0.1/x", { allowPrivateHosts: true }).ok).toBe(true);
    expect(validateTargetUrl("https://localhost/x", { allowPrivateHosts: true }).ok).toBe(true);
    // ...but https, and the did:web host binding, are never relaxed.
    expect(validateTargetUrl("http://localhost/x", { allowPrivateHosts: true })).toEqual({
      ok: false,
      reason: "https_required",
    });
    expect(
      validateTargetUrl("https://127.0.0.1/x", {
        allowPrivateHosts: true,
        requiredDidWebHost: "good.example",
      }),
    ).toEqual({ ok: false, reason: "host_mismatch" });
  });
});

describe("didWebHost", () => {
  it("extracts the host from a did:web", () => {
    expect(didWebHost("did:web:r.example")).toBe("r.example");
    expect(didWebHost("did:web:r.example:agents:bot")).toBe("r.example");
  });
  it("returns null for non-did:web", () => {
    expect(didWebHost("did:key:z6Mk")).toBeNull();
    expect(didWebHost("did:web:")).toBeNull();
  });
  it("rejects a port-bearing did:web rather than stripping the port", () => {
    // host%3Aport. Stripping the port would let an endpoint on a different
    // port satisfy the hostname binding, so it must fail closed.
    expect(didWebHost("did:web:example.com%3A8443")).toBeNull();
  });
});

describe("deliverEnvelope", () => {
  it("refuses to deliver to a private host before any fetch", async () => {
    const id = await generateSenderIdentity();
    const env = await buildSignedEnvelope({
      identity: id,
      to: "did:key:z6Mkrecipient",
      intent: "ping",
      payload: pingPayload(),
    });
    let called = false;
    const r = await deliverEnvelope({
      identity: id,
      targetUrl: "https://127.0.0.1/ink/v1/inbound",
      recipientDid: "did:key:z6Mkrecipient",
      envelope: env as unknown as Record<string, unknown>,
      fetchImpl: async () => {
        called = true;
        return new Response("{}", { status: 200 });
      },
    });
    expect(r).toEqual({ ok: false, reason: "private_host_blocked" });
    expect(called).toBe(false);
  });

  it("delivers to a private host when allowPrivateHosts is set", async () => {
    const id = await generateSenderIdentity();
    const env = await buildSignedEnvelope({
      identity: id,
      to: "did:key:z6Mkrecipient",
      intent: "ping",
      payload: pingPayload(),
    });
    let called = false;
    const r = await deliverEnvelope({
      identity: id,
      targetUrl: "https://127.0.0.1/ink/v1/inbound",
      recipientDid: "did:key:z6Mkrecipient",
      envelope: env as unknown as Record<string, unknown>,
      allowPrivateHosts: true,
      fetchImpl: async () => {
        called = true;
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      },
    });
    expect(called).toBe(true);
    expect(r.ok).toBe(true);
  });

  it("refuses a did:web recipient when the URL host does not match the DID host", async () => {
    const id = await generateSenderIdentity();
    const env = await buildSignedEnvelope({
      identity: id,
      to: "did:web:good.example",
      intent: "ping",
      payload: pingPayload(),
    });
    const r = await deliverEnvelope({
      identity: id,
      targetUrl: "https://evil.example/ink/v1/inbound",
      recipientDid: "did:web:good.example",
      envelope: env as unknown as Record<string, unknown>,
      fetchImpl: async () => new Response("{}", { status: 200 }),
    });
    expect(r).toEqual({ ok: false, reason: "host_mismatch" });
  });

  it("posts a signed request and returns the ack on success", async () => {
    const id = await generateSenderIdentity();
    const env = await buildSignedEnvelope({
      identity: id,
      to: "did:key:z6Mkrecipient",
      intent: "ping",
      payload: pingPayload(),
    });
    let sawAuth = false;
    const r = await deliverEnvelope({
      identity: id,
      targetUrl: "https://ink-echo.tulpa.network/ink/v1/inbound",
      recipientDid: "did:key:z6Mkrecipient",
      envelope: env as unknown as Record<string, unknown>,
      fetchImpl: async (_url, init) => {
        const auth = (init?.headers as Record<string, string>)?.Authorization ?? "";
        sawAuth = auth.startsWith("INK-Ed25519 ");
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      },
    });
    expect(sawAuth).toBe(true);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.status).toBe(200);
  });

  it("refuses a port-bearing did:web recipient (binding cannot be weakened)", async () => {
    const id = await generateSenderIdentity();
    const env = await buildSignedEnvelope({
      identity: id,
      to: "did:web:example.com%3A8443",
      intent: "ping",
      payload: pingPayload(),
    });
    let called = false;
    const r = await deliverEnvelope({
      identity: id,
      targetUrl: "https://example.com/ink/v1/inbound",
      recipientDid: "did:web:example.com%3A8443",
      envelope: env as unknown as Record<string, unknown>,
      fetchImpl: async () => {
        called = true;
        return new Response("{}", { status: 200 });
      },
    });
    expect(r).toEqual({ ok: false, reason: "invalid_target_url" });
    expect(called).toBe(false);
  });

  it("times out when the response body stalls after headers", async () => {
    const id = await generateSenderIdentity();
    const env = await buildSignedEnvelope({
      identity: id,
      to: "did:key:z6Mkrecipient",
      intent: "ping",
      payload: pingPayload(),
    });
    // Headers arrive (200), then the body never completes. The request
    // budget must still fire and cancel the read.
    const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
      const signal = init?.signal;
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          signal?.addEventListener("abort", () =>
            controller.error(new DOMException("aborted", "AbortError")),
          );
        },
      });
      return new Response(body, {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    const r = await deliverEnvelope({
      identity: id,
      targetUrl: "https://ink-echo.tulpa.network/ink/v1/inbound",
      recipientDid: "did:key:z6Mkrecipient",
      envelope: env as unknown as Record<string, unknown>,
      fetchImpl,
      timeoutMs: 50,
    });
    expect(r).toEqual({ ok: false, reason: "timeout" });
  });

  it("maps a non-2xx response to non_2xx with its status", async () => {
    const id = await generateSenderIdentity();
    const env = await buildSignedEnvelope({
      identity: id,
      to: "did:key:z6Mkrecipient",
      intent: "ping",
      payload: pingPayload(),
    });
    const r = await deliverEnvelope({
      identity: id,
      targetUrl: "https://ink-echo.tulpa.network/ink/v1/inbound",
      recipientDid: "did:key:z6Mkrecipient",
      envelope: env as unknown as Record<string, unknown>,
      fetchImpl: async () => new Response("nope", { status: 400 }),
    });
    expect(r).toEqual({ ok: false, reason: "non_2xx", status: 400 });
  });
});
