/**
 * Security regression tests — round 23.
 *
 * Findings (Codex final pre-push pass):
 *  - jcsCanonicalize is publicly re-exported via src/index.ts but had
 *    no upstream bound check on its own; a consumer using the helper
 *    directly could canonicalize unbounded objects.
 *  - base64urlDecode is publicly re-exported with no input cap; an
 *    attacker-supplied multi-MB string would burn CPU in atob.
 *  - sendReceiptFireAndForget only checked https://; no userinfo,
 *    private-hostname, redirect-manual, or timeout guards — a softer
 *    SSRF path than fetchAgentCard.
 */
import { describe, it, expect } from "vitest";
import { jcsCanonicalize, base64urlDecode } from "../src/crypto/ink.js";
import { sendReceiptFireAndForget } from "../src/ink/receipts.js";
import type { InkReceipt } from "../src/models/ink-audit.js";
import * as ed from "@noble/ed25519";

describe("jcsCanonicalize (exported): self-defending bounds", () => {
  it("throws on a pathologically-large object", () => {
    const huge: Record<string, string> = {};
    for (let i = 0; i < 20_000; i++) huge[`k${i}`] = "v";
    expect(() => jcsCanonicalize(huge)).toThrow(/complexity/i);
  });

  it("throws on a single huge string value", () => {
    const huge = { data: "x".repeat(5_000_000) };
    expect(() => jcsCanonicalize(huge)).toThrow(/complexity|size/i);
  });

  it("throws on excessively-deep object", () => {
    let cur: Record<string, unknown> = {};
    const root = cur;
    for (let i = 0; i < 200; i++) {
      const next: Record<string, unknown> = {};
      cur.next = next;
      cur = next;
    }
    expect(() => jcsCanonicalize(root)).toThrow(/complexity/i);
  });

  it("still canonicalizes a normal object", () => {
    expect(jcsCanonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });
});

describe("base64urlDecode (exported): self-defending bounds", () => {
  it("rejects a multi-MB string input", () => {
    const huge = "a".repeat(3_000_000);
    expect(() => base64urlDecode(huge)).toThrow(/maximum length/i);
  });

  it("rejects non-string input", () => {
    expect(() => base64urlDecode(null as unknown as string)).toThrow();
    expect(() => base64urlDecode(42 as unknown as string)).toThrow();
  });

  it("rejects invalid characters (e.g. padding leftovers, plus signs)", () => {
    expect(() => base64urlDecode("abc=")).toThrow(/invalid base64url character/i);
    expect(() => base64urlDecode("a+b/c")).toThrow(/invalid base64url character/i);
  });

  it("decodes a valid base64url signature shape", () => {
    const out = base64urlDecode("A".repeat(86));
    expect(out.length).toBe(64);
  });
});

describe("sendReceiptFireAndForget: SSRF defenses", () => {
  async function makeReceipt(): Promise<InkReceipt> {
    return {
      protocol: "ink/0.1",
      type: "network.tulpa.receipt",
      from: "did:plc:sender",
      to: "did:plc:recipient",
      messageId: "msg-1",
      disposition: "delivered",
      dispositionAt: "2026-04-01T00:00:00Z",
      messageHash: "a".repeat(64),
      nonce: "n".repeat(22),
      timestamp: "2026-04-01T00:00:00Z",
      signature: "A".repeat(86),
    } as InkReceipt;
  }

  async function run(endpoint: string, opts?: { allowPrivateHosts?: boolean }) {
    let called = false;
    const fakeFetch = (async () => { called = true; return new Response("", { status: 200 }); }) as typeof fetch;
    const priv = ed.utils.randomSecretKey();
    const receipt = await makeReceipt();
    await sendReceiptFireAndForget(endpoint, receipt, priv, fakeFetch, undefined, opts);
    return called;
  }

  it("rejects http://", async () => {
    expect(await run("http://example.com/receipts")).toBe(false);
  });

  it("rejects literal loopback hostname", async () => {
    expect(await run("https://localhost/receipts")).toBe(false);
  });

  it("rejects literal private IPv4", async () => {
    expect(await run("https://192.168.1.1/receipts")).toBe(false);
  });

  it("rejects 169.254.169.254 (cloud metadata)", async () => {
    expect(await run("https://169.254.169.254/receipts")).toBe(false);
  });

  it("rejects userinfo in URL", async () => {
    expect(await run("https://user:pass@example.com/receipts")).toBe(false);
  });

  it("allows a normal public https endpoint", async () => {
    expect(await run("https://agent.example.com/receipts")).toBe(true);
  });

  it("allowPrivateHosts opt-in re-enables private hosts (for intranet)", async () => {
    expect(await run("https://localhost/receipts", { allowPrivateHosts: true })).toBe(true);
  });
});
