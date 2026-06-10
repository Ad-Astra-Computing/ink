import { describe, it, expect } from "vitest";
import { verifyInkAuth } from "../src/middleware/ink-auth.js";
import { signInkMessage, buildAuthHeader } from "../src/crypto/ink.js";
import { generateKeypair, deriveAgentId, canonicalAgentPrincipal } from "../src/crypto/keys.js";

describe("canonicalAgentPrincipal", () => {
  it("collapses the tulpa: and ink: spellings of one key to a single principal", async () => {
    const kp = await generateKeypair();
    const tulpaId = deriveAgentId(kp.publicKey);
    const inkId = "ink:" + tulpaId.slice("tulpa:".length);
    const p1 = canonicalAgentPrincipal(tulpaId);
    const p2 = canonicalAgentPrincipal(inkId);
    expect(p1).toBe(p2);
    expect(p1.startsWith("key:")).toBe(true);
  });

  it("returns a DID unchanged", () => {
    expect(canonicalAgentPrincipal("did:web:example.com")).toBe("did:web:example.com");
  });

  it("escapes a raw key: input so it cannot collide with a canonical key principal", () => {
    expect(canonicalAgentPrincipal("key:zABC")).toBe("raw:key:zABC");
  });

  it("is total: a malformed key body is escaped, not thrown", () => {
    expect(canonicalAgentPrincipal("tulpa:zNOT_VALID_base58!!")).toMatch(/^raw:/);
  });

  it("throws only on non-string, empty, or over-length input", () => {
    expect(() => canonicalAgentPrincipal("")).toThrow();
    expect(() => canonicalAgentPrincipal("x".repeat(513))).toThrow();
    // @ts-expect-error deliberately wrong type
    expect(() => canonicalAgentPrincipal(null)).toThrow();
  });
});

describe("verifyInkAuth returns a canonical principal", () => {
  async function signedReq(fromId: string, kp: Awaited<ReturnType<typeof generateKeypair>>) {
    const now = new Date().toISOString();
    const body = {
      protocol: "ink/0.1",
      type: "network.tulpa.receipt",
      from: fromId,
      to: "tulpa:zR",
      messageId: "m1",
      disposition: "received",
      dispositionAt: now,
      messageHash: "abc",
      nonce: "n1",
      timestamp: now,
    };
    const sig = await signInkMessage(
      { method: "POST", path: "/ink/v1/tulpa:zR/receipt", recipientDid: "tulpa:zR", body, timestamp: now },
      kp.privateKey,
    );
    return verifyInkAuth({
      nonceStore: "deferred",
      authHeader: buildAuthHeader(sig),
      method: "POST",
      path: "/ink/v1/tulpa:zR/receipt",
      recipientAgentId: "tulpa:zR",
      body,
    });
  }

  it("maps both prefix spellings of one key to the same principal, preserving the raw senderAgentId", async () => {
    const kp = await generateKeypair();
    const tulpaId = deriveAgentId(kp.publicKey);
    const inkId = "ink:" + tulpaId.slice("tulpa:".length);
    const r1 = await signedReq(tulpaId, kp);
    const r2 = await signedReq(inkId, kp);
    expect(r1.valid && r2.valid).toBe(true);
    if (r1.valid && r2.valid) {
      expect(r1.principal).toBe(r2.principal);
      expect(r1.principal.startsWith("key:")).toBe(true);
      expect(r1.senderAgentId).toBe(tulpaId);
      expect(r2.senderAgentId).toBe(inkId);
    }
  });
});
