/**
 * Security review (2026-06) hardening regressions for the key/auth/encryption
 * paths. Covers:
 *  - H1: the NonceStore atomic check-and-record (addIfAbsent) is preferred over
 *    the racy has()+add() pair, closing the concurrent-replay TOCTOU.
 *  - L2: decodeBase58 no longer over-decodes all-zero (leading-'1') inputs.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { signInkMessage } from "../src/crypto/ink.js";
import { verifyInkAuth, type NonceStore } from "../src/middleware/ink-auth.js";
import { encodeBase58, decodeBase58 } from "../src/crypto/keys.js";

async function signedRequest(nonce: string) {
  const { secretKey: priv, publicKey: pub } = await ed.keygenAsync();
  const method = "POST";
  const path = "/ink/v1/intent";
  const recipientDid = "did:plc:recipient";
  const body = { from: "did:plc:alice", timestamp: new Date().toISOString(), nonce };
  const sig = await signInkMessage({ method, path, recipientDid, body, timestamp: body.timestamp }, priv);
  return { authHeader: `INK-Ed25519 ${sig}`, method, path, recipientDid, body, pub };
}

describe("H1: NonceStore atomic check-and-record", () => {
  it("uses addIfAbsent when present and never calls has()/add()", async () => {
    const seen = new Set<string>();
    let hasCalls = 0;
    let addCalls = 0;
    const store: NonceStore = {
      has: () => { hasCalls++; return false; },
      add: () => { addCalls++; },
      addIfAbsent: (n) => {
        if (seen.has(n)) return false;
        seen.add(n);
        return true;
      },
    };
    const nonce = "atomicnonce0000000000000001";
    const req = await signedRequest(nonce);
    const opts = {
      authHeader: req.authHeader,
      method: req.method,
      path: req.path,
      recipientAgentId: req.recipientDid,
      body: req.body,
      resolvePublicKey: () => req.pub,
      nonceStore: store,
    };
    const first = await verifyInkAuth(opts);
    expect(first.valid).toBe(true);
    const second = await verifyInkAuth(opts);
    expect(second.valid).toBe(false);
    if (!second.valid) expect(second.error).toBe("nonce_replay");
    // The atomic path is used exclusively; the racy pair is never touched.
    expect(hasCalls).toBe(0);
    expect(addCalls).toBe(0);
  });

  it("falls back to has()+add() for a store without addIfAbsent", async () => {
    const seen = new Set<string>();
    const store: NonceStore = {
      has: (n) => seen.has(n),
      add: (n) => { seen.add(n); },
    };
    const nonce = "fallbacknonce000000000000001";
    const req = await signedRequest(nonce);
    const opts = {
      authHeader: req.authHeader,
      method: req.method,
      path: req.path,
      recipientAgentId: req.recipientDid,
      body: req.body,
      resolvePublicKey: () => req.pub,
      nonceStore: store,
    };
    expect((await verifyInkAuth(opts)).valid).toBe(true);
    const replay = await verifyInkAuth(opts);
    expect(replay.valid).toBe(false);
    if (!replay.valid) expect(replay.error).toBe("nonce_replay");
  });

  it("fails closed when addIfAbsent throws", async () => {
    const store: NonceStore = {
      has: () => false,
      add: () => {},
      addIfAbsent: () => { throw new Error("backend down"); },
    };
    const req = await signedRequest("throwingnonce0000000000000001");
    const result = await verifyInkAuth({
      authHeader: req.authHeader,
      method: req.method,
      path: req.path,
      recipientAgentId: req.recipientDid,
      body: req.body,
      resolvePublicKey: () => req.pub,
      nonceStore: store,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe("nonce_store_error");
  });
});

describe("L2: decodeBase58 does not over-decode all-zero inputs", () => {
  it("decodes a single leading '1' to exactly one zero byte", () => {
    const out = decodeBase58("1");
    expect(Array.from(out)).toEqual([0]);
  });

  it("decodes N leading '1's to exactly N zero bytes", () => {
    expect(Array.from(decodeBase58("111"))).toEqual([0, 0, 0]);
  });

  it("round-trips arbitrary byte strings including leading zeros", () => {
    const samples = [
      new Uint8Array([0]),
      new Uint8Array([0, 0, 1, 2, 3]),
      new Uint8Array([255, 254, 0, 7]),
      new Uint8Array([1]),
    ];
    for (const s of samples) {
      expect(Array.from(decodeBase58(encodeBase58(s)))).toEqual(Array.from(s));
    }
  });
});
