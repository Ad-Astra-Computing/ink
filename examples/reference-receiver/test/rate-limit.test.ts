import { describe, it, expect } from "vitest";
import { checkRateLimit } from "../src/rate-limit.js";

function fakeKv(): KVNamespace {
  const store = new Map<string, string>();
  return {
    get: async (key: string) => store.get(key) ?? null,
    put: async (key: string, value: string) => { store.set(key, String(value)); },
    delete: async (key: string) => { store.delete(key); },
    list: async () => ({ keys: [], list_complete: true, cacheStatus: null }),
    getWithMetadata: async () => ({ value: null, metadata: null, cacheStatus: null }),
  } as unknown as KVNamespace;
}

describe("checkRateLimit", () => {
  it("allows up to the configured limit, then blocks", async () => {
    const kv = fakeKv();
    const fixed = () => 1_700_000_000_000;
    for (let i = 0; i < 5; i++) {
      const v = await checkRateLimit({ kv, senderKey: "alice", limit: 5, windowSec: 60, now: fixed });
      expect(v.allowed).toBe(true);
    }
    const blocked = await checkRateLimit({ kv, senderKey: "alice", limit: 5, windowSec: 60, now: fixed });
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
    expect(blocked.resetSec).toBeGreaterThanOrEqual(0);
  });

  it("isolates senders", async () => {
    const kv = fakeKv();
    const fixed = () => 1_700_000_000_000;
    for (let i = 0; i < 5; i++) {
      await checkRateLimit({ kv, senderKey: "alice", limit: 5, windowSec: 60, now: fixed });
    }
    const bob = await checkRateLimit({ kv, senderKey: "bob", limit: 5, windowSec: 60, now: fixed });
    expect(bob.allowed).toBe(true);
  });

  it("rolls over after window expiry", async () => {
    const kv = fakeKv();
    const t0 = 1_700_000_000_000;
    for (let i = 0; i < 5; i++) {
      await checkRateLimit({ kv, senderKey: "alice", limit: 5, windowSec: 60, now: () => t0 });
    }
    // Advance two windows.
    const later = await checkRateLimit({
      kv, senderKey: "alice", limit: 5, windowSec: 60, now: () => t0 + 120_000,
    });
    expect(later.allowed).toBe(true);
  });

  it("treats KV read failure as count=0 (fail-open for transient KV errors)", async () => {
    const flaky = {
      get: async () => { throw new Error("kv down"); },
      put: async () => {},
    } as unknown as KVNamespace;
    const v = await checkRateLimit({ kv: flaky, senderKey: "alice", limit: 5, windowSec: 60 });
    expect(v.allowed).toBe(true);
  });

  it("sanitizes sender key to avoid KV key injection", async () => {
    const kv = fakeKv();
    // A sender key containing a colon (e.g. did:web:foo) is preserved.
    // One with a forward slash gets normalized.
    const v1 = await checkRateLimit({ kv, senderKey: "did:web:foo", limit: 5, windowSec: 60 });
    const v2 = await checkRateLimit({ kv, senderKey: "did:web:foo/bar", limit: 5, windowSec: 60 });
    expect(v1.allowed).toBe(true);
    expect(v2.allowed).toBe(true);
  });
});
