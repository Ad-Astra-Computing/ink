import { describe, it, expect } from "vitest";
import { recordAudit, AUDIT_TTL_SEC } from "../src/audit-log.js";

function fakeKv(): { kv: KVNamespace; store: Map<string, { value: string; ttl?: number }> } {
  const store = new Map<string, { value: string; ttl?: number }>();
  const kv = {
    get: async (key: string) => store.get(key)?.value ?? null,
    put: async (key: string, value: string, opts?: { expirationTtl?: number }) => {
      store.set(key, { value: String(value), ttl: opts?.expirationTtl });
    },
    delete: async (key: string) => { store.delete(key); },
  } as unknown as KVNamespace;
  return { kv, store };
}

describe("recordAudit", () => {
  it("writes a row with TTL", async () => {
    const { kv, store } = fakeKv();
    await recordAudit({ kv, sender: "did:web:s.example", intent: "ping", verdict: "accepted", now: () => 1_700_000_000_000 });
    expect(store.size).toBe(1);
    const [, entry] = Array.from(store.entries())[0]!;
    expect(entry.ttl).toBe(AUDIT_TTL_SEC);
    const parsed = JSON.parse(entry.value);
    expect(parsed.sender).toBe("did:web:s.example");
    expect(parsed.intent).toBe("ping");
    expect(parsed.verdict).toBe("accepted");
  });

  it("clamps oversize sender + intent so KV value stays small", async () => {
    const { kv, store } = fakeKv();
    await recordAudit({
      kv,
      sender: "x".repeat(2000),
      intent: "yyy".repeat(50),
      verdict: "rejected_schema",
      errorCode: "z".repeat(500),
    });
    const [, entry] = Array.from(store.entries())[0]!;
    const parsed = JSON.parse(entry.value);
    expect(parsed.sender.length).toBeLessThanOrEqual(200);
    expect(parsed.intent.length).toBeLessThanOrEqual(32);
    expect(parsed.errorCode.length).toBeLessThanOrEqual(64);
  });

  it("swallows KV failures (best-effort)", async () => {
    const flakyKv = {
      put: async () => { throw new Error("kv down"); },
    } as unknown as KVNamespace;
    await expect(recordAudit({ kv: flakyKv, sender: "did:web:s.example", intent: "ping", verdict: "accepted" }))
      .resolves.toBeUndefined();
  });

  it("uses reverse-timestamp key prefix so a list returns newest first", async () => {
    const { kv, store } = fakeKv();
    await recordAudit({ kv, sender: "a", intent: "ping", verdict: "accepted", now: () => 1_700_000_000_000 });
    await recordAudit({ kv, sender: "b", intent: "ping", verdict: "accepted", now: () => 1_700_000_001_000 });
    const keys = Array.from(store.keys()).sort();
    // Reverse-timestamp means the LATER write has the SMALLER prefix.
    // The first key after sort should correspond to b's entry.
    const firstValue = store.get(keys[0]!)!.value;
    expect(JSON.parse(firstValue).sender).toBe("b");
  });
});
