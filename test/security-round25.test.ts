/**
 * Security regression tests, round 25.
 *
 * Codex BLOCKERS (post-republish security pass):
 *
 * 1. verifyInkAuth does not enforce nonce uniqueness, so a captured
 *    valid signed request can replay within the 5-minute freshness
 *    window. The middleware must require an explicit nonceStore (or
 *    explicit "deferred" sentinel acknowledging the caller will call
 *    checkReplay) so that production deployments fail closed rather
 *    than silently accepting replays.
 *
 * 2. verifyAuditResponseSignature verifies only the response wrapper
 *    signature, not chain continuity, so gaps, reordered events, and
 *    fork events (same sequence, different content) can be accepted
 *    as valid responses. A separate verifyAuditEventChain primitive
 *    must validate monotonic sequence, previousEventHash linkage and
 *    duplicate-sequence fork detection.
 */
import { describe, it, expect } from "vitest";
import {
  verifyInkAuth,
  signInkMessage,
  buildAuthHeader,
  generateKeypair,
  deriveAgentId,
  signAuditEvent,
  computeEventHash,
  verifyAuditEventChain,
  type NonceStore,
} from "../src/index.js";

// ── helper: sign a valid INK request and return middleware-ready inputs ──
async function makeSignedRequest(nonce: string = "nonce-aaaaaaaaaaaaaaaaaaaa") {
  const kp = await generateKeypair();
  const agentId = deriveAgentId(kp.publicKey);
  const now = new Date().toISOString();
  const body = {
    protocol: "ink/0.1",
    type: "network.tulpa.intent",
    from: agentId,
    to: "tulpa:zRecipient",
    intent: "meeting_request",
    nonce,
    timestamp: now,
  };
  const sig = await signInkMessage({
    method: "POST",
    path: "/ink/v1/tulpa:zRecipient/intent",
    recipientDid: "tulpa:zRecipient",
    body,
    timestamp: now,
  }, kp.privateKey);
  return {
    authHeader: buildAuthHeader(sig),
    method: "POST" as const,
    path: "/ink/v1/tulpa:zRecipient/intent",
    recipientAgentId: "tulpa:zRecipient",
    body,
  };
}

// ── BLOCKER 1: verifyInkAuth nonce enforcement ──

describe("verifyInkAuth: nonceStore fail-closed default", () => {
  it("rejects with nonce_handling_required when nonceStore is omitted", async () => {
    const req = await makeSignedRequest();
    // Intentional misuse: omit nonceStore to verify the fail-closed default.
    // Cast bypasses the type-level requirement; the runtime guard is what
    // protects misconfigured production deployments.
    const r = await verifyInkAuth(req as unknown as Parameters<typeof verifyInkAuth>[0]);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error).toBe("nonce_handling_required");
  });

  it("accepts a valid request when nonceStore is 'deferred'", async () => {
    const req = await makeSignedRequest();
    const r = await verifyInkAuth({ ...req, nonceStore: "deferred" });
    expect(r.valid).toBe(true);
  });
});

describe("verifyInkAuth: nonceStore object enforcement", () => {
  function makeStore(): NonceStore & { seen: Set<string> } {
    const seen = new Set<string>();
    return {
      seen,
      has: (n: string) => seen.has(n),
      add: (n: string) => { seen.add(n); },
    };
  }

  it("accepts first occurrence and records the nonce", async () => {
    const store = makeStore();
    const req = await makeSignedRequest("nonce-aaaaaaaaaaaaaaaaaaaa");
    const r = await verifyInkAuth({ ...req, nonceStore: store });
    expect(r.valid).toBe(true);
    expect(store.seen.has("nonce-aaaaaaaaaaaaaaaaaaaa")).toBe(true);
  });

  it("rejects a replay of the same nonce with nonce_replay", async () => {
    const store = makeStore();
    const req = await makeSignedRequest("nonce-bbbbbbbbbbbbbbbbbbbb");
    const first = await verifyInkAuth({ ...req, nonceStore: store });
    expect(first.valid).toBe(true);
    const second = await verifyInkAuth({ ...req, nonceStore: store });
    expect(second.valid).toBe(false);
    if (!second.valid) expect(second.error).toBe("nonce_replay");
  });

  it("rejects when body.nonce is missing and nonceStore is supplied", async () => {
    const store = makeStore();
    const req = await makeSignedRequest();
    // strip nonce
    const { nonce: _drop, ...bodyWithoutNonce } = req.body;
    const r = await verifyInkAuth({ ...req, body: bodyWithoutNonce, nonceStore: store });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error).toBe("missing_nonce");
  });

  it("rejects when body.nonce is not a string", async () => {
    const store = makeStore();
    const req = await makeSignedRequest();
    const r = await verifyInkAuth({ ...req, body: { ...req.body, nonce: 42 as unknown as string }, nonceStore: store });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error).toBe("missing_nonce");
  });

  it("rejects when body.nonce length is out of bounds", async () => {
    const store = makeStore();
    const reqShort = await makeSignedRequest("x");
    const rShort = await verifyInkAuth({ ...reqShort, nonceStore: store });
    expect(rShort.valid).toBe(false);
    if (!rShort.valid) expect(rShort.error).toBe("missing_nonce");

    const reqLong = await makeSignedRequest("n".repeat(257));
    const rLong = await verifyInkAuth({ ...reqLong, nonceStore: store });
    expect(rLong.valid).toBe(false);
    if (!rLong.valid) expect(rLong.error).toBe("missing_nonce");
  });

  it("does NOT record the nonce when the signature is invalid (avoids store pollution)", async () => {
    const store = makeStore();
    const req = await makeSignedRequest("nonce-cccccccccccccccccccc");
    // Tamper a middle char of the signature. The last base64url char of an
    // 86-char Ed25519 signature carries only 4 informational bits (the rest
    // are padding); flipping it can leave the decoded bytes unchanged. A
    // middle char always changes the decoded bytes.
    const parts = req.authHeader.split(" ");
    const sig = parts[1]!;
    const flip = (c: string) => (c === "A" ? "B" : "A");
    const tamperedSig = sig.slice(0, 40) + flip(sig[40]!) + sig.slice(41);
    const bad = { ...req, authHeader: `${parts[0]} ${tamperedSig}`, nonceStore: store };
    const r = await verifyInkAuth(bad);
    expect(r.valid).toBe(false);
    expect(store.seen.has("nonce-cccccccccccccccccccc")).toBe(false);
  });

  it("supports async has/add", async () => {
    const seen = new Set<string>();
    const store: NonceStore = {
      has: async (n: string) => seen.has(n),
      add: async (n: string) => { seen.add(n); },
    };
    const req = await makeSignedRequest("nonce-dddddddddddddddddddd");
    const first = await verifyInkAuth({ ...req, nonceStore: store });
    expect(first.valid).toBe(true);
    const second = await verifyInkAuth({ ...req, nonceStore: store });
    expect(second.valid).toBe(false);
    if (!second.valid) expect(second.error).toBe("nonce_replay");
  });

  it("fails closed if nonceStore.has throws", async () => {
    const store: NonceStore = {
      has: () => { throw new Error("backend down"); },
      add: () => {},
    };
    const req = await makeSignedRequest("nonce-eeeeeeeeeeeeeeeeeeee");
    const r = await verifyInkAuth({ ...req, nonceStore: store });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error).toBe("nonce_store_error");
  });

  it("fails closed if nonceStore.add throws (does not return valid)", async () => {
    const store: NonceStore = {
      has: () => false,
      add: () => { throw new Error("backend down"); },
    };
    const req = await makeSignedRequest("nonce-ffffffffffffffffffff");
    const r = await verifyInkAuth({ ...req, nonceStore: store });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error).toBe("nonce_store_error");
  });
});

// ── BLOCKER 2: verifyAuditEventChain ──

async function makeChain(count: number) {
  const kp = await generateKeypair();
  const agentId = deriveAgentId(kp.publicKey);
  const events: Record<string, unknown>[] = [];
  let prevHash: string | null = null;
  for (let i = 1; i <= count; i++) {
    const ev: Record<string, unknown> = {
      id: `01JBTEST${String(i).padStart(4, "0")}`,
      version: "ink-audit/1",
      agentId,
      sequence: i,
      previousEventHash: prevHash,
      eventType: "message.sent",
      timestamp: new Date(Date.parse("2026-01-01T00:00:00Z") + i * 1000).toISOString(),
      messageId: `msg-${i}`,
    };
    const sig = await signAuditEvent(ev, kp.privateKey);
    ev.agentSignature = sig;
    prevHash = await computeEventHash(ev);
    events.push(ev);
  }
  return events;
}

describe("verifyAuditEventChain: shape and emptiness", () => {
  it("rejects non-array input", async () => {
    const r = await verifyAuditEventChain(null as unknown as unknown[]);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error).toBe("invalid_input");
  });

  it("accepts an empty events array", async () => {
    const r = await verifyAuditEventChain([]);
    expect(r.valid).toBe(true);
  });

  it("rejects events containing non-objects", async () => {
    const r = await verifyAuditEventChain([null as unknown as Record<string, unknown>]);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error).toBe("invalid_event");
  });
});

describe("verifyAuditEventChain: well-formed chains", () => {
  it("validates a single event", async () => {
    const events = await makeChain(1);
    const r = await verifyAuditEventChain(events);
    expect(r.valid).toBe(true);
  });

  it("validates a five-event chain", async () => {
    const events = await makeChain(5);
    const r = await verifyAuditEventChain(events);
    expect(r.valid).toBe(true);
  });
});

describe("verifyAuditEventChain: sequence enforcement", () => {
  it("rejects a gap in sequence (1, 3)", async () => {
    const events = await makeChain(3);
    events.splice(1, 1); // remove middle event, now sequences are 1, 3
    const r = await verifyAuditEventChain(events);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error).toBe("sequence_gap");
  });

  it("rejects a fork (duplicate sequence with different content)", async () => {
    const events = await makeChain(2);
    // Append a duplicate-sequence event with different messageId
    const kp = await generateKeypair();
    const fork: Record<string, unknown> = {
      ...(events[1] as Record<string, unknown>),
      messageId: "msg-fork",
    };
    fork.agentSignature = await signAuditEvent(fork, kp.privateKey);
    events.push(fork);
    const r = await verifyAuditEventChain(events);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error === "sequence_fork" || r.error === "sequence_gap").toBe(true);
  });

  it("rejects decreasing sequence", async () => {
    const events = await makeChain(2);
    // Swap to make sequence go 2, 1
    [events[0], events[1]] = [events[1]!, events[0]!];
    const r = await verifyAuditEventChain(events);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error === "sequence_gap" || r.error === "previous_hash_mismatch").toBe(true);
  });

  it("rejects non-integer sequence", async () => {
    const events = await makeChain(1);
    (events[0] as Record<string, unknown>).sequence = 1.5;
    const r = await verifyAuditEventChain(events);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error).toBe("invalid_event");
  });
});

describe("verifyAuditEventChain: previousEventHash enforcement", () => {
  it("rejects a tampered previousEventHash on event[1]", async () => {
    const events = await makeChain(2);
    (events[1] as Record<string, unknown>).previousEventHash = "a".repeat(64);
    const r = await verifyAuditEventChain(events);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error).toBe("previous_hash_mismatch");
  });

  it("rejects when event[1].previousEventHash is null but it is not the first in the chain", async () => {
    const events = await makeChain(2);
    (events[1] as Record<string, unknown>).previousEventHash = null;
    const r = await verifyAuditEventChain(events);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.error).toBe("previous_hash_mismatch");
  });

  it("accepts when event[0].previousEventHash is non-null (cannot verify the boundary)", async () => {
    // Partial-window responses are valid: caller is responsible for
    // verifying the boundary against a prior anchor if they have one.
    const events = await makeChain(3);
    events.shift(); // drop event 1, now starts at sequence 2 with non-null prevHash
    const r = await verifyAuditEventChain(events);
    expect(r.valid).toBe(true);
  });
});
