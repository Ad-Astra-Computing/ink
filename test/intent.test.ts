import { describe, it, expect } from "vitest";
import {
  IntentTypeSchema,
  isWellFormedIntent,
  REGISTERED_INTENTS,
  CORE_INTENTS,
  validateEnvelope,
  validateIntentPayload,
  validateMessage,
  getPayloadSchema,
  MessageEnvelopeSchema,
} from "../src/models/intent.js";

function baseEnvelope(overrides: Record<string, unknown> = {}) {
  return {
    protocol: "ink/0.1",
    id: "msg-1",
    correlationId: "corr-1",
    createdAt: "2026-01-01T00:00:00.000Z",
    from: "did:web:sender.example",
    to: "did:web:receiver.example",
    intent: "ping",
    payload: {},
    signature: "A".repeat(86),
    ...overrides,
  };
}

describe("isWellFormedIntent / IntentTypeSchema (§3.1.1)", () => {
  it("accepts every registered intent", () => {
    for (const intent of REGISTERED_INTENTS) {
      expect(isWellFormedIntent(intent)).toBe(true);
      expect(IntentTypeSchema.safeParse(intent).success).toBe(true);
    }
  });

  it("accepts an unregistered but well-formed bare token", () => {
    expect(isWellFormedIntent("teleport")).toBe(true);
    expect(isWellFormedIntent("com")).toBe(true); // single label, no dot: bare, not vendor
  });

  it("accepts a well-formed vendor reverse-domain token", () => {
    expect(isWellFormedIntent("com.example.custom_intent")).toBe(true);
    expect(isWellFormedIntent("net.ad-astra.foo")).toBe(true);
  });

  it("rejects a string matching neither grammar", () => {
    for (const bad of [
      "",
      "a.",
      ".a",
      "a..b",
      "Com.Example.x",
      "Teleport",
      "123intent",
      "intent name",
      "intent-name",
      "a".repeat(64), // one over the 63-char bare cap
      `a.${"b".repeat(64)}`, // one label over the 63-char vendor-label cap
    ]) {
      expect(isWellFormedIntent(bad)).toBe(false);
      expect(IntentTypeSchema.safeParse(bad).success).toBe(false);
    }
  });

  it("rejects a vendor name over the 253-char total cap", () => {
    const label = "a".repeat(60);
    const over = Array.from({ length: 5 }, () => label).join("."); // 5*60 + 4 = 304 chars
    expect(over.length).toBeGreaterThan(253);
    expect(isWellFormedIntent(over)).toBe(false);
  });

  it("matches the exact string only: no case fold, trim, or normalization", () => {
    for (const variant of [" ping", "ping ", "PING", "Ping"]) {
      expect(isWellFormedIntent(variant)).toBe(false);
    }
  });

  it("marks exactly the two connection intents as core", () => {
    expect([...CORE_INTENTS].sort()).toEqual(["connection_request", "connection_response"]);
    for (const intent of CORE_INTENTS) {
      expect(REGISTERED_INTENTS).toContain(intent);
    }
  });
});

describe("validateEnvelope", () => {
  it("accepts a well-formed envelope with a registered intent", () => {
    const envelope = validateEnvelope(baseEnvelope());
    expect(envelope.intent).toBe("ping");
  });

  it("accepts an envelope carrying an unregistered but well-formed intent", () => {
    const envelope = validateEnvelope(baseEnvelope({ intent: "teleport", payload: { note: "hi" } }));
    expect(envelope.intent).toBe("teleport");
  });

  it("accepts an envelope carrying a vendor reverse-domain intent", () => {
    const envelope = validateEnvelope(baseEnvelope({ intent: "com.example.custom_intent", payload: {} }));
    expect(envelope.intent).toBe("com.example.custom_intent");
  });

  it("rejects an envelope whose intent matches neither grammar", () => {
    expect(() => validateEnvelope(baseEnvelope({ intent: "Not An Intent" }))).toThrow();
  });

  it("rejects a non-object payload for every intent, registered or not", () => {
    expect(() => validateEnvelope(baseEnvelope({ payload: "a string" }))).toThrow();
    expect(() => validateEnvelope(baseEnvelope({ payload: [] }))).toThrow();
    expect(() => validateEnvelope(baseEnvelope({ intent: "teleport", payload: "a string" }))).toThrow();
    expect(() => validateEnvelope(baseEnvelope({ intent: "teleport", payload: null }))).toThrow();
  });

  it("accepts an empty object payload for an unregistered intent", () => {
    expect(() => validateEnvelope(baseEnvelope({ intent: "teleport", payload: {} }))).not.toThrow();
  });

  it("rejects an envelope whose canonical form exceeds the 1 MiB ceiling", () => {
    const envelope = baseEnvelope({ payload: { note: "x".repeat(1_100_000) } });
    expect(() => validateEnvelope(envelope)).toThrow(/pre-signature validation/);
  });

  it("rejects an envelope carrying a lone UTF-16 surrogate in the payload", () => {
    const envelope = baseEnvelope({ payload: { note: "\uD800" } });
    expect(() => validateEnvelope(envelope)).toThrow(/pre-signature validation/);
  });

  it("rejects an envelope carrying an object key that would serialize as an escaped member name", () => {
    const envelope = baseEnvelope({ payload: { "bad\nkey": 1 } });
    expect(() => validateEnvelope(envelope)).toThrow(/pre-signature validation/);
  });

  it("accepts a bare intent that shares a name with an inherited Object.prototype member, instead of crashing", () => {
    // "constructor" is the only Object.prototype member name that is
    // entirely lowercase, so it alone passes the bare-token grammar. A
    // plain-object lookup without an own-property guard resolves it to the
    // inherited function instead of undefined.
    const intent = "constructor";
    const envelope = validateEnvelope(baseEnvelope({ intent, payload: { anything: "goes" } }));
    expect(envelope.intent).toBe(intent);
    expect(() => validateIntentPayload(intent, { anything: "goes" })).not.toThrow();
    expect(getPayloadSchema(intent)).not.toBe(Object.prototype.constructor);
  });

  it("MessageEnvelopeSchema alone (no validateEnvelope) enforces the same intent grammar", () => {
    expect(MessageEnvelopeSchema.safeParse(baseEnvelope({ intent: "Not An Intent" })).success).toBe(false);
    expect(MessageEnvelopeSchema.safeParse(baseEnvelope({ intent: "teleport" })).success).toBe(true);
  });
});

describe("validateIntentPayload / getPayloadSchema", () => {
  it("applies the exact registered schema for a registered intent", () => {
    expect(() => validateIntentPayload("ping", { note: "hi" })).not.toThrow();
    expect(() => validateIntentPayload("ping", { note: "hi", extra: true })).toThrow(); // .strict()
    expect(() => validateIntentPayload("retract", { targetMessageId: "m-1" })).not.toThrow();
  });

  it("applies no per-field schema for an unregistered or vendor intent", () => {
    expect(() => validateIntentPayload("teleport", { anything: "goes", nested: { ok: true } })).not.toThrow();
    expect(() => validateIntentPayload("com.example.custom_intent", {})).not.toThrow();
  });

  it("throws on a grammar-invalid intent before even looking at the payload", () => {
    expect(() => validateIntentPayload("Not An Intent", {})).toThrow();
  });

  it("getPayloadSchema never returns undefined", () => {
    expect(getPayloadSchema("ping")).toBeDefined();
    expect(getPayloadSchema("teleport")).toBeDefined();
    expect(getPayloadSchema("com.example.custom_intent")).toBeDefined();
  });
});

describe("validateMessage (combined convenience)", () => {
  it("behaves exactly as before for every registered intent", () => {
    expect(() => validateMessage(baseEnvelope({ intent: "ping", payload: { note: "hi" } }))).not.toThrow();
    expect(() => validateMessage(baseEnvelope({ intent: "ping", payload: { note: "hi", extra: 1 } }))).toThrow();
  });

  it("accepts a well-formed unregistered intent with any object payload", () => {
    expect(() => validateMessage(baseEnvelope({ intent: "teleport", payload: { x: 1 } }))).not.toThrow();
  });

  it("documents its own caveat: an unsupported REGISTERED intent with a malformed payload reports the payload failure, not unsupported_intent", () => {
    // validateMessage has no supported-intent list, so it cannot and does not
    // produce "unsupported_intent" itself; a receiver with a narrower
    // supported set must call validateEnvelope + checkIntentDisposition +
    // validateIntentPayload instead, exactly so this case does not arise.
    expect(() => validateMessage(baseEnvelope({ intent: "opportunity", payload: { title: "x" } }))).toThrow();
  });
});
