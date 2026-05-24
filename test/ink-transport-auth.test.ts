import { describe, it, expect } from "vitest";
import {
  InkTransportSchema,
  InkBackoffHintSchema,
  RejectionReasonSchema,
} from "../src/models/ink-handshake.js";
import {
  resolveEffectiveTransports,
  checkTransportAllowed,
  checkTransportAttenuation,
  LEGACY_MIGRATION_TRANSPORTS,
} from "../src/ink/transport-auth.js";

// ── Schema tests ──

describe("InkTransportSchema", () => {
  it("accepts all valid transport identifiers", () => {
    const transports = [
      "ink_http",
      "ink_ws",
      "extension_api",
      "voice",
      "line_phone",
      "human_review_queue",
    ];
    for (const t of transports) {
      const result = InkTransportSchema.safeParse(t);
      expect(result.success, `transport "${t}" should be valid`).toBe(true);
    }
  });

  it("rejects invalid transport identifiers", () => {
    const result = InkTransportSchema.safeParse("carrier_pigeon");
    expect(result.success).toBe(false);
  });
});

describe("InkBackoffHintSchema", () => {
  it("parses a valid backoff hint with all fields", () => {
    const result = InkBackoffHintSchema.safeParse({
      retryAfterSeconds: 30,
      cooldownUntil: "2026-04-01T12:00:00Z",
      backoffClass: "sender",
    });
    expect(result.success).toBe(true);
  });

  it("parses an empty object (all fields optional)", () => {
    const result = InkBackoffHintSchema.safeParse({});
    expect(result.success).toBe(true);
  });

  it("accepts all valid backoffClass values", () => {
    for (const cls of ["sender", "intent_ref", "counterparty"]) {
      const result = InkBackoffHintSchema.safeParse({ backoffClass: cls });
      expect(result.success, `backoffClass "${cls}" should be valid`).toBe(true);
    }
  });

  it("rejects invalid backoffClass", () => {
    const result = InkBackoffHintSchema.safeParse({ backoffClass: "global" });
    expect(result.success).toBe(false);
  });

  it("rejects negative retryAfterSeconds", () => {
    const result = InkBackoffHintSchema.safeParse({ retryAfterSeconds: -5 });
    expect(result.success).toBe(false);
  });
});

describe("new rejection reasons", () => {
  it("accepts containment rejection reasons", () => {
    const newReasons = [
      "handshake_budget_exhausted",
      "counterparty_cooldown",
      "sender_rate_limited",
      "delegation_budget_exhausted",
      "transport_scope_violation",
    ];
    for (const reason of newReasons) {
      const result = RejectionReasonSchema.safeParse(reason);
      expect(result.success, `reason "${reason}" should be valid`).toBe(true);
    }
  });

  it("still accepts existing rejection reasons", () => {
    const existing = [
      "policy_violation",
      "trust_threshold",
      "capacity",
      "unsupported_intent",
      "rate_limited",
      "expired",
    ];
    for (const reason of existing) {
      const result = RejectionReasonSchema.safeParse(reason);
      expect(result.success, `existing reason "${reason}" should still be valid`).toBe(true);
    }
  });
});

// ── Transport-bound authorization logic ──

describe("resolveEffectiveTransports", () => {
  it("returns explicit allowedTransports when present", () => {
    const result = resolveEffectiveTransports(["ink_http", "voice"], "0.3");
    expect(result).toEqual(["ink_http", "voice"]);
  });

  it("defaults v0.3 tokens without allowedTransports to ink_http only", () => {
    const result = resolveEffectiveTransports(undefined, "0.3");
    expect(result).toEqual(["ink_http"]);
  });

  it("defaults legacy tokens (no tokenVersion) to permissive set before migration deadline", () => {
    const beforeDeadline = new Date("2026-06-30T00:00:00Z");
    const result = resolveEffectiveTransports(undefined, undefined, beforeDeadline);
    expect(result).toEqual(LEGACY_MIGRATION_TRANSPORTS);
  });

  it("defaults legacy tokens to ink_http only after migration deadline", () => {
    const afterDeadline = new Date("2026-07-02T00:00:00Z");
    const result = resolveEffectiveTransports(undefined, undefined, afterDeadline);
    expect(result).toEqual(["ink_http"]);
  });

  it("defaults legacy tokens to ink_http on the exact migration deadline", () => {
    const onDeadline = new Date("2026-07-01T00:00:00Z");
    const result = resolveEffectiveTransports(undefined, undefined, onDeadline);
    expect(result).toEqual(["ink_http"]);
  });

  it("respects explicit allowedTransports even on legacy tokens", () => {
    const result = resolveEffectiveTransports(["voice"], undefined, new Date("2026-06-01T00:00:00Z"));
    expect(result).toEqual(["voice"]);
  });
});

describe("checkTransportAllowed", () => {
  it("accepts when current transport is in allowed list", () => {
    const result = checkTransportAllowed("ink_http", ["ink_http", "voice"]);
    expect(result.allowed).toBe(true);
  });

  it("rejects when current transport is not in allowed list", () => {
    const result = checkTransportAllowed("extension_api", ["ink_http"]);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("transport_scope_violation");
  });

  it("rejects ink_http token used on voice transport", () => {
    const result = checkTransportAllowed("voice", ["ink_http"]);
    expect(result.allowed).toBe(false);
  });

  it("accepts voice transport when explicitly allowed", () => {
    const result = checkTransportAllowed("voice", ["ink_http", "voice"]);
    expect(result.allowed).toBe(true);
  });
});

describe("checkTransportAttenuation", () => {
  it("accepts when child transports are a subset of parent", () => {
    const result = checkTransportAttenuation(
      ["ink_http", "voice"],
      ["ink_http"],
    );
    expect(result.valid).toBe(true);
  });

  it("accepts when child transports are identical to parent", () => {
    const result = checkTransportAttenuation(
      ["ink_http", "voice"],
      ["ink_http", "voice"],
    );
    expect(result.valid).toBe(true);
  });

  it("rejects when child adds a transport parent did not allow", () => {
    const result = checkTransportAttenuation(
      ["ink_http"],
      ["ink_http", "extension_api"],
    );
    expect(result.valid).toBe(false);
    expect(result.addedTransports).toEqual(["extension_api"]);
  });

  it("rejects when child adds multiple transports parent did not allow", () => {
    const result = checkTransportAttenuation(
      ["ink_http"],
      ["ink_http", "voice", "line_phone"],
    );
    expect(result.valid).toBe(false);
    expect(result.addedTransports).toEqual(["voice", "line_phone"]);
  });

  it("accepts empty child transport list (narrows to nothing)", () => {
    const result = checkTransportAttenuation(
      ["ink_http", "voice"],
      [],
    );
    expect(result.valid).toBe(true);
  });
});
