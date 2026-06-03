/**
 * Envelope-layer protocol version acceptance.
 *
 * The message envelope accepts ink/0.1 and ink/0.2 strictly: an unknown
 * version is rejected at schema validation, never inferred. This is the
 * layer that gives the version-keyed body-signature domain (see
 * src/crypto/sign.ts) its "reject unknown version" guarantee.
 */

import { describe, it, expect } from "vitest";
import {
  ProtocolVersionSchema,
  INK_PROTOCOL_VERSIONS,
  MessageEnvelopeSchema,
} from "../src/index.js";

function envelope(protocol: unknown): Record<string, unknown> {
  return {
    protocol,
    id: "01ABC",
    correlationId: "01DEF",
    createdAt: "2026-06-03T00:00:00Z",
    from: "did:key:zSender",
    to: "did:key:zRecipient",
    intent: "connection_request",
    payload: { method: "discovery" },
    signature: "x".repeat(86),
  };
}

describe("ProtocolVersionSchema", () => {
  it("exposes exactly the supported versions", () => {
    expect(INK_PROTOCOL_VERSIONS).toEqual(["ink/0.1", "ink/0.2"]);
  });

  it("accepts the known versions", () => {
    expect(ProtocolVersionSchema.parse("ink/0.1")).toBe("ink/0.1");
    expect(ProtocolVersionSchema.parse("ink/0.2")).toBe("ink/0.2");
  });

  it("rejects unknown or near-match versions", () => {
    for (const bad of ["ink/0.3", "ink/2.0", "ink/0.20", "ink/0.1 ", " ink/0.2", "INK/0.2", "", "0.1", "ink"]) {
      expect(ProtocolVersionSchema.safeParse(bad).success).toBe(false);
    }
  });

  it("rejects non-string versions", () => {
    for (const bad of [undefined, null, 1, {}, ["ink/0.1"]]) {
      expect(ProtocolVersionSchema.safeParse(bad).success).toBe(false);
    }
  });
});

describe("MessageEnvelopeSchema protocol acceptance", () => {
  it("accepts an ink/0.1 envelope", () => {
    expect(MessageEnvelopeSchema.safeParse(envelope("ink/0.1")).success).toBe(true);
  });

  it("accepts an ink/0.2 envelope", () => {
    expect(MessageEnvelopeSchema.safeParse(envelope("ink/0.2")).success).toBe(true);
  });

  it("rejects an unknown protocol version", () => {
    expect(MessageEnvelopeSchema.safeParse(envelope("ink/0.3")).success).toBe(false);
    expect(MessageEnvelopeSchema.safeParse(envelope("")).success).toBe(false);
  });
});
