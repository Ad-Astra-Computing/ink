/**
 * Agent-card opt-in discovery descriptor (#188).
 *
 * A card MAY carry an optional `discovery` object that opts the agent in to
 * being surfaced by a directory/index. It is additive and forward compatible:
 * a card without it parses unchanged and is not discoverable. The descriptor
 * can only ever NARROW exposure: its `scope` reuses the card `visibility`
 * enum and MUST NOT exceed the card's `visibility` (the hard upper bound).
 * Self-declared `tags` are hints, not verified claims.
 */

import { describe, it, expect } from "vitest";
import {
  AgentCardSchema,
  isDiscoverable,
  effectiveDiscoveryScope,
} from "../src/index.js";

const baseCard = {
  protocol: "ink/0.1" as const,
  agentId: "tulpa:zABC",
  handle: "alice.tulpa.network",
  displayName: "Alice",
  endpoint: "https://example.com/ink/v1/zABC/intent",
  publicKeyMultibase: "zABCDEFGH",
  capabilities: { intentsAccepted: [], intentsSent: [] },
  availability: { timezone: "UTC" },
};

const ts = "2026-06-26T00:00:00.000Z";

describe("agent card discovery descriptor", () => {
  it("a card without a discovery object parses and is not discoverable", () => {
    const card = AgentCardSchema.parse({ ...baseCard });
    expect(card.discovery).toBeUndefined();
    expect(isDiscoverable(card)).toBe(false);
    expect(effectiveDiscoveryScope(card)).toBeNull();
  });

  it("discovery is opt-in: enabled:false is parsed but not discoverable", () => {
    const card = AgentCardSchema.parse({
      ...baseCard,
      visibility: "public",
      discovery: { enabled: false, scope: "public" },
    });
    expect(isDiscoverable(card)).toBe(false);
    expect(effectiveDiscoveryScope(card)).toBeNull();
  });

  it("an enabled descriptor at or below visibility is accepted and discoverable", () => {
    const card = AgentCardSchema.parse({
      ...baseCard,
      visibility: "public",
      discovery: { enabled: true, scope: "public", tags: ["hiring", "ai"], queryable: true, updatedAt: ts },
    });
    expect(isDiscoverable(card)).toBe(true);
    expect(effectiveDiscoveryScope(card)).toBe("public");
    expect(card.discovery?.tags).toEqual(["hiring", "ai"]);
  });

  it("the descriptor may narrow exposure below visibility", () => {
    const card = AgentCardSchema.parse({
      ...baseCard,
      visibility: "public",
      discovery: { enabled: true, scope: "network_only" },
    });
    expect(effectiveDiscoveryScope(card)).toBe("network_only");
  });

  it("rejects a scope wider than the card's visibility (hard upper bound)", () => {
    expect(AgentCardSchema.safeParse({
      ...baseCard,
      visibility: "network_only",
      discovery: { enabled: true, scope: "public" },
    }).success).toBe(false);
    expect(AgentCardSchema.safeParse({
      ...baseCard,
      visibility: "private",
      discovery: { enabled: true, scope: "network_only" },
    }).success).toBe(false);
    expect(AgentCardSchema.safeParse({
      ...baseCard,
      visibility: "capability_gated",
      discovery: { enabled: true, scope: "public" },
    }).success).toBe(false);
  });

  it("treats an absent visibility as the public upper bound (the card is publicly fetchable)", () => {
    const card = AgentCardSchema.parse({
      ...baseCard,
      discovery: { enabled: true, scope: "public" },
    });
    expect(card.visibility).toBeUndefined();
    expect(effectiveDiscoveryScope(card)).toBe("public");
  });

  it("accepts an enabled private-scope descriptor under private visibility", () => {
    const card = AgentCardSchema.parse({
      ...baseCard,
      visibility: "private",
      discovery: { enabled: true, scope: "private" },
    });
    expect(effectiveDiscoveryScope(card)).toBe("private");
  });

  it("requires enabled and scope inside the descriptor", () => {
    expect(AgentCardSchema.safeParse({ ...baseCard, discovery: { scope: "public" } }).success).toBe(false);
    expect(AgentCardSchema.safeParse({ ...baseCard, discovery: { enabled: true } }).success).toBe(false);
  });

  it("rejects an unknown scope enum value", () => {
    expect(AgentCardSchema.safeParse({
      ...baseCard,
      visibility: "public",
      discovery: { enabled: true, scope: "everyone" },
    }).success).toBe(false);
  });

  it("bounds tags: at most 32, each non-empty and at most 64 chars", () => {
    expect(AgentCardSchema.safeParse({
      ...baseCard,
      visibility: "public",
      discovery: { enabled: true, scope: "public", tags: Array(33).fill("x") },
    }).success).toBe(false);
    expect(AgentCardSchema.safeParse({
      ...baseCard,
      visibility: "public",
      discovery: { enabled: true, scope: "public", tags: [""] },
    }).success).toBe(false);
    expect(AgentCardSchema.safeParse({
      ...baseCard,
      visibility: "public",
      discovery: { enabled: true, scope: "public", tags: ["x".repeat(65)] },
    }).success).toBe(false);
  });

  it("requires a strict RFC 3339 updatedAt when present", () => {
    expect(AgentCardSchema.safeParse({
      ...baseCard,
      visibility: "public",
      discovery: { enabled: true, scope: "public", updatedAt: "2026-06-26" },
    }).success).toBe(false);
  });

  it("is forward compatible: an unknown descriptor key is ignored, not rejected", () => {
    const parsed = AgentCardSchema.safeParse({
      ...baseCard,
      visibility: "public",
      discovery: { enabled: true, scope: "public", rank: 5, capabilities: ["x"] },
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect((parsed.data.discovery as Record<string, unknown>).rank).toBeUndefined();
    }
  });

  it("isDiscoverable and effectiveDiscoveryScope work on a discovery-only shape", () => {
    expect(isDiscoverable({ discovery: { enabled: true, scope: "public" } })).toBe(true);
    expect(isDiscoverable({ discovery: undefined })).toBe(false);
    expect(effectiveDiscoveryScope({ visibility: "public", discovery: { enabled: true, scope: "network_only" } })).toBe("network_only");
  });
});
