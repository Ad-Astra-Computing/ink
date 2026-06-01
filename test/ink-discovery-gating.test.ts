import { describe, it, expect } from "vitest";
import {
  buildRedactedCard,
  AgentCardQuerySchema,
  AgentCardResponseSchema,
  AgentCardDeniedSchema,
} from "../src/ink/discovery-gating.js";
import {
  AgentCardVisibilitySchema,
  type AgentCardVisibility,
} from "../src/models/ink-handshake.js";
import type { AgentCard } from "../src/models/agent-card.js";

// ── Visibility schema ──

describe("AgentCardVisibilitySchema", () => {
  it("accepts all valid visibility values", () => {
    const values: AgentCardVisibility[] = [
      "public",
      "network_only",
      "capability_gated",
      "private",
    ];
    for (const v of values) {
      const result = AgentCardVisibilitySchema.safeParse(v);
      expect(result.success, `visibility "${v}" should be valid`).toBe(true);
    }
  });

  it("rejects invalid visibility value", () => {
    const result = AgentCardVisibilitySchema.safeParse("semi_public");
    expect(result.success).toBe(false);
  });
});

// ── Redacted card ──

describe("buildRedactedCard", () => {
  const fullCard: AgentCard = {
    protocol: "ink/0.1",
    agentId: "agent:test123",
    handle: "alice.example.network",
    displayName: "Alice's Tulpa",
    endpoint: "https://example.network/ink/v1/agent:test123/intent",
    publicKeyMultibase: "z6Mk...",
    capabilities: {
      intentsAccepted: ["schedule_meeting", "intro_request"],
      intentsSent: ["intro_request"],
    },
    availability: {
      timezone: "America/New_York",
      meetingHours: "9-17",
      responseSla: "4h",
    },
  };

  it("includes only safe fields in redacted card", () => {
    const redacted = buildRedactedCard(fullCard);
    expect(redacted.agentId).toBe(fullCard.agentId);
    expect(redacted.displayName).toBe(fullCard.displayName);
    expect(redacted.supportsInk).toBe(true);
    expect(redacted.discoveryMode).toBe("authenticate_for_details");
    // INK v0.1.1 emits the protocol-generic name; the type union
    // still accepts the legacy "tulpa.agent.card" for inbound parsing.
    expect(redacted.type).toBe("ink.agent.card");
    expect(redacted.version).toBe("1.0");
  });

  it("does not include capabilities", () => {
    const redacted = buildRedactedCard(fullCard);
    expect((redacted as any).capabilities).toBeUndefined();
  });

  it("does not include endpoint", () => {
    const redacted = buildRedactedCard(fullCard);
    expect((redacted as any).endpoint).toBeUndefined();
  });

  it("includes publicKeyMultibase (public keys are safe to expose)", () => {
    // Ed25519 public keys are the agent's identity, not a secret. Hiding them
    // would prevent peers from verifying signed traffic from an agent with
    // non-public visibility across key rotation.
    const redacted = buildRedactedCard(fullCard);
    expect(redacted.publicKeyMultibase).toBe(fullCard.publicKeyMultibase);
  });

  it("does not include availability", () => {
    const redacted = buildRedactedCard(fullCard);
    expect((redacted as any).availability).toBeUndefined();
  });

  it("includes keys.signing block for rotation discovery", () => {
    // Needed so a peer can verify an Ed25519 signature made with a rotated
    // active key even when the rest of the Card is gated. Public signing
    // keys are safe to reveal.
    const cardWithKeys = {
      ...fullCard,
      keys: {
        signing: [
          { keyId: "k1", publicKeyMultibase: "zAAA", status: "active" as const, addedAt: "2026-01-01T00:00:00Z" },
          { keyId: "k0", publicKeyMultibase: "zBBB", status: "retired" as const, addedAt: "2025-01-01T00:00:00Z" },
        ],
        encryption: [],
      },
    };
    const redacted = buildRedactedCard(cardWithKeys as unknown as Parameters<typeof buildRedactedCard>[0]);
    expect(redacted.keys?.signing).toHaveLength(2);
    expect(redacted.keys?.signing[0]).toMatchObject({ keyId: "k1", publicKeyMultibase: "zAAA", status: "active" });
    expect(redacted.keys?.signing[1]).toMatchObject({ keyId: "k0", publicKeyMultibase: "zBBB", status: "retired" });
  });

  it("does not include profileSnapshot", () => {
    const cardWithProfile = {
      ...fullCard,
      profileSnapshot: { headline: "Security architect" },
    };
    const redacted = buildRedactedCard(cardWithProfile as unknown as Parameters<typeof buildRedactedCard>[0]);
    expect((redacted as { profileSnapshot?: unknown }).profileSnapshot).toBeUndefined();
  });
});

// ── Query/Response schemas ──

describe("AgentCardQuerySchema", () => {
  const validQuery = {
    protocol: "ink/0.1",
    type: "network.tulpa.agent_card_query",
    from: "did:plc:requester",
    nonce: "nonce123",
    timestamp: "2026-04-01T12:00:00Z",
  };

  it("parses a valid query", () => {
    const result = AgentCardQuerySchema.safeParse(validQuery);
    expect(result.success).toBe(true);
  });

  it("parses a query with requestedFields", () => {
    const result = AgentCardQuerySchema.safeParse({
      ...validQuery,
      requestedFields: ["capabilities", "availability"],
    });
    expect(result.success).toBe(true);
  });

  it("rejects missing from", () => {
    const { from, ...rest } = validQuery;
    const result = AgentCardQuerySchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects wrong type literal", () => {
    const result = AgentCardQuerySchema.safeParse({
      ...validQuery,
      type: "network.tulpa.intent",
    });
    expect(result.success).toBe(false);
  });
});

describe("AgentCardResponseSchema", () => {
  it("parses a valid response", () => {
    const result = AgentCardResponseSchema.safeParse({
      protocol: "ink/0.1",
      type: "network.tulpa.agent_card_response",
      card: {
        protocol: "ink/0.1",
        agentId: "agent:test",
        handle: "test.example.network",
        displayName: "Test",
        endpoint: "https://example.network/ink/v1/agent:test/intent",
        publicKeyMultibase: "z6Mk...",
        capabilities: { intentsAccepted: [], intentsSent: [] },
        availability: { timezone: "UTC" },
      },
      grantedFields: ["capabilities", "availability"],
      timestamp: "2026-04-01T12:00:00Z",
    });
    expect(result.success).toBe(true);
  });
});

describe("AgentCardDeniedSchema", () => {
  it("parses a valid denial", () => {
    const result = AgentCardDeniedSchema.safeParse({
      protocol: "ink/0.1",
      type: "network.tulpa.agent_card_denied",
      reason: "unknown_requester",
      timestamp: "2026-04-01T12:00:00Z",
    });
    expect(result.success).toBe(true);
  });

  it("accepts all valid deny reasons", () => {
    for (const reason of ["unknown_requester", "insufficient_trust", "not_connected"]) {
      const result = AgentCardDeniedSchema.safeParse({
        protocol: "ink/0.1",
        type: "network.tulpa.agent_card_denied",
        reason,
        timestamp: "2026-04-01T12:00:00Z",
      });
      expect(result.success, `reason "${reason}" should be valid`).toBe(true);
    }
  });

  it("rejects invalid deny reason", () => {
    const result = AgentCardDeniedSchema.safeParse({
      protocol: "ink/0.1",
      type: "network.tulpa.agent_card_denied",
      reason: "no_vibe",
      timestamp: "2026-04-01T12:00:00Z",
    });
    expect(result.success).toBe(false);
  });
});
