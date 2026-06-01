/**
 * v0.1.1 added `inboxEndpoint` as an optional synonym for `endpoint`.
 * The spec rule is that, when both are present, they MUST equal each
 * other — the alias is forward-compat, not a way to publish two
 * distinct inbound URLs. This test pins that invariant and the
 * `resolveAgentInbox(card)` helper.
 */

import { describe, it, expect } from "vitest";
import { AgentCardSchema, resolveAgentInbox } from "../src/models/agent-card.js";

const baseCard = {
  protocol: "ink/0.1" as const,
  agentId: "tulpa:zABC",
  handle: "alice.tulpa.network",
  displayName: "Alice",
  publicKeyMultibase: "zABCDEFGH",
  capabilities: {
    intentsAccepted: [],
    intentsSent: [],
  },
  availability: { timezone: "UTC" },
};

describe("AgentCard inboxEndpoint v0.1.1", () => {
  it("accepts endpoint alone (v0.1.0 shape, unchanged)", () => {
    const card = AgentCardSchema.parse({
      ...baseCard,
      endpoint: "https://example.com/ink/v1/zABC/intent",
    });
    expect(resolveAgentInbox(card)).toBe(
      "https://example.com/ink/v1/zABC/intent",
    );
  });

  it("accepts endpoint and inboxEndpoint when they agree", () => {
    const url = "https://example.com/ink/v1/zABC/intent";
    const card = AgentCardSchema.parse({
      ...baseCard,
      endpoint: url,
      inboxEndpoint: url,
    });
    expect(card.inboxEndpoint).toBe(url);
    expect(resolveAgentInbox(card)).toBe(url);
  });

  it("rejects a card where endpoint and inboxEndpoint disagree", () => {
    const r = AgentCardSchema.safeParse({
      ...baseCard,
      endpoint: "https://example.com/ink/v1/zABC/intent",
      inboxEndpoint: "https://attacker.example/ink/v1/zABC/intent",
    });
    expect(r.success).toBe(false);
    if (!r.success) {
      expect(r.error.issues.some((i) => i.path.includes("inboxEndpoint"))).toBe(true);
    }
  });
});
