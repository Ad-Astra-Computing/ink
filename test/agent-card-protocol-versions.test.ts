/**
 * Agent-card supportedProtocolVersions advertisement.
 *
 * Receivers advertise the message protocol versions they can verify. The
 * field is optional and forward compatible: an unknown version does not
 * make the card unparseable, and a missing field defaults to ink/0.1.
 */

import { describe, it, expect } from "vitest";
import { AgentCardSchema, agentSupportedProtocolVersions } from "../src/index.js";

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

describe("agent card supportedProtocolVersions", () => {
  it("a card without the field parses and defaults to ink/0.1", () => {
    const card = AgentCardSchema.parse({ ...baseCard });
    expect(card.supportedProtocolVersions).toBeUndefined();
    expect(agentSupportedProtocolVersions(card)).toEqual(["ink/0.1"]);
  });

  it("a card advertising both versions returns them", () => {
    const card = AgentCardSchema.parse({ ...baseCard, supportedProtocolVersions: ["ink/0.1", "ink/0.2"] });
    expect(agentSupportedProtocolVersions(card)).toEqual(["ink/0.1", "ink/0.2"]);
  });

  it("an empty advertised list defaults to ink/0.1", () => {
    expect(agentSupportedProtocolVersions({ supportedProtocolVersions: [] })).toEqual(["ink/0.1"]);
  });

  it("is forward compatible: an unknown advertised version does not break the card", () => {
    const card = AgentCardSchema.parse({ ...baseCard, supportedProtocolVersions: ["ink/0.1", "ink/0.9"] });
    expect(agentSupportedProtocolVersions(card)).toEqual(["ink/0.1", "ink/0.9"]);
  });

  it("rejects an over-long or oversized version list", () => {
    expect(AgentCardSchema.safeParse({ ...baseCard, supportedProtocolVersions: ["x".repeat(17)] }).success).toBe(false);
    expect(AgentCardSchema.safeParse({ ...baseCard, supportedProtocolVersions: Array(9).fill("ink/0.1") }).success).toBe(false);
  });
});
