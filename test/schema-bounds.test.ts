import { describe, it, expect } from "vitest";
import { AgentCardSchema } from "../src/models/agent-card.js";
import { InkAuditEventSchema, InkAuditResponseSchema } from "../src/models/ink-audit.js";

function validCard(overrides: Record<string, unknown> = {}) {
  return {
    protocol: "ink/0.1",
    agentId: "tulpa:zABC",
    handle: "agent.example",
    displayName: "Agent",
    endpoint: "https://example.com/ink",
    publicKeyMultibase: "zABCDEF",
    capabilities: { intentsAccepted: ["ping"], intentsSent: [] },
    availability: { timezone: "UTC" },
    ...overrides,
  };
}

function validAuditEvent(overrides: Record<string, unknown> = {}) {
  return {
    id: "e1",
    version: "ink-audit/1",
    agentId: "tulpa:zABC",
    agentSignature: "sig",
    sequence: 1,
    previousEventHash: null,
    eventType: "message.sent",
    timestamp: "2026-06-10T00:00:00.000Z",
    ...overrides,
  };
}

describe("AgentCard schema bounds", () => {
  it("accepts a well-formed card", () => {
    expect(AgentCardSchema.safeParse(validCard()).success).toBe(true);
  });

  it("rejects an over-length agentId", () => {
    expect(AgentCardSchema.safeParse(validCard({ agentId: "tulpa:z" + "a".repeat(600) })).success).toBe(false);
  });

  it("rejects an over-length endpoint URL", () => {
    expect(AgentCardSchema.safeParse(validCard({ endpoint: "https://example.com/" + "p".repeat(3000) })).success).toBe(false);
  });

  it("rejects an over-count intentsAccepted array", () => {
    const tooMany = Array.from({ length: 40 }, () => "ping");
    expect(AgentCardSchema.safeParse(validCard({ capabilities: { intentsAccepted: tooMany, intentsSent: [] } })).success).toBe(false);
  });

  it("rejects an unbounded timezone string", () => {
    expect(AgentCardSchema.safeParse(validCard({ availability: { timezone: "z".repeat(100) } })).success).toBe(false);
  });
});

describe("audit schema bounds", () => {
  it("accepts a well-formed audit event", () => {
    expect(InkAuditEventSchema.safeParse(validAuditEvent()).success).toBe(true);
  });

  it("rejects an over-length agentId on an audit event", () => {
    expect(InkAuditEventSchema.safeParse(validAuditEvent({ agentId: "z".repeat(600) })).success).toBe(false);
  });

  it("rejects an audit response carrying more than the bounded number of events", () => {
    const events = Array.from({ length: 1001 }, (_, i) => validAuditEvent({ id: `e${i}`, sequence: i + 1 }));
    const resp = {
      protocol: "ink/0.1",
      type: "network.tulpa.audit_response",
      messageId: "m1",
      events,
      responseSignature: "sig",
    };
    expect(InkAuditResponseSchema.safeParse(resp).success).toBe(false);
  });
});
