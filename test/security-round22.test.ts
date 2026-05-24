/**
 * Security regression tests — round 22.
 *
 * Findings (Codex convergence pass on round 21):
 *  - HIGH: buildRedactedCard() dropped `keys.signing: []` because the
 *    check was truthy + length > 0. An authoritative empty signing
 *    set was downgraded to "no key block", letting peers fall back to
 *    publicKeyMultibase / bootstrap. Same family as the
 *    allowedTransports `[]` bug closed in round 20.
 *  - LOW: parseCheckpoint() walked an unbounded caller-supplied body
 *    before any reject. Added a body-size cap and per-line caps.
 */
import { describe, it, expect } from "vitest";
import { buildRedactedCard } from "../src/ink/discovery-gating.js";
import { parseCheckpoint, formatCheckpoint } from "../src/ink/checkpoint.js";
import type { AgentCard } from "../src/models/agent-card.js";

describe("buildRedactedCard: preserves an explicitly empty signing array", () => {
  it("a card with keys.signing=[] keeps an empty signing array in the redacted form", () => {
    const card: AgentCard = {
      protocol: "ink/0.1",
      agentId: "tulpa:test",
      handle: "test",
      displayName: "Test",
      endpoint: "https://example.com",
      publicKeyMultibase: "zabcdef",
      capabilities: { intentsAccepted: [], intentsSent: [] },
      availability: { timezone: "UTC" },
      keys: { signing: [], encryption: [] },
    } as unknown as AgentCard;
    const redacted = buildRedactedCard(card);
    expect(redacted.keys).toBeDefined();
    expect(redacted.keys!.signing).toEqual([]);
  });

  it("a card with no keys field at all gets no keys block in the redacted form", () => {
    const card: AgentCard = {
      protocol: "ink/0.1",
      agentId: "tulpa:test",
      handle: "test",
      displayName: "Test",
      endpoint: "https://example.com",
      publicKeyMultibase: "zabcdef",
      capabilities: { intentsAccepted: [], intentsSent: [] },
      availability: { timezone: "UTC" },
    } as unknown as AgentCard;
    const redacted = buildRedactedCard(card);
    expect(redacted.keys).toBeUndefined();
  });

  it("a card with one signing key is preserved", () => {
    const card: AgentCard = {
      protocol: "ink/0.1",
      agentId: "tulpa:test",
      handle: "test",
      displayName: "Test",
      endpoint: "https://example.com",
      publicKeyMultibase: "zabcdef",
      capabilities: { intentsAccepted: [], intentsSent: [] },
      availability: { timezone: "UTC" },
      keys: {
        signing: [
          {
            keyId: "k1",
            algorithm: "Ed25519",
            publicKeyMultibase: "zabcdef",
            status: "active",
            validFrom: "2026-01-01T00:00:00Z",
          },
        ],
        encryption: [],
      },
    } as unknown as AgentCard;
    const redacted = buildRedactedCard(card);
    expect(redacted.keys?.signing).toHaveLength(1);
    expect(redacted.keys!.signing[0]!.keyId).toBe("k1");
  });
});

describe("parseCheckpoint: rejects oversized inputs before parsing", () => {
  it("rejects a multi-megabyte body without scanning it", () => {
    const huge = "x".repeat(2_000_000);
    expect(parseCheckpoint(huge)).toBeNull();
  });

  it("rejects an empty body", () => {
    expect(parseCheckpoint("")).toBeNull();
  });

  it("rejects a body where a single line exceeds the per-line cap", () => {
    // Build a body that splits into exactly 4 lines and stays under
    // MAX_CHECKPOINT_BODY but blows the per-line cap on origin.
    const big = "x".repeat(500);
    const body = `${big}\n42\n${"0".repeat(64)}\n`;
    expect(parseCheckpoint(body)).toBeNull();
  });

  it("still parses a legitimate checkpoint", () => {
    const body = formatCheckpoint({
      origin: "tulpa.witness/main",
      treeSize: 12345,
      rootHash: "0".repeat(64),
    });
    const out = parseCheckpoint(body);
    expect(out).not.toBeNull();
    expect(out!.treeSize).toBe(12345);
    expect(out!.origin).toBe("tulpa.witness/main");
  });
});
