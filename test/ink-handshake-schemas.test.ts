import { describe, it, expect } from "vitest";
import {
  InkChallengeSchema,
  InkRejectionSchema,
  InkResolutionSchema,
} from "../src/models/ink-handshake.js";
import {
  IntentTypeSchema,
  ContextSharePayloadSchema,
} from "../src/models/intent.js";

// ── Helpers ──

const validNonce = "abc123nonce";
const validTimestamp = "2026-03-25T12:00:00Z";

// ── Challenge (network.tulpa.challenge) ──

describe("InkChallengeSchema", () => {
  const validChallenge = {
    protocol: "ink/0.1",
    type: "network.tulpa.challenge",
    intentRef: "msg:intent-001",
    challengeType: "identity_verification",
    nonce: validNonce,
    timestamp: validTimestamp,
  };

  it("parses a valid challenge with required fields only", () => {
    const result = InkChallengeSchema.safeParse(validChallenge);
    expect(result.success).toBe(true);
  });

  it("parses a valid challenge with all optional fields", () => {
    const result = InkChallengeSchema.safeParse({
      ...validChallenge,
      fields: ["name", "email"],
      availableWindows: ["2026-03-26T09:00:00Z/2026-03-26T10:00:00Z"],
      contextFields: ["role", "company"],
    });
    expect(result.success).toBe(true);
  });

  it("accepts all valid challengeType values", () => {
    const types = [
      "mutual_connection_proof",
      "identity_verification",
      "availability_query",
      "context_request",
      "none",
    ];
    for (const challengeType of types) {
      const result = InkChallengeSchema.safeParse({
        ...validChallenge,
        challengeType,
      });
      expect(result.success, `challengeType "${challengeType}" should be valid`).toBe(true);
    }
  });

  it("rejects invalid challengeType", () => {
    const result = InkChallengeSchema.safeParse({
      ...validChallenge,
      challengeType: "invalid_type",
    });
    expect(result.success).toBe(false);
  });

  it("rejects wrong protocol literal", () => {
    const result = InkChallengeSchema.safeParse({
      ...validChallenge,
      protocol: "ink/0.2",
    });
    expect(result.success).toBe(false);
  });

  it("rejects wrong type literal", () => {
    const result = InkChallengeSchema.safeParse({
      ...validChallenge,
      type: "network.tulpa.rejection",
    });
    expect(result.success).toBe(false);
  });

  it("rejects missing nonce", () => {
    const { nonce, ...rest } = validChallenge;
    const result = InkChallengeSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects missing timestamp", () => {
    const { timestamp, ...rest } = validChallenge;
    const result = InkChallengeSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects missing challengeType", () => {
    const { challengeType, ...rest } = validChallenge;
    const result = InkChallengeSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects missing intentRef", () => {
    const { intentRef, ...rest } = validChallenge;
    const result = InkChallengeSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("parses correctly when optional fields are absent", () => {
    const result = InkChallengeSchema.safeParse(validChallenge);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.fields).toBeUndefined();
      expect(result.data.availableWindows).toBeUndefined();
      expect(result.data.contextFields).toBeUndefined();
    }
  });

  it("rejects fields with non-string array items", () => {
    const result = InkChallengeSchema.safeParse({
      ...validChallenge,
      fields: [123, true],
    });
    expect(result.success).toBe(false);
  });
});

// ── Rejection (network.tulpa.rejection) ──

describe("InkRejectionSchema", () => {
  const validRejection = {
    protocol: "ink/0.1",
    type: "network.tulpa.rejection",
    intentRef: "msg:intent-001",
    reason: "capacity",
    nonce: validNonce,
    timestamp: validTimestamp,
  };

  it("parses a valid rejection with required fields only", () => {
    const result = InkRejectionSchema.safeParse(validRejection);
    expect(result.success).toBe(true);
  });

  it("parses a valid rejection with all optional fields", () => {
    const result = InkRejectionSchema.safeParse({
      ...validRejection,
      detail: "Sender trust score too low",
      retryAfter: "2026-03-26T12:00:00Z",
    });
    expect(result.success).toBe(true);
  });

  it("accepts all valid reason values", () => {
    const reasons = [
      "policy_violation",
      "trust_threshold",
      "capacity",
      "unsupported_intent",
      "rate_limited",
      "expired",
    ];
    for (const reason of reasons) {
      const result = InkRejectionSchema.safeParse({
        ...validRejection,
        reason,
      });
      expect(result.success, `reason "${reason}" should be valid`).toBe(true);
    }
  });

  it("rejects invalid reason value", () => {
    const result = InkRejectionSchema.safeParse({
      ...validRejection,
      reason: "bad_vibes",
    });
    expect(result.success).toBe(false);
  });

  it("rejects detail exceeding 500 characters", () => {
    const result = InkRejectionSchema.safeParse({
      ...validRejection,
      detail: "x".repeat(501),
    });
    expect(result.success).toBe(false);
  });

  it("accepts detail at exactly 500 characters", () => {
    const result = InkRejectionSchema.safeParse({
      ...validRejection,
      detail: "x".repeat(500),
    });
    expect(result.success).toBe(true);
  });

  it("rejects wrong protocol literal", () => {
    const result = InkRejectionSchema.safeParse({
      ...validRejection,
      protocol: "ink/1.0",
    });
    expect(result.success).toBe(false);
  });

  it("rejects wrong type literal", () => {
    const result = InkRejectionSchema.safeParse({
      ...validRejection,
      type: "network.tulpa.challenge",
    });
    expect(result.success).toBe(false);
  });

  it("rejects missing reason", () => {
    const { reason, ...rest } = validRejection;
    const result = InkRejectionSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects missing intentRef", () => {
    const { intentRef, ...rest } = validRejection;
    const result = InkRejectionSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects missing nonce", () => {
    const { nonce, ...rest } = validRejection;
    const result = InkRejectionSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects missing timestamp", () => {
    const { timestamp, ...rest } = validRejection;
    const result = InkRejectionSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("parses correctly when optional fields are absent", () => {
    const result = InkRejectionSchema.safeParse(validRejection);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.detail).toBeUndefined();
      expect(result.data.retryAfter).toBeUndefined();
    }
  });
});

// ── Resolution (network.tulpa.resolution) ──

describe("InkResolutionSchema", () => {
  const validResolution = {
    protocol: "ink/0.1",
    type: "network.tulpa.resolution",
    intentRef: "msg:abc123",
    outcome: "accepted",
    nonce: validNonce,
    timestamp: validTimestamp,
  };

  it("parses a valid resolution with required fields only", () => {
    const result = InkResolutionSchema.safeParse(validResolution);
    expect(result.success).toBe(true);
  });

  it("parses a valid resolution with all optional fields", () => {
    const result = InkResolutionSchema.safeParse({
      ...validResolution,
      details: {
        scheduledAt: "2026-03-27T14:00:00Z",
        duration: "30m",
      },
      counterpartyDid: "did:plc:abc123",
    });
    expect(result.success).toBe(true);
  });

  it("accepts all valid outcome values", () => {
    const outcomes = ["accepted", "declined", "escalated_to_human", "expired"];
    for (const outcome of outcomes) {
      const result = InkResolutionSchema.safeParse({
        ...validResolution,
        outcome,
      });
      expect(result.success, `outcome "${outcome}" should be valid`).toBe(true);
    }
  });

  it("rejects invalid outcome value", () => {
    const result = InkResolutionSchema.safeParse({
      ...validResolution,
      outcome: "maybe",
    });
    expect(result.success).toBe(false);
  });

  it("rejects wrong protocol literal", () => {
    const result = InkResolutionSchema.safeParse({
      ...validResolution,
      protocol: "ink/2.0",
    });
    expect(result.success).toBe(false);
  });

  it("rejects wrong type literal", () => {
    const result = InkResolutionSchema.safeParse({
      ...validResolution,
      type: "network.tulpa.challenge",
    });
    expect(result.success).toBe(false);
  });

  it("rejects missing intentRef", () => {
    const { intentRef, ...rest } = validResolution;
    const result = InkResolutionSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects missing outcome", () => {
    const { outcome, ...rest } = validResolution;
    const result = InkResolutionSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects missing nonce", () => {
    const { nonce, ...rest } = validResolution;
    const result = InkResolutionSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects missing timestamp", () => {
    const { timestamp, ...rest } = validResolution;
    const result = InkResolutionSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("parses correctly when optional fields are absent", () => {
    const result = InkResolutionSchema.safeParse(validResolution);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.details).toBeUndefined();
      expect(result.data.counterpartyDid).toBeUndefined();
    }
  });
});

// ── context_share intent type ──

describe("IntentTypeSchema — context_share", () => {
  it("accepts context_share as a valid intent type", () => {
    const result = IntentTypeSchema.safeParse("context_share");
    expect(result.success).toBe(true);
  });

  it("still accepts existing intent types", () => {
    const result = IntentTypeSchema.safeParse("schedule_meeting");
    expect(result.success).toBe(true);
  });

  it("rejects unknown intent types", () => {
    const result = IntentTypeSchema.safeParse("telepathy");
    expect(result.success).toBe(false);
  });
});

// ── ContextSharePayloadSchema ──

describe("ContextSharePayloadSchema", () => {
  const validPayload = {
    context: "I have 10 years of experience in distributed systems.",
    category: "professional_background",
  };

  it("parses a valid payload with required fields only", () => {
    const result = ContextSharePayloadSchema.safeParse(validPayload);
    expect(result.success).toBe(true);
  });

  it("parses a valid payload with all optional fields", () => {
    const result = ContextSharePayloadSchema.safeParse({
      ...validPayload,
      referenceId: "ref:xyz789",
      expiresAt: "2026-06-01T00:00:00Z",
    });
    expect(result.success).toBe(true);
  });

  it("accepts all valid category values", () => {
    const categories = [
      "professional_background",
      "project_update",
      "expertise",
      "availability",
      "general",
    ];
    for (const category of categories) {
      const result = ContextSharePayloadSchema.safeParse({
        ...validPayload,
        category,
      });
      expect(result.success, `category "${category}" should be valid`).toBe(true);
    }
  });

  it("rejects invalid category value", () => {
    const result = ContextSharePayloadSchema.safeParse({
      ...validPayload,
      category: "hobbies",
    });
    expect(result.success).toBe(false);
  });

  it("rejects context exceeding 5000 characters", () => {
    const result = ContextSharePayloadSchema.safeParse({
      ...validPayload,
      context: "x".repeat(5001),
    });
    expect(result.success).toBe(false);
  });

  it("accepts context at exactly 5000 characters", () => {
    const result = ContextSharePayloadSchema.safeParse({
      ...validPayload,
      context: "x".repeat(5000),
    });
    expect(result.success).toBe(true);
  });

  it("rejects missing context", () => {
    const { context, ...rest } = validPayload;
    const result = ContextSharePayloadSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects missing category", () => {
    const { category, ...rest } = validPayload;
    const result = ContextSharePayloadSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("parses correctly when optional fields are absent", () => {
    const result = ContextSharePayloadSchema.safeParse(validPayload);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.referenceId).toBeUndefined();
      expect(result.data.expiresAt).toBeUndefined();
    }
  });
});
