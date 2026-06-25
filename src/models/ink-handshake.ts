import { z } from "zod";
import { dualWireType } from "./wire-type.js";

// ── Transport identifiers (INK Containment §7) ──

export const InkTransportSchema = z.enum([
  "ink_http",
  "ink_ws",
  "extension_api",
  "voice",
  "line_phone",
  "human_review_queue",
]);

export type InkTransport = z.infer<typeof InkTransportSchema>;

// ── Backoff hints (INK Containment §5.2) ──

export const InkBackoffHintSchema = z.object({
  retryAfterSeconds: z.number().int().positive().optional(),
  cooldownUntil: z.string().datetime().optional(),
  backoffClass: z.enum(["sender", "intent_ref", "counterparty"]).optional(),
});

export type InkBackoffHint = z.infer<typeof InkBackoffHintSchema>;

// ── Agent Card visibility (INK Containment §6) ──

export const AgentCardVisibilitySchema = z.enum([
  "public",
  "network_only",
  "capability_gated",
  "private",
]);

export type AgentCardVisibility = z.infer<typeof AgentCardVisibilitySchema>;

// ── Challenge (network.tulpa.challenge) — Stage 2a ──

export const ChallengeTypeSchema = z.enum([
  "mutual_connection_proof",
  "identity_verification",
  "availability_query",
  "context_request",
  "none",
]);

export type ChallengeType = z.infer<typeof ChallengeTypeSchema>;

export const InkChallengeSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: dualWireType("challenge"),
  intentRef: z.string().max(256),
  challengeType: ChallengeTypeSchema,
  fields: z.array(z.string().max(256)).max(32).optional(),
  availableWindows: z.array(z.string().max(64)).max(32).optional(),
  contextFields: z.array(z.string().max(256)).max(32).optional(),
  nonce: z.string().max(256),
  timestamp: z.string().datetime(),
});

export type InkChallenge = z.infer<typeof InkChallengeSchema>;

// ── Rejection (network.tulpa.rejection) — Stage 2b ──

export const RejectionReasonSchema = z.enum([
  "policy_violation",
  "trust_threshold",
  "capacity",
  "unsupported_intent",
  "rate_limited",
  "expired",
  // Containment extension (Phase 1)
  "handshake_budget_exhausted",
  "counterparty_cooldown",
  "sender_rate_limited",
  "delegation_budget_exhausted",
  "transport_scope_violation",
]);

export type RejectionReason = z.infer<typeof RejectionReasonSchema>;

export const InkRejectionSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: dualWireType("rejection"),
  intentRef: z.string().max(256),
  reason: RejectionReasonSchema,
  detail: z.string().max(500).optional(),
  retryAfter: z.string().max(64).optional(),
  backoffHint: InkBackoffHintSchema.optional(),
  nonce: z.string().max(256),
  timestamp: z.string().datetime(),
});

export type InkRejection = z.infer<typeof InkRejectionSchema>;

// ── Resolution (network.tulpa.resolution) — Stage 3 ──

export const ResolutionOutcomeSchema = z.enum([
  "accepted",
  "declined",
  "escalated_to_human",
  "expired",
]);

export type ResolutionOutcome = z.infer<typeof ResolutionOutcomeSchema>;

export const ResolutionDetailsSchema = z.object({
  scheduledAt: z.string().max(64).optional(),
  duration: z.string().max(64).optional(),
}).passthrough();

export const InkResolutionSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: dualWireType("resolution"),
  intentRef: z.string().max(256),
  outcome: ResolutionOutcomeSchema,
  details: ResolutionDetailsSchema.optional(),
  counterpartyDid: z.string().max(512).optional(),
  nonce: z.string().max(256),
  timestamp: z.string().datetime(),
});

export type InkResolution = z.infer<typeof InkResolutionSchema>;
