import { z } from "zod";
import { ProfileSnapshotSchema } from "./profile.js";

// --- Intent Types ---

export const IntentTypeSchema = z.enum([
  "schedule_meeting",
  "schedule_meeting_response",
  "intro_request",
  "intro_response",
  "opportunity",
  "opportunity_response",
  "follow_up",
  "ask",
  "ask_response",
  "connection_request",
  "connection_response",
  "context_share",
  "ping",
  "retract",
  "multi_party_sync",
]);

export type IntentType = z.infer<typeof IntentTypeSchema>;

// --- Intent Payloads ---

export const ScheduleMeetingPayloadSchema = z.object({
  proposedTimes: z.array(z.string()).min(1).max(10),
  topic: z.string().max(500),
  format: z.enum(["video", "phone", "in_person", "async"]),
  urgency: z.enum(["low", "normal", "urgent"]),
  context: z.string().max(2000).optional(),
  location: z.string().max(500).optional(),
});

export const ScheduleMeetingResponsePayloadSchema = z.object({
  status: z.enum(["accepted", "declined", "countered"]),
  confirmedTime: z.string().optional(),
  counterTimes: z.array(z.string()).max(10).optional(),
  meetingLink: z.string().url().optional(),
  note: z.string().max(1000).optional(),
  declineReason: z
    .enum(["unavailable", "not_interested", "too_busy", "deferred"])
    .optional(),
});

export const IntroRequestPayloadSchema = z.object({
  target: z.string(),
  reason: z.string().max(2000),
  context: z.string().max(2000).optional(),
  urgency: z.enum(["low", "normal"]),
});

export const IntroResponsePayloadSchema = z.object({
  status: z.enum(["forwarded", "declined", "pending_target"]),
  note: z.string().max(1000).optional(),
  targetResponse: z.enum(["accepted", "declined", "pending"]).optional(),
});

export const OpportunityPayloadSchema = z.object({
  type: z.enum([
    "role",
    "investment",
    "collaboration",
    "advisory",
    "event",
    "other",
  ]),
  title: z.string().max(500),
  org: z.string().max(200).optional(),
  description: z.string().max(5000),
  matchReason: z.string().max(2000),
  expiresAt: z.string().optional(),
  url: z.string().url().optional(),
});

export const OpportunityResponsePayloadSchema = z.object({
  status: z.enum(["interested", "not_interested", "maybe_later"]),
  note: z.string().max(1000).optional(),
  followUpIntent: IntentTypeSchema.optional(),
});

export const ConnectionRequestPayloadSchema = z.object({
  method: z.enum(["qr", "intro", "discovery", "import"]),
  introducedBy: z.string().optional(),
  context: z.string().max(2000),
  profileSnapshot: ProfileSnapshotSchema,
});

export const ConnectionResponsePayloadSchema = z.object({
  status: z.enum(["accepted", "declined", "pending"]),
  profileSnapshot: ProfileSnapshotSchema.optional(),
  note: z.string().max(1000).optional(),
});

export const FollowUpPayloadSchema = z.object({
  referenceId: z.string(),
  message: z.string().max(5000),
  actionRequested: z.enum(["reply", "schedule", "review", "none"]).optional(),
});

export const AskPayloadSchema = z.object({
  question: z.string().max(5000),
  context: z.string().max(2000).optional(),
  responseFormat: z.enum(["text", "choice"]).optional(),
  choices: z.array(z.string().max(500)).max(10).optional(),
  deadline: z.string().optional(),
});

export const AskResponsePayloadSchema = z.object({
  answer: z.string().max(5000),
  choiceIndex: z.number().int().min(0).optional(),
});

export const PingPayloadSchema = z.object({
  note: z.string().max(1000).optional(),
});

export const RetractPayloadSchema = z.object({
  targetMessageId: z.string(),
  reason: z.string().max(1000).optional(),
});

export const ContextSharePayloadSchema = z.object({
  context: z.string().max(5000),
  category: z.enum(["professional_background", "project_update", "expertise", "availability", "general"]),
  referenceId: z.string().optional(),
  expiresAt: z.string().optional(),
});

export const MultiPartySyncPayloadSchema = z.object({
  enclaveType: z.enum(["meeting_sync"]),
  purpose: z.string().max(500),
  participants: z.array(z.string()).min(2).max(20),
  expiresAt: z.string(),
});

// --- Payload discriminated union ---

const payloadSchemas = {
  schedule_meeting: ScheduleMeetingPayloadSchema,
  schedule_meeting_response: ScheduleMeetingResponsePayloadSchema,
  intro_request: IntroRequestPayloadSchema,
  intro_response: IntroResponsePayloadSchema,
  opportunity: OpportunityPayloadSchema,
  opportunity_response: OpportunityResponsePayloadSchema,
  follow_up: FollowUpPayloadSchema,
  ask: AskPayloadSchema,
  ask_response: AskResponsePayloadSchema,
  connection_request: ConnectionRequestPayloadSchema,
  connection_response: ConnectionResponsePayloadSchema,
  context_share: ContextSharePayloadSchema,
  ping: PingPayloadSchema,
  retract: RetractPayloadSchema,
  multi_party_sync: MultiPartySyncPayloadSchema,
} as const;

// --- Message Envelope ---

export const MessageProvenanceSchema = z.object({
  origin: z.enum(["human", "agent_approved", "agent_autonomous"]),
  extensionId: z.string(),
  installationId: z.string().uuid(),
}).optional();

export const MessageEnvelopeSchema = z.object({
  protocol: z.literal("ink/0.1"),
  id: z.string(),
  correlationId: z.string(),
  createdAt: z.string(),
  expiresAt: z.string().optional(),
  from: z.string(),
  to: z.string(),
  intent: IntentTypeSchema,
  payload: z.unknown(),
  signature: z.string(),
  signingKeyId: z.string().optional(),
  provenance: MessageProvenanceSchema,
});

export type MessageEnvelope = z.infer<typeof MessageEnvelopeSchema>;

/**
 * Validate a message envelope AND its payload based on the intent type.
 * Returns the validated message or throws a ZodError.
 */
export function validateMessage(raw: unknown): MessageEnvelope {
  const envelope = MessageEnvelopeSchema.parse(raw);
  const payloadSchema = payloadSchemas[envelope.intent];
  // Validate payload strictly — reject unknown fields
  payloadSchema.strict().parse(envelope.payload);
  return envelope;
}

/**
 * Get the payload schema for a given intent type.
 */
export function getPayloadSchema(intent: IntentType) {
  return payloadSchemas[intent];
}
