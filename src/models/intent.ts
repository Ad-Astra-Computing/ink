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

// Reusable scalar caps. Timestamps cap at 64 chars (ISO-8601 fits in
// ~30), correlation/message IDs at 256, DIDs at 512. URL fields cap
// at 2048 BEFORE `.url()` parsing so the parser never runs on attacker-
// sized strings. Every exported schema is `.strict()` so adopters using
// the schemas directly (without `validateMessage()`) still get the
// same unknown-field rejection that the central validator applies.
const TIMESTAMP_MAX = 64;
const ID_MAX = 256;
const DID_MAX = 512;
const URL_MAX = 2048;

export const ScheduleMeetingPayloadSchema = z.object({
  proposedTimes: z.array(z.string().max(TIMESTAMP_MAX)).min(1).max(10),
  topic: z.string().max(500),
  format: z.enum(["video", "phone", "in_person", "async"]),
  urgency: z.enum(["low", "normal", "urgent"]),
  context: z.string().max(2000).optional(),
  location: z.string().max(500).optional(),
}).strict();

export const ScheduleMeetingResponsePayloadSchema = z.object({
  status: z.enum(["accepted", "declined", "countered"]),
  confirmedTime: z.string().max(TIMESTAMP_MAX).optional(),
  counterTimes: z.array(z.string().max(TIMESTAMP_MAX)).max(10).optional(),
  meetingLink: z.string().max(URL_MAX).url().optional(),
  note: z.string().max(1000).optional(),
  declineReason: z
    .enum(["unavailable", "not_interested", "too_busy", "deferred"])
    .optional(),
}).strict();

export const IntroRequestPayloadSchema = z.object({
  target: z.string().max(DID_MAX),
  reason: z.string().max(2000),
  context: z.string().max(2000).optional(),
  urgency: z.enum(["low", "normal"]),
}).strict();

export const IntroResponsePayloadSchema = z.object({
  status: z.enum(["forwarded", "declined", "pending_target"]),
  note: z.string().max(1000).optional(),
  targetResponse: z.enum(["accepted", "declined", "pending"]).optional(),
}).strict();

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
  expiresAt: z.string().max(TIMESTAMP_MAX).optional(),
  url: z.string().max(URL_MAX).url().optional(),
}).strict();

export const OpportunityResponsePayloadSchema = z.object({
  status: z.enum(["interested", "not_interested", "maybe_later"]),
  note: z.string().max(1000).optional(),
  followUpIntent: IntentTypeSchema.optional(),
}).strict();

export const ConnectionRequestPayloadSchema = z.object({
  method: z.enum(["qr", "intro", "discovery", "import"]),
  introducedBy: z.string().max(DID_MAX).optional(),
  context: z.string().max(2000),
  profileSnapshot: ProfileSnapshotSchema,
}).strict();

export const ConnectionResponsePayloadSchema = z.object({
  status: z.enum(["accepted", "declined", "pending"]),
  profileSnapshot: ProfileSnapshotSchema.optional(),
  note: z.string().max(1000).optional(),
}).strict();

export const FollowUpPayloadSchema = z.object({
  referenceId: z.string().max(ID_MAX),
  message: z.string().max(5000),
  actionRequested: z.enum(["reply", "schedule", "review", "none"]).optional(),
}).strict();

export const AskPayloadSchema = z.object({
  question: z.string().max(5000),
  context: z.string().max(2000).optional(),
  responseFormat: z.enum(["text", "choice"]).optional(),
  choices: z.array(z.string().max(500)).max(10).optional(),
  deadline: z.string().max(TIMESTAMP_MAX).optional(),
}).strict();

export const AskResponsePayloadSchema = z.object({
  answer: z.string().max(5000),
  choiceIndex: z.number().int().min(0).optional(),
}).strict();

export const PingPayloadSchema = z.object({
  note: z.string().max(1000).optional(),
}).strict();

export const RetractPayloadSchema = z.object({
  targetMessageId: z.string().max(ID_MAX),
  reason: z.string().max(1000).optional(),
}).strict();

export const ContextSharePayloadSchema = z.object({
  context: z.string().max(5000),
  category: z.enum(["professional_background", "project_update", "expertise", "availability", "general"]),
  referenceId: z.string().max(ID_MAX).optional(),
  expiresAt: z.string().max(TIMESTAMP_MAX).optional(),
}).strict();

export const MultiPartySyncPayloadSchema = z.object({
  enclaveType: z.enum(["meeting_sync"]),
  purpose: z.string().max(500),
  participants: z.array(z.string().max(DID_MAX)).min(2).max(20),
  expiresAt: z.string().max(TIMESTAMP_MAX),
}).strict();

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

// Caps for envelope-level fields. Signatures are base64url-encoded
// Ed25519 (64 bytes raw → 86 chars base64url, plus the legacy keyId=
// suffix). 256 is comfortable headroom without permitting megabyte
// signature blobs.
const SIGNATURE_MAX = 256;
const KEY_ID_MAX = 128;

export const MessageProvenanceSchema = z.object({
  origin: z.enum(["human", "agent_approved", "agent_autonomous"]),
  extensionId: z.string().max(ID_MAX),
  installationId: z.string().uuid(),
}).strict().optional();

/**
 * INK protocol versions a receiver accepts. ink/0.1 is the original wire
 * version; ink/0.2 differs only in the body-signature domain (see
 * src/crypto/sign.ts). The enum is strict: an unknown version is rejected
 * at schema validation, never inferred. Senders still emit ink/0.1 by
 * default; emitting ink/0.2 is a later, negotiated step.
 */
export const INK_PROTOCOL_VERSIONS = ["ink/0.1", "ink/0.2"] as const;
export const ProtocolVersionSchema = z.enum(INK_PROTOCOL_VERSIONS);
export type ProtocolVersion = z.infer<typeof ProtocolVersionSchema>;

export const MessageEnvelopeSchema = z.object({
  protocol: ProtocolVersionSchema,
  id: z.string().max(ID_MAX),
  correlationId: z.string().max(ID_MAX),
  createdAt: z.string().max(TIMESTAMP_MAX),
  expiresAt: z.string().max(TIMESTAMP_MAX).optional(),
  from: z.string().max(DID_MAX),
  to: z.string().max(DID_MAX),
  intent: IntentTypeSchema,
  payload: z.unknown(),
  signature: z.string().max(SIGNATURE_MAX),
  signingKeyId: z.string().max(KEY_ID_MAX).optional(),
  // HTTP §3.3 transport-auth metadata that rides alongside the
  // canonical envelope fields. The body-level signature commits to
  // both (they cannot be tampered in transit) and `verifyInkAuth`
  // reads them from the body for freshness + replay checks. Explicit
  // optional capped declarations are required for `.strict()` to keep
  // accepting documented sender envelopes (see README signing example).
  timestamp: z.string().max(TIMESTAMP_MAX).optional(),
  nonce: z.string().max(ID_MAX).optional(),
  provenance: MessageProvenanceSchema,
}).strict();

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
 *
 * Runtime-validates the `intent` argument against IntentTypeSchema so a
 * JS caller cannot pass an arbitrary string and silently get `undefined`
 * back; the function instead throws ZodError on an invalid intent.
 */
export function getPayloadSchema(intent: IntentType) {
  IntentTypeSchema.parse(intent);
  return payloadSchemas[intent];
}
