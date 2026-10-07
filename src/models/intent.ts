import { z } from "zod";
import { ProfileSnapshotSchema } from "./profile.js";
import { isWithinBounds, violatesSignableBounds, UNSIGNABLE_BODY_MESSAGE } from "../crypto/sign.js";

// --- Intent vocabulary (Protocol §3.1.1) ---

/**
 * The intent names this version of the library ships a payload schema for.
 * This is NOT the full set of intents a receiver may accept: Protocol
 * §3.1.1 opens the `intent` field to any syntactically well-formed bare
 * token or reverse-domain vendor token, registered or not, so a newer
 * registered name or a vendor's own intent reaches an older build as
 * `unsupported_intent` rather than a schema rejection. This list is only the
 * lookup key for `payloadSchemas` below.
 */
export const REGISTERED_INTENTS = [
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
] as const;

export type RegisteredIntentType = (typeof REGISTERED_INTENTS)[number];

/**
 * The two intents every conformant implementation MUST handle, since first
 * contact depends on them. Every other registered or vendor intent is
 * optional: a receiver supports whichever ones it chooses to.
 */
export const CORE_INTENTS = ["connection_request", "connection_response"] as const;

/**
 * A registered intent is a lowercase bare token: a letter, then up to 62
 * more letters, digits or underscores (63 chars total, the same cap a DNS
 * label uses). It never contains a dot.
 */
const BARE_INTENT_RE = /^[a-z][a-z0-9_]{0,62}$/;

/**
 * A vendor intent is a lowercase reverse-domain token: at least two labels
 * separated by dots, each 1-63 chars of `[a-z0-9]`, `-` or `_`, not starting
 * or ending with `-` or `_`. It is owned and defined by whoever controls the
 * reversed domain; INK does not verify that ownership on the wire. A single
 * label with no dot (for example "com") is a well-formed, unregistered BARE
 * token, not a vendor token, accepted at the schema layer and, unless
 * some receiver happens to support it, answered `unsupported_intent`.
 */
const VENDOR_LABEL = "[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?";
const VENDOR_INTENT_RE = new RegExp(`^${VENDOR_LABEL}(?:\\.${VENDOR_LABEL})+$`);

/** Total length cap for either intent form, in UTF-16 code units. Both
 * grammars are pure ASCII, so this is also a byte and code-point count. */
const INTENT_MAX = 253;

/**
 * Whether `value` is a syntactically well-formed intent: a registered-shape
 * bare token or a vendor-shape reverse-domain token. This answers nothing
 * about whether any particular receiver supports it; that is
 * `checkIntentDisposition` in `ink/encryption-policy.ts`, an application
 * decision, not a wire validity rule. The match is on the exact string: no
 * case folding, no trimming, no Unicode normalization, anchored at both
 * ends (no `i`, `u` or `m` flag).
 */
export function isWellFormedIntent(value: string): boolean {
  if (value.length === 0 || value.length > INTENT_MAX) return false;
  return BARE_INTENT_RE.test(value) || VENDOR_INTENT_RE.test(value);
}

export const IntentTypeSchema = z
  .string()
  .min(1)
  .max(INTENT_MAX)
  .refine(isWellFormedIntent, {
    message:
      "intent must be a registered bare token (^[a-z][a-z0-9_]{0,62}$) or a reverse-domain vendor token (two or more dot-separated [a-z0-9_-] labels)",
  });

export type IntentType = string;

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

/**
 * `payload` (Protocol §3.1) is a JSON object for every intent, registered or
 * not: this is what lets the complexity bound and the malformed-member rule
 * apply the same way regardless of whether the library knows the intent's
 * specific shape. An empty object is fine. A vendor or otherwise unregistered
 * intent gets no further structural check here; `payloadSchemas` below
 * supplies the strict per-field schema only for a registered intent.
 */
const PayloadObjectSchema = z.custom<Record<string, unknown>>(
  (v) => typeof v === "object" && v !== null && !Array.isArray(v),
  { message: "payload must be a JSON object" },
);

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
  payload: PayloadObjectSchema,
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
 * Validate only the envelope: schema shape, the open intent grammar, the
 * payload-is-an-object requirement, and the two size bounds every INK body
 * must fit under before any signature work runs. Does NOT validate the
 * payload against its intent-specific schema. Call `validateIntentPayload`
 * for that, after deciding (via `checkIntentDisposition` in
 * `ink/encryption-policy.ts`) that this receiver actually supports the
 * intent. Splitting the two means an intent a receiver does not support
 * never has its payload schema-checked at all, so an unsupported intent with
 * a malformed payload still reports `unsupported_intent`, not a payload
 * error, which is the order Protocol §3.4 requires.
 *
 * `raw` is assumed to be a JSON-decoded value (the output of `JSON.parse`
 * or an equivalent decoder), never a hand-constructed object a caller built
 * directly. A function, symbol, bigint or `undefined` value, which
 * `JSON.parse` can never produce, is outside that contract and is not
 * guaranteed to be rejected.
 */
export function validateEnvelope(raw: unknown): MessageEnvelope {
  // Bound the raw object's complexity BEFORE Zod walks it. A strict-mode parse
  // must enumerate every key to reject unknowns, so a million-key object would
  // otherwise burn hundreds of ms of CPU before being rejected. This also
  // rejects JCS-unsafe numbers so a validated envelope is always one a
  // canonicalizer can sign unambiguously.
  if (!isWithinBounds(raw)) {
    throw new Error("message exceeds complexity bounds");
  }
  const envelope = MessageEnvelopeSchema.parse(raw);
  // The complexity walk above misses what signMessage/verifyMessage also
  // check: non-JSON values, lone surrogates, escaped member names, and the
  // canonical-byte ceiling. Apply that bundle here too, over the same
  // signature-stripped body, so a bad envelope fails here, not at signing.
  const { signature: _signature, ...unsigned } = envelope;
  if (violatesSignableBounds(unsigned)) {
    throw new Error(UNSIGNABLE_BODY_MESSAGE);
  }
  return envelope;
}

/**
 * Validate `payload` against the schema for `intent`. A registered intent
 * gets its exact strict per-field schema; any other well-formed intent
 * (vendor, or a bare token this build does not register) gets no further
 * check, since `validateEnvelope` already required `payload` to be a JSON
 * object and bounded its size; the library cannot know a vendor's payload
 * shape, so it does not pretend to.
 */
export function validateIntentPayload(intent: string, payload: unknown): void {
  getPayloadSchema(intent).parse(payload);
}

/**
 * Validate a message envelope AND, for a registered intent, its payload
 * against that intent's specific schema. Convenience for a caller that
 * supports every intent it accepts, so the ordering `validateEnvelope` /
 * `checkIntentDisposition` / `validateIntentPayload` enforces is moot for it.
 *
 * A receiver with a narrower supported set should NOT call this directly:
 * call `validateEnvelope`, decide support and confidentiality via
 * `checkIntentDisposition`, and only then call `validateIntentPayload` for
 * an intent it actually supports. Calling `validateMessage` for an intent
 * outside that receiver's supported set reports the payload's schema
 * failure (or success) rather than `unsupported_intent`, because this
 * function has no supported-intent list to consult.
 */
export function validateMessage(raw: unknown): MessageEnvelope {
  const envelope = validateEnvelope(raw);
  validateIntentPayload(envelope.intent, envelope.payload);
  return envelope;
}

/**
 * Get the payload schema for a given intent.
 *
 * Runtime-validates `intent` against `IntentTypeSchema` so a caller cannot
 * pass a malformed string and silently get a permissive schema back; the
 * function throws ZodError on a grammar-invalid intent. A well-formed but
 * unregistered intent (vendor, or a bare token this build does not
 * register) returns `PayloadObjectSchema`: the same bare "must be a JSON
 * object" requirement `validateEnvelope` already applied, never `undefined`.
 *
 * The lookup is gated on `hasOwnProperty`, not a plain `payloadSchemas[intent]`
 * read: `payloadSchemas` is a plain object, so a well-formed bare intent that
 * happens to share a name with an inherited `Object.prototype` member
 * (`constructor`, `toString`, `valueOf`, `hasOwnProperty`, and others, all of
 * which match the bare-token grammar) would otherwise resolve to that
 * inherited function instead of `undefined`, defeating the `??` fallback and
 * handing a non-Zod value to the caller.
 */
export function getPayloadSchema(intent: string): z.ZodTypeAny {
  IntentTypeSchema.parse(intent);
  return Object.prototype.hasOwnProperty.call(payloadSchemas, intent)
    ? payloadSchemas[intent as RegisteredIntentType]
    : PayloadObjectSchema;
}
