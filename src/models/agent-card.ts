import { z } from "zod";
import { IntentTypeSchema } from "./intent.js";
import { InkReceiptDispositionSchema } from "./ink-audit.js";
import { ProfileSnapshotSchema } from "./profile.js";
import { KeyEntrySchema } from "./key-entry.js";
import { InkTransportSchema, AgentCardVisibilitySchema } from "./ink-handshake.js";

export const ThirdPartyAuditServiceSchema = z.object({
  endpoint: z.string().max(2048).url(),
  did: z.string().max(512),
  publicKey: z.string().max(256),
});

export const AgentCardSchema = z.object({
  protocol: z.literal("ink/0.1"),
  agentId: z.string().max(512),
  ownerDid: z.string().max(512).optional(),
  ownerHandle: z.string().max(256).optional(),
  atprotoRecordUri: z.string().max(2048).optional(),
  handle: z.string().max(256),
  displayName: z.string().max(200),
  /**
   * Inbound message endpoint URL. Required.
   *
   * `inboxEndpoint` is accepted as an optional forward-compat hint
   * from v0.1.1 onward; when present it MUST equal `endpoint`. The
   * long-term name is settled at the next wire-version bump, so
   * publishers SHOULD continue to emit `endpoint` for v0.1.x and
   * MAY emit `inboxEndpoint` alongside it. The runtime helper
   * `resolveAgentInbox(card)` returns whichever value is present.
   */
  endpoint: z.string().max(2048).url(),
  inboxEndpoint: z.string().max(2048).url().optional(),
  publicKeyMultibase: z.string().startsWith("z").max(128),
  // (other fields below; the `inboxEndpoint === endpoint` invariant
  // is enforced by the .superRefine() at the bottom of this schema.)
  profileSnapshot: ProfileSnapshotSchema.optional(),
  capabilities: z.object({
    intentsAccepted: z.array(IntentTypeSchema).max(32),
    intentsSent: z.array(IntentTypeSchema).max(32),
    receipts: z.object({
      send: z.boolean(),
      dispositions: z.array(InkReceiptDispositionSchema).max(16),
    }).optional(),
    auditExchange: z.boolean().optional(),
    thirdPartyAudit: z.object({
      services: z.array(ThirdPartyAuditServiceSchema).max(16),
      submitPolicy: z.enum(["all", "high_value", "none"]),
    }).optional(),
  }),
  availability: z.object({
    timezone: z.string().max(64),
    meetingHours: z.string().max(200).optional(),
    responseSla: z.string().max(200).optional(),
  }),
  keys: z.object({
    signing: z.array(KeyEntrySchema).max(32),
    encryption: z.array(KeyEntrySchema).max(32),
  }).optional(),
  currentSigningKeyId: z.string().max(128).optional(),
  currentEncryptionKeyId: z.string().max(128).optional(),
  keySetVersion: z.number().int().positive().optional(),
  // Message protocol versions this agent's receiver can verify on the
  // body signature. When absent, assume ink/0.1 only. A sender MUST NOT
  // emit a newer version to a card that does not advertise it; advertising
  // a version here is necessary but not sufficient for a sender to use it.
  //
  // The entries are advisory hints, so they are accepted as bounded
  // strings rather than the strict version enum: a newer peer may
  // advertise a version this build does not know yet, and that must not
  // make its whole card unparseable. A sender intersects this list with
  // the versions it can actually emit. The strict enum lives on the
  // envelope (MessageEnvelopeSchema), where an unknown version is rejected.
  supportedProtocolVersions: z.array(z.string().max(16)).max(8).optional(),
  // Containment extension (Phase 1)
  visibility: AgentCardVisibilitySchema.optional(),
  governance: z.object({
    maxAcceptedDelegationDepth: z.number().int().positive().optional(),
    supportedTransports: z.array(InkTransportSchema).optional(),
    supportsCapabilityGatedDiscovery: z.boolean().optional(),
    handshakeBudget: z.object({
      maxChallengesPerCorrelation: z.number().int().positive().optional(),
      maxIntentsPerMinute: z.number().int().positive().optional(),
    }).optional(),
  }).optional(),
}).superRefine((card, ctx) => {
  // v0.1.1: when both endpoint and inboxEndpoint are present they
  // MUST refer to the same URL. The spec rationale is that the alias
  // exists for forward compat, not as a way to publish two distinct
  // inbound URLs under one card — a card with mismatched endpoints
  // is ambiguous about which one to deliver to.
  if (card.inboxEndpoint && card.endpoint && card.inboxEndpoint !== card.endpoint) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["inboxEndpoint"],
      message: "inboxEndpoint MUST equal endpoint when both are present (v0.1.1 spec).",
    });
  }
});

export type AgentCard = z.infer<typeof AgentCardSchema>;

/**
 * The message protocol versions a card's receiver can verify. Falls back
 * to ink/0.1 when the card does not advertise the field, so a sender
 * defaults to the original version for any card that predates it.
 */
export function agentSupportedProtocolVersions(
  card: Pick<AgentCard, "supportedProtocolVersions">,
): string[] {
  const advertised = card.supportedProtocolVersions;
  return advertised && advertised.length > 0 ? advertised : ["ink/0.1"];
}

/**
 * Return the inbound message URL for an Agent Card.
 *
 * Under v0.1.1, `endpoint` is still required on every parsed
 * `AgentCard`, so this helper effectively returns `card.endpoint`
 * today. The `?? card.inboxEndpoint` fallback is in place for the
 * future v0.x revision where `inboxEndpoint` will become primary
 * (with `endpoint` accepted as the legacy alias). Consumers SHOULD
 * use this helper rather than reading `.endpoint` directly so the
 * eventual swap is a one-import change.
 *
 * `inboxEndpoint` (when present alongside `endpoint`) MUST equal
 * `endpoint`; that invariant is enforced by `AgentCardSchema`.
 */
export function resolveAgentInbox(card: AgentCard): string {
  // `card.endpoint` is required by the v0.1.x schema so the first
  // branch always succeeds today. The `??` chain is in place for the
  // future revision where `endpoint` becomes optional and
  // `inboxEndpoint` becomes the primary field; consumers using this
  // helper get the swap for free.
  return card.endpoint ?? card.inboxEndpoint;
}
