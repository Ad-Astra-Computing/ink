import { z } from "zod";
import { IntentTypeSchema } from "./intent.js";
import { InkReceiptDispositionSchema } from "./ink-audit.js";
import { ProfileSnapshotSchema } from "./profile.js";
import { KeyEntrySchema, KeyStatusSchema } from "./key-entry.js";
import { InkTransportSchema, AgentCardVisibilitySchema, type AgentCardVisibility } from "./ink-handshake.js";
import { isInkEndpointUrl } from "./endpoint-url.js";
import { isInkTimestamp } from "../crypto/timestamp.js";

// Opt-in discoverability descriptor (#188). A card MAY carry a `discovery`
// object that opts the agent in to being surfaced by a directory/index. It is
// additive and forward compatible: a card without it is not discoverable, and
// unknown descriptor keys are ignored so later additive fields do not break old
// parsers. The descriptor can only ever NARROW exposure: `scope` reuses the
// card visibility enum and MUST NOT exceed the card's `visibility` (enforced by
// the card superRefine). Self-declared `tags` are hints, not verified claims.
const discoveryUpdatedAt = z
  .string()
  .refine(isInkTimestamp, { message: "must be a strict RFC 3339 timestamp" });

export const DiscoveryDescriptorSchema = z.object({
  enabled: z.boolean(),
  scope: AgentCardVisibilitySchema,
  tags: z.array(z.string().min(1).max(64)).max(32).optional(),
  queryable: z.boolean().optional(),
  updatedAt: discoveryUpdatedAt.optional(),
});

export type DiscoveryDescriptor = z.infer<typeof DiscoveryDescriptorSchema>;

// Exposure lattice, most-exposed to least. `public` reaches the widest
// audience, `private` the narrowest. Discovery exposure is the minimum of the
// card's visibility and the descriptor's scope, and the descriptor MUST NOT
// declare a scope above the card's visibility.
const DISCOVERY_EXPOSURE_RANK: Record<AgentCardVisibility, number> = {
  public: 3,
  network_only: 2,
  capability_gated: 1,
  private: 0,
};

// Endpoint fields use the pinned INK endpoint grammar (https, no userinfo, no
// fragment, <=2048 UTF-8 bytes, no control/whitespace) rather than the broad
// z.string().url(); see endpoint-url.ts.
const endpointUrl = z.string().refine(isInkEndpointUrl, { message: "Invalid INK endpoint URL" });

export const ThirdPartyAuditServiceSchema = z.object({
  endpoint: endpointUrl,
  did: z.string().max(512),
  publicKey: z.string().max(256),
});

// Base64url no-padding Ed25519 signature: exactly 86 characters `[A-Za-z0-9_-]`
// (64 raw bytes), per ink-agent-card-signature.md §3.1 and Protocol §3.3.
const base64urlSignature = z
  .string()
  .regex(/^[A-Za-z0-9_-]{86}$/, "must be 86-char base64url (no padding)");

// OPTIONAL self-authenticating card proof (ink-agent-card-signature.md §3.1).
// `keyId` names the signing key resolved under §3.3; `signature` covers
// `ink/agent-card\n` + JCS(card without `cardSignature`). Optional and
// backward-compatible: a card without it validates exactly as before.
export const CardSignatureSchema = z.object({
  keyId: z.string().min(1).max(128),
  signature: base64urlSignature,
});

export type CardSignature = z.infer<typeof CardSignatureSchema>;

// A single committed signing-key entry inside a rotation-chain link
// (ink-agent-card-signature.md §4.1). It carries NO `algorithm` (Ed25519 is
// pinned for chain-capable keys) and NO key-window timestamps: a link commits
// the complete `{keyId, publicKeyMultibase, status}` set at its `keySetVersion`.
export const RotationChainSigningEntrySchema = z.object({
  keyId: z.string().min(1).max(128),
  publicKeyMultibase: z.string().startsWith("z").max(128),
  status: KeyStatusSchema,
});

export type RotationChainSigningEntry = z.infer<typeof RotationChainSigningEntrySchema>;

// A rotation-chain link (ink-agent-card-signature.md §4.1). `signature` covers
// `ink/card-rotation\n` + JCS(link without `signature`). Every `keyId` within
// a link's `signing` set MUST be unique so the head-binding correspondence of
// §4.1 step 3b is unambiguous.
export const RotationChainLinkSchema = z
  .object({
    keySetVersion: z.number().int().positive(),
    signing: z.array(RotationChainSigningEntrySchema).min(1).max(32),
    prevKeyId: z.string().min(1).max(128),
    signature: base64urlSignature,
  })
  .superRefine((link, ctx) => {
    const seen = new Set<string>();
    for (const entry of link.signing) {
      if (seen.has(entry.keyId)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["signing"],
          message: "keyId MUST be unique within a rotation link's signing set (§4.1).",
        });
      }
      seen.add(entry.keyId);
    }
  });

export type RotationChainLink = z.infer<typeof RotationChainLinkSchema>;

// OPTIONAL rotation chain (ink-agent-card-signature.md §4.1): at most 32 links
// walked genesis-to-head. A verifier MUST reject a chain longer than 32 links.
export const RotationChainSchema = z.array(RotationChainLinkSchema).max(32);

export type RotationChain = z.infer<typeof RotationChainSchema>;

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
  endpoint: endpointUrl,
  inboxEndpoint: endpointUrl.optional(),
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
  // Opt-in discoverability descriptor (#188). Absent => not discoverable.
  discovery: DiscoveryDescriptorSchema.optional(),
  governance: z.object({
    maxAcceptedDelegationDepth: z.number().int().positive().optional(),
    supportedTransports: z.array(InkTransportSchema).optional(),
    supportsCapabilityGatedDiscovery: z.boolean().optional(),
    handshakeBudget: z.object({
      maxChallengesPerCorrelation: z.number().int().positive().optional(),
      maxIntentsPerMinute: z.number().int().positive().optional(),
    }).optional(),
  }).optional(),
  // Self-authenticating Agent Card (ink-agent-card-signature.md, Phase A).
  // All three members are OPTIONAL and backward-compatible: an existing card
  // without them still validates, and a consumer that predates the spec ignores
  // them as unknown top-level fields (Protocol §2). A card that carries a
  // `cardSignature` becomes the authoritative key set only after the §5 verifier
  // (verifyAgentCardSignature) accepts it.
  cardSignature: CardSignatureSchema.optional(),
  rotationChain: RotationChainSchema.optional(),
  // Informational strict RFC 3339 timestamp (§6). MUST-present on publish when
  // the card is signed; carries no comparison rule (keySetVersion is the sole
  // monotonic quantity the continuity rules compare).
  updatedAt: z
    .string()
    .refine(isInkTimestamp, { message: "must be a strict RFC 3339 timestamp" })
    .optional(),
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
  // #188: the discovery descriptor's scope MUST NOT exceed the card's
  // visibility. An absent visibility is the public upper bound because the
  // card is itself publicly fetchable. The descriptor can only narrow.
  if (card.discovery) {
    const upperBound = card.visibility ?? "public";
    if (DISCOVERY_EXPOSURE_RANK[card.discovery.scope] > DISCOVERY_EXPOSURE_RANK[upperBound]) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["discovery", "scope"],
        message: "discovery.scope MUST NOT exceed the card's visibility (#188).",
      });
    }
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

/**
 * Whether the card has opted in to discovery (#188). A card is discoverable
 * only when it carries a `discovery` descriptor with `enabled: true`. This is
 * never inferred: an absent descriptor or `enabled: false` is not discoverable.
 */
export function isDiscoverable(
  card: Pick<AgentCard, "discovery">,
): boolean {
  return card.discovery?.enabled === true;
}

/**
 * The effective discovery exposure for a card (#188), or `null` when the card
 * is not discoverable. The effective scope is the minimum of the card's
 * `visibility` (the hard upper bound, defaulting to `public` when absent since
 * the card is publicly fetchable) and the descriptor's `scope`. A card parsed
 * by `AgentCardSchema` already guarantees `scope <= visibility`, so this
 * returns the descriptor scope; the min is defensive for unvalidated input.
 */
export function effectiveDiscoveryScope(
  card: Pick<AgentCard, "discovery" | "visibility">,
): AgentCardVisibility | null {
  if (!card.discovery?.enabled) return null;
  const upperBound = card.visibility ?? "public";
  const scope = card.discovery.scope;
  return DISCOVERY_EXPOSURE_RANK[scope] <= DISCOVERY_EXPOSURE_RANK[upperBound]
    ? scope
    : upperBound;
}
