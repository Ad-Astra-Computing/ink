/**
 * Capability-gated Agent Card discovery.
 *
 * Implements §6 of the INK Containment spec:
 * - Redacted cards for unauthenticated requests on non-public visibility
 * - Authenticated card query endpoint schemas
 * - Access denial response schemas
 */

import { z } from "zod";
import { AgentCardSchema, type AgentCard } from "../models/agent-card.js";
import { AgentCardVisibilitySchema, type AgentCardVisibility } from "../models/ink-handshake.js";

export { AgentCardVisibilitySchema, type AgentCardVisibility } from "../models/ink-handshake.js";

// ── Redacted card ──

export interface RedactedAgentCard {
  type: "tulpa.agent.card";
  version: "1.0";
  agentId: string;
  displayName?: string;
  visibility: "network_only" | "capability_gated";
  supportsInk: true;
  discoveryMode: "authenticate_for_details";
  /**
   * Bootstrap / legacy single public key. Preserved so peers can still verify
   * Ed25519 signatures from cards without a full keys block.
   */
  publicKeyMultibase: string;
  /**
   * Authoritative signing key set (rotation). Public material only — revealing
   * these is safe and necessary so peers can discover key rotations even when
   * the rest of the Card is gated. Without this, an agent that rotated to a
   * new key under network_only / capability_gated visibility would be
   * unverifiable to first-contact peers.
   */
  keys?: {
    signing: Array<{
      keyId: string;
      publicKeyMultibase: string;
      status: "active" | "retired" | "revoked";
      /** Validity-window fields are preserved in the redacted card so a
       * first-contact peer that only ever sees the redacted form still
       * enforces the same `[validFrom, validUntil]` bound the full card
       * would. Stripping them creates a softer verification path. */
      validFrom?: string;
      validUntil?: string;
      revokedAt?: string;
    }>;
  };
  updatedAt: string;
}

/**
 * Build a redacted Agent Card from a full card.
 *
 * Strips capabilities, endpoints, availability, profile, and other
 * sensitive-on-a-closed-card fields. **Public signing keys are preserved**:
 * Ed25519 public keys are not secrets — they are the identity. Hiding them
 * would prevent peers from verifying signatures across key rotation when the
 * full Card is gated.
 */
export function buildRedactedCard(card: AgentCard): RedactedAgentCard {
  // `visibility` is typed on AgentCard but a malformed runtime value can
  // still slip through (e.g. a card deserialised without schema validation).
  // Default to `capability_gated` — the least-privilege visibility — when
  // the field is anything other than the known enum members.
  const visibility: "network_only" | "capability_gated" =
    card.visibility === "network_only" ? "network_only" : "capability_gated";
  const out: RedactedAgentCard = {
    type: "tulpa.agent.card",
    version: "1.0",
    agentId: card.agentId,
    displayName: card.displayName,
    supportsInk: true,
    discoveryMode: "authenticate_for_details",
    visibility,
    publicKeyMultibase: card.publicKeyMultibase,
    updatedAt: new Date().toISOString(),
  };
  // Preserve `keys.signing` on PRESENCE, not on truthiness/length.
  // An empty signing array is an authoritative "no usable signing
  // keys" statement (e.g. all keys revoked) and the verifier's key
  // rotation authority rule treats it as a reject-all signal. Dropping
  // the field here would let peers fall back to publicKeyMultibase or
  // bootstrap derivation, undoing the rotation. See
  // multi-key-verify and middleware/ink-auth for the authority rule.
  if (Array.isArray(card.keys?.signing)) {
    out.keys = {
      signing: card.keys.signing.map((k) => ({
        keyId: k.keyId,
        publicKeyMultibase: k.publicKeyMultibase,
        status: k.status,
        // Preserve validity / revocation metadata: these are public
        // facts about the key, not secrets, and a redacted card must
        // not be weaker than the full card for signature verification.
        validFrom: k.validFrom,
        validUntil: k.validUntil,
        revokedAt: k.revokedAt,
      })),
    };
  }
  return out;
}

// ── Query/Response schemas ──

export const AgentCardQuerySchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.agent_card_query"),
  from: z.string(),
  nonce: z.string(),
  timestamp: z.string().datetime(),
  requestedFields: z.array(z.string()).optional(),
});

export type AgentCardQuery = z.infer<typeof AgentCardQuerySchema>;

export const AgentCardResponseSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.agent_card_response"),
  card: AgentCardSchema,
  grantedFields: z.array(z.string()),
  timestamp: z.string().datetime(),
});

export type AgentCardResponse = z.infer<typeof AgentCardResponseSchema>;

export const AgentCardDeniedSchema = z.object({
  protocol: z.literal("ink/0.1"),
  type: z.literal("network.tulpa.agent_card_denied"),
  reason: z.enum(["unknown_requester", "insufficient_trust", "not_connected"]),
  timestamp: z.string().datetime(),
});

export type AgentCardDenied = z.infer<typeof AgentCardDeniedSchema>;

// ── Visibility check ──

/**
 * Determine whether an unauthenticated GET should return a full card
 * or a redacted card based on visibility setting.
 */
export function shouldRedactOnGet(visibility: AgentCardVisibility): boolean {
  return visibility !== "public";
}
