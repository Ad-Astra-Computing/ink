/**
 * Agent card construction.
 *
 * Returns an object that conforms to AgentCardSchema. The schema is
 * also re-validated before serialization so any drift in the OSS
 * schema (or in a host-config typo) surfaces at request time as a
 * 500, not as a silently-broken card on the wire.
 */

import { AgentCardSchema } from "@adastracomputing/ink";
import type { ReceiverIdentity } from "./keys.js";

export interface AgentCardConfig {
  did: string;
  host: string;
  identity: ReceiverIdentity;
}

/**
 * The intents this reference receiver acknowledges. Keep small and
 * well-scoped; the inbound handler MUST agree with the card.
 *
 * `connection_request` and `intro_request` are the foreign-first-contact
 * bootstrap intents the `interop-cli` reference sender emits, so a test
 * sender can exercise the full wire against this target. `ping` and
 * `ask` round out a minimal liveness + query set.
 */
export const SUPPORTED_INTENTS = ["ping", "ask", "connection_request", "intro_request"] as const;

export function buildAgentCard(cfg: AgentCardConfig): unknown {
  const endpoint = `https://${cfg.host}/ink/v1/inbound`;
  const card = {
    protocol: "ink/0.1",
    agentId: cfg.did,
    handle: cfg.host,
    displayName: "INK Reference Receiver",
    endpoint,
    inboxEndpoint: endpoint,
    publicKeyMultibase: cfg.identity.publicKeyMultibase,
    capabilities: {
      intentsAccepted: [...SUPPORTED_INTENTS],
      intentsSent: [] as Array<never>,
      receipts: {
        send: false,
        dispositions: [] as Array<never>,
      },
    },
    availability: {
      timezone: "UTC",
      responseSla: "best_effort",
    },
  };
  // Re-validate against the canonical schema. If the OSS schema gets
  // stricter in a future release this surfaces immediately rather than
  // shipping a card that downstream verifiers reject.
  const parsed = AgentCardSchema.safeParse(card);
  if (!parsed.success) {
    throw new Error(`agent_card_invalid: ${JSON.stringify(parsed.error.issues)}`);
  }
  return parsed.data;
}
