/**
 * Agent card construction.
 *
 * Returns an object that conforms to AgentCardSchema. The schema is
 * also re-validated before serialization so any drift in the OSS
 * schema (or in a host-config typo) surfaces at request time as a
 * 500, not as a silently-broken card on the wire.
 */

import { AgentCardSchema, signAgentCard } from "@adastracomputing/ink";
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

export async function buildAgentCard(cfg: AgentCardConfig): Promise<unknown> {
  const endpoint = `https://${cfg.host}/ink/v1/inbound`;
  const card = {
    protocol: "ink/0.1",
    // Runs the 0.2 runtime and accepts both ink/0.1 and ink/0.2 envelopes (the
    // schema admits either, and transport auth covers the canonical body), so
    // advertise both and a sender may negotiate up to ink/0.2.
    supportedProtocolVersions: ["ink/0.1", "ink/0.2"],
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
    // MUST-on-publish once the card is signed (ink-agent-card-signature.md §6).
    // This receiver holds one fixed key that never rotates, so its key set is
    // version 1; `updatedAt` is informational and carries no comparison rule.
    keySetVersion: 1,
    updatedAt: new Date().toISOString(),
  };
  // Re-validate against the canonical schema. If the OSS schema gets
  // stricter in a future release this surfaces immediately rather than
  // shipping a card that downstream verifiers reject.
  const parsed = AgentCardSchema.safeParse(card);
  if (!parsed.success) {
    throw new Error(`agent_card_invalid: ${JSON.stringify(parsed.error.issues)}`);
  }
  // Phase B (producer MUST, ink-agent-card-signature.md §10). Sign the card so a
  // cold verifier can establish key authority from the card itself. This is a
  // legacy single-key card (no `keys.signing` set), so the signer keyId is the
  // literal `bootstrap` and the verifying key is the top-level
  // `publicKeyMultibase` (§3.3). The receiver is a did:web identity whose DID
  // document (`/.well-known/did.json`) anchors exactly this key, so the signed
  // card roots under §4.2. Sign the schema-parsed object so the bytes the
  // verifier reconstructs from the served body match byte-for-byte.
  const signature = await signAgentCard(
    parsed.data as unknown as Record<string, unknown>,
    cfg.identity.privateKey,
  );
  return { ...parsed.data, cardSignature: { keyId: "bootstrap", signature } };
}
