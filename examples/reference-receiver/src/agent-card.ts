/**
 * Agent card construction.
 *
 * Returns an object that conforms to AgentCardSchema. The schema is
 * also re-validated before serialization so any drift in the OSS
 * schema (or in a host-config typo) surfaces at request time as a
 * 500, not as a silently-broken card on the wire.
 *
 * The build is a PURE FUNCTION of configuration and key material: same config
 * and same seed in, same bytes out, in any isolate, in any process, at any
 * time. Ed25519 signing is deterministic, JCS canonicalization is total, and
 * nothing here reads a clock or a random source. Do not introduce one — the
 * served body is signed over itself, so anything that varies per build makes
 * two fetches of the same document disagree.
 */

import { AgentCardSchema, signAgentCard, isInkTimestamp } from "@adastracomputing/ink";
import type { ReceiverIdentity, ReceiverEncryptionIdentity, ReceiverEnv } from "./keys.js";

export interface AgentCardConfig {
  did: string;
  host: string;
  identity: ReceiverIdentity;
  /**
   * Optional X25519 identity. When present the card publishes a `keys` block
   * with the signing key and this encryption key, which is what lets a sender
   * seal an envelope to this receiver (§3.4). When absent the card carries no
   * `keys` block at all, exactly as before, and a sender that tries to encrypt
   * is told the receiver advertises no encryption key.
   */
  encryption?: ReceiverEncryptionIdentity | null;
  /**
   * The card's `updatedAt`. Operator-supplied configuration, NOT a clock read.
   * See `resolveCardUpdatedAt`.
   */
  updatedAt: string;
}

/**
 * The `updatedAt` this receiver publishes when the operator sets no override.
 *
 * It is the date the card's CONTENT last changed in this source file, which is
 * exactly what the field means. Bump it in the same commit that changes what
 * the card says (intents, availability, protocol versions, displayName). An
 * operator whose card differs from this source only in wrangler config sets
 * `INK_RECEIVER_CARD_UPDATED_AT` instead and leaves this alone.
 */
export const DEFAULT_CARD_UPDATED_AT = "2026-08-18T00:00:00Z";

/**
 * Resolve the card's `updatedAt` from configuration.
 *
 * The card MUST be byte-identical across isolates, processes and time until
 * the operator actually changes it: the body is signed over itself, so any
 * per-build nondeterminism makes two spellings of the same document disagree
 * and makes a polling consumer see an "update" that never happened. Cloudflare
 * hands a low-traffic worker a cold isolate for nearly every request, so a
 * per-isolate cache cannot supply that guarantee — determinism has to come
 * from the value itself.
 *
 * `updatedAt` is the only field that was ever a clock read, and the spec makes
 * a configured constant a legal value for it: `ink-agent-card.md` defines it as
 * an informational strict RFC 3339 timestamp that "carries no comparison rule",
 * `ink-agent-card-signature.md` §6 makes `keySetVersion` the SOLE monotonic
 * quantity and forbids a verifier from rejecting on `updatedAt` ordering, and
 * `ink-resolver.md` refuses to derive a cache lifetime from it. Nothing in the
 * TypeScript library or the Go implementation compares or orders on it; both
 * only check the strict RFC 3339 grammar. So the field must be a valid
 * timestamp and must be present on a signed card (§6), and that is the whole
 * contract.
 *
 * Validated here rather than left to the schema so a typo in a wrangler var
 * fails with a message naming the var instead of a generic card-invalid dump.
 */
export function resolveCardUpdatedAt(env: Pick<ReceiverEnv, "INK_RECEIVER_CARD_UPDATED_AT">): string {
  const raw = env.INK_RECEIVER_CARD_UPDATED_AT?.trim();
  const value = raw ? raw : DEFAULT_CARD_UPDATED_AT;
  if (!isInkTimestamp(value)) {
    throw new Error(
      `invalid_card_updated_at: INK_RECEIVER_CARD_UPDATED_AT must be a strict RFC 3339 timestamp, got ${JSON.stringify(value)}`,
    );
  }
  return value;
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
/**
 * `validFrom` for the published key entries. Configuration, not a clock read,
 * for the same reason `updatedAt` is: a card whose key windows move on every
 * request is a card nobody can cache or reason about.
 */
export const CARD_KEYS_VALID_FROM = "2026-08-26T00:00:00Z";

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
    // The `keys` block appears only when an encryption identity is configured.
    // Publishing a signing-only `keys` block would be a no-op restatement of
    // `publicKeyMultibase`, so the two states stay meaningfully distinct: no
    // block means no encryption, never "encryption you have to guess at".
    ...(cfg.encryption
      ? {
          keys: {
            signing: [
              {
                keyId: "receiver-signing-1",
                algorithm: "Ed25519" as const,
                publicKeyMultibase: cfg.identity.publicKeyMultibase,
                status: "active" as const,
                validFrom: CARD_KEYS_VALID_FROM,
              },
            ],
            encryption: [
              {
                keyId: "receiver-encryption-1",
                algorithm: "X25519" as const,
                publicKeyMultibase: cfg.encryption.publicKeyMultibase,
                status: "active" as const,
                validFrom: CARD_KEYS_VALID_FROM,
              },
            ],
          },
          currentSigningKeyId: "receiver-signing-1",
          currentEncryptionKeyId: "receiver-encryption-1",
          keySetVersion: 1,
        }
      : {}),
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
    // version 1; `updatedAt` is informational, carries no comparison rule, and
    // comes from configuration so the signed body is deterministic.
    keySetVersion: 1,
    updatedAt: cfg.updatedAt,
  };
  // Re-validate against the canonical schema. If the OSS schema gets
  // stricter in a future release this surfaces immediately rather than
  // shipping a card that downstream verifiers reject.
  const parsed = AgentCardSchema.safeParse(card);
  if (!parsed.success) {
    throw new Error(`agent_card_invalid: ${JSON.stringify(parsed.error.issues)}`);
  }
  // Phase B (producer MUST, ink-agent-card-signature.md §10). Sign the card so a
  // cold verifier can establish key authority from the card itself. Without an
  // encryption identity this is a legacy single-key card (no `keys.signing`),
  // so the signer keyId is the literal `bootstrap` and the verifying key is the
  // top-level `publicKeyMultibase` (§3.3). With the `keys` block present the
  // signer keyId MUST name the active signing entry and equal
  // `currentSigningKeyId` (§3.3) — `bootstrap` on a key-set card is a verifier
  // reject (`signer_absent_from_signing`), which would make the advertised
  // X25519 key unusable for exactly the strict senders it exists for. The
  // receiver is a did:web identity whose DID document (`/.well-known/did.json`)
  // anchors this key, so the signed card roots under §4.2. Sign the
  // schema-parsed object so the bytes the verifier reconstructs from the
  // served body match byte-for-byte.
  const signature = await signAgentCard(
    parsed.data as unknown as Record<string, unknown>,
    cfg.identity.privateKey,
  );
  const signerKeyId = cfg.encryption ? "receiver-signing-1" : "bootstrap";
  return { ...parsed.data, cardSignature: { keyId: signerKeyId, signature } };
}
