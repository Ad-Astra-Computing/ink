/**
 * Encryption requirement gate (Protocol §3.4).
 *
 * The protocol marks a small set of intents confidential. A sender MUST
 * deliver them inside an encrypted envelope, and a receiver MUST refuse them
 * in plaintext with `encryption_required`. The set is a protocol fact, so it
 * lives here once and every receiver applies the same one; a receiver that
 * wants to require encryption for more of its own intents passes a wider set.
 *
 * The gate runs on a plaintext intent envelope after schema validation and
 * before any work that depends on the intent, in the same position the
 * intent allowlist sits: a confidential intent in plaintext is refused for
 * being plaintext, whatever else the receiver would have said about it. An
 * encrypted outer envelope (§3.4) never reaches this gate; its inner envelope,
 * once decrypted, is by construction not plaintext.
 */

/** The intents Protocol §3.4 requires to be sent encrypted. */
export const CONFIDENTIAL_INTENTS = ["schedule_meeting", "context_share", "multi_party_sync"] as const;

export type ConfidentialIntent = (typeof CONFIDENTIAL_INTENTS)[number];

/** Whether `intent` is one the protocol requires to be sent encrypted. */
export function intentRequiresEncryption(intent: string): intent is ConfidentialIntent {
  return (CONFIDENTIAL_INTENTS as readonly string[]).includes(intent);
}

export type EncryptionRequirementResult =
  | { allowed: true }
  | { allowed: false; reason: "encryption_required"; intent: string };

export interface EncryptionRequirementOptions {
  /**
   * The intents to refuse in plaintext. Defaults to `CONFIDENTIAL_INTENTS`.
   * A receiver may widen the set with intents of its own; narrowing it below
   * the protocol set makes the receiver non-conforming.
   */
  confidentialIntents?: readonly string[];
}

/**
 * Decide whether a plaintext envelope may proceed. Returns
 * `encryption_required` with the offending intent when the envelope carries
 * a confidential intent. An envelope whose `intent` is absent or not a string
 * is allowed through: there is no intent to gate, and the envelope schema,
 * which runs before this gate, is what rejects it.
 */
export function checkEncryptionRequired(
  envelope: { intent?: unknown } | null | undefined,
  opts: EncryptionRequirementOptions = {},
): EncryptionRequirementResult {
  const intent = envelope?.intent;
  if (typeof intent !== "string") {
    return { allowed: true };
  }
  const set = opts.confidentialIntents ?? CONFIDENTIAL_INTENTS;
  if (set.includes(intent)) {
    return { allowed: false, reason: "encryption_required", intent };
  }
  return { allowed: true };
}
