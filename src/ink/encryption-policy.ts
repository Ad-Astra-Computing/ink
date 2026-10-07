/**
 * Encryption requirement gate (Protocol §3.4).
 *
 * The protocol marks a small set of intents confidential. A sender MUST
 * deliver them inside an encrypted envelope, and a receiver that supports
 * one of them MUST refuse its plaintext form with `encryption_required`.
 * The set is a protocol fact, so it lives here once and every receiver
 * applies the same one; a receiver that wants to require encryption for more
 * of its own intents, including a vendor intent it has installed, passes a
 * wider set via `extraConfidentialIntents`.
 *
 * This gate has no opinion about intent SUPPORT: it assumes the caller has
 * already decided the receiver supports the intent (Protocol §3.1.1's
 * `unsupported_intent` check), and runs after that decision, before any
 * other work that depends on the intent. Calling it for an intent the
 * receiver does not support is the caller's error, not the gate's. There is
 * no reason to demand encryption for an intent the receiver never acts on.
 * `checkIntentDisposition` below composes both checks in the required order
 * and is the normative reference for it; call this function directly only
 * when the caller has already run its own support check. An encrypted outer
 * envelope (§3.4) never reaches this gate; its inner envelope, once
 * decrypted, is by construction not plaintext, so only the support decision
 * (`isIntentSupported` below) applies to it, after transport auth and
 * decryption. This gate (and therefore `checkIntentDisposition`, which
 * always calls it) MUST NOT be called on a decrypted inner envelope: it has
 * no way to know the envelope already arrived encrypted, and would wrongly
 * refuse a supported confidential intent.
 */

import { CORE_INTENTS } from "../models/intent.js";

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
   * Intents of the receiver's own to refuse in plaintext, in addition to
   * `CONFIDENTIAL_INTENTS`. The protocol set always applies; there is no
   * option to narrow it, since a receiver that accepted a confidential intent
   * in plaintext would be non-conforming.
   */
  extraConfidentialIntents?: readonly string[];
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
  if (intentRequiresEncryption(intent) || (opts.extraConfidentialIntents ?? []).includes(intent)) {
    return { allowed: false, reason: "encryption_required", intent };
  }
  return { allowed: true };
}

/**
 * Whether a receiver supports `intent`: a core intent
 * (`connection_request`/`connection_response`), always, or one of its own
 * `supportedIntents`. This is the support-only half of
 * `checkIntentDisposition` below, exposed on its own because the
 * confidentiality half (`checkEncryptionRequired`) does NOT apply to an
 * intent already delivered inside an encrypted outer envelope (§3.4): once
 * decrypted it is by construction not plaintext, and that gate has no way
 * to know it arrived encrypted, so calling the COMPOSED
 * `checkIntentDisposition` on a decrypted inner envelope would wrongly
 * refuse a receiver's own correctly-encrypted confidential intents. A
 * decrypted inner envelope's support decision calls this function directly
 * instead.
 */
export function isIntentSupported(intent: string, supportedIntents: readonly string[]): boolean {
  return CORE_INTENTS.includes(intent as (typeof CORE_INTENTS)[number]) || supportedIntents.includes(intent);
}

export type IntentDispositionResult =
  | { allowed: true }
  | { allowed: false; reason: "unsupported_intent"; intent: string }
  | { allowed: false; reason: "encryption_required"; intent: string };

export interface IntentDispositionOptions extends EncryptionRequirementOptions {
  /**
   * The intents this receiver actually implements. `connection_request` and
   * `connection_response` are always treated as supported, whether or not
   * this list names them, since every conformant receiver handles the two
   * core intents (Protocol §3.1.1).
   */
  supportedIntents: readonly string[];
}

/**
 * Decide whether a PLAINTEXT intent envelope may proceed, in the order
 * Protocol §3.4 requires: `unsupported_intent` before `encryption_required`.
 * An intent the receiver does not support at all is refused
 * `unsupported_intent` even when it is one of the protocol's confidential
 * names, since there is no reason to demand encryption for an intent the
 * receiver never acts on.
 *
 * This is the normative reference for that ordering; a conforming
 * implementation is judged by the conformance vectors, not by exposing this
 * exact function signature. Call this ONLY on a plaintext envelope or on an
 * outer envelope you have not yet decrypted. For an encrypted outer
 * envelope, the decrypted inner envelope's support decision uses
 * `isIntentSupported` directly (after transport auth and decryption), never
 * this function: `checkIntentDisposition` always runs the confidentiality
 * gate, which would wrongly refuse an inner envelope that is, by
 * construction, never plaintext.
 */
export function checkIntentDisposition(
  envelope: { intent?: unknown } | null | undefined,
  opts: IntentDispositionOptions,
): IntentDispositionResult {
  const intent = envelope?.intent;
  if (typeof intent !== "string") {
    return { allowed: true };
  }
  if (!isIntentSupported(intent, opts.supportedIntents)) {
    return { allowed: false, reason: "unsupported_intent", intent };
  }
  const encResult = checkEncryptionRequired(envelope, opts);
  if (!encResult.allowed) {
    return { allowed: false, reason: "encryption_required", intent };
  }
  return { allowed: true };
}
