/**
 * Key material loader.
 *
 * The receiver's identity is a stable Ed25519 keypair.
 *
 *   INK_RECEIVER_SIGNING_SEED         — secret. 32-byte Ed25519 private
 *                                       key seed, base64url-encoded.
 *                                       Set with `wrangler secret put`.
 *   INK_RECEIVER_PUBLIC_KEY_MULTIBASE — public. multibase ed25519-pub
 *                                       encoding ("z6Mk..."). Set as a
 *                                       wrangler `[vars]` entry.
 *
 * Storing the public key as a config var (rather than re-deriving it
 * at boot) keeps the receiver self-contained: the only library API
 * surface we need is the signer itself. Adopters pre-compute the
 * keypair once with `npx ink keygen` (or any libsodium-compatible
 * tool) and paste both halves into Wrangler.
 *
 * The match between seed and public key is checked at request time
 * via `signInkMessage` + the OSS `verifyInkSignature`: a startup
 * mismatch would be visible the first time a signed response fails
 * verification against the published agent card. We surface that as
 * a deploy-time check below.
 */

import {
  signInkMessage,
  verifyInkSignature,
  base64urlDecode,
  decodePublicKeyMultibase,
} from "@adastracomputing/ink";

export interface ReceiverIdentity {
  /** Raw Ed25519 32-byte private seed. Keep close. */
  privateKey: Uint8Array;
  /** Raw Ed25519 public key (32 bytes). */
  publicKey: Uint8Array;
  /** Multibase-encoded public key, per the AgentCard schema. */
  publicKeyMultibase: string;
}

export interface ReceiverEnv {
  INK_RECEIVER_SIGNING_SEED?: string;
  INK_RECEIVER_PUBLIC_KEY_MULTIBASE?: string;
  INK_RECEIVER_HOST?: string;
  /**
   * Optional. The card's `updatedAt`, a strict RFC 3339 timestamp. Set it when
   * you change what the card says; leave it unset to take the source default.
   * It is deliberately configuration and not a clock read — see
   * `resolveCardUpdatedAt` in `agent-card.ts`.
   */
  INK_RECEIVER_CARD_UPDATED_AT?: string;
}

export function loadReceiverIdentity(env: ReceiverEnv): ReceiverIdentity {
  const seedRaw = env.INK_RECEIVER_SIGNING_SEED;
  const pubRaw = env.INK_RECEIVER_PUBLIC_KEY_MULTIBASE;
  if (!seedRaw) {
    throw new Error("missing_seed: set INK_RECEIVER_SIGNING_SEED via wrangler secret put");
  }
  if (!pubRaw) {
    throw new Error("missing_public_key: set INK_RECEIVER_PUBLIC_KEY_MULTIBASE in wrangler vars");
  }
  let privateKey: Uint8Array;
  try {
    privateKey = base64urlDecode(seedRaw);
  } catch {
    throw new Error("invalid_seed: INK_RECEIVER_SIGNING_SEED is not valid base64url");
  }
  if (privateKey.length !== 32) {
    throw new Error(`invalid_seed_length: expected 32 bytes, got ${privateKey.length}`);
  }
  let publicKey: Uint8Array;
  try {
    publicKey = decodePublicKeyMultibase(pubRaw);
  } catch {
    throw new Error("invalid_public_key: INK_RECEIVER_PUBLIC_KEY_MULTIBASE failed to decode");
  }
  return {
    privateKey,
    publicKey,
    publicKeyMultibase: pubRaw,
  };
}

/**
 * Round-trip sanity check: sign a fixed canary then verify with the
 * published public key. Catches "seed and publicKey don't match"
 * misconfigurations BEFORE any envelope work fans out to the network.
 *
 * Run lazily once per worker isolate, not per request — Ed25519 sign
 * + verify is ~1ms but adding it to every inbound is needless tax.
 */
export async function selfCheckIdentity(id: ReceiverIdentity): Promise<void> {
  const canary = {
    method: "POST",
    path: "/__selfcheck",
    recipientDid: "did:web:selfcheck.invalid",
    body: { canary: true } as Record<string, unknown>,
    timestamp: "1970-01-01T00:00:00Z",
  };
  const sig = await signInkMessage(canary, id.privateKey);
  const ok = await verifyInkSignature(canary, sig, id.publicKey);
  if (!ok) {
    throw new Error("identity_mismatch: signing seed does not derive the published public key");
  }
}

const HOST_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

/**
 * Build the canonical did:web id from the configured host.
 *
 * Rejects ports, paths, anything with uppercase, and bare hostnames
 * without a dot — did:web requires a globally addressable host.
 */
export function deriveDidWeb(host: string): string {
  const h = host.trim().toLowerCase();
  if (!HOST_PATTERN.test(h)) {
    throw new Error(`invalid_host: ${JSON.stringify(host)} is not a bare lowercase host (no port, no path)`);
  }
  return `did:web:${h}`;
}
