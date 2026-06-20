/**
 * Sender identity.
 *
 * A sender is identified by an Ed25519 keypair. The wire identity is a
 * `did:key:` — the multibase-encoded public key IS the identifier, so a
 * receiver can decode the verification key inline with no network fetch.
 * That makes `did:key:` the simplest, SSRF-free sender identity and the
 * one this example uses, matching the `interop-cli` reference sender and
 * the `did:key` path in the reference receiver.
 *
 * Two ways to get an identity:
 *
 *   - `generateSenderIdentity()` mints a fresh ephemeral keypair. The
 *     DID changes every run, so use it for one-off pokes at a receiver
 *     that accepts first-contact intents (`connection_request`, `ping`).
 *   - `loadSenderIdentity(env)` restores a stable identity from a seed +
 *     published public key, the same split the reference receiver uses.
 *     A stable DID is what a receiver allow-lists.
 *
 * The only library surface used here is the key encode/decode helpers and
 * the base64url codec — no private modules.
 */

import {
  generateKeypair,
  encodePublicKeyMultibase,
  decodePublicKeyMultibase,
  base64urlEncode,
  base64urlDecode,
  signInkMessage,
  verifyInkSignature,
} from "@adastracomputing/ink";

export interface SenderIdentity {
  /** Raw 32-byte Ed25519 seed/private key. Treat like a password. */
  privateKey: Uint8Array;
  /** Raw 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  /** Multibase ed25519-pub encoding ("z6Mk..."). */
  publicKeyMultibase: string;
  /** Wire identity: `did:key:<multibase>`. */
  did: string;
}

/** `did:key:` for a multibase-encoded Ed25519 public key. */
export function didKeyFromMultibase(publicKeyMultibase: string): string {
  // Decode-then-reject so a malformed multibase never becomes a DID.
  decodePublicKeyMultibase(publicKeyMultibase);
  return `did:key:${publicKeyMultibase}`;
}

function identityFromKeypair(privateKey: Uint8Array, publicKey: Uint8Array): SenderIdentity {
  if (privateKey.length !== 32) {
    throw new Error(`invalid_seed_length: expected 32 bytes, got ${privateKey.length}`);
  }
  const publicKeyMultibase = encodePublicKeyMultibase(publicKey);
  return {
    privateKey,
    publicKey,
    publicKeyMultibase,
    did: didKeyFromMultibase(publicKeyMultibase),
  };
}

/** Mint a fresh ephemeral sender identity. The DID changes every call. */
export async function generateSenderIdentity(): Promise<SenderIdentity> {
  const kp = await generateKeypair();
  return identityFromKeypair(kp.privateKey, kp.publicKey);
}

/**
 * Print a freshly minted identity's halves so an operator can persist
 * them. The seed is the secret; the multibase is the public half.
 */
export function describeIdentitySeed(id: SenderIdentity): {
  INK_SENDER_SIGNING_SEED: string;
  INK_SENDER_PUBLIC_KEY_MULTIBASE: string;
} {
  return {
    INK_SENDER_SIGNING_SEED: base64urlEncode(id.privateKey),
    INK_SENDER_PUBLIC_KEY_MULTIBASE: id.publicKeyMultibase,
  };
}

export interface SenderEnv {
  INK_SENDER_SIGNING_SEED?: string;
  INK_SENDER_PUBLIC_KEY_MULTIBASE?: string;
}

/**
 * Restore a stable identity from a base64url 32-byte seed and the
 * published public key multibase. Mirrors the receiver's seed + var
 * split: the seed alone cannot be expanded to a public key with only the
 * library's exported surface, so the public half is supplied explicitly
 * and the two are cross-checked.
 */
export function loadSenderIdentity(env: SenderEnv): SenderIdentity {
  const seedRaw = env.INK_SENDER_SIGNING_SEED;
  const pubRaw = env.INK_SENDER_PUBLIC_KEY_MULTIBASE;
  if (!seedRaw) {
    throw new Error("missing_seed: set INK_SENDER_SIGNING_SEED (base64url 32-byte seed)");
  }
  if (!pubRaw) {
    throw new Error("missing_public_key: set INK_SENDER_PUBLIC_KEY_MULTIBASE (z6Mk... multibase)");
  }
  let privateKey: Uint8Array;
  try {
    privateKey = base64urlDecode(seedRaw);
  } catch {
    throw new Error("invalid_seed: INK_SENDER_SIGNING_SEED is not valid base64url");
  }
  let publicKey: Uint8Array;
  try {
    publicKey = decodePublicKeyMultibase(pubRaw);
  } catch {
    throw new Error("invalid_public_key: INK_SENDER_PUBLIC_KEY_MULTIBASE failed to decode");
  }
  return identityFromKeypair(privateKey, publicKey);
}

/**
 * Round-trip check that the seed actually derives the published public
 * key: sign a fixed canary and verify it with the public half. Catches a
 * mismatched seed/public-key pair before any envelope is signed and sent,
 * rather than as an opaque rejection at the receiver.
 */
export async function selfCheckIdentity(id: SenderIdentity): Promise<void> {
  const canary = {
    method: "POST",
    path: "/__selfcheck",
    recipientDid: "did:key:selfcheck",
    body: { canary: true } as Record<string, unknown>,
    timestamp: "1970-01-01T00:00:00Z",
  };
  const sig = await signInkMessage(canary, id.privateKey);
  const ok = await verifyInkSignature(canary, sig, id.publicKey);
  if (!ok) {
    throw new Error("identity_mismatch: signing seed does not derive the published public key");
  }
}
