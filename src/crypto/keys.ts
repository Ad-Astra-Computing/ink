import * as ed from "@noble/ed25519";
import { x25519 } from "@noble/curves/ed25519.js";

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Ed25519 multicodec prefix: 0xed01 */
const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);

/** X25519 multicodec prefix: 0xec01 */
const X25519_MULTICODEC = new Uint8Array([0xec, 0x01]);

export interface Keypair {
  privateKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array; // 32 bytes
}

/** Generate a new Ed25519 keypair (signing). */
export async function generateKeypair(): Promise<Keypair> {
  const { secretKey, publicKey } = await ed.keygenAsync();
  return { privateKey: secretKey, publicKey };
}

/** Generate a new X25519 keypair (encryption). */
export function generateEncryptionKeypair(): Keypair {
  const privateKey = crypto.getRandomValues(new Uint8Array(32));
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** Encode bytes as base58btc (no multibase prefix). */
export function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  // Count leading zeros
  let zeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    zeros++;
  }

  // Convert to bigint
  let num = 0n;
  for (const b of bytes) {
    num = num * 256n + BigInt(b);
  }

  let result = "";
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    result = BASE58_ALPHABET[remainder]! + result;
  }

  // Add leading '1's for zero bytes
  return "1".repeat(zeros) + result;
}

/** Cap base58 input length BEFORE the BigInt accumulation loop. A poisoned
 *  Agent Card with a multi-KB `publicKeyMultibase` would otherwise force
 *  O(n^2) BigInt arithmetic — large `num * 58n + BigInt(idx)` per char — for
 *  every input byte before any trailing length check fires.
 *
 *  1024 is well above any legitimate multibase-encoded public key (Ed25519
 *  is ~50 chars, even multi-codec wrappers are well under 100).
 */
const MAX_BASE58_INPUT_LEN = 1024;

/** Decode base58btc string to bytes. */
export function decodeBase58(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);
  if (str.length > MAX_BASE58_INPUT_LEN) {
    throw new Error(`base58 input exceeds maximum length of ${MAX_BASE58_INPUT_LEN}`);
  }

  let num = 0n;
  for (const ch of str) {
    const idx = BASE58_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid base58 character: ${ch}`);
    num = num * 58n + BigInt(idx);
  }

  // Convert bigint to bytes
  const hex = num.toString(16).padStart(2, "0");
  const padded = hex.length % 2 ? "0" + hex : hex;
  const bytes: number[] = [];
  for (let i = 0; i < padded.length; i += 2) {
    bytes.push(parseInt(padded.slice(i, i + 2), 16));
  }

  // Add leading zero bytes
  let zeros = 0;
  for (const ch of str) {
    if (ch !== "1") break;
    zeros++;
  }

  return new Uint8Array([...new Uint8Array(zeros), ...bytes]);
}

/**
 * Encode a public key as a multibase base58btc string.
 * Format: 'z' prefix + base58btc(multicodec_prefix + public_key)
 */
export function encodePublicKeyMultibase(publicKey: Uint8Array): string {
  if (!(publicKey instanceof Uint8Array)) {
    throw new Error("publicKey must be a Uint8Array");
  }
  if (publicKey.length !== 32) {
    throw new Error(`publicKey must be 32 bytes, got ${publicKey.length}`);
  }
  const prefixed = new Uint8Array(
    ED25519_MULTICODEC.length + publicKey.length,
  );
  prefixed.set(ED25519_MULTICODEC);
  prefixed.set(publicKey, ED25519_MULTICODEC.length);
  return "z" + encodeBase58(prefixed);
}

/**
 * Encode an X25519 public key as a multibase base58btc string.
 * Format: 'z' prefix + base58btc(x25519_multicodec_prefix + public_key)
 */
export function encodeEncryptionKeyMultibase(publicKey: Uint8Array): string {
  if (!(publicKey instanceof Uint8Array)) {
    throw new Error("publicKey must be a Uint8Array");
  }
  if (publicKey.length !== 32) {
    throw new Error(`publicKey must be 32 bytes, got ${publicKey.length}`);
  }
  const prefixed = new Uint8Array(
    X25519_MULTICODEC.length + publicKey.length,
  );
  prefixed.set(X25519_MULTICODEC);
  prefixed.set(publicKey, X25519_MULTICODEC.length);
  return "z" + encodeBase58(prefixed);
}

/**
 * Decode a multibase base58btc public key string.
 * Returns the raw 32-byte public key.
 */
export function decodePublicKeyMultibase(multibase: string): Uint8Array {
  if (typeof multibase !== "string" || multibase.length === 0 || multibase.length > 1024) {
    throw new Error("multibase must be a non-empty string under 1024 chars");
  }
  if (!multibase.startsWith("z")) {
    throw new Error("Expected multibase base58btc prefix 'z'");
  }
  const decoded = decodeBase58(multibase.slice(1));
  if (
    decoded[0] !== ED25519_MULTICODEC[0] ||
    decoded[1] !== ED25519_MULTICODEC[1]
  ) {
    throw new Error("Invalid Ed25519 multicodec prefix");
  }
  const key = decoded.slice(2);
  if (key.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: expected 32, got ${key.length}`);
  }
  return key;
}

/**
 * Decode a multibase base58btc X25519 public key string.
 * Returns the raw 32-byte public key.
 */
export function decodeEncryptionKeyMultibase(multibase: string): Uint8Array {
  if (typeof multibase !== "string" || multibase.length === 0 || multibase.length > 1024) {
    throw new Error("multibase must be a non-empty string under 1024 chars");
  }
  if (!multibase.startsWith("z")) {
    throw new Error("Expected multibase base58btc prefix 'z'");
  }
  const decoded = decodeBase58(multibase.slice(1));
  if (
    decoded[0] !== X25519_MULTICODEC[0] ||
    decoded[1] !== X25519_MULTICODEC[1]
  ) {
    throw new Error("Invalid X25519 multicodec prefix");
  }
  const key = decoded.slice(2);
  if (key.length !== 32) {
    throw new Error(`Invalid X25519 public key length: expected 32, got ${key.length}`);
  }
  return key;
}

/**
 * agentId method prefixes that carry the same key-derived identity. Both encode
 * the identical multibase public key, so they denote the same actor. `tulpa:`
 * is canonical for emission (see deriveAgentId); `ink:` is an accepted inbound
 * alias introduced in ink/0.4. Accept both, emit one.
 */
export const AGENT_ID_KEY_PREFIXES = Object.freeze(["tulpa:", "ink:"] as const);

/**
 * Derive agent ID from a public key.
 * Format: tulpa:<multibase-encoded-public-key> (canonical emission).
 */
export function deriveAgentId(publicKey: Uint8Array): string {
  return `tulpa:${encodePublicKeyMultibase(publicKey)}`;
}

/**
 * Extract the public key from an agent ID.
 * Only used for initial key exchange — after that, always resolve via identity store.
 *
 * Accepts either the canonical `tulpa:` prefix or the `ink:` alias (ink/0.4):
 * both carry the identical multibase key, so a signature made with that key
 * verifies regardless of which accepted prefix carried it. The prefix is
 * identity syntax, not signing authority. The multibase tail is decoded the
 * same way for both, so a malformed tail is rejected identically.
 */
export function extractPublicKeyFromAgentId(agentId: string): Uint8Array {
  if (typeof agentId !== "string" || agentId.length === 0 || agentId.length > 512) {
    throw new Error("Invalid agent ID");
  }
  const prefix = AGENT_ID_KEY_PREFIXES.find((p) => agentId.startsWith(p));
  if (!prefix) {
    throw new Error("Invalid agent ID format");
  }
  return decodePublicKeyMultibase(agentId.slice(prefix.length));
}

/**
 * Collapse an agent ID to a single, prefix-independent principal string that
 * per-sender security state (block lists, rate limits, duplicate-payload
 * checks, cached verification keys, connection identity) MUST key on.
 *
 * The accepted spellings `tulpa:zKEY` and `ink:zKEY` encode the same Ed25519
 * key and are therefore the same actor; this maps both — and any non-canonical
 * multibase encoding of that key — to `key:<canonical-multibase>`, so a sender
 * cannot switch prefix or re-encode to dodge a block or split a rate-limit
 * window. DIDs (and any other identifier) are returned unchanged. A raw `key:`
 * input — never a legitimate agent ID — is escaped to `raw:key:…` so a sender
 * cannot forge a collision with a canonicalized key principal.
 *
 * Not idempotent: call exactly once, at the storage boundary, on the raw
 * agent ID. Total over well-formed string input (it never throws on a
 * malformed key body — that is escaped to `raw:…` so a principal is always
 * derivable); throws only on a non-string, empty, or over-length argument.
 */
export function canonicalAgentPrincipal(agentId: string): string {
  if (typeof agentId !== "string" || agentId.length === 0 || agentId.length > 512) {
    throw new Error("Invalid agent ID");
  }
  const prefix = AGENT_ID_KEY_PREFIXES.find((p) => agentId.startsWith(p));
  if (prefix) {
    try {
      return "key:" + encodePublicKeyMultibase(decodePublicKeyMultibase(agentId.slice(prefix.length)));
    } catch {
      // Malformed multibase body: keep the function total by treating it as an
      // opaque identifier. Such an ID cannot authenticate via the bootstrap
      // path anyway, so it never collides with a real key principal.
      return "raw:" + agentId;
    }
  }
  if (agentId.startsWith("key:")) {
    return "raw:" + agentId;
  }
  return agentId;
}
