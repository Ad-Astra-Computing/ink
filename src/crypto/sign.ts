import * as ed from "@noble/ed25519";
import canonicalize from "canonicalize";

/** Same bounds used by the ink.ts verify paths. Kept in sync so a peer
 * cannot pick the "softer" sign.ts path to bypass the cap. */
const MAX_MESSAGE_NODES = 10_000;
const MAX_MESSAGE_DEPTH = 32;
const MAX_MESSAGE_CHARS = 1_200_000;
/** Upper limit on the canonicalized message length, matching
 * MAX_SIGBASE_BODY_BYTES in ink.ts. Defense in depth alongside the node
 * walk: a message can be small in node count but still expand to huge
 * canonical bytes via long string values. */
const MAX_MESSAGE_CANONICAL_BYTES = 1_048_576;

/**
 * Cheap depth/node/byte walk over a value before it is handed to
 * `canonicalize`. Bails before the recursive sort+serialize runs, so an
 * attacker who supplies a syntactically valid-shape signature with a
 * pathological message body cannot burn CPU/memory inside the verify
 * path. Mirrors src/crypto/ink.ts:isWithinCanonicalizeBounds, including
 * the byte counter that stops a single huge string from sneaking past
 * the node check.
 */
function isWithinBounds(value: unknown): boolean {
  let nodes = 0;
  let chars = 0;
  function walk(v: unknown, depth: number): boolean {
    if (depth > MAX_MESSAGE_DEPTH) return false;
    if (++nodes > MAX_MESSAGE_NODES) return false;
    if (v === null || typeof v !== "object") {
      if (typeof v === "string") {
        chars += v.length;
        if (chars > MAX_MESSAGE_CHARS) return false;
      }
      return true;
    }
    if (Array.isArray(v)) {
      for (const item of v) if (!walk(item, depth + 1)) return false;
      return true;
    }
    for (const key of Object.keys(v as Record<string, unknown>)) {
      if (++nodes > MAX_MESSAGE_NODES) return false;
      chars += key.length;
      if (chars > MAX_MESSAGE_CHARS) return false;
      if (!walk((v as Record<string, unknown>)[key], depth + 1)) return false;
    }
    return true;
  }
  return walk(value, 0);
}

/**
 * Body-signature domain-separation prefix, keyed off the message's
 * declared `protocol` version.
 *
 * - `ink/0.2` -> `ink/sign\n` (neutral, current).
 * - everything else (`ink/0.1`, or any object with no explicit
 *   `ink/0.2` protocol) -> `tulpa/sign\n`, the legacy domain, kept
 *   forever so every signature ever produced still verifies.
 *
 * The prefix is derived from the `protocol` field that is part of the
 * signed body, so a verifier selects exactly one domain and tampering
 * with `protocol` after signing breaks the signature (an `ink/0.2` body
 * re-labelled `ink/0.1` is verified under `tulpa/sign\n` against a
 * signature made over `ink/sign\n`, and fails). Only the exact string
 * `"ink/0.2"` switches domains, so no other value can smuggle one in.
 *
 * This raw signer stays permissive on purpose: it is a general-purpose
 * Ed25519 message signer (receipts, arbitrary objects), not envelope-
 * specific. Strict "reject unknown protocol version" lives at the
 * envelope schema layer, which validates `protocol` against the allowed
 * set before this function is reached.
 */
const LEGACY_SIGN_DOMAIN = "tulpa/sign\n";
const V02_SIGN_DOMAIN = "ink/sign\n";

function bodySignatureDomain(unsigned: Record<string, unknown>): string {
  return unsigned.protocol === "ink/0.2" ? V02_SIGN_DOMAIN : LEGACY_SIGN_DOMAIN;
}

/**
 * Sign a message object using Ed25519.
 *
 * 1. Remove `signature` field if present
 * 2. JCS canonicalize (RFC 8785) via `canonicalize` library
 * 3. Sign domain-prefixed canonical bytes directly with Ed25519
 * 4. Return base64url-encoded signature (no padding)
 */
export async function signMessage(
  message: Record<string, unknown>,
  privateKey: Uint8Array,
): Promise<string> {
  if (message === null || typeof message !== "object" || Array.isArray(message)) {
    throw new Error("message must be a non-null object");
  }
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) {
    throw new Error("privateKey must be a 32-byte Uint8Array");
  }
  const { signature: _, ...unsigned } = message;
  // Refuse oversized inputs at sign time so the sign side cannot mint
  // signatures over payloads larger than any conformant verifier will
  // accept. Mirrors the matching guard in verifyMessage().
  if (!isWithinBounds(unsigned)) {
    throw new Error("Message exceeds maximum allowed complexity");
  }
  const canonical = canonicalize(unsigned);
  if (canonical === undefined) {
    throw new Error("Failed to canonicalize message");
  }
  if (canonical.length > MAX_MESSAGE_CANONICAL_BYTES) {
    throw new Error("Canonicalized message exceeds maximum allowed size");
  }
  // Domain-separated signing to prevent cross-protocol signature replay.
  // Domain is keyed off the (signed) protocol version; see
  // bodySignatureDomain. Legacy ink/0.1 keeps the tulpa/sign domain.
  const prefixed = `${bodySignatureDomain(unsigned)}${canonical}`;
  const bytes = new TextEncoder().encode(prefixed);
  const sig = await ed.signAsync(bytes, privateKey);
  return base64urlEncode(sig);
}

/**
 * Verify a message signature.
 *
 * 1. Extract and remove `signature`
 * 2. JCS canonicalize the rest
 * 3. Verify Ed25519 signature against canonical bytes
 */
export async function verifyMessage(
  message: Record<string, unknown>,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (message === null || typeof message !== "object" || Array.isArray(message)) return false;
  if (!(publicKey instanceof Uint8Array)) return false;
  const { signature, ...unsigned } = message;
  if (typeof signature !== "string") {
    return false;
  }
  // Ed25519 signatures are 64 bytes = 86 base64url chars (no padding).
  // Strict format check before decoding rejects non-canonical encodings outright.
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) {
    return false;
  }

  // Pre-canonicalize complexity cap: bail before `canonicalize()` walks
  // an attacker-supplied object that would only be rejected later by
  // signature verification. Mirrors the guard in verifyInkSignature so
  // a peer can't pick whichever entrypoint is softer.
  if (!isWithinBounds(unsigned)) {
    return false;
  }
  const canonical = canonicalize(unsigned);
  if (canonical === undefined) {
    return false;
  }
  if (canonical.length > MAX_MESSAGE_CANONICAL_BYTES) {
    return false;
  }

  // Domain-prefixed verification only. The domain is selected from the
  // signed `protocol` field (see bodySignatureDomain); a verifier never
  // tries an alternate prefix, so a signature made under one version's
  // domain cannot be replayed under another. Legacy unprefixed
  // signatures are not accepted.
  const prefixed = `${bodySignatureDomain(unsigned)}${canonical}`;
  const prefixedBytes = new TextEncoder().encode(prefixed);
  try {
    const sig = base64urlDecode(signature);
    // RFC 8032 strict verification, not the library default ZIP-215 mode:
    // reject small-order public keys and non-canonical point encodings so a
    // signature binds to exactly one (key, message). Identity is the embedded
    // public key and signatures feed the audit log, so strictness is required.
    return await ed.verifyAsync(sig, prefixedBytes, publicKey, { zip215: false });
  } catch {
    // Malformed signature (invalid base64url, wrong byte length, bad key) — treat as invalid
    return false;
  }
}

/** Encode Uint8Array as base64url (no padding). */
function base64urlEncode(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  const base64 = btoa(binString);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url string to Uint8Array. */
function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binString = atob(padded);
  return Uint8Array.from(binString, (c) => c.charCodeAt(0));
}
