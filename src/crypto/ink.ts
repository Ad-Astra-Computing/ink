import * as ed from "@noble/ed25519";
import { x25519 } from "@noble/curves/ed25519.js";
import canonicalize from "canonicalize";
import { isJcsSafeNumber, isSignableBody, hasNonJsonObject, type SignableBody } from "./sign.js";
import { parseInkTimestampMs } from "./timestamp.js";
import { hasUnpairedSurrogate } from "./surrogate.js";
import { hasUnsafeObjectKey } from "./member-name.js";
import { verifyDetachedSignatureWithKeys, type MultiKeyVerifyResult } from "./multi-key-verify.js";
import type { CandidateKey } from "../models/key-entry.js";

// ── Encoding helpers ──

// @types/node 26 types Uint8Array as generic over ArrayBufferLike, which the DOM
// WebCrypto BufferSource parameter no longer accepts (it wants an ArrayBuffer-
// backed view). Copy into a fresh ArrayBuffer-backed Uint8Array at the WebCrypto
// boundary. The bytes are identical, so the AES-GCM ciphertext, tag, and every
// signature are unchanged: this is a type-level fix, not a behavior change.
function toWebCryptoBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out;
}

const MAX_ENCODE_INPUT_BYTES = 2_000_000;

function base64urlEncode(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error("base64urlEncode: input must be a Uint8Array");
  }
  if (bytes.length > MAX_ENCODE_INPUT_BYTES) {
    throw new Error(`base64urlEncode: input exceeds maximum of ${MAX_ENCODE_INPUT_BYTES} bytes`);
  }
  const binString = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  const base64 = btoa(binString);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const MAX_BASE64URL_INPUT_LEN = 2_000_000;

function base64urlDecode(str: string): Uint8Array {
  if (typeof str !== "string") {
    throw new Error("base64urlDecode: input must be a string");
  }
  if (str.length > MAX_BASE64URL_INPUT_LEN) {
    throw new Error(`base64urlDecode: input exceeds maximum length of ${MAX_BASE64URL_INPUT_LEN}`);
  }
  if (!/^[A-Za-z0-9_-]*$/.test(str)) {
    throw new Error("base64urlDecode: invalid base64url character");
  }
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binString = atob(padded);
  return Uint8Array.from(binString, (c) => c.charCodeAt(0));
}

/** Defense-in-depth cap on hex input length. The longest legitimate input
 *  the package decodes is a 64-byte hex string (Ed25519 keypair concat); the
 *  cap is set generously above that so an attacker-supplied multi-megabyte
 *  hex string can't drive an O(n) regex scan and a multi-megabyte
 *  Uint8Array allocation before the downstream length check fires. */
const MAX_HEX_INPUT_LEN = 4096;

function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string") {
    throw new Error("hexToBytes: input must be a string");
  }
  if (hex.length > MAX_HEX_INPUT_LEN) {
    throw new Error(`hex input exceeds maximum length of ${MAX_HEX_INPUT_LEN}`);
  }
  if (hex.length % 2 !== 0) throw new Error(`Invalid hex string length: ${hex.length}`);
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("Invalid hex character in string");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error("bytesToHex: input must be a Uint8Array");
  }
  if (bytes.length > MAX_ENCODE_INPUT_BYTES) {
    throw new Error(`bytesToHex: input exceeds maximum of ${MAX_ENCODE_INPUT_BYTES} bytes`);
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ── JCS Canonicalization (RFC 8785) ──

function jcsCanonicalize(obj: unknown): string {
  if (!isWithinCanonicalizeBounds(obj)) {
    throw new Error("Input exceeds maximum allowed complexity");
  }
  // No signed or AAD-bound JCS object may carry a lone UTF-16 surrogate: it is
  // not portable across implementations (a parser like Go's encoding/json
  // rewrites it to U+FFFD, producing different canonical bytes). Centralized
  // here so every canonicalization path, request auth, audit events, and ECIES
  // AAD, is covered. A receiver should additionally scan the raw request body
  // before parsing, since a parsed body has already lost the original surrogate.
  if (hasUnpairedSurrogate(obj)) {
    throw new Error("Input contains an unpaired UTF-16 surrogate");
  }
  // Nor may it carry an object key that would serialize as an escaped member
  // name. V8 can decode such a member name to a different string entirely, so a
  // receiver on Node 24+ or workerd would canonicalize bytes the signer never
  // produced. Rejecting rather than rewriting the key: a signing API must not
  // silently change what the caller asked to sign, and normalizing could merge
  // two keys into one.
  if (hasUnsafeObjectKey(obj)) {
    throw new Error(
      "Input contains an object key with a quote, backslash or control character",
    );
  }
  const result = canonicalize(obj);
  if (result === undefined) throw new Error("Failed to canonicalize");
  if (result.length > MAX_SIGBASE_BODY_BYTES) {
    throw new Error("Canonical output exceeds maximum allowed size");
  }
  return result;
}

// ── INK v0.1 Signing (§3.3) ──

export interface InkSignInput {
  method: string;
  path: string;
  recipientDid: string;
  body: SignableBody;
  timestamp: string;
}

/**
 * Construct the INK v0.1 signature base string per §3.3:
 * ink/0.1\nMETHOD\nPATH\nrecipientDid\nJCS(body)\ntimestamp
 *
 * The protocol version prefix prevents cross-version signature replay.
 *
 * Newlines (CR or LF) are forbidden in all scalar fields. Because the base
 * string is newline-delimited, a field containing \n could shift field
 * boundaries and allow two distinct logical inputs to produce the same
 * signed bytes (a signature-base collision).
 */
/** Defense-in-depth cap on the canonicalized body size used to build the
 * INK signature base. Callers are expected to validate input size at the
 * transport boundary (the hosting HTTP layer typically caps total request
 * body size; INK-aware endpoints should additionally cap submit/query
 * bodies). This is an internal upper limit in case any caller forgets —
 * protects against canonicalize-then-encode burning CPU/memory on unbounded
 * `input.body`. 1 MB is well above any realistic signed payload. */
const MAX_SIGBASE_BODY_BYTES = 1_048_576;

/** Hard caps for the cheap pre-canonicalize bound walk. These are well above
 * any realistic INK body (signing payloads are typically <50 keys and ≤6
 * levels deep) but small enough that the walk itself remains O(n) on tiny
 * structures and bails fast on adversarial ones. The shape of the limits
 * mirrors what jcsCanonicalize would have to traverse anyway, so an attacker
 * cannot get past the pre-check and then explode inside canonicalize.
 *
 * MAX_PRECHECK_CHARS bounds aggregate string content (keys + string values)
 * so a single huge string can't slip past the node-count cap. Set slightly
 * above MAX_SIGBASE_BODY_BYTES so the post-canonicalize byte cap stays the
 * authoritative reject, but the pre-check stops `JSON.stringify` / the
 * recursive `canonicalize` from ever allocating that much in the first
 * place. The aggregate counter is approximate (counts JS string length not
 * UTF-8 bytes) but is intentionally a cheap upper-bound — the precise byte
 * count happens after canonicalize. */
const MAX_PRECHECK_NODES = 10_000;
const MAX_PRECHECK_DEPTH = 32;
const MAX_PRECHECK_CHARS = 1_200_000;

/**
 * Cheap depth/node-count/byte walk over a value before it is handed to
 * jcsCanonicalize. Returns true if the value is within bounds. The goal is
 * NOT to validate the value; it is to bail BEFORE canonicalize() does its
 * recursive sort+serialize on something that should be rejected anyway.
 * Non-throwing — the caller decides what to do with `false`.
 *
 * The byte counter accumulates every string value and every object key.
 * Without it, an attacker can pass the node check with a single value
 * like `{data: "x".repeat(100_000_000)}` (1 node, gigabytes of memory).
 */
function isWithinCanonicalizeBounds(value: unknown): boolean {
  let nodes = 0;
  let chars = 0;
  function walk(v: unknown, depth: number): boolean {
    if (depth > MAX_PRECHECK_DEPTH) return false;
    if (++nodes > MAX_PRECHECK_NODES) return false;
    if (v === null || typeof v !== "object") {
      if (typeof v === "string") {
        chars += v.length;
        if (chars > MAX_PRECHECK_CHARS) return false;
      } else if (typeof v === "number" && !isJcsSafeNumber(v)) {
        // Reject numbers that don't canonicalize identically across JSON
        // serializers (non-finite, -0, exponential notation). See sign.ts.
        return false;
      }
      return true;
    }
    if (Array.isArray(v)) {
      for (const item of v) {
        if (!walk(item, depth + 1)) return false;
      }
      return true;
    }
    for (const key of Object.keys(v as Record<string, unknown>)) {
      if (++nodes > MAX_PRECHECK_NODES) return false;
      chars += key.length;
      if (chars > MAX_PRECHECK_CHARS) return false;
      if (!walk((v as Record<string, unknown>)[key], depth + 1)) return false;
    }
    return true;
  }
  return walk(value, 0);
}


export function buildSignatureBase(input: InkSignInput): string {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Invalid signature-base input");
  }
  // Validate scalar shape FIRST: each field is a non-empty string within
  // a reasonable cap. An attacker who reaches this with a 100 MB path or
  // recipientDid would otherwise force large TextEncoder allocations and
  // a worst-case regex scan before signature failure.
  // Caps:
  //   method:        16 chars  (HTTP verb)
  //   path:        2048 chars  (URI Section 3.3 practical bound)
  //   recipientDid:  256 chars (same as middleware senderDid cap)
  //   timestamp:      64 chars (ISO 8601 with subsecond + timezone)
  const isScalar = (x: unknown, max: number): x is string =>
    typeof x === "string" && x.length > 0 && x.length <= max;
  if (!isScalar(input.method, 16)) throw new Error("Invalid signature-base method");
  if (!isScalar(input.path, 2048)) throw new Error("Invalid signature-base path");
  if (!isScalar(input.recipientDid, 256)) throw new Error("Invalid signature-base recipientDid");
  if (!isScalar(input.timestamp, 64)) throw new Error("Invalid signature-base timestamp");

  // Guard against newline injection in each scalar field.
  // CR (\r) is included because \r\n is a common line-ending and would
  // produce the same boundary-shift as \n alone.
  const crlf = /[\r\n]/;
  if (crlf.test(input.method)) throw new Error("Invalid character in method: newline or CR not allowed");
  if (crlf.test(input.path)) throw new Error("Invalid character in path: newline or CR not allowed");
  if (crlf.test(input.recipientDid)) throw new Error("Invalid character in recipientDid: newline or CR not allowed");
  if (crlf.test(input.timestamp)) throw new Error("Invalid character in timestamp: newline or CR not allowed");

  // Bound the cost of the canonicalize step BEFORE invoking it. Without
  // this, an attacker can submit a syntactically valid body that bloats
  // the recursive sort+serialize work inside jcsCanonicalize and then
  // gets rejected by the size cap below — burning CPU/memory pre-reject.
  if (!isSignableBody(input.body)) {
    throw new Error("Invalid signature-base body: expected a plain JSON object");
  }
  if (!isWithinCanonicalizeBounds(input.body)) {
    throw new Error("Signature base body exceeds maximum allowed complexity");
  }
  if (hasNonJsonObject(input.body)) {
    throw new Error("Invalid signature-base body: contains a value that is not JSON data");
  }
  const canonical = jcsCanonicalize(input.body);
  if (new TextEncoder().encode(canonical).length > MAX_SIGBASE_BODY_BYTES) {
    throw new Error("Signature base body exceeds maximum allowed size");
  }
  return `ink/0.1\n${input.method}\n${input.path}\n${input.recipientDid}\n${canonical}\n${input.timestamp}`;
}

/**
 * Sign an INK message. Returns the base64url-encoded Ed25519 signature.
 */
export async function signInkMessage(
  input: InkSignInput,
  privateKey: Uint8Array,
): Promise<string> {
  const sigBase = buildSignatureBase(input);
  const bytes = new TextEncoder().encode(sigBase);
  const sig = await ed.signAsync(bytes, privateKey);
  return base64urlEncode(sig);
}

/**
 * Verify an INK message signature.
 * Returns false (never throws) for malformed or wrong-length signatures.
 */
export async function verifyInkSignature(
  input: InkSignInput,
  signatureBase64url: string,
  publicKey: Uint8Array,
): Promise<boolean> {
  // Reject obviously-malformed signatures BEFORE canonicalizing the body.
  // canonicalize() walks the entire body to sort keys; doing that work
  // for a request with a junk signature lets attackers burn CPU/memory
  // on the verifier without ever supplying a valid signature.
  if (!/^[A-Za-z0-9_-]{86}$/.test(signatureBase64url)) return false;
  let sigBase: string;
  try {
    sigBase = buildSignatureBase(input);
  } catch {
    return false;
  }
  const bytes = new TextEncoder().encode(sigBase);
  try {
    const sig = base64urlDecode(signatureBase64url);
    // RFC 8032 strict verification (not the default ZIP-215): reject
    // small-order keys and non-canonical encodings. See verifyMessage.
    return await ed.verifyAsync(sig, bytes, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/**
 * Build the Authorization header value for an INK request.
 * Optionally includes keyId for key-rotation-aware verification.
 *
 * Both values are validated against the same grammar the receiver uses so that
 * invalid characters (including CR/LF that could cause header injection) are
 * rejected before they reach the HTTP layer.
 */
export function buildAuthHeader(signatureBase64url: string, keyId?: string): string {
  // Ed25519 signatures are exactly 64 bytes which encode to exactly 86 unpadded base64url chars.
  // Reject any other length at the builder so callers get an early error rather than sending
  // a syntactically-valid but semantically-wrong Authorization header.
  if (!/^[A-Za-z0-9_-]{86}$/.test(signatureBase64url)) {
    throw new Error("Invalid signature for Authorization header: must be exactly 86 base64url characters (Ed25519)");
  }
  if (keyId !== undefined) {
    // keyId must match the verifier's grammar — alphanumeric plus safe punctuation, no CR/LF or spaces.
    if (!/^[A-Za-z0-9_:.-]{1,128}$/.test(keyId)) {
      throw new Error("Invalid keyId for Authorization header: must be 1-128 chars [A-Za-z0-9_:.-]");
    }
    return `INK-Ed25519 ${signatureBase64url} keyId=${keyId}`;
  }
  return `INK-Ed25519 ${signatureBase64url}`;
}

// ── INK v0.1 Encryption (§3.4 — ECIES) ──

export interface InkEncryptedEnvelope {
  protocol: "ink/0.1";
  // Receivers dual-accept both spellings; senders emit the legacy form by
  // default (see specs/ink-compatibility-policy.md §1.3 and `messageType`).
  type: "network.tulpa.encrypted" | "network.ink.encrypted";
  from: string;
  ephemeralKey: string;
  nonce: string;
  ciphertext: string;
  timestamp: string;
  messageNonce: string;
}

export interface InkEncryptResult {
  envelope: InkEncryptedEnvelope;
  ephemeralPublicKey: Uint8Array;
}

/**
 * Encrypt an INK message payload using ECIES:
 *   1. Generate ephemeral X25519 keypair (or accept one for deterministic tests)
 *   2. ECDH with recipient's X25519 public key
 *   3. HKDF-SHA256(sharedSecret, salt="ink/0.1", info="ink/0.1/encrypt") → 32-byte AES key
 *   4. AES-256-GCM encrypt the JSON-serialized plaintext
 *   5. Pack into outer envelope
 */
export async function encryptInkPayload(
  plaintext: Record<string, unknown>,
  senderDid: string,
  recipientEncryptionKeyHex: string,
  timestamp: string,
  messageNonce: string,
  options?: {
    // SECURITY: these overrides exist only to make the conformance corpus
    // deterministic. They MUST NOT be set on production traffic. Reusing a
    // fixed `ephemeralPrivateKey` across messages to the same recipient
    // derives the same AES key, and a fixed/colliding `aesNonce` then reuses
    // the (key, nonce) pair — catastrophic for AES-GCM (forgery plus
    // plaintext recovery). Leave both unset so each call draws a fresh
    // ephemeral key and a random nonce.
    ephemeralPrivateKey?: Uint8Array;
    aesNonce?: Uint8Array;
    // Wire-namespace prefix to emit. Defaults to the legacy
    // `network.tulpa.encrypted`; a sender that has negotiated the
    // vendor-neutral namespace may set `network.ink.encrypted`. The chosen
    // type is bound into the AAD, so it is authenticated, not malleable.
    messageType?: "network.tulpa.encrypted" | "network.ink.encrypted";
    // The recipient identity this envelope is addressed to. When supplied, the
    // inner plaintext's `to` MUST equal it, so the seal cannot mint an envelope
    // whose inner binding disagrees with the recipient the sender intends. It is
    // the outer half of the binding decryptInkPayload enforces with its
    // mandatory recipientDid argument.
    recipientDid?: string;
  },
): Promise<InkEncryptResult> {
  const messageType = options?.messageType ?? "network.tulpa.encrypted";
  // Pre-AAD scalar caps. AAD is canonicalized and TextEncoder-allocated;
  // unbounded sender DID / timestamp / messageNonce values would force
  // the encrypt path to spend CPU/memory before any GCM work. These
  // caps mirror the decrypt-side guards so encrypt cannot mint AAD that
  // a conformant decrypter would refuse.
  if (typeof senderDid !== "string" || senderDid.length === 0 || senderDid.length > 512) {
    throw new Error("Invalid senderDid");
  }
  if (typeof timestamp !== "string" || timestamp.length === 0 || timestamp.length > 64) {
    throw new Error("Invalid timestamp");
  }
  if (typeof messageNonce !== "string" || messageNonce.length === 0 || messageNonce.length > 256) {
    throw new Error("Invalid messageNonce");
  }
  // Inner/outer binding. decryptInkPayload requires the sealed plaintext to
  // carry `from` equal to the outer envelope sender and `to` equal to the
  // recipient identity the decrypter asserts (which is mandatory and non-empty),
  // so a plaintext that fails either rule produces an envelope no conformant
  // decrypter will ever open. Checking it here keeps the encrypt path to the
  // same rule as every other guard on it: never mint what decrypt refuses.
  // `to` is checked against options.recipientDid when the caller asserts one;
  // with or without that assertion it must still be a non-empty string, because
  // an absent or non-string `to` cannot match any recipient identity.
  if (typeof plaintext !== "object" || plaintext === null || Array.isArray(plaintext)) {
    throw new Error("Invalid plaintext: must be a non-null object");
  }
  if (plaintext.from !== senderDid) {
    throw new Error("Invalid inner from: plaintext.from must equal the outer senderDid");
  }
  if (typeof plaintext.to !== "string" || plaintext.to.length === 0) {
    throw new Error("Invalid inner to: plaintext.to must be a non-empty string");
  }
  if (options?.recipientDid !== undefined && plaintext.to !== options.recipientDid) {
    throw new Error("Invalid inner to: plaintext.to must equal the asserted recipientDid");
  }
  // 1. Ephemeral X25519 keypair.
  // Test-supplied overrides must be the right length to produce a clean
  // error instead of an opaque crypto exception.
  if (options?.ephemeralPrivateKey && options.ephemeralPrivateKey.length !== 32) {
    throw new Error("ephemeralPrivateKey must be exactly 32 bytes");
  }
  const ephPriv = options?.ephemeralPrivateKey ?? crypto.getRandomValues(new Uint8Array(32));
  const ephPub = x25519.getPublicKey(ephPriv);

  // 2. ECDH shared secret. Explicit 32-byte length check on the decoded
  //    recipient public key so we surface a clean error rather than an
  //    opaque noble-curves exception (matches the ephemeralPrivateKey path
  //    guard above).
  const recipientPub = hexToBytes(recipientEncryptionKeyHex);
  if (recipientPub.length !== 32) {
    throw new Error("recipientEncryptionKeyHex must decode to exactly 32 bytes");
  }
  const sharedSecret = x25519.getSharedSecret(ephPriv, recipientPub);

  // Refuse all-zero shared secrets. A low-order recipient public key (a
  // 32-byte value in the small subgroup) forces every X25519 ECDH to
  // produce an all-zero shared secret. Without this check, the encrypt
  // path would derive a deterministic, publicly-known AES key from HKDF,
  // making the ciphertext decryptable by anyone. The decrypt path has the
  // mirrored guard at the all-zeros check below.
  if (sharedSecret.every((b) => b === 0)) {
    throw new Error("Invalid recipient public key: ECDH shared secret is all zeros");
  }

  // 3. HKDF-SHA256 → AES key
  const hkdfKey = await crypto.subtle.importKey(
    "raw", sharedSecret, "HKDF", false, ["deriveBits"],
  );
  const symmetricBits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode("ink/0.1"), info: new TextEncoder().encode("ink/0.1/encrypt") },
    hkdfKey, 256,
  );
  const symmetricKey = new Uint8Array(symmetricBits);

  // 4. AES-256-GCM
  if (options?.aesNonce && options.aesNonce.length !== 12) {
    throw new Error("aesNonce must be exactly 12 bytes");
  }
  const aesNonce = options?.aesNonce ?? crypto.getRandomValues(new Uint8Array(12));

  // Bound the plaintext BEFORE JSON.stringify and TextEncoder.encode so
  // a caller asked to encrypt attacker-supplied data can't be forced
  // into large allocations. Decrypt already caps the resulting
  // ciphertext; we mirror that here so encrypt cannot mint envelopes a
  // conformant decryptor would refuse. Cheap node walk first, then
  // string-length cap on the encoded bytes.
  if (!isWithinCanonicalizeBounds(plaintext)) {
    throw new Error("Plaintext exceeds maximum allowed complexity");
  }
  const plaintextJson = JSON.stringify(plaintext);
  if (plaintextJson.length > MAX_SIGBASE_BODY_BYTES) {
    throw new Error("Plaintext exceeds maximum allowed size");
  }
  const plaintextBytes = new TextEncoder().encode(plaintextJson);

  const aesKey = await crypto.subtle.importKey("raw", symmetricKey, "AES-GCM", false, ["encrypt"]);
  // AAD binds the ciphertext to all security-relevant outer envelope fields using
  // an unambiguous JSON-canonical representation. This prevents an attacker from
  // replaying the same ciphertext with modified outer metadata (timestamp, nonce, etc.)
  // or reattributing the ciphertext to a different sender.
  // Fields bound: protocol, type, from (sender), recipientKey (the recipient's
  // static X25519 public key), ephemeralKey, AES nonce (base64url), timestamp,
  // messageNonce. Binding recipientKey ties the ciphertext to one recipient
  // identity so it cannot be re-attributed to a different recipient envelope;
  // the decrypt side recomputes it from the recipient's own private key, so a
  // mismatch fails the tag. Including protocol and type prevents type-confusion
  // attacks where an attacker reinterprets the envelope as a different message type.
  const aadObject = {
    protocol: "ink/0.1",
    type: messageType,
    from: senderDid,
    recipientKey: base64urlEncode(recipientPub),
    ephemeralKey: base64urlEncode(ephPub),
    nonce: base64urlEncode(aesNonce),
    timestamp,
    messageNonce,
  };
  const aadString = `ink/0.1:envelope\n${jcsCanonicalize(aadObject)}`;
  const aad = new TextEncoder().encode(aadString);
  const ciphertextWithTag = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toWebCryptoBytes(aesNonce), additionalData: toWebCryptoBytes(aad) },
      aesKey,
      toWebCryptoBytes(plaintextBytes),
    ),
  );

  // 5. Outer envelope
  const envelope: InkEncryptedEnvelope = {
    protocol: "ink/0.1",
    type: messageType,
    from: senderDid,
    ephemeralKey: base64urlEncode(ephPub),
    nonce: base64urlEncode(aesNonce),
    ciphertext: base64urlEncode(ciphertextWithTag),
    timestamp,
    messageNonce,
  };

  return { envelope, ephemeralPublicKey: ephPub };
}

/**
 * Decrypt an INK encrypted envelope using the recipient's X25519 private key.
 * Returns the decrypted inner envelope and verifies inner/outer consistency.
 */
export async function decryptInkPayload(
  envelope: InkEncryptedEnvelope,
  recipientEncryptionPrivateKeyHex: string,
  // Required: the decrypter MUST assert which recipient identity it is. An
  // empty string is still a runtime reject so a JS caller that bypasses the
  // type cannot decrypt without asserting recipient identity.
  recipientDid: string,
): Promise<Record<string, unknown>> {
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new Error("envelope must be a non-null object");
  }
  if (envelope.protocol !== "ink/0.1") {
    throw new Error("Unsupported protocol version");
  }
  // Receivers dual-accept the legacy and vendor-neutral spellings. The actual
  // type is bound into the AAD below (never normalized), so a relabelled
  // envelope (e.g. a tulpa-tagged ciphertext changed to the ink spelling)
  // reconstructs a different AAD and fails the GCM tag.
  if (envelope.type !== "network.tulpa.encrypted" && envelope.type !== "network.ink.encrypted") {
    throw new Error("Invalid encrypted envelope type");
  }

  // Pre-auth length caps on AAD fields. These all flow into JCS canonicalize
  // + TextEncoder allocation before the AES-GCM tag check, so unbounded
  // attacker-supplied strings would burn CPU/memory pre-verification.
  // Non-empty check mirrors encryptInkPayload's input validation so
  // encrypt and decrypt accept exactly the same scalar set — without
  // the matching `length === 0` reject, decrypt would accept an
  // envelope that encrypt could never have produced.
  if (
    typeof envelope.from !== "string" ||
    envelope.from.length === 0 ||
    envelope.from.length > 512
  ) {
    throw new Error("Invalid envelope from");
  }
  if (
    typeof envelope.timestamp !== "string" ||
    envelope.timestamp.length === 0 ||
    envelope.timestamp.length > 64
  ) {
    throw new Error("Invalid envelope timestamp");
  }
  if (
    typeof envelope.messageNonce !== "string" ||
    envelope.messageNonce.length === 0 ||
    envelope.messageNonce.length > 256
  ) {
    throw new Error("Invalid envelope messageNonce");
  }

  // 1. Decode and validate ephemeral public key from envelope.
  // X25519 public keys are exactly 32 bytes = 43 unpadded base64url chars.
  // Pre-check the encoded length BEFORE decoding so a 100 MB ephemeralKey
  // field doesn't get fully decoded into a ~75 MB Uint8Array before the
  // length === 32 check fires — same memory-exhaustion class the
  // ciphertext cap below defends against.
  if (typeof envelope.ephemeralKey !== "string" || envelope.ephemeralKey.length > 64) {
    throw new Error("Invalid ephemeral key");
  }
  const ephPub = base64urlDecode(envelope.ephemeralKey);
  if (ephPub.length !== 32) {
    throw new Error("Invalid ephemeral key length");
  }

  // 2. ECDH shared secret. Explicit 32-byte length check on the decoded
  //    recipient private key (matches the encrypt path).
  const recipientPriv = hexToBytes(recipientEncryptionPrivateKeyHex);
  if (recipientPriv.length !== 32) {
    throw new Error("recipientEncryptionPrivateKeyHex must decode to exactly 32 bytes");
  }
  const sharedSecret = x25519.getSharedSecret(recipientPriv, ephPub);

  // Reject low-order / malicious ephemeral keys that produce an all-zero shared secret.
  // An all-zero ECDH output is cryptographically invalid and would allow an attacker
  // to construct ciphertexts decryptable by any recipient.
  if (sharedSecret.every((b) => b === 0)) {
    throw new Error("Invalid ephemeral key: ECDH shared secret is all zeros");
  }

  // 3. HKDF-SHA256 → AES key
  const hkdfKey = await crypto.subtle.importKey(
    "raw", sharedSecret, "HKDF", false, ["deriveBits"],
  );
  const symmetricBits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode("ink/0.1"), info: new TextEncoder().encode("ink/0.1/encrypt") },
    hkdfKey, 256,
  );
  const symmetricKey = new Uint8Array(symmetricBits);

  // 4. AES-256-GCM decrypt.
  // AES-GCM nonce is exactly 12 bytes = 16 unpadded base64url chars.
  // Pre-check the encoded length BEFORE decoding to avoid allocating a
  // large Uint8Array for an attacker-supplied oversized nonce field.
  if (typeof envelope.nonce !== "string" || envelope.nonce.length > 32) {
    throw new Error("Invalid AES-GCM nonce");
  }
  const aesNonce = base64urlDecode(envelope.nonce);
  // AES-GCM requires a 12-byte IV. Reject any other length explicitly so callers
  // get a clean error rather than an opaque WebCrypto exception.
  if (aesNonce.length !== 12) {
    throw new Error(`Invalid AES-GCM nonce length: expected 12 bytes, got ${aesNonce.length}`);
  }
  // Cap ciphertext size before base64url decode + AES-GCM allocation. Without
  // this, a ~100 MB ciphertext would be decoded into ~75 MB Uint8Array and
  // sent through GCM before the auth tag rejects it. 1 MB easily fits any
  // realistic INK message payload while bounding memory under adversarial load.
  const MAX_CIPHERTEXT_B64URL = 1_400_000;
  if (typeof envelope.ciphertext !== "string" || envelope.ciphertext.length > MAX_CIPHERTEXT_B64URL) {
    throw new Error("Ciphertext exceeds maximum allowed size");
  }
  const ciphertextWithTag = base64urlDecode(envelope.ciphertext);

  const aesKey = await crypto.subtle.importKey("raw", symmetricKey, "AES-GCM", false, ["decrypt"]);
  // AAD must match what was used during encryption — same unambiguous JSON-canonical format.
  // protocol and type bind the ciphertext to this specific envelope type. recipientKey is
  // recomputed locally from the recipient's own private key (not read from the envelope),
  // so a ciphertext encrypted for a different recipient derives a different AAD and fails
  // the GCM tag — binding the ciphertext to this recipient identity cryptographically.
  const recipientPub = x25519.getPublicKey(recipientPriv);
  const aadObject = {
    protocol: "ink/0.1",
    // Bind the type AS RECEIVED (legacy or vendor-neutral), never normalized,
    // so a relabelled envelope fails the tag.
    type: envelope.type,
    from: envelope.from,
    recipientKey: base64urlEncode(recipientPub),
    ephemeralKey: envelope.ephemeralKey,
    nonce: envelope.nonce,
    timestamp: envelope.timestamp,
    messageNonce: envelope.messageNonce,
  };
  const aadString = `ink/0.1:envelope\n${jcsCanonicalize(aadObject)}`;
  const aad = new TextEncoder().encode(aadString);
  const plaintextBytes = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toWebCryptoBytes(aesNonce), additionalData: toWebCryptoBytes(aad) },
      aesKey,
      toWebCryptoBytes(ciphertextWithTag),
    ),
  );

  // Plaintext is now AES-GCM-authenticated, so any well-formed JSON object
  // here came from the sender. Still type-check before property access so
  // a sender posting `null`/array/scalar payloads gets a clean validation
  // error instead of a TypeError on `.from`.
  const decryptedRaw = JSON.parse(new TextDecoder().decode(plaintextBytes));
  if (decryptedRaw === null || typeof decryptedRaw !== "object" || Array.isArray(decryptedRaw)) {
    throw new Error("Inner envelope must be a JSON object");
  }
  const decrypted = decryptedRaw as Record<string, unknown>;

  // 5. Verify inner/outer consistency
  if (decrypted.from !== envelope.from) {
    throw new Error("Inner envelope 'from' does not match outer envelope");
  }
  // recipientDid is MANDATORY: the decrypter must assert which recipient
  // identity it is, and the decrypted inner `to` must equal it. The AAD
  // recipientKey binding ties the ciphertext to the recipient's static key;
  // this binds the DID on top, which matters when one X25519 key backs more
  // than one alias/tenant. A missing or empty recipientDid is a reject, not a
  // silent skip, so an integrator cannot accidentally decrypt without
  // asserting recipient identity.
  if (typeof recipientDid !== "string" || recipientDid.length === 0) {
    throw new Error("recipientDid is required to assert recipient identity");
  }
  if (decrypted.to !== recipientDid) {
    throw new Error("Inner envelope 'to' does not match recipient DID");
  }

  return decrypted;
}

// ── INK v0.1 Replay Protection (§3.5) ──

export interface ReplayCheckInput {
  messageTimestamp: string;
  receiverClock: string;
  nonce: string;
  previouslySeenNonces: string[];
}

export interface ReplayCheckResult {
  accepted: boolean;
  errorCode?: "expired_message" | "duplicate_nonce";
}

export const MAX_TIMESTAMP_AGE_MS = 5 * 60 * 1000; // 5 minutes
export const MAX_FUTURE_TIMESTAMP_MS = 30 * 1000;   // 30 seconds

/**
 * Check whether an INK message should be accepted or rejected
 * based on timestamp freshness and nonce deduplication (§3.5).
 */
export function checkReplay(input: ReplayCheckInput): ReplayCheckResult {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return { accepted: false, errorCode: "expired_message" };
  }
  if (
    typeof input.nonce !== "string" ||
    input.nonce.length < 16 ||
    input.nonce.length > 256 ||
    !/^[A-Za-z0-9_-]+$/.test(input.nonce)
  ) {
    return { accepted: false, errorCode: "expired_message" };
  }
  if (!Array.isArray(input.previouslySeenNonces) || input.previouslySeenNonces.length > 10_000) {
    return { accepted: false, errorCode: "expired_message" };
  }

  // Length-cap both timestamp strings before handing them to Date()
  // so a multi-megabyte value can't burn CPU in the engine's date
  // parser before the finite-time check rejects. 64 chars matches the
  // cap used elsewhere in INK (ISO 8601 fits in ~30 chars).
  // Parse both timestamps with the strict RFC 3339 / millisecond grammar
  // shared across implementations. A lenient (date-only, no-zone,
  // space-separated) or oversized value another implementation rejects is
  // rejected here too; the length cap inside the parser bounds work before
  // the date parser runs. A null result fails closed: leaving the drift
  // comparisons to a NaN would let any timestamp pass (NaN > x and NaN < x
  // are both false).
  const msgTime = parseInkTimestampMs(input.messageTimestamp);
  const recvTime = parseInkTimestampMs(input.receiverClock);
  if (msgTime === null || recvTime === null) {
    return { accepted: false, errorCode: "expired_message" };
  }

  const drift = msgTime - recvTime;

  // Reject if timestamp is too far in the future
  if (drift > MAX_FUTURE_TIMESTAMP_MS) {
    return { accepted: false, errorCode: "expired_message" };
  }

  // Reject if timestamp is too old
  if (-drift > MAX_TIMESTAMP_AGE_MS) {
    return { accepted: false, errorCode: "expired_message" };
  }

  // Reject if nonce was already seen
  if (input.previouslySeenNonces.includes(input.nonce)) {
    return { accepted: false, errorCode: "duplicate_nonce" };
  }

  return { accepted: true };
}

// ── INK Audit Crypto (Auditability §2) ──

/**
 * Compute SHA-256 hash of JCS-canonicalized body. Returns hex string.
 * Used for messageHash in receipts and previousEventHash in audit chains.
 */
export async function computeMessageHash(body: SignableBody): Promise<string> {
  if (!isSignableBody(body)) {
    throw new Error("Invalid message body: expected a plain JSON object");
  }
  // Mirrors the sign/verify-side guards. messageHash is bound into
  // receipts; a poisoned receipt body would otherwise burn CPU inside
  // canonicalize before the receipt verifier ever rejects it.
  if (!isWithinCanonicalizeBounds(body)) {
    throw new Error("Message body exceeds maximum allowed complexity");
  }
  if (hasNonJsonObject(body)) {
    throw new Error("Invalid message body: contains a value that is not JSON data");
  }
  const canonical = jcsCanonicalize(body);
  const bytes = new TextEncoder().encode(canonical);
  if (bytes.length > MAX_SIGBASE_BODY_BYTES) {
    throw new Error("Message body exceeds maximum allowed size");
  }
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Sign an INK audit event. Returns base64url-encoded Ed25519 signature.
 * Signs the JCS-canonicalized event with the agentSignature field excluded.
 */
export async function signAuditEvent(
  event: Record<string, unknown>,
  privateKey: Uint8Array,
): Promise<string> {
  if (event === null || typeof event !== "object" || Array.isArray(event)) {
    throw new Error("event must be a non-null object");
  }
  // Remove agentSignature before canonicalizing
  const { agentSignature: _, ...eventWithoutSig } = event;
  // Mirror the verify-side guards: refuse pathological events at sign
  // time so a service can't be coerced into burning CPU/memory minting
  // a signature over an event no verifier would accept.
  if (!isWithinCanonicalizeBounds(eventWithoutSig)) {
    throw new Error("Audit event exceeds maximum allowed complexity");
  }
  const canonical = jcsCanonicalize(eventWithoutSig);
  const prefixed = `ink/audit-event\n${canonical}`;
  const bytes = new TextEncoder().encode(prefixed);
  if (bytes.length > MAX_SIGBASE_BODY_BYTES) {
    throw new Error("Audit event exceeds maximum allowed size");
  }
  const sig = await ed.signAsync(bytes, privateKey);
  return base64urlEncode(sig);
}

/**
 * Verify an INK audit event signature.
 * Returns false (never throws) for malformed or wrong-length signatures.
 */
export async function verifyAuditEventSignature(
  event: Record<string, unknown>,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (event === null || typeof event !== "object" || Array.isArray(event)) return false;
  const signature = event.agentSignature as string;
  if (typeof signature !== "string") return false;
  // Ed25519 signatures are exactly 64 bytes = 86 unpadded base64url chars.
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
  const { agentSignature: _, ...eventWithoutSig } = event;
  // Pre-canonicalize complexity cap: bail before jcsCanonicalize walks an
  // attacker-supplied object that would only get rejected by the size cap
  // below. Cheap enough that it adds no cost for real events.
  if (!isWithinCanonicalizeBounds(eventWithoutSig)) return false;
  try {
    const canonical = jcsCanonicalize(eventWithoutSig);
    const prefixed = `ink/audit-event\n${canonical}`;
    const bytes = new TextEncoder().encode(prefixed);
    // Defense-in-depth: cap signed-body byte count to bound pre-verify work.
    // UTF-8 byte length, not JS string length, so multi-byte event data
    // cannot smuggle past the cap.
    if (bytes.length > MAX_SIGBASE_BODY_BYTES) return false;
    const sig = base64urlDecode(signature);
    return await ed.verifyAsync(sig, bytes, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/**
 * Verify an INK audit event signature against a rotation-aware candidate key
 * set (spec §6.2/§12.1: historical audit events verify against a retired key
 * still inside its validity window; a revoked key never verifies, even for
 * events predating its revocation).
 *
 * The artifact clock is the event's own `timestamp` field, parsed with the
 * shared strict RFC 3339 grammar; a missing, non-string, or unparseable
 * timestamp fails closed. When `opts.hintKeyId` is not given, the event's own
 * `signingKeyId` (when present) is used as the hint: the event already
 * carries the keyId the signer used, so trying it first avoids an O(n)
 * trial-verify across the candidate set.
 */
export async function verifyAuditEventSignatureWithKeys(
  event: Record<string, unknown>,
  keys: CandidateKey[],
  opts?: { hintKeyId?: string },
): Promise<MultiKeyVerifyResult> {
  if (event === null || typeof event !== "object" || Array.isArray(event)) {
    return { verified: false };
  }
  const artifactMs = parseInkTimestampMs(event.timestamp);
  if (artifactMs === null) {
    return { verified: false };
  }
  const hintKeyId =
    opts?.hintKeyId ?? (typeof event.signingKeyId === "string" ? event.signingKeyId : undefined);
  return verifyDetachedSignatureWithKeys(
    (publicKey) => verifyAuditEventSignature(event, publicKey),
    keys,
    artifactMs,
    hintKeyId,
  );
}

/**
 * Compute the RFC 6962 Merkle leaf hash for an INK audit event:
 *
 *   SHA-256(0x00 || JCS(event-without-agentSignature))
 *
 * This is the leaf-hashing rule a witness MUST use when building its
 * transparency log (Auditability §7.3). It is distinct from
 * `computeEventHash`, which omits the 0x00 prefix and is used only for
 * `previousEventHash` chain linkage inside the agent's local audit log.
 *
 * Returns the lowercase-hex digest.
 */
export async function computeAuditMerkleLeafHash(event: SignableBody): Promise<string> {
  if (!isSignableBody(event)) {
    throw new Error("event must be a plain JSON object");
  }
  const { agentSignature: _, ...eventWithoutSig } = event;
  if (!isWithinCanonicalizeBounds(eventWithoutSig)) {
    throw new Error("Audit event exceeds maximum allowed complexity");
  }
  if (hasNonJsonObject(eventWithoutSig)) {
    throw new Error("Audit event contains a value that is not JSON data");
  }
  const canonical = jcsCanonicalize(eventWithoutSig);
  const canonicalBytes = new TextEncoder().encode(canonical);
  if (canonicalBytes.length > MAX_SIGBASE_BODY_BYTES) {
    throw new Error("Audit event exceeds maximum allowed size");
  }
  const prefixed = new Uint8Array(canonicalBytes.length + 1);
  prefixed[0] = 0x00;
  prefixed.set(canonicalBytes, 1);
  const digest = await crypto.subtle.digest("SHA-256", prefixed);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Compute SHA-256 hash of JCS-canonicalized audit event (excluding agentSignature).
 * Used for previousEventHash chain linkage. NOT the Merkle leaf hash:
 * see `computeAuditMerkleLeafHash` for the RFC 6962 leaf-hash rule used
 * by witness transparency logs.
 */
export async function computeEventHash(event: Record<string, unknown>): Promise<string> {
  if (event === null || typeof event !== "object" || Array.isArray(event)) {
    throw new Error("event must be a non-null object");
  }
  const { agentSignature: _, ...eventWithoutSig } = event;
  // Mirrors the sign/verify-side guards: previousEventHash flows from
  // this function into hash-chained audit logs, so a poisoned event
  // could otherwise burn CPU/memory inside canonicalize before the
  // chain insertion path notices the size.
  if (!isWithinCanonicalizeBounds(eventWithoutSig)) {
    throw new Error("Audit event exceeds maximum allowed complexity");
  }
  const canonical = jcsCanonicalize(eventWithoutSig);
  const bytes = new TextEncoder().encode(canonical);
  if (bytes.length > MAX_SIGBASE_BODY_BYTES) {
    throw new Error("Audit event exceeds maximum allowed size");
  }
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Sign an INK audit response. Returns base64url-encoded Ed25519 signature.
 * Domain-separated: signs "ink/audit-response\n" + JCS(events) to prevent
 * cross-protocol signature replay.
 */
export async function signAuditResponse(
  events: unknown[],
  privateKey: Uint8Array,
): Promise<string> {
  // Pre-canonicalize complexity cap — mirrors verifyAuditResponseSignature
  // so a peer requesting an audit response cannot make the responder
  // burn CPU/memory inside jcsCanonicalize before the length cap below.
  if (!isWithinCanonicalizeBounds(events)) {
    throw new Error("Audit response events exceed maximum allowed complexity");
  }
  const canonical = jcsCanonicalize(events);
  const prefixed = `ink/audit-response\n${canonical}`;
  const bytes = new TextEncoder().encode(prefixed);
  // Cap signed-body byte count. Mirrors the verify path's guard so the
  // sign side can't mint signatures over payloads larger than any
  // conformant verifier would accept.
  if (bytes.length > MAX_SIGBASE_BODY_BYTES) {
    throw new Error("Audit response events exceed maximum allowed size");
  }
  const sig = await ed.signAsync(bytes, privateKey);
  return base64urlEncode(sig);
}

/**
 * Verify an INK audit response signature.
 * Expects the domain-separated format: "ink/audit-response\n" + JCS(events).
 * Returns false (never throws) for malformed or wrong-length signatures.
 */
export async function verifyAuditResponseSignature(
  events: unknown[],
  signature: string,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (!Array.isArray(events)) return false;
  if (typeof signature !== "string") return false;
  // Ed25519 signatures are exactly 64 bytes = 86 unpadded base64url chars.
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
  // Pre-canonicalize complexity cap (see verifyAuditEventSignature).
  if (!isWithinCanonicalizeBounds(events)) return false;
  try {
    const canonical = jcsCanonicalize(events);
    const prefixed = `ink/audit-response\n${canonical}`;
    const bytes = new TextEncoder().encode(prefixed);
    if (bytes.length > MAX_SIGBASE_BODY_BYTES) return false;
    const sig = base64urlDecode(signature);
    return await ed.verifyAsync(sig, bytes, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/**
 * Verify an INK audit response signature against a rotation-aware candidate
 * key set (spec §6.2/§12.1). Unlike a single audit event, the `events` array
 * carries no intrinsic timestamp of its own: the response is a bundle over
 * events that may span an arbitrary time range, so the caller MUST supply
 * `artifactMs` explicitly (the response's own send/receive time, or the
 * caller's best evidence of when the response was produced). A non-finite
 * `artifactMs` fails closed.
 */
export async function verifyAuditResponseSignatureWithKeys(
  events: unknown[],
  signature: string,
  keys: CandidateKey[],
  artifactMs: number,
  opts?: { hintKeyId?: string },
): Promise<MultiKeyVerifyResult> {
  if (!Array.isArray(events)) return { verified: false };
  if (typeof signature !== "string") return { verified: false };
  return verifyDetachedSignatureWithKeys(
    (publicKey) => verifyAuditResponseSignature(events, signature, publicKey),
    keys,
    artifactMs,
    opts?.hintKeyId,
  );
}

/**
 * Validate the internal continuity of an audit event chain. Distinct
 * from verifyAuditResponseSignature, which only verifies the response
 * wrapper signature. Callers fetching audit responses MUST call both:
 * the signature gate proves the witness/agent attested to this slice,
 * this gate proves the slice itself is contiguous and fork-free.
 *
 * Rules enforced:
 * - input must be an array of non-null plain objects
 * - each event must have integer sequence and string-or-null previousEventHash
 * - sequences within the response must be strictly increasing by 1
 *   (a partial-window response anchored elsewhere is fine, but no internal gaps)
 * - duplicate sequence numbers within the response are a fork
 * - events[i].previousEventHash MUST equal computeEventHash(events[i-1]) for i >= 1
 * - events[0].previousEventHash is NOT verified against any external
 *   anchor; callers that have one (a prior pinned event hash) must
 *   verify the boundary themselves
 */
export async function verifyAuditEventChain(
  events: unknown,
): Promise<
  | { valid: true }
  | { valid: false; error: "invalid_input" | "invalid_event" | "sequence_gap" | "sequence_fork" | "previous_hash_mismatch" }
> {
  if (!Array.isArray(events)) return { valid: false, error: "invalid_input" };
  if (events.length === 0) return { valid: true };

  let lastSeq: number | null = null;
  let lastHash: string | null = null;
  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    if (ev === null || typeof ev !== "object" || Array.isArray(ev)) {
      return { valid: false, error: "invalid_event" };
    }
    const seq = (ev as Record<string, unknown>).sequence;
    const prev = (ev as Record<string, unknown>).previousEventHash;
    if (typeof seq !== "number" || !Number.isInteger(seq) || seq < 1) {
      return { valid: false, error: "invalid_event" };
    }
    if (prev !== null && typeof prev !== "string") {
      return { valid: false, error: "invalid_event" };
    }
    if (i > 0) {
      if (seq === lastSeq) return { valid: false, error: "sequence_fork" };
      if (seq !== (lastSeq as number) + 1) return { valid: false, error: "sequence_gap" };
      if (prev !== lastHash) return { valid: false, error: "previous_hash_mismatch" };
    }
    let thisHash: string;
    try {
      thisHash = await computeEventHash(ev as Record<string, unknown>);
    } catch {
      return { valid: false, error: "invalid_event" };
    }
    lastSeq = seq;
    lastHash = thisHash;
  }
  return { valid: true };
}

// ── Audit-query response (witness side, Auditability Section 7.3) ──
//
// Distinct from signAuditResponse, which is the bilateral peer-to-peer
// audit-exchange response between two agents. The witness query response
// commits the WITNESS to (a) the events, (b) per-event Merkle proofs,
// (c) the witness's treeSize / rootHash at response time, (d) the
// messageId queried, signed under the witness's identity key.

/**
 * Sign an INK audit-query response from a witness. The signed bytes are:
 *
 *   "ink/audit-query-response/v1\n" + JCS(response object minus serviceSignature)
 *
 * Callers pass the response object EXCLUDING `serviceSignature`. The
 * canonical bytes bind every other field, including `protocol`, `type`,
 * `messageId`, `events`, `proofs`, `treeSize`, `rootHash`, `serviceDid`,
 * and `timestamp`, so verifiers cannot rebind a valid signature to a
 * different witness/message/root.
 */
export async function signAuditQueryResponse(
  responseWithoutSignature: Record<string, unknown>,
  privateKey: Uint8Array,
): Promise<string> {
  if (responseWithoutSignature === null || typeof responseWithoutSignature !== "object" || Array.isArray(responseWithoutSignature)) {
    throw new Error("response must be a non-null object");
  }
  // §7.3 / §7.4 sign-side scope enforcement. A conformant witness must
  // not mint a signature over a response where any event falls outside
  // the envelope's (messageId, requester) scope: those rules apply at
  // sign time as well as at verify time. Without this, a witness that
  // composed payloads incorrectly could ship alpha.3-invalid signed
  // bytes that the high-level verifier would then reject. Catching it
  // here ensures the primitive is self-defending.
  const envMessageId = (responseWithoutSignature as { messageId?: unknown }).messageId;
  const envRequester = (responseWithoutSignature as { requester?: unknown }).requester;
  const events = (responseWithoutSignature as { events?: unknown }).events;
  if (Array.isArray(events) && events.length > 0) {
    if (typeof envMessageId !== "string" || envMessageId.length === 0) {
      throw new Error("Audit-query response must include a non-empty messageId");
    }
    if (typeof envRequester !== "string" || envRequester.length === 0) {
      throw new Error("Audit-query response must include a non-empty requester");
    }
    for (const event of events) {
      if (event === null || typeof event !== "object" || Array.isArray(event)) {
        throw new Error("Every event must be a non-null object");
      }
      const e = event as { messageId?: unknown; agentId?: unknown; counterpartyId?: unknown; agentSignature?: unknown };
      if (e.messageId !== envMessageId) {
        throw new Error("Per-event scope violation: event.messageId does not match envelope.messageId");
      }
      const requesterIsParty =
        (typeof e.agentId === "string" && e.agentId === envRequester) ||
        (typeof e.counterpartyId === "string" && e.counterpartyId === envRequester);
      if (!requesterIsParty) {
        throw new Error("Per-event scope violation: requester is not a party (agentId/counterpartyId)");
      }
      // §7.3 verifier MUST check agentSignature; sign-side mirror so a
      // witness using this primitive cannot ship signed responses that
      // strip per-event provenance.
      if (typeof e.agentSignature !== "string" || e.agentSignature.length === 0) {
        throw new Error("Per-event scope violation: event.agentSignature is missing or empty");
      }
    }
  }
  if (!isWithinCanonicalizeBounds(responseWithoutSignature)) {
    throw new Error("Audit-query response exceeds maximum allowed complexity");
  }
  const canonical = jcsCanonicalize(responseWithoutSignature);
  const prefixed = `ink/audit-query-response/v1\n${canonical}`;
  const bytes = new TextEncoder().encode(prefixed);
  if (bytes.length > MAX_SIGBASE_BODY_BYTES) {
    throw new Error("Audit-query response exceeds maximum allowed size");
  }
  const sig = await ed.signAsync(bytes, privateKey);
  return base64urlEncode(sig);
}

/**
 * Verify the Ed25519 signature on an audit-query response. This is the
 * LOW-LEVEL primitive. Most consumers should call
 * `verifyAuditQueryResponse` (from `src/audit/inclusion-receipt.ts`)
 * instead: it enforces envelope shape, requester binding, the
 * events-to-proofs one-to-one mapping, and walks every Merkle proof.
 *
 * Calling this function alone does NOT prove the response is acceptable.
 * A signed but malformed envelope (wrong type, wrong protocol, no
 * proofs, wrong requester) can still pass here. Caller is responsible
 * for pinning / resolving the witness public key out of band (e.g.
 * via /.well-known/did.json). Returns false (never throws) for any
 * malformed input.
 */
export async function verifyAuditQueryResponseSignature(
  responseWithoutSignature: Record<string, unknown>,
  signature: string,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (responseWithoutSignature === null || typeof responseWithoutSignature !== "object" || Array.isArray(responseWithoutSignature)) return false;
  if (typeof signature !== "string") return false;
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
  if (!isWithinCanonicalizeBounds(responseWithoutSignature)) return false;
  try {
    const canonical = jcsCanonicalize(responseWithoutSignature);
    const prefixed = `ink/audit-query-response/v1\n${canonical}`;
    const bytes = new TextEncoder().encode(prefixed);
    if (bytes.length > MAX_SIGBASE_BODY_BYTES) return false;
    const sig = base64urlDecode(signature);
    return await ed.verifyAsync(sig, bytes, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/**
 * Verify the Ed25519 signature on an audit-query response against a
 * rotation-aware candidate key set (spec §6.2/§12.2: witness query
 * verification MUST use the same rotation-aware signing-key lookup rules as
 * other INK transport verification).
 *
 * The envelope's own `timestamp` field is the artifact clock: a witness
 * query response is a single signed snapshot, not a bundle spanning
 * multiple events, so unlike `verifyAuditResponseSignatureWithKeys`,
 * it carries an intrinsic strict timestamp the caller need not supply.
 * A missing, non-string, or unparseable `timestamp` fails closed.
 *
 * This is the LOW-LEVEL primitive; see `verifyAuditQueryResponse` (from
 * `src/audit/inclusion-receipt.ts`) for the full §7.3 envelope verification.
 */
export async function verifyAuditQueryResponseSignatureWithKeys(
  responseWithoutSignature: Record<string, unknown>,
  signature: string,
  keys: CandidateKey[],
  opts?: { hintKeyId?: string },
): Promise<MultiKeyVerifyResult> {
  if (
    responseWithoutSignature === null ||
    typeof responseWithoutSignature !== "object" ||
    Array.isArray(responseWithoutSignature)
  ) {
    return { verified: false };
  }
  if (typeof signature !== "string") return { verified: false };
  const artifactMs = parseInkTimestampMs(responseWithoutSignature.timestamp);
  if (artifactMs === null) return { verified: false };
  return verifyDetachedSignatureWithKeys(
    (publicKey) => verifyAuditQueryResponseSignature(responseWithoutSignature, signature, publicKey),
    keys,
    artifactMs,
    opts?.hintKeyId,
  );
}

// Re-export encoding helpers for test use
export { base64urlEncode, base64urlDecode, hexToBytes, bytesToHex, jcsCanonicalize };
