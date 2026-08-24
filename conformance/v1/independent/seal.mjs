// The §3.4 sealing scheme's receive side, written from
// specs/ink-payload-encryption.md rather than from `src/`. See README.md here.
//
// This module goes one step further than the signature constructions: it uses
// no crypto library at all beyond node:crypto, whose X25519, HKDF-SHA256 and
// AES-256-GCM are the primitives the spec names. The AAD reconstruction is the
// part an implementer actually gets wrong, and it is built here from the spec's
// field list and this directory's own JCS.
import { createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, hkdfSync } from "node:crypto";
import { jcs } from "./jcs.mjs";

// Spec §"Derives": HKDF-SHA256(secret, salt = "ink/0.1", info =
// "ink/0.1/encrypt", length = 32). The salt and info are protocol constants,
// not per-message values.
const HKDF_SALT = "ink/0.1";
const HKDF_INFO = "ink/0.1/encrypt";
// Spec §"Reconstructs": the AAD domain line, then the JCS of the bound fields.
const AAD_DOMAIN = "ink/0.1:envelope\n";

// STRICT base64url: the grammar says "base64url, no padding", and Node's
// decoder ignores characters it does not understand, so a permissive decode
// accepts an envelope whose ciphertext carries bytes the grammar forbids. The
// encoded length is capped BEFORE decoding (spec steps 3 and 6), so a hostile
// field bounds work before it allocates anything.
function b64u(s, maxEncoded) {
  if (typeof s !== "string" || s.length === 0 || s.length > maxEncoded) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return null;
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
const toB64u = (buf) =>
  buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// node:crypto speaks DER, not raw keys. These wrap a raw X25519 key in the
// fixed PKCS#8 / SPKI prefixes for the 1110 (X25519) OID, which is mechanical
// framing rather than cryptography.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const rawPrivate = (raw) =>
  createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, raw]), format: "der", type: "pkcs8" });
const rawPublic = (raw) =>
  createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });

// X25519 scalar multiplication of the base point, to recompute the recipient's
// static PUBLIC key from the private key the vector supplies. The spec binds
// the recipient's public key into the AAD "recomputed locally", so the
// decrypter must derive it rather than accept it from the envelope.
function x25519PublicFromPrivate(privRaw) {
  const key = rawPrivate(privRaw);
  const pub = createPublicKey(key).export({ format: "der", type: "spki" });
  return pub.subarray(pub.length - 32);
}

// Decrypts a sealed envelope and validates the inner message, returning the
// JCS canonical string of the inner object, or null on any rejection. The
// spec's receive side is fail-closed and reports no reason to the peer, so a
// null-shaped result mirrors it.
export function openSealedEnvelope(envelope, recipientPrivateKeyHex, recipientDid) {
  try {
    // Steps 1 and 2 run before any cryptography: the type set is
    // network.tulpa.encrypted plus its ink/0.4 alias (Protocol §wire
    // namespace), and the scalars mirror the encrypt-side caps in UTF-16 code
    // units, so decrypt accepts exactly the scalar set encrypt could have
    // produced. Skipping these makes the oracle looser than the spec: a
    // sender can produce a valid tag over an out-of-grammar envelope, and
    // only these checks refuse it.
    if (envelope.protocol !== "ink/0.1") return null;
    if (envelope.type !== "network.tulpa.encrypted" && envelope.type !== "network.ink.encrypted")
      return null;
    const scalarOk = (v, max) => typeof v === "string" && v.length >= 1 && v.length <= max;
    if (!scalarOk(envelope.from, 512)) return null;
    if (!scalarOk(envelope.timestamp, 64)) return null;
    if (!scalarOk(envelope.messageNonce, 256)) return null;

    const priv = Buffer.from(recipientPrivateKeyHex, "hex");
    if (priv.length !== 32) return null;

    // 32 bytes is exactly 43 unpadded base64url characters, and 12 bytes is
    // exactly 16, so the encoded caps are the exact lengths.
    const ephemeral = b64u(envelope.ephemeralKey, 43);
    if (ephemeral === null || ephemeral.length !== 32) return null;

    const nonce = b64u(envelope.nonce, 16);
    if (nonce === null || nonce.length !== 12) return null;

    const secret = diffieHellman({
      privateKey: rawPrivate(priv),
      publicKey: rawPublic(ephemeral),
    });
    // An all-zero shared secret means a small-order ephemeral point; RFC 7748
    // requires checking it, and accepting it would let anyone forge a seal.
    // node:crypto's OpenSSL backend refuses the computation natively, so on
    // this runtime the line below is unreachable; it stays because a runtime
    // whose X25519 returns the zeros silently (@noble does) needs it, and the
    // requirement should be visible in the construction rather than an
    // accident of the platform underneath.
    if (secret.every((b) => b === 0)) return null;

    const key = Buffer.from(
      hkdfSync("sha256", secret, Buffer.from(HKDF_SALT), Buffer.from(HKDF_INFO), 32),
    );

    // The AAD binds exactly the eight members the spec lists, with recipientKey recomputed from
    // the private key rather than read from anywhere the sender controls, so a
    // seal made for a different recipient derives a different AAD and fails
    // the tag rather than decrypting.
    const recipientKey = toB64u(x25519PublicFromPrivate(priv));
    const aad = Buffer.concat([
      Buffer.from(AAD_DOMAIN),
      Buffer.from(
        jcs({
          protocol: envelope.protocol,
          type: envelope.type,
          from: envelope.from,
          recipientKey,
          ephemeralKey: envelope.ephemeralKey,
          nonce: envelope.nonce,
          timestamp: envelope.timestamp,
          messageNonce: envelope.messageNonce,
        }),
      ),
    ]);

    // The ciphertext cap mirrors the §3.2 canonical-output ceiling, since the
    // plaintext is a canonicalized inner message and GCM adds 16 bytes.
    const raw = b64u(envelope.ciphertext, 1400000);
    if (raw === null || raw.length < 17) return null;
    const tag = raw.subarray(raw.length - 16);
    const body = raw.subarray(0, raw.length - 16);

    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(body), decipher.final()]);

    // Steps 9 and 10: the plaintext must parse to a non-null object, the inner
    // `from` must equal the outer `from`, and the inner `to` must equal the
    // recipient DID, which is mandatory. The AAD already bound the recipient
    // KEY; this binds the recipient IDENTITY on top, which matters when one
    // X25519 key backs more than one alias. A missing recipient DID rejects
    // rather than skipping the check.
    const inner = JSON.parse(plaintext.toString("utf8"));
    if (inner === null || typeof inner !== "object" || Array.isArray(inner)) return null;
    if (inner.from !== envelope.from) return null;
    if (typeof recipientDid !== "string" || recipientDid.length === 0) return null;
    if (inner.to !== recipientDid) return null;

    // An accepted case pins the exact canonical bytes, so the return value is
    // the JCS of the inner object rather than the raw plaintext, whose member
    // order is not covered by any rule.
    return jcs(inner);
  } catch {
    return null;
  }
}
