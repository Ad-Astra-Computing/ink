# INK payload encryption (ECIES)

This document pins the decision an implementation makes when decrypting an INK
encrypted payload envelope: does this envelope, under this recipient key,
decrypt to a specific plaintext, or must it be rejected? It is verified by the
`payload-encryption` conformance category.

INK §3.4 encrypts a message payload with ECIES: an ephemeral X25519 key
agreement, an HKDF-SHA256 key derivation, and AES-256-GCM with the outer
envelope bound as additional authenticated data (AAD).

## Scope

The decision is over a parsed envelope object (the decrypt function receives an
object, not raw bytes). Unknown outer fields are ignored and are not AAD-bound,
so an envelope that carries extra members still decrypts. Rejecting a lone
UTF-16 surrogate in a raw request body is a transport-ingestion concern pinned
by the `jcs-string-safety` category, not this one: a lone surrogate that does
reach the AAD canonicalizes to U+FFFD identically on both sides (the JS
`TextEncoder` replaces it, and a JSON parser that rewrites it to U+FFFD reaches
the same bytes), so the decrypt decision stays in agreement.

## Outer envelope

A `network.tulpa.encrypted` envelope is a JSON object with these fields, all
strings:

- `protocol` — exactly `ink/0.1`.
- `type` — exactly `network.tulpa.encrypted`.
- `from` — the sender DID.
- `ephemeralKey` — the sender's ephemeral X25519 public key, base64url, no padding.
- `nonce` — the AES-GCM nonce, base64url, no padding.
- `ciphertext` — the AES-GCM output (ciphertext followed by the 16-byte tag),
  base64url, no padding.
- `timestamp` — the message timestamp.
- `messageNonce` — the message replay nonce.

## Encryption

The decision this document pins is the decrypt decision, but a producer is
bound by it too: a conformant sealer MUST NOT emit an envelope its own
decrypt rule would reject. Concretely, before sealing, an implementation
rejects unless the inner plaintext carries `from` equal to the outer envelope
sender and `to` equal to a non-empty recipient DID; where the caller asserts
which recipient the envelope is addressed to, inner `to` must equal that
value. The seal-side scalar caps, the plaintext bounds and the all-zero
shared-secret reject follow the same rule, so every envelope a conformant
producer emits is one a conformant decrypter can open.

## Decryption

Given the envelope, the recipient's 32-byte X25519 private key, and the
mandatory bound recipient DID, an implementation:

1. Rejects unless `protocol` is `ink/0.1` and `type` is `network.tulpa.encrypted`.
2. Rejects unless `from` (1 to 512), `timestamp` (1 to 64), and `messageNonce`
   (1 to 256) are non-empty strings within their length caps, measured in
   UTF-16 code units. These mirror the encrypt-side caps so decrypt accepts
   exactly the scalar set encrypt could have produced.
3. Decodes `ephemeralKey` (its encoded length capped first) and rejects unless
   it is exactly 32 bytes.
4. Computes the X25519 ECDH shared secret with the recipient private key.
   Rejects an all-zero shared secret (a low-order ephemeral key), which would
   otherwise derive a publicly known AES key.
5. Derives the AES key as `HKDF-SHA256(secret, salt = "ink/0.1",
   info = "ink/0.1/encrypt", length = 32 bytes)`.
6. Decodes `nonce` (encoded length capped first) and rejects unless it is
   exactly 12 bytes. Caps the encoded `ciphertext` length before decoding.
7. Reconstructs the AAD as the bytes of `ink/0.1:envelope\n` followed by the
   RFC 8785 JCS canonicalization of `{ protocol, type, from, recipientKey,
   ephemeralKey, nonce, timestamp, messageNonce }`. All values except
   `recipientKey` are the envelope's own strings. `recipientKey` is the
   recipient's static X25519 public key, base64url, recomputed locally from the
   recipient private key (it is not carried in the envelope), so a ciphertext
   encrypted for a different recipient derives a different AAD and fails the
   tag. Any tamper of an AAD-bound field changes these bytes and fails the tag.
8. Runs AES-256-GCM decryption over `ciphertext` with that nonce and AAD.
   Rejects on an authentication failure (a tampered ciphertext, tag, AAD field,
   or wrong recipient key).
9. Parses the plaintext as JSON and rejects unless it is a non-null object
   (not an array or scalar).
10. Rejects unless the decrypted inner `from` equals the outer envelope `from`.
    A recipient DID is mandatory: it must be a non-empty string and the
    decrypted inner `to` must equal it. The AAD `recipientKey` already binds the
    ciphertext to the recipient's encryption key; this binds the recipient DID
    on top, which matters when one X25519 key backs more than one alias. A
    missing recipient DID is a reject, not a silent skip.

An accepted case pins the exact decrypted plaintext as its canonical bytes, so
a verifier that decrypts to different bytes, or accepts a tampered or malformed
envelope, diverges from the corpus.

## Determinism

The corpus is generated from a fixed recipient X25519 key, a fixed ephemeral
key, and a fixed AES-GCM nonce, so `encryptInkPayload` produces one stable
envelope that both implementations decrypt identically. AES-GCM places the
16-byte tag immediately after the ciphertext (the Web Crypto layout), so an
implementation using a split tag must concatenate in the same order.
