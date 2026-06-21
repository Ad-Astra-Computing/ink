# INK conformance vectors (ink.conformance.v1)

These vectors are the cross-implementation contract for INK's security
decisions. They pin the exact accept or reject outcome for a fixed set of
inputs, so that an independent implementation can prove it makes the same
decisions as the reference, rather than inferring behavior from the source.

A credible wire spec specifies its failures, not just its happy path, so the
corpus is mostly negative and adversarial cases.

## Layout

- `manifest.json` is the machine-readable index of the corpus: one entry per
  category with its vector file, spec, summary, case count, and the SHA-256 of
  the vector bytes. A second implementation reads it to enumerate the corpus and
  to detect drift. It is `{ "format": "ink.conformance.manifest.v1", "corpus":
  "ink.conformance.v1", "categories": [...] }`.
- `schema.json` is the JSON Schema for a vector file.
- `vectors/*.json` are the vector files, one per category. Each file is
  `{ "format": "ink.conformance.v1", "category": "...", "cases": [...] }`.
- `generate.mjs` regenerates the vectors and the manifest deterministically (a
  fixed test seed drives a single Ed25519 key), so re-running produces
  byte-identical output. Counts and hashes in the manifest are derived from the
  same bytes, never hand-maintained.

## A case

```json
{
  "caseId": "ink-alias-same-principal",
  "description": "The ink: alias of the same key normalizes to the same principal.",
  "input": { "agentId": "ink:z6Mk..." },
  "expect": { "result": "accept", "canonicalPrincipal": "key:z6Mk..." }
}
```

`expect.result` is `accept` or `reject`, and `expect.canonicalPrincipal`
(principal cases) carries the expected identity. Implementations assert the
result and, where present, the canonical principal. The `description` records why
a case rejects; a machine-readable error-code field is intentionally left out of
v1 until the implementation emits stable codes, and would be added as an
additive field then.

## Categories

- **principal-normalization** — `tulpa:` and `ink:` aliases of one key collapse
  to the same canonical principal; a literal `key:` agentId is escaped rather
  than confused with that principal; DIDs pass through; an empty id is rejected.
- **signature-base** — a signature over the canonical signature base verifies;
  reordering JSON members of the signed body does not change the canonical bytes;
  altering a signed field or the key fails verification.
- **jcs-number** — a signed-body number must be a safe integer (`|v| <= 2^53-1`,
  not negative zero); an accepted body pins the exact canonical bytes. A safe
  integer, including one written with an exponent (`1e2` to `100`), is accepted;
  a fraction, an above-safe magnitude, a negative zero, and the integer just past
  `2^53` are rejected, so the signed bytes stay agnostic to which canonicalizer
  produced them. See [`../../specs/ink-jcs-number-profile.md`](../../specs/ink-jcs-number-profile.md).
- **key-rotation** — a signature is verified against a key set under the
  authority rule: an active key verifies; a retired key verifies only while its
  validity window contains the message timestamp; a revoked key, an expired key,
  and a key set without the signing key all fail. Accept cases also pin the
  `keyStatus` that verified.
- **replay-freshness** — a message is accepted only inside the freshness window
  (5 minutes old to 30 seconds ahead of the receiver clock) and only if its
  nonce has not been seen; a stale or future timestamp, a duplicate nonce, and a
  malformed nonce all reject.
- **timestamp-validity** — INK timestamps use one strict RFC 3339 date-time
  grammar at millisecond precision; a full UTC or numeric-offset value is accepted
  and pins its epoch milliseconds, while a date-only, zoneless, space-separated,
  lowercase-`t`, comma-fraction, or out-of-range value rejects. See
  [`../../specs/ink-timestamp-grammar.md`](../../specs/ink-timestamp-grammar.md).
- **jcs-string-safety** — a signed body must not carry a `\uXXXX` escape for an
  unpaired UTF-16 surrogate in any member name or value; the scan runs on the raw
  JSON text before parsing, because a parser that rewrites a lone surrogate to
  U+FFFD would sign different bytes. See
  [`../../specs/ink-signed-string-safety.md`](../../specs/ink-signed-string-safety.md).
- **merkle-inclusion** — an RFC 6962 inclusion-proof walk: a leaf hash and a
  top-down list of sibling hashes recompute the claimed Merkle root, with internal
  nodes hashed `SHA-256(0x01 || left || right)`. Every leaf position in a
  power-of-two and a non-power-of-two tree accepts; a tampered root, an
  out-of-range index, a proof that is too short, one padded with an unused entry,
  a treeSize past the JavaScript safe-integer range, and a malformed element all
  reject, so a mis-ordered or under-checked walker diverges. See
  [`../../specs/ink-merkle-inclusion.md`](../../specs/ink-merkle-inclusion.md).
- **merkle-consistency** — an RFC 6962 consistency proof: that the tree of
  `first` leaves is an append-only prefix of the tree of `second` leaves, the
  check that detects a forked (split-view) log rather than one that merely grew.
  A boundary matrix of prefixes accepts (power-of-two and non-power-of-two first
  sizes, the equal-size case, the empty prefix); a tampered first or second root,
  a wrong, short, or padded proof, `first > second`, an equal-size root mismatch,
  a non-empty root for `first = 0`, a malformed node, and a size past the
  safe-integer range all reject. See
  [`../../specs/ink-merkle-consistency.md`](../../specs/ink-merkle-consistency.md).
- **merkle-checkpoint** — the C2SP tlog-checkpoint body grammar a witness
  publishes its log head as: three lines (origin, decimal tree size, 64-hex root
  hash) plus a trailing newline. An accepted body pins its canonical
  re-serialization; a missing or extra newline, trailing junk, an empty origin, a
  non-decimal, signed, or out-of-range tree size, a mis-cased, short, long, or
  non-hex root hash, and an oversized body all reject, so a parser differential
  cannot let a malformed checkpoint through one implementation. See
  [`../../specs/ink-merkle-checkpoint.md`](../../specs/ink-merkle-checkpoint.md).
- **merkle-leaf** — the RFC 6962 leaf hash a witness commits for one audit
  event: `SHA-256(0x00 || JCS(event-without-agentSignature))`. An accepted event
  pins the exact digest; reordering members or attaching an `agentSignature`
  does not change it, while a non-object, a lone surrogate, and an
  unsafe-integer number reject, so the leaf path enforces the same signed-body
  profile as signing. See
  [`../../specs/ink-merkle-leaf.md`](../../specs/ink-merkle-leaf.md).
- **inclusion-receipt** — end-to-end verification of a witness inclusion receipt:
  structural validation, the witness Ed25519 service signature over
  `"ink/audit-inclusion/v1\n"` plus the JCS of the committed fields, an optional
  event-bound leaf-to-root proof walk, and an optional later-checkpoint
  anti-rollback and fork cross-check. A signature-only receipt accepts; the
  structural edges, a tamper of any signed field, a wrong key or malformed
  signature, an event-id mismatch or out-of-tree leaf, a tampered proof, and a
  rolled-back or forked checkpoint all reject, so a verifier that skips or
  mis-orders a step diverges. See
  [`../../specs/ink-inclusion-receipt.md`](../../specs/ink-inclusion-receipt.md).
- **audit-query-response** — end-to-end verification of a witness audit-query
  response: structure, the requester and messageId bindings, the witness envelope
  Ed25519 signature, the per-event scope rule, the events-to-proofs one-to-one
  mapping, every Merkle proof walk, the required per-event agent signature, and an
  optional later-checkpoint cross-check. A valid and empty-tree response accept;
  the structural edges, binding mismatches, a signature tamper or wrong key, scope
  violations, mapping violations, a tampered proof, a wrong-key or unresolvable
  agent signature, and a rolled-back or forked checkpoint all reject. See
  [`../../specs/ink-audit-query-response.md`](../../specs/ink-audit-query-response.md).
- **handshake-message** — schema validation for the three INK handshake messages
  (challenge, rejection, resolution): the protocol and type literals, the enum
  fields, the UTF-16 string and array caps, and the handshake timestamp grammar
  (a UTC date-time with a literal Z, no offset). A valid message of each type
  accepts; a wrong protocol or type, an unknown enum, a missing or non-string
  required field, an oversized string or array, an out-of-range or offset
  timestamp, and a malformed backoff hint all reject. See
  [`../../specs/ink-handshake-message.md`](../../specs/ink-handshake-message.md).
- **connection-payload** — schema validation for the connection_request and
  connection_response payloads, which are strict (an unknown key rejects) and
  embed a profile snapshot and availability config. A valid request and response
  accept; an unknown kind, an unknown key at any level, an unknown enum, a
  missing required field, an oversized string or array, and a type-confused field
  all reject. See
  [`../../specs/ink-connection-payload.md`](../../specs/ink-connection-payload.md).
- **agent-card** — schema validation for the `.well-known/ink/agent.json`
  discovery document, including a pinned endpoint URL grammar (https, no
  userinfo, no fragment, no control/whitespace) used for all endpoint fields, the
  nested capabilities, key entries, and governance, and the invariant that
  inboxEndpoint equals endpoint when both are present. A minimal and a full card
  accept; a wrong protocol, a missing required field, a non-grammar endpoint
  (javascript:/mailto:/ftp:/http:/userinfo/fragment/no-host/bad-port), an
  inboxEndpoint mismatch, a bad publicKeyMultibase, an unknown or over-cap enum,
  and a malformed key entry all reject. See
  [`../../specs/ink-agent-card.md`](../../specs/ink-agent-card.md).
- **agent-card-fetch** — the discovery response-handling contract over synthetic
  response metadata (status, Content-Type, Content-Length, body, requested
  agentId): status must be 200, Content-Type must be application/json with at
  most a utf-8 charset, the body is capped at 64 KiB by declared and actual
  size, and the parsed card must satisfy the schema, carry protocol ink/0.1, and
  bind to the requested agentId. The request-side SSRF gate and card-content
  host checks are out of scope. See
  [`../../specs/ink-agent-card-discovery-fetch.md`](../../specs/ink-agent-card-discovery-fetch.md).
- **private-hostname** — the SSRF host-safety gate over a hostname string:
  accept means a public destination, reject means loopback, private, link-local,
  IANA special-use, or a malformed IP-shaped name (an over-range octet, a
  malformed IPv6 literal, or an IPv6 zone id all fail closed). Covers IPv4 and
  IPv6 special-use blocks, IPv4-mapped and 6to4 embedded addresses, bracketed
  and bare literals, and FQDN/case normalization. Hostname strings only; URL
  parsing is out of scope. See
  [`../../specs/ink-private-hostname.md`](../../specs/ink-private-hostname.md).
- **payload-encryption** — ECIES payload decryption (§3.4): X25519 key
  agreement, HKDF-SHA256, and AES-256-GCM with the outer envelope bound as AAD.
  A valid envelope decrypts to exact plaintext bytes; an optional recipient-DID
  binding to the inner `to` accepts or rejects; and a tamper of any AAD-bound
  field (`protocol`, `type`, `from`, `ephemeralKey`, `nonce`, `timestamp`,
  `messageNonce`), a ciphertext-or-tag tamper, the wrong recipient key, a
  malformed or wrong-length ephemeral key or nonce, an all-zero (low-order)
  shared secret, and an inner/outer `from` mismatch all reject. See
  [`../../specs/ink-payload-encryption.md`](../../specs/ink-payload-encryption.md).

## String length and ordering

INK measures string lengths (the agentId and multibase caps) in UTF-16 code
units, matching JavaScript's `String.length`, and JCS sorts object members by
UTF-16 code unit per RFC 8785. An implementation in another language must measure
and sort the same way or it will disagree with these vectors on a multi-byte
input; the `non-ascii-under-utf16-cap-passes-through` case exercises exactly that
boundary. Inputs are assumed to be well-formed Unicode; a lone surrogate is the
one value whose UTF-16 length does not round-trip through UTF-8, and is out of
scope for v1.

## Running them

The reference implementation runs the corpus in `test/conformance.test.ts` as
part of `npm test`. Another implementation consumes the same files: load each
file, dispatch by `category`, run the input through its own pipeline, and assert
the outcome equals `expect`.
