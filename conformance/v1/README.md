# INK conformance vectors (ink.conformance.v1)

These vectors are the cross-implementation contract for INK's security
decisions. They pin the exact accept or reject outcome for a fixed set of
inputs, so that an independent implementation can prove it makes the same
decisions as the reference, rather than inferring behavior from the source.

A credible wire spec specifies its failures, not just its happy path, so the
corpus is mostly negative and adversarial cases.

## Layout

- `schema.json` is the JSON Schema for a vector file.
- `vectors/*.json` are the vector files, one per category. Each file is
  `{ "format": "ink.conformance.v1", "category": "...", "cases": [...] }`.
- `generate.mjs` regenerates the vectors deterministically (a fixed test seed
  drives a single Ed25519 key), so re-running produces byte-identical output.

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
