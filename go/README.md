# INK Go implementation

An independent Go implementation of INK's security-relevant decisions, built to
run the shared conformance vectors in [`../conformance/v1`](../conformance/v1).
It is deliberately not a port of the TypeScript reference: agreement on the same
vectors, reached from different code, is what proves the wire spec is not
accidentally TypeScript-shaped.

## What it covers

The `ink` package implements, and the conformance runner verifies against the
shared vectors:

- **Principal normalization** (`principal.go`, `multibase.go`) — base58btc
  multibase encode/decode and the canonical agent-principal rules, with string
  lengths measured in UTF-16 code units to match the reference contract.
- **Signature base** (`jcs.go`, `signature.go`) — RFC 8785 JCS canonicalization
  (object members sorted by UTF-16 code unit, minimal string escaping), the INK
  signature-base construction, and RFC 8032 strict Ed25519 verification.
- **Replay and freshness** (`replay.go`) — the timestamp freshness window and
  nonce de-duplication.
- **Key rotation** (`multikey.go`) — the multi-key authority rule (hint, then
  active, then retired; revoked and out-of-window keys skipped).
- **Merkle inclusion** (`merkle.go`) — the RFC 6962 inclusion-proof walk that a
  witness receipt's `(leafIndex, treeSize, rootHash)` is checked against.
- **Merkle consistency** (`consistency.go`) — the RFC 6962 consistency-proof walk
  that confirms a later checkpoint is an append-only extension of an earlier one.

Signed-body numbers follow INK's safe-integer profile in both implementations: a
number must be an integer in `|v| <= 2^53-1` and not negative zero, and is
canonicalized as a plain base-10 integer that equals ECMAScript `String(v)`
byte-for-byte. A fraction, an out-of-range magnitude, a negative zero, or a
non-finite value fails closed rather than producing a possibly divergent
exponential serialization. The `jcs-number` vectors pin the accept set and the
exact canonical bytes. See
[`../specs/ink-jcs-number-profile.md`](../specs/ink-jcs-number-profile.md).

Ed25519 verification matches the reference's strict mode (`@noble/ed25519` with
`zip215:false`): the public key must be canonically encoded (`y < p`) and must
not be a small-order point, both enforced before the cofactorless equation. Go's
bare `crypto/ed25519.Verify` accepts both, so the verifier adds an explicit
public-key check.

Timestamps follow INK's strict RFC 3339 profile in both implementations: a full
date-time with a `T` and a `Z` or numeric offset, calendar-range validated, with
the instant floored to whole milliseconds. The shared `timestamp-validity`
vectors pin the grammar and precision. See
[`../specs/ink-timestamp-grammar.md`](../specs/ink-timestamp-grammar.md).

Key-window presence is semantic in both implementations: a present `validFrom`,
`validUntil`, or `revokedAt` constrains the key even when empty, `null`, or
non-string, via the `OptionalTimestamp` type that distinguishes absent from
present. The `key-rotation` vectors pin the present-empty, present-null, and
non-string cases. See
[`../specs/ink-key-rotation-spec.md`](../specs/ink-key-rotation-spec.md) §6.5.

Lone UTF-16 surrogates in signed strings are banned in both implementations,
because `encoding/json` would rewrite a lone surrogate to U+FFFD and canonicalize
different bytes. A receiver MUST parse a signed body through `ParseSignedBody`,
which scans the raw JSON for an unpaired surrogate escape before unmarshaling;
`VerifyInkSignature` takes an already-parsed body and cannot recover a dropped
surrogate on its own. The `jcs-string-safety` vectors pin the scanner. See
[`../specs/ink-signed-string-safety.md`](../specs/ink-signed-string-safety.md).

Merkle inclusion proofs walk identically in both implementations:
`VerifyInclusionProof`'s sibling order is top-down, internal nodes are hashed
`SHA-256(0x01 || left || right)`, and a proof that is too short or padded with an
unused entry is rejected rather than silently matched. A `treeSize` past the JS
safe-integer range (`2^53 - 1`) is rejected before the walk, matching the
reference, so neither side splits on a value the other cannot represent exactly.
The `merkle-inclusion` vectors pin every leaf position plus the rejection edges.
See [`../specs/ink-merkle-inclusion.md`](../specs/ink-merkle-inclusion.md).

Merkle consistency proofs walk identically in both implementations:
`VerifyConsistencyProof` confirms the tree of `first` leaves is an append-only
prefix of the tree of `second` leaves, the check that detects a forked log a size
comparison cannot. The shift logic, `0x01` node prefix, and short/extra-node
rejection match the reference, and a size past the safe-integer range rejects
before the walk. The `merkle-consistency` vectors pin the prefix matrix plus the
rejection edges. See
[`../specs/ink-merkle-consistency.md`](../specs/ink-merkle-consistency.md).

This package targets 64-bit platforms: it uses native `int` for `treeSize`,
`leafIndex`, and the consistency `first`/`second` sizes, and a `2^53 - 1` integer
bound that does not fit a 32-bit `int`, so the safe-integer edge is deterministic
only where `int` is 64 bits wide.

## Known divergences pending a spec decision

These are edges the shared conformance vectors do not yet cover. They are
recorded so the 1.0 spec can mandate one behavior and both implementations
converge by specification:

- **Raw UTF-8 validity.** `encoding/json` replaces invalid UTF-8 with U+FFFD,
  the same parser-loss class as lone surrogates; a receiver should require valid
  UTF-8 before parsing. Tracked at the same boundary as the surrogate check.

## Running the conformance suite

```sh
cd ink
go test ./...
```

Each `Test*` loads its category from `../../conformance/v1/vectors` and asserts
this implementation makes the expected accept or reject decision on every
vector, plus the canonical principal or verifying key where the vector pins it.
