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

The JCS number profile is out of scope for this version: a number in a signed
body fails closed, and the conformance signed envelopes contain none. Faithful
cross-implementation number canonicalization needs ECMAScript number
formatting and is tracked as future work.

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

## Known divergences pending a spec decision

These are edges the shared conformance vectors do not yet cover. They are
recorded so the 1.0 spec can mandate one behavior and both implementations
converge by specification:

- **Lone UTF-16 surrogates in signed strings.** JavaScript can carry a lone
  surrogate through `JSON.parse`/`stringify`; Go's `encoding/json` replaces it
  with U+FFFD, so a signed string containing one would canonicalize differently.
  The intended resolution is to ban lone surrogates in signed strings.

## Running the conformance suite

```sh
cd ink
go test ./...
```

Each `Test*` loads its category from `../../conformance/v1/vectors` and asserts
this implementation makes the expected accept or reject decision on every
vector, plus the canonical principal or verifying key where the vector pins it.
