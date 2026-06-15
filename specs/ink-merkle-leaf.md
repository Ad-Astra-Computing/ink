# INK Audit Merkle Leaf Hash Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-06-15

## Purpose

An INK witness builds a transparency log over the audit events agents submit to
it (INK Auditability §7.3). Every event becomes one leaf of an RFC 6962 Merkle
tree, and the witness commits to the tree root in its checkpoints. An inclusion
proof later shows that a specific event sits in the committed tree, and a
consistency proof shows the tree only ever grew. All of that rests on one rule:
how an audit event is hashed into a leaf. If two implementations hash the same
event into different leaves, their roots diverge and no proof verifies across
them.

This profile pins the **leaf hash** only: the bytes a witness commits for one
audit event. The tree-walk rules that combine leaves into a root are pinned by
the [`ink-merkle-inclusion`](ink-merkle-inclusion.md) and
[`ink-merkle-consistency`](ink-merkle-consistency.md) profiles.

## Leaf hash rule

The Merkle leaf hash of an audit event is

```
SHA-256(0x00 || JCS(event-without-agentSignature))
```

returned as 64 lowercase hexadecimal characters. Concretely:

- **Strip `agentSignature`.** The event's own `agentSignature` member is removed
  before canonicalization. A witness logs the event the agent committed to, and
  attaching or detaching the agent signature MUST NOT change which leaf is
  logged. No other member is removed.
- **Canonicalize.** The remaining event is canonicalized with RFC 8785 JCS under
  INK's signed-body profile: object members sorted by UTF-16 code unit, minimal
  string escaping, and numbers restricted to the safe-integer profile (see
  [`ink-jcs-number-profile`](ink-jcs-number-profile.md)). The event MUST be a
  JSON object; an array, a string, a number, or `null` is not an audit event and
  has no leaf hash.
- **Prefix with `0x00`.** The single byte `0x00` is prepended to the
  canonical UTF-8 bytes before hashing. This is the RFC 6962 leaf-domain prefix:
  it separates a leaf from an internal node, which is hashed
  `SHA-256(0x01 || left || right)`, so an attacker cannot present an internal
  node as if it were a leaf. The leaf hash is therefore distinct from a bare
  `SHA-256(JCS(event))`, which INK uses only for `previousEventHash` chain
  linkage inside an agent's local log and never as a Merkle leaf.

## Signed-body safety

The leaf hash carries the same input safety as a signed body. A receiver MUST
parse the raw event bytes before hashing through the path that rejects a lone
UTF-16 surrogate escape (see [`ink-signed-string-safety`](ink-signed-string-safety.md)),
because a JSON parser that rewrites a lone surrogate to U+FFFD would commit a
different leaf than one that preserves it. A number outside the safe-integer
range fails closed rather than serializing in a form the two implementations
might disagree on. The leaf path enforces the same profile as signing, so an
event that cannot be signed cannot be logged either.

## Reference and second-implementation behavior

In the TypeScript reference, `computeAuditMerkleLeafHash` (in
[`src/crypto/ink.ts`](../src/crypto/ink.ts)) strips `agentSignature`,
canonicalizes through `jcsCanonicalize`, prepends `0x00`, and returns the
lowercase-hex SHA-256 digest. The Go implementation mirrors it in
`ComputeAuditMerkleLeafHash` (in [`go/ink/auditleaf.go`](../go/ink/auditleaf.go)),
taking the value parsed by `ParseSignedBody` so the surrogate check has already
run, and reusing the same JCS canonicalizer so the number profile and member
ordering match.

## Conformance

The `merkle-leaf` category of the [`ink.conformance.v1`](../conformance/v1)
corpus pins this rule. Each vector supplies an `eventRaw` JSON document; an
accepted event pins the exact `leafHash` digest. The corpus covers a minimal
event, the same event with its members reordered and with an `agentSignature`
attached (both pinning the same digest, so a stripping or ordering regression is
caught), a nested object with an array and a safe-integer number, a non-ASCII
string value, and an empty object, plus the rejection edges a non-object, a lone
surrogate, and an unsafe-integer number.
