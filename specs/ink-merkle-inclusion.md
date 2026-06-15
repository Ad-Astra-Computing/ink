# INK Merkle Inclusion Proof Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-06-15

## Purpose

An INK witness keeps an append-only transparency log of audit events as an RFC
6962 Merkle tree. When an agent submits an event the witness returns an inclusion
receipt committing to a specific `(leafIndex, treeSize, rootHash)`. A verifier
re-derives the event's leaf hash and walks the receipt's inclusion proof up to
the claimed `rootHash`; a successful walk attests that the leaf sits at
`leafIndex` in a tree of `treeSize` leaves whose root is `rootHash`.

The walk is a pure hashing algorithm with several places a second implementation
can diverge: the leaf-versus-internal hash prefix bytes, the left/right split
point of a non-power-of-two subtree, the orientation of each proof element, and
the rejection of a proof that is too short or carries unused entries. Two
implementations that disagree on any of these accept different proofs, which is a
consensus failure. This profile pins the construction and the
`conformance/v1` corpus pins the accept/reject boundary with shared vectors both
implementations run.

## Tree construction (RFC 6962 §2.1)

Hashes are SHA-256, rendered as 64 lowercase hex characters.

- **Leaf hash.** The hash of a single leaf whose data is `d` is
  `SHA-256(0x00 || d)`. For an INK audit event, `d` is the JCS canonicalization
  of the event with its `agentSignature` member removed; see
  [`computeAuditMerkleLeafHash`](../src/crypto/ink.ts). This profile takes the
  leaf hash as given and pins only the proof walk over leaf hashes.
- **Internal node hash.** The hash of a node with children `l` and `r` is
  `SHA-256(0x01 || l || r)`, where `l` and `r` are the raw 32-byte child hashes.
- **Tree shape.** The Merkle Tree Hash of `n` leaves with `n > 1` splits at
  `k = largest power of two strictly less than n`: the left subtree holds the
  first `k` leaves and the right subtree the remaining `n - k`. A single leaf is
  its own root. The empty tree's root is `SHA-256("")`.

The distinct `0x00` leaf prefix and `0x01` internal prefix are second-preimage
protection: without them a single leaf whose data happened to equal a node
concatenation could be presented as an interior node.

## Inclusion proof

An inclusion proof for the leaf at index `m` in a tree of `n` leaves is the
ordered list of sibling hashes needed to recompute the root from the leaf. This
profile orders proof elements **top-down**: the first element is the sibling at
the level just below the root, and the last element is the sibling adjacent to
the leaf.

A verifier walks the tree's index space from the root:

1. Begin with the subtree `[0, n)` and the leaf hash as the running hash.
2. For a subtree `[start, start + size)` with `size > 1`, let
   `split = largest power of two strictly less than size`. If
   `m - start < split` the leaf is in the left subtree: recurse left for the
   subtree result, then combine as `node(leftResult, nextProofElement)`.
   Otherwise the leaf is in the right subtree: recurse right, then combine as
   `node(nextProofElement, rightResult)`.
3. A subtree of `size == 1` is the leaf; the running hash is returned unchanged.

The proof is accepted only when the recomputed root equals the claimed
`rootHash`.

## Strictness

A conforming verifier MUST reject, not merely fail to match, the following:

- `leafIndex < 0` or `leafIndex >= treeSize`.
- A `treeSize < 1`, or a `treeSize` or `leafIndex` past the ECMAScript
  safe-integer range (`2^53 - 1`). A JSON number above that range loses
  precision, so a receipt committing to such a value cannot be relied on; both
  implementations reject it before walking rather than disagree on a value one
  cannot represent exactly.
- A `rootHash` or any proof element that is not 64 lowercase hex characters.
- A proof with **unused entries**: the walk reached the leaf (`size == 1`) while
  proof elements remain. A padded proof must not verify even if its used prefix
  reconstructs the root.
- A proof that is **too short**: the walk needs another sibling but the proof is
  exhausted. Without this check a short proof against a multi-leaf tree could
  return the leaf hash itself, which a careless verifier might equate to a
  single-leaf root.
- A proof longer than 64 entries, an implausible depth that bounds verifier work
  against a hostile receipt whose signed payload commits to `treeSize` but not to
  the proof array.

Rejection is a boolean outcome; the verifier never throws on malformed input.

## Reference and second-implementation behavior

In the TypeScript reference, `verifyInclusionProof` (in
[`src/audit/inclusion-receipt.ts`](../src/audit/inclusion-receipt.ts)) performs
the index-space walk in `recomputeRoot`, hashing pairs with the `0x01` prefix in
`hashPair` and splitting with `largestPowerOf2LessThan`. The full
`verifyInclusionReceipt` adds structural validation, the witness signature, and
an optional later-checkpoint cross-check around this core.

The Go implementation mirrors the walk in `VerifyInclusionProof` (in
[`go/ink/merkle.go`](../go/ink/merkle.go)) with the same split function, prefix
bytes, top-down proof order, and short/extra-entry rejection, so it reconstructs
the identical root from the identical proof.

## Conformance

The `merkle-inclusion` category of the [`ink.conformance.v1`](../conformance/v1)
corpus pins this walk. Each vector supplies a `leafHash`, an `inclusionProof`, a
`leafIndex`, a `treeSize`, and a claimed `rootHash`, with an expected accept or
reject. The corpus covers a single-leaf tree, every leaf position in
power-of-two and non-power-of-two trees, a tampered root, an out-of-range index,
a proof that is one entry too short, a proof padded with an unused entry, and a
malformed proof element, so an implementation that mis-orders proof elements,
splits a subtree incorrectly, or skips the length checks diverges on the shared
bytes.
