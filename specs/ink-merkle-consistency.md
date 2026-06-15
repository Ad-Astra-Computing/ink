# INK Merkle Consistency Proof Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-06-15

## Purpose

An INK witness keeps an append-only transparency log of audit events as an RFC
6962 Merkle tree. A consistency proof lets a verifier that has seen one signed
checkpoint `(first, firstRoot)` confirm that a later checkpoint
`(second, secondRoot)` extends the same log rather than forking it. The size
comparison `second >= first` alone proves only that the log grew; it cannot
detect a witness that presents two different histories to two readers (a split
view). The consistency proof closes that gap: it reconstructs both roots from a
shared set of node hashes, so a second root that is not a true extension of the
first cannot produce a proof.

This profile shares its tree construction with
[`ink-merkle-inclusion.md`](./ink-merkle-inclusion.md): leaves are
`SHA-256(0x00 || d)`, internal nodes are `SHA-256(0x01 || l || r)`, and a subtree
of `n > 1` leaves splits at the largest power of two strictly less than `n`. The
empty tree's root is `SHA-256("")` =
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## Consistency proof

A consistency proof between a tree of `first` leaves and a tree of `second`
leaves (`0 <= first <= second`) is the ordered list of node hashes that lets a
verifier recompute both `firstRoot` and `secondRoot`. The reference algorithm is
the RFC 6962 §2.1.2 imperative walk:

1. If `first == second`, there is nothing to extend: accept only when the proof
   is empty and `firstRoot == secondRoot`.
2. If `first == 0`, the empty tree is a prefix of every tree: accept only when
   the proof is empty and `firstRoot` is the fixed empty-tree root.
3. Otherwise `0 < first < second`. Shift `node = first - 1` and
   `last = second - 1` right (halving both) while `node` is odd, to reach the
   first node on the rightmost path of the `first` tree that the two trees do not
   share. The old subtree hash is `firstRoot` when `first` is an exact power of
   two (and `node` has reached `0`), otherwise the first proof node. Walk up,
   consuming one proof node per level: at an odd `node`, the left sibling is
   shared and feeds both reconstructions; at an even `node` with `node < last`,
   the right sibling exists only in the second tree and feeds the new
   reconstruction. After `node` reaches `0`, any remaining proof nodes extend the
   second tree to its root.

The proof is accepted only when every proof node is consumed and the two walks
reproduce `firstRoot` and `secondRoot` exactly.

## Strictness

A conforming verifier MUST reject, not merely fail to match, the following:

- A `first` or `second` that is negative or past the ECMAScript safe-integer
  range (`2^53 - 1`). A JSON number above that range loses precision, so a
  checkpoint committing to such a size cannot be relied on; both implementations
  reject it before walking.
- `first > second`: a larger tree cannot be a prefix of a smaller one.
- A `firstRoot`, `secondRoot`, or any proof node that is not 64 lowercase hex
  characters.
- A proof that is **too short**: the walk needs another node but the proof is
  exhausted.
- A proof with **unused nodes**: nodes remain after both roots are reconstructed.
  A padded proof must not verify.
- Equal sizes with differing roots, or `first == 0` with a `firstRoot` other than
  the empty-tree root.

Rejection is a boolean outcome; the verifier never throws on malformed input.

## Reference and second-implementation behavior

In the TypeScript reference, `verifyConsistencyProof` (in
[`src/audit/inclusion-receipt.ts`](../src/audit/inclusion-receipt.ts)) performs
the imperative walk, hashing pairs with the `0x01` prefix in `hashPair`. The Go
implementation mirrors it in `VerifyConsistencyProof` (in
[`go/ink/consistency.go`](../go/ink/consistency.go)) with the same shift logic,
prefix bytes, and short/extra-node rejection, so it reconstructs the identical
roots from the identical proof.

`verifyConsistencyProof` is a low-level primitive: it attests only that two roots
are in a prefix relationship, not the witness signature that committed to either
checkpoint. Binding the proof to authenticated checkpoints belongs to the caller.

## Conformance

The `merkle-consistency` category of the [`ink.conformance.v1`](../conformance/v1)
corpus pins this walk. Each vector supplies `first`, `firstRoot`, `second`,
`secondRoot`, and a `proof`, with an expected accept or reject. The corpus covers
a boundary matrix of accepted prefixes (power-of-two and non-power-of-two first
sizes, the equal-size case, and the empty prefix) plus the rejection edges
(tampered first and second roots, a wrong, short, or padded proof,
`first > second`, an equal-size root mismatch, a non-empty root for `first = 0`, a
malformed node, and a size past the safe-integer range), so an implementation
that shifts the path incorrectly or skips a strictness check diverges on the
shared bytes.
