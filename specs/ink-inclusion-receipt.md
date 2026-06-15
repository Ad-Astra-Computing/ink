# INK Inclusion Receipt Verification Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-06-15

## Purpose

When an agent submits an audit event to a witness, the witness returns a signed
inclusion receipt: a commitment that the event sits at a specific position in
its transparency log (INK Auditability §7). A verifier uses the receipt to prove,
without trusting the witness, that the event was logged. This profile pins how a
receipt is verified end to end, so a verifier that skips or mis-orders one of the
checks is caught by the shared vectors rather than in production.

Verification composes the lower-level primitives pinned by the
[`ink-merkle-leaf`](ink-merkle-leaf.md), [`ink-merkle-inclusion`](ink-merkle-inclusion.md),
and [`ink-merkle-checkpoint`](ink-merkle-checkpoint.md) profiles.

## Receipt shape

A receipt is an object with `eventId` (non-empty string), `leafIndex`
(non-negative integer), `treeSize` (integer at least 1), `rootHash` (64
lowercase hex characters), `inclusionProof` (an array of 64-hex strings, at most
64 entries, possibly empty for a single-leaf tree), `timestamp` (non-empty
string), and `serviceSignature` (non-empty string). `leafIndex` must be less
than `treeSize`. A receipt failing any of these is rejected before any
cryptography runs.

A receipt is parsed at the receiver boundary, not just type-coerced. A body that
carries a lone UTF-16 surrogate escape in any signed field is rejected before it
is parsed, because a parser that rewrote it to U+FFFD would verify different
bytes than the signer committed. `leafIndex` and `treeSize` are integer-valued
JSON numbers in the safe-integer range; the spelling does not matter (`1`, `1.0`,
and `1e0` are the same integer), but a fractional value is rejected. A verifier
that throws on a malformed receipt rather than returning a rejection is
non-conforming: a malformed receipt fails closed.

## Verification steps

A receipt is verified in order. The first failing step rejects.

1. **Structure.** The shape rules above.
2. **Witness signature.** The `serviceSignature` is a base64url Ed25519
   signature, verified against the witness's published key under the same strict
   mode as INK request signatures (canonical, non-small-order key; RFC 8032
   cofactorless equation). The signed bytes are
   `"ink/audit-inclusion/v1\n"` followed by the RFC 8785 JCS canonicalization of
   `{eventId, leafIndex, rootHash, timestamp, treeSize}` (members sorted by code
   unit). The `inclusionProof` is **not** signed: a verifier authenticates the
   committed `(leafIndex, treeSize, rootHash)` and re-derives the proof's
   validity in step 3, so tampering the proof cannot make a forged leaf verify.
3. **Inclusion-proof walk (optional).** When the caller supplies the audit
   `event`, its leaf hash is recomputed with the leaf-hash rule and `event.id`
   is bound to `eventId`, so the proof attests the named event's inclusion rather
   than an arbitrary hash. A caller may instead supply a pre-computed `eventHash`
   (lower assurance: not bound to `eventId`). Either way the leaf is walked up
   the `inclusionProof` to `rootHash`; a walk that does not reconstruct
   `rootHash` rejects. With neither input, the step is skipped.
4. **Later-checkpoint cross-check (optional).** When the caller supplies a later
   checkpoint it has already authenticated (its witness signature and origin
   verified first), the receipt is rejected if the checkpoint's `treeSize` is
   smaller than the receipt's (the witness rewound the log) or equal with a
   different `rootHash` (a fork). A larger tree, or an equal tree with the same
   root, is consistent. With no checkpoint, the step is skipped.

A receipt that passes every applicable step verifies. The proof and checkpoint
steps are skippable because a verifier may only hold the receipt and the
witness key, but when the inputs are present they MUST be enforced.

## Reference and second-implementation behavior

In the TypeScript reference, `verifyInclusionReceipt` (in
[`src/audit/inclusion-receipt.ts`](../src/audit/inclusion-receipt.ts)) performs
the four steps and returns a per-step result. The Go implementation mirrors it in
`VerifyInclusionReceipt` (in [`go/ink/receipt.go`](../go/ink/receipt.go)),
reusing the same JCS canonicalizer, the strong-key Ed25519 check, the leaf-hash
rule, and the inclusion-proof walk, so the two agree on the signed bytes and on
every accept or reject.

## Conformance

The `inclusion-receipt` category of the [`ink.conformance.v1`](../conformance/v1)
corpus pins this composition. Each vector supplies a `receipt`, a
`witnessPublicKeyHex`, and optionally an `event`, an `eventHash`, or a
`laterCheckpoint`. The corpus covers a signature-only accept, the structural
rejection edges, signature rejections from tampering each signed field and from a
wrong key or malformed signature, the event-bound and legacy-hash proof walks
with their mismatch and out-of-tree rejections, a tampered proof under a still
valid signature, the checkpoint newer, equal, rollback, and fork cases, and a
full receipt that passes all four steps at once.
