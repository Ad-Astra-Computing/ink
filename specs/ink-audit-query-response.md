# INK Audit-Query Response Verification Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-06-16

## Purpose

A verifier asks a witness to enumerate the audit events it holds for a given
message and requester. The witness answers with a signed audit-query response
(INK Auditability §7.3): the matching events, an inclusion proof for each, and a
commitment to the tree size and root, signed under the witness identity key. This
profile pins how that response is verified end to end, so an independent
implementation makes the same accept or reject decision as the reference rather
than inferring the rules from one codebase.

Verification composes the primitives pinned by the
[`ink-merkle-leaf`](ink-merkle-leaf.md), [`ink-merkle-inclusion`](ink-merkle-inclusion.md),
and [`ink-merkle-checkpoint`](ink-merkle-checkpoint.md) profiles, and the
per-event agent signature defined below.

## Response shape

A response is an object with `protocol` (`"ink/0.1"`), `type`
(`"network.tulpa.audit_query_response"`), `serviceDid`, `messageId`,
`requester`, `timestamp`, and `serviceSignature` (all non-empty strings),
`treeSize` (integer at least 0), `rootHash` (64 lowercase hex), and `events` and
`proofs` arrays. Each event is an object with a non-empty string `id` and a
non-empty `agentSignature`. Each proof is an object with a non-empty `eventId`, a
`leafIndex` integer in `[0, treeSize)`, and an `inclusionProof` array of at most
64 entries of 64-hex. A `treeSize` of 0 is the empty log: it MUST carry no events
or proofs and the empty-tree root `SHA-256("")`.

## Per-event agent signature

An audit event's `agentSignature` is a base64url Ed25519 signature over
`"ink/audit-event\n"` followed by the JCS canonicalization of the event with its
`agentSignature` removed. It binds the submitting agent to the event content.
This is distinct from the witness envelope signature: Merkle inclusion proves the
witness committed to the event bytes, not that an agent produced them.

## Verification steps

A response is verified in order; the first failing step rejects.

1. **Structure.** The shape rules above.
2. **Binding.** `messageId` and `requester` MUST equal the values the verifier
   asked about (so a response signed for one requester cannot be replayed to
   another), and `serviceDid` MUST equal the expected witness DID when the
   verifier pins one.
3. **Witness signature.** The `serviceSignature` is a base64url Ed25519 signature
   over `"ink/audit-query-response/v1\n"` plus the JCS of the response without
   `serviceSignature`, verified against the witness key under the strict mode
   (canonical, non-small-order key).
4. **Per-event scope.** Every event's own `messageId` MUST equal the envelope
   `messageId`, and the requester MUST be a party to each event (its `agentId` or
   `counterpartyId`). This rejects a Merkle-valid event from a different message
   or one the requester is not part of.
5. **Events to proofs.** A strict one-to-one mapping by `eventId`: no duplicate
   event id, no duplicate proof, no proof for an unknown event, and every event
   has a proof.
6. **Proof walk.** Each event's leaf hash is recomputed and walked up its proof
   to the response `rootHash` at `treeSize`.
7. **Per-event agent signature.** The verifier MUST be given a callback that
   resolves each event's submitting agent key and validates its `agentSignature`.
   The callback is REQUIRED: without it the response is rejected, because Merkle
   inclusion alone does not prove agent provenance (§7.5).
8. **Later-checkpoint cross-check (optional).** When the verifier supplies a
   checkpoint it has already authenticated, the response is rejected if the
   checkpoint's tree is smaller than the response's (a rewind) or equal with a
   different root (a fork).

A `valid` result attests the response was a complete enumeration of the
requester's visible events at the signed `(treeSize, rootHash)` snapshot, not
that it is the witness's current view; freshness requires a separately fetched
checkpoint.

## Reference and second-implementation behavior

In the TypeScript reference, `verifyAuditQueryResponse` (in
[`src/audit/inclusion-receipt.ts`](../src/audit/inclusion-receipt.ts)) performs
the steps. The Go implementation mirrors it in `VerifyInkAuditQueryResponse` (in
[`go/ink/auditquery.go`](../go/ink/auditquery.go)) with `VerifyAuditEventSignature`
(in [`go/ink/auditevent.go`](../go/ink/auditevent.go)) for the per-event check,
reusing the shared JCS canonicalizer, the strong-key Ed25519 check, the leaf-hash
rule, and the inclusion-proof walk.

## Conformance

The `audit-query-response` category of the [`ink.conformance.v1`](../conformance/v1)
corpus pins this composition. Each vector supplies a `response`, a
`witnessPublicKeyHex`, the `expectedRequester` and `expectedMessageId`, an
`agentKeysHex` map for resolving per-event keys, and optionally an
`expectedServiceDid` and `laterCheckpoint`. The corpus covers a valid response,
the empty-tree response, the structural edges, the binding mismatches, a witness
signature tamper and wrong key, the scope rejections, the events-to-proofs
mapping violations, a tampered proof, a wrong-key and an unresolvable per-event
agent signature, and the checkpoint newer, rollback, and fork cases.
