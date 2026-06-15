# INK Checkpoint Body Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-06-15

## Purpose

An INK witness publishes the head of its transparency log as a checkpoint: a
short, signed note that commits to a tree size and a Merkle root at a point in
time (INK Auditability §7.7). A verifier parses the checkpoint body, checks the
witness signature over it, and uses the committed `(treeSize, rootHash)` as the
authenticated anchor for inclusion and consistency proofs and for anti-rollback
and freshness checks.

This profile pins the **body grammar** only: how a checkpoint body is parsed into
`(origin, treeSize, rootHash)` and which bodies are rejected. The signature
envelope (the `-- <origin> <base64url(sig)>` cosignature lines) is verified
separately and is out of scope for this profile. The grammar matters on its own
because a parser differential, where one implementation accepts a body another
rejects, can let a malformed or ambiguous checkpoint through one side of a
two-implementation system.

## Body grammar (C2SP tlog-checkpoint)

A checkpoint body is exactly three lines, each terminated by a line feed
(`\n`, U+000A):

```
<origin>\n<treeSize>\n<rootHash>\n
```

Splitting the body on `\n` yields exactly four parts: the origin, the tree size,
the root hash, and the empty string that follows the final line feed. A
conforming parser accepts a body only when all of the following hold:

- The body is a non-empty string of at most 1024 UTF-16 code units, and each line
  is at most 256 UTF-16 code units. The size caps are checked before the body is
  split or scanned, so a hostile blob cannot drive a large allocation or scan
  before rejection.
- Splitting on `\n` yields exactly four parts and the fourth is the empty string.
  Any extra trailing line or non-empty trailing content is rejected.
- The origin is non-empty. It is the log identity and the domain separator the
  signature binds to.
- The tree size is a run of ASCII decimal digits (`[0-9]+`) with no sign, leading
  `+`, or trailing characters, whose value is a non-negative integer at most
  `2^53 - 1` (the ECMAScript safe-integer ceiling). A leading zero is permitted on
  input and normalized away on re-serialization.
- The root hash is exactly 64 lowercase hexadecimal characters.

Parsing is a total function: a malformed body yields a rejection, never an
exception.

## Canonical form

The canonical serialization of a parsed checkpoint is
`<origin>\n<treeSize>\n<rootHash>\n` with the tree size written as its shortest
decimal form (no leading zeros). Re-serializing a parsed body MUST reproduce this
exactly, so an accepted body with a leading-zero tree size normalizes to the same
canonical bytes in every implementation.

## Reference and second-implementation behavior

In the TypeScript reference, `parseCheckpoint` and `formatCheckpoint` (in
[`src/ink/checkpoint.ts`](../src/ink/checkpoint.ts)) implement the grammar and the
canonical form. The Go implementation mirrors them in `ParseCheckpoint` and
`FormatCheckpoint` (in [`go/ink/checkpoint.go`](../go/ink/checkpoint.go)), with the
line and body caps measured in UTF-16 code units so the two agree on a
non-ASCII origin.

## Conformance

The `merkle-checkpoint` category of the [`ink.conformance.v1`](../conformance/v1)
corpus pins this grammar. Each vector supplies a `body`; an accepted body also
pins its canonical re-serialization, so a parser that accepts but mis-extracts a
field is caught alongside one that mis-draws the accept/reject boundary. The
corpus covers a valid body, the zero and safe-integer-ceiling tree sizes, a
leading-zero normalization, and the rejection edges (a missing or extra newline,
trailing junk, an empty origin, a non-decimal, signed, or out-of-range tree size,
a mis-cased, short, long, or non-hex root hash, a carriage return left by CRLF
splitting, and an oversized body).
