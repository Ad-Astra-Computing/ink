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

This format is C2SP-shaped but not C2SP wire-compatible: no existing C2SP
tool can consume these bytes. The line structure and field order follow
C2SP's tlog-checkpoint note, but at least these divergences remain by
design: the root hash is lowercase hex here, C2SP uses base64; the
cosignature separator is the ASCII string `-- `, C2SP notes use an em dash;
signatures here are a bare `base64url(64 bytes)`, C2SP prepends a 4-byte key
hint. A real C2SP profile, negotiated and additive, is out of scope for this
document.

A fetcher that retrieves a checkpoint over the network MUST cap the response
at `MAX_CHECKPOINT_WIRE_BYTES` (TypeScript, `src/ink/checkpoint.ts`) /
`MaxCheckpointWireBytes` (Go, `go/ink/checkpoint.go`), 4096 bytes, before
decoding it to a string. The body and line caps below are measured in UTF-16
code units, which undercounts a multi-byte UTF-8 origin on the wire; the byte
cap is the bound that actually limits the network payload a consumer reads.
Neither library enforces this itself, since neither performs the network
fetch; a consumer applies it at its own fetch site.

## Body grammar

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
- The origin is non-empty, at most 256 UTF-16 code units, a well-formed Unicode
  string (no lone surrogate), and contains no C0 control character, DEL, C1
  control character, U+002B `+` or Unicode `White_Space` code point. It is the
  log identity and the domain separator the signature binds to, and banning
  whitespace keeps the `-- <origin> <sig>` cosignature line's first-space split
  unambiguous: an origin can never itself contain the character that grammar
  uses as a delimiter.
- The tree size is a run of ASCII decimal digits (`[0-9]+`) with no sign, leading
  `+`, leading zero or trailing characters, whose value is a non-negative
  integer at most `2^53 - 1` (the ECMAScript safe-integer ceiling). `0` is the
  only value that may begin with a zero, since it has no other representation;
  every other value's first digit is 1-9. `"007"` is rejected rather than
  normalized to `"7"`, since the two are different byte strings and accepting
  both as the same value would make an accepted body's canonical serialization
  ambiguous.
- The root hash is exactly 64 lowercase hexadecimal characters.

Parsing is a total function: a malformed body yields a rejection, never an
exception.

A verifier applies the same origin grammar to a caller-supplied expected
origin as to the one read out of a parsed body, rejecting a verification call
whose expected origin fails the grammar rather than treating it as "no
checkpoint matches" and silently rejecting every checkpoint. A witness that
constructs its own log additionally applies the grammar to its own configured
origin at construction time (see `NewWitnessLog` in `go/ink/witnesslog.go`),
so a misconfigured witness fails to start rather than mint signed checkpoints
whose origin no verifier using the correct grammar can ever accept.

## Canonical form

The canonical serialization of a parsed checkpoint is
`<origin>\n<treeSize>\n<rootHash>\n` with the tree size written as its shortest
decimal form. Re-serializing a parsed body MUST reproduce this exactly. Since a
leading-zero tree size is rejected at parse time rather than normalized, every
accepted body's tree-size field already equals its canonical form.

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
corpus covers a valid body, the zero and safe-integer-ceiling tree sizes, and
rejection edges including a missing or extra newline, trailing junk, an empty
origin, a leading-zero tree size, a non-decimal, signed or out-of-range tree
size, a mis-cased, short, long or non-hex root hash, a carriage return left by
CRLF splitting, an oversized body and an origin carrying a forbidden character
(ASCII space, `+`, DEL, a C1 control character or a Unicode whitespace code
point outside ASCII). A lone surrogate in the origin has no valid UTF-8
encoding and so cannot be expressed in a corpus vector shared across both
implementations; it is pinned instead by a language-specific unit test in
each (`test/ink-checkpoint.test.ts`, `go/ink/checkpoint_test.go`).
