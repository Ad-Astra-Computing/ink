# INK Handshake Message Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-06-16

## Purpose

After discovery, two agents negotiate a connection through a short sequence of
handshake messages (INK Containment): a **challenge**
(`network.tulpa.challenge`), a **rejection** (`network.tulpa.rejection`), and a
**resolution** (`network.tulpa.resolution`). For independent implementations to
interoperate, they must accept and reject the same messages. This profile pins
the structural validation of those three messages: the literals, the enumerated
fields, the string and array bounds, and the timestamp grammar.

This is schema-shape validation. The signature, replay, and canonicalization
rules that a transported handshake message is also subject to are pinned by
their own profiles; this profile is only the document shape.

## Common fields

Every handshake message carries:

- `protocol`: the literal string `"ink/0.1"`.
- `type`: the message's literal type string.
- `intentRef`: a string of at most 256 code units.
- `nonce`: a string of at most 256 code units.
- `timestamp`: a handshake date-time (see below).

String length bounds are measured in UTF-16 code units, matching the reference
schema's `.max()`. Unknown top-level keys are ignored, not rejected.

## Timestamp grammar

A handshake `timestamp` is a UTC date-time with a literal `Z` and no numeric
offset: `YYYY-MM-DDTHH:MM:SS` with optional fractional seconds, then `Z`. The
calendar and clock fields are range-validated, so an out-of-range value such as
month `13` is rejected. A numeric offset (`+00:00`), a missing zone, a space
separator, or a lowercase `t` is rejected.

Note this is the handshake-message grammar specifically. INK has two distinct
timestamp surfaces with two distinct grammars: this handshake grammar (literal
`Z` only) and the signed-body timestamp grammar
([`ink-timestamp-grammar.md`](ink-timestamp-grammar.md)), which also accepts a
numeric `±HH:MM` offset. Neither grammar covers the other surface, so an
implementer MUST NOT assume a value valid on one is valid on the other. The
divergence is intentional and pinned by separate vectors; a 1.0 decision to
unify the two would be a separate, vectored tightening.

## Per-message fields

- **challenge**: `challengeType` is one of `mutual_connection_proof`,
  `identity_verification`, `availability_query`, `context_request`, `none`.
  Optional `fields`, `availableWindows`, and `contextFields` are arrays of at
  most 32 strings; `fields` and `contextFields` elements are at most 256 code
  units, `availableWindows` at most 64.
- **rejection**: `reason` is one of the policy, trust, capacity, intent, rate,
  expiry, or containment reasons. Optional `detail` (at most 500), `retryAfter`
  (at most 64), and `backoffHint` (`retryAfterSeconds` a positive integer,
  `cooldownUntil` a handshake date-time, `backoffClass` one of `sender`,
  `intent_ref`, `counterparty`).
- **resolution**: `outcome` is one of `accepted`, `declined`,
  `escalated_to_human`, `expired`. Optional `details` (with optional
  `scheduledAt` and `duration` strings at most 64, and pass-through of other
  keys) and `counterpartyDid` (at most 512).

## Reference and second-implementation behavior

In the TypeScript reference, `InkChallengeSchema`, `InkRejectionSchema`, and
`InkResolutionSchema` (in [`src/models/ink-handshake.ts`](../src/models/ink-handshake.ts))
are the validation source. The Go implementation mirrors them in
`ValidateHandshakeMessage` (in [`go/ink/handshake.go`](../go/ink/handshake.go)),
which dispatches on `type` and applies the same literals, enums, UTF-16 caps,
array bounds, and timestamp grammar.

## Conformance

The `handshake-message` category of the [`ink.conformance.v1`](../conformance/v1)
corpus pins this. Each vector supplies a `message`. The corpus covers a valid
message of each type (including the optional arrays, backoff hint, and
pass-through details), and the rejection edges: a wrong protocol or type, a
missing type, an unknown enum value, a missing or non-string required field, an
oversized string or array, an over-cap array element, an offset / zoneless /
out-of-range timestamp, and a malformed backoff hint.
