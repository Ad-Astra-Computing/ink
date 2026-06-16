# INK Connection Payload Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-06-16

## Purpose

A connection handshake carries two payloads: a `connection_request` and a
`connection_response`. For independent implementations to interoperate they must
accept and reject the same payloads. This profile pins their schema validation:
the enumerated fields, the string and array bounds, the embedded profile
snapshot, and the strict rejection of unknown keys.

Unlike the challenge, rejection, and resolution messages (which strip unknown
keys), these payloads and the structures they embed are **strict**: an unknown
key is rejected, not ignored.

## connection_request

A strict object with:

- `method`: one of `qr`, `intro`, `discovery`, `import`.
- `introducedBy`: an optional string of at most 512 code units.
- `context`: a required string of at most 2000 code units.
- `profileSnapshot`: a required profile snapshot (below).

## connection_response

A strict object with:

- `status`: one of `accepted`, `declined`, `pending`.
- `profileSnapshot`: an optional profile snapshot.
- `note`: an optional string of at most 1000 code units.

## Profile snapshot

A strict object with:

- `headline`: a required string of at most 500 code units.
- `skills`: a required array of at most 50 strings, each at most 100 code units.
- `interests`: a required array of at most 50 strings, each at most 100 code
  units.
- `openTo`: a required array of at most 20 strings, each at most 100 code units.
- `availability`: an optional availability config (below). The arrays may be
  empty, but the keys must be present.

### Availability config

A strict object with `timezone` (a required string of at most 64 code units),
`meetingHours` (an optional string of at most 200), and `responseSla` (an
optional string of at most 200).

String length bounds are measured in UTF-16 code units, matching the reference
schema's `.max()`.

## Reference and second-implementation behavior

In the TypeScript reference, `ConnectionRequestPayloadSchema` and
`ConnectionResponsePayloadSchema` (in [`src/models/intent.ts`](../src/models/intent.ts)),
`ProfileSnapshotSchema`, and `AvailabilityConfigSchema` (in
[`src/models/profile.ts`](../src/models/profile.ts)) are the validation source.
The Go implementation mirrors them in `ValidateConnectionPayload` (in
[`go/ink/connection.go`](../go/ink/connection.go)), applying the same enums,
UTF-16 caps, required-versus-optional rules, and strict unknown-key rejection at
every level.

## Conformance

The `connection-payload` category of the [`ink.conformance.v1`](../conformance/v1)
corpus pins this. Each vector supplies a `kind` and a `payload`. The corpus
covers a valid request and response (full and minimal), and the rejection edges:
an unknown kind, an unknown key at the top level or in the nested profile or
availability, an unknown enum, a missing required field, an oversized string or
array, an over-cap element, and a type-confused field.
