# INK Discovery Query Envelope Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-07-09

## Purpose

A directory or index surfaces agents that have opted in through the Agent Card
discovery descriptor (see [`ink-discovery-descriptor.md`](ink-discovery-descriptor.md)).
This profile pins the request a requester sends to that directory: an
authenticated discovery query envelope. It is a bounded protocol fact only. It
expresses which tags and scope ceiling a requester asks to match and how many
results it wants. It carries no ranking, no response, no consent policy, and no
field-release semantics; those are the directory's responsibility and are out of
scope here. For independent implementations to interoperate they must accept and
reject the same envelopes and verify the same signature.

## Envelope

An envelope is a JSON object with exactly these fields and no others:

- `protocol`: the string `ink/0.1`.
- `type`: the wire type, either `network.tulpa.discovery_query` (legacy) or
  `network.ink.discovery_query` (vendor-neutral). A receiver accepts both. The
  signed bytes bind whichever spelling was sent; it is never normalized.
- `from`: the requester's DID or agent id, a non-empty string of at most 512
  UTF-16 code units.
- `to`: the directory's DID or service id, same bound as `from`.
- `nonce`: a requester-chosen string, 16 to 256 UTF-16 code units.
- `timestamp`: a strict INK timestamp (RFC 3339 date-time, uppercase `T`,
  seconds required, `Z` or numeric offset).
- `query`: the query object, described below.
- `signature`: the Ed25519 body signature, base64url without padding.

### Query object

The `query` object is strict (unknown keys are rejected) and every field is
optional:

- `tags`: if present, an array of 1 to 32 strings, each 1 to 64 UTF-16 code
  units. Tags reuse the discovery descriptor's tag form.
- `scope`: if present, one of `public`, `network_only`, `capability_gated`, or
  `private`, reusing the Agent Card visibility enum. It names the widest scope
  the requester is asking the directory to consider.
- `limit`: if present, an integer from 1 to 100.

An empty `query` object is valid: it asks for any discoverable agent up to the
directory's own default limit.

## Signature

The signature covers every field except `signature` itself: `protocol`, `type`,
`from`, `to`, `nonce`, `timestamp`, and `query`. It is computed over the
domain-separated JCS canonicalization of the unsigned object, the same body
signature scheme INK uses elsewhere (`ink/0.1` keeps the `tulpa/sign` domain).
A verifier resolves `from` to a public key by its own policy, then checks the
signature; key resolution is not part of this envelope.

Because the signature binds `to`, `type`, `nonce`, `timestamp`, and the full
`query`, a directory can reject a tampered or redirected request. Freshness and
replay windows (how old a `timestamp` may be, whether a `nonce` was seen before)
are directory policy and are not fixed by this profile.

## Acceptance

A conformant verifier accepts an envelope if and only if it is structurally
valid under the schema above and the signature verifies against the requester's
public key. Any unknown top-level or `query` key, an out-of-range field, an
invalid timestamp, a nonce outside 16 to 256 code units, a missing signature, or
a signature that does not verify is a rejection. Verification fails closed and
never throws.
