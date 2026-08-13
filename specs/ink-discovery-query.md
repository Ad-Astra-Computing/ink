# INK Discovery Query Envelope Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-08-13

## Purpose

A directory or index surfaces agents that have opted in through the Agent Card
discovery descriptor (see [`ink-discovery-descriptor.md`](ink-discovery-descriptor.md)).
This profile pins the request a requester sends to that directory: an
authenticated discovery query envelope. It is a bounded protocol fact only. It
expresses which tags and scope ceiling a requester asks to match and how many
results it wants. It carries no ranking, no response, no consent policy, and no
field-release semantics; those are the directory's responsibility and are out of
scope here. For independent implementations to interoperate they must accept and
reject the same envelopes: the same signature check, the same audience binding,
the same freshness window and the same replay rule.

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
- `signature`: the Ed25519 body signature, base64url without padding: 64 raw
  bytes, so exactly 86 characters of `[A-Za-z0-9_-]`. A string that is not that
  shape is a structural rejection, before any signature work.

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
`query`, a directory can reject a tampered or redirected request.

## Verification context

The signature alone proves who wrote the envelope, not that it was addressed to
this directory, that it is current or that it has not been presented before.
Those three facts are carried by signed fields (`to`, `timestamp`, `nonce`), so
verification consumes them rather than leaving each directory to rediscover that
it must. A verifier supplies, alongside the requester's public key:

- **Audience**: the directory's own identity. A directory that answers to
  several spellings of itself (an origin, a bare host, a `did:web`) supplies all
  of them. Comparison against the signed `to` is exact: no case folding, no
  trailing-slash normalization, no deriving one spelling from another, so a
  directory that accepts a spelling states it. An empty audience set is a
  verifier input error, not a wildcard.
- **Clock**: the verifier's own `now`, a strict INK timestamp.
- **Seen nonces**: the `(from, nonce)` pairs this directory has already
  accepted. Replay is keyed on the pair, so one requester's nonce cannot burn
  another's. Replay is receiver state, not a signed field, so a verifier given no
  seen-nonce state makes no replay decision: a directory that omits it is stating
  that it enforces replay elsewhere, and it is still bound by the rule below. A
  directory MUST record an accepted pair atomically with acceptance: check the
  pair is absent and insert it in one step, under the same guard that admits the
  query. Two concurrent presentations of one pair MUST NOT both be accepted; a
  directory that scans and inserts in separate steps leaves a window where both
  pass the scan before either inserts, which defeats the control. The verifier
  reads this state and never records into it.

A query is fresh when its `timestamp` is within 5 minutes before and 30 seconds
after the verifier clock, both bounds inclusive. That is the INK message
freshness window of [`ink-protocol.md`](ink-protocol.md) §3.5: a query is a
single signed request, not a credential with its own window, so it ages by the
same rule as every other INK message.

## Acceptance

A conformant verifier accepts an envelope if and only if all of the following
hold, checked in this order:

1. It is structurally valid under the schema above.
2. The signature verifies against the requester's public key.
3. The signed `to` equals one of the verifier's own identifiers.
4. The signed `timestamp` is inside the freshness window at the verifier clock.
5. The signed `(from, nonce)` pair has not already been accepted.

Any unknown top-level or `query` key, an out-of-range field, an invalid
timestamp, a nonce outside 16 to 256 code units, a missing or malformed
signature, an empty audience set and a verifier clock that is not a strict INK
timestamp are structural rejections. A signature that does not verify, a query
addressed elsewhere, a stale or too-far-future timestamp and a burned nonce are
the four security rejections. Verification fails closed and never throws.

The signature is checked before any context decision, so a rejection never
reveals whether the audience or the window would have passed. A verifier reports
which check rejected: `schema`, `signature`, `audience`, `expired`,
`not_yet_valid` or `replay`. What a directory does after acceptance (ranking,
consent, which fields to release) remains out of scope.
