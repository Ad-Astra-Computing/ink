# INK Discovery Descriptor Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-06-26

## Purpose

INK is point-resolution: a peer fetches an Agent Card only when it already knows
the agent's id, DID, or handle. The discovery descriptor is an opt-in way for an
agent to declare that it consents to being surfaced by a directory or index, and
under what exposure. It standardizes only the **declaration**. The directory,
index, and search behavior is a separate non-core companion profile owned by
consumers and federations, not part of this protocol surface.

The descriptor is additive and lives on the Agent Card
([`ink-agent-card`](ink-agent-card.md)). A card carrying it stays valid for a
peer that does not understand discovery, and the descriptor never widens what
the card already exposes.

## Shape

The card MAY carry an optional `discovery` object:

- `enabled`: required boolean. Discovery is opt-in and never inferred. A card
  with no `discovery` object, or with `enabled: false`, is not discoverable.
- `scope`: required, one of the card `visibility` values (`public`,
  `network_only`, `capability_gated`, `private`). It declares the widest
  audience a directory may surface the agent to. It MUST NOT exceed the card's
  `visibility` (see Exposure bound).
- `tags`: optional array of at most 32 strings, each non-empty and at most 64
  UTF-16 code units. Self-declared hints (for example a topic or role), not
  verified claims. A consumer MUST NOT treat a tag as an attested capability.
- `queryable`: optional boolean. A hint that the agent is willing to be returned
  by a directory query, distinct from being indexed. Defaults to absent.
- `updatedAt`: optional timestamp in INK's strict RFC 3339 profile (see
  [`ink-timestamp-grammar`](ink-timestamp-grammar.md)). A staleness signal for
  an indexer.

Unknown keys inside `discovery` are ignored, so later additive fields do not
make the card unparseable to an older peer. The descriptor is carried inside the
signed Agent Card, so an indexer cannot strip its constraints without breaking
the card's signature.

## Exposure bound

The descriptor can only ever narrow exposure. Both `visibility` and `scope` draw
from one ordered exposure lattice, most-exposed to least:

```
public > network_only > capability_gated > private
```

The effective discovery exposure is `min(visibility, scope)`. A descriptor whose
`scope` ranks above the card's `visibility` is rejected: a card cannot use
discovery to reach a wider audience than its own visibility permits. When the
card omits `visibility`, the upper bound is `public`, because the card is itself
served publicly at the discovery path
[`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md) pins;
the descriptor may then declare up to `public`.

This makes the mandatory guard a single ordinal comparison rather than a mapping
between two taxonomies, and it means a reviewer can reason about exposure from
the card's `visibility` alone.

## Deferred

Two parts of discovery are intentionally out of this descriptor and are not
specified here:

- A **query envelope** (an authenticated directory request). It requires an
  authenticated request context, so it is deferred behind the transport-auth and
  foreign-interop work and will be specified separately.
- The **directory, index, and search** service itself. It is a non-core
  companion profile owned by consumers and federations. The protocol commits to
  no global-search guarantee.

## Reference and second-implementation behavior

In the TypeScript reference, `DiscoveryDescriptorSchema` and the card
superRefine (in [`src/models/agent-card.ts`](../src/models/agent-card.ts))
validate the descriptor and the exposure bound; `isDiscoverable` and
`effectiveDiscoveryScope` are the helpers a consumer uses. The Go implementation
mirrors them in `validateDiscovery` and `ValidateAgentCard` (in
[`go/ink/agentcard.go`](../go/ink/agentcard.go)), reusing the strict timestamp
parser for `updatedAt`.

## Conformance

The `agent-card` category of the [`ink.conformance.v1`](../conformance/v1) corpus
pins this. The discovery vectors cover an enabled descriptor at the card's
visibility, an opt-out (`enabled: false`), a narrowing descriptor, an absent
visibility treated as the public upper bound, and the rejection edges: a scope
that exceeds visibility, a missing `enabled` or `scope`, an unknown scope enum,
an over-cap or empty or over-long tag, and a non-strict `updatedAt`. The
TypeScript reference and the independent Go verifier must reach the same accept
or reject decision on every vector.
