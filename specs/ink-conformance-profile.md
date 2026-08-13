# INK conformance profiles

This document freezes what a conforming INK implementation MUST do. The
conformance corpus (`conformance/v1`) pins a decision per category, but it does
not by itself say which categories a minimal implementation has to satisfy. This
profile closes that gap: it declares the base profile that every conforming INK
sender and receiver MUST implement, and the capability-gated profiles that are
required only when an implementation advertises the matching capability.

Requirement levels follow RFC 2119. Each conformance category carries a
`profile` field in `conformance/v1/manifest.json`; the set of `base` categories
is frozen by drift tripwires in `test/conformance-profile.test.ts` and
`go/ink/conformance_manifest_test.go`, so it cannot change silently.

## Roles

An INK implementation acts as a **sender** (it discovers a peer and originates
messages), a **receiver** (it publishes an Agent Card and verifies inbound
messages), or both. The base profile defines obligations for each role. A
category may bind one role, the other, or both; an implementation that performs
a role MUST satisfy every base obligation for that role.

## Base profile (MUST)

Every conforming INK implementation MUST satisfy the base profile categories for
the roles it performs. The base profile is the fifteen[^ck] categories tagged
`profile: "base"` in the manifest:

`agent-card`, `agent-card-fetch`, `agent-card-signature`,
`authorization-header`, `connection-payload`, `first-contact-transcript`,
`jcs-number`, `jcs-string-safety`, `key-rotation`, `principal-normalization`,
`private-hostname`, `replay-freshness`, `signature-base`, `signed-body-utf8`,
`timestamp-validity`.[^ck]

| Category[^ck] | Base sender MUST | Base receiver MUST |
|---|---|---|
| principal-normalization | Canonicalize its own and the peer's agentId before any identity comparison. | Canonicalize the sender's agentId the same way before authorizing it. |
| signature-base | Build the §3.3 signature base and produce the Ed25519 signature over its UTF-8 bytes. | Reconstruct the same base and verify the signature, failing closed on any mismatch. |
| authorization-header | Emit the `INK-Ed25519 <base64url(sig)> [keyId=<keyId>]` Authorization header in the exact §3.3 grammar. | Parse the header under the same grammar, extracting the signature and optional keyId and rejecting stray whitespace, an embedded CR/LF, or a malformed keyId. |
| jcs-number | Canonicalize signed bodies under RFC 8785 with the safe-integer number profile. | Canonicalize the body the same way before verifying, rejecting an unsafe number. |
| jcs-string-safety | Reject a lone UTF-16 surrogate in any body it signs. | Reject a lone UTF-16 surrogate in any signed body it verifies, scanning the raw text before parsing. |
| signed-body-utf8 | Emit a signed body whose raw bytes are valid UTF-8. | Reject a signed body whose raw bytes are not valid UTF-8, before parsing. |
| timestamp-validity | Emit timestamps in the strict INK RFC 3339 millisecond grammar. | Parse and validate inbound timestamps under the same grammar. |
| replay-freshness | Emit a fresh timestamp and a unique per-message nonce. | Enforce the freshness window and reject a replayed nonce, recording the nonce only after the other checks pass. |
| key-rotation | Sign with an active key and emit its `keyId`. | Verify against the peer's published key set, honoring active, retired, and revoked status, and accept a legacy single-key card. |
| agent-card | Parse a peer's Agent Card under the schema and the pinned endpoint URL grammar. | Publish a schema-valid Agent Card at the discovery path. |
| agent-card-fetch | Apply the discovery response contract (status, content type, size cap, identity binding) to every card it fetches. | Apply the same contract to any card it fetches (for owner or peer resolution). |
| agent-card-signature | Verify a present card signature, rooting it by principal kind, before treating the card as authoritative. | Verify a present card proof, enforce the unsigned-card ratchet, and apply the continuity and rollback rules against any cached card. |
| private-hostname | Gate every outbound discovery and delivery URL through the SSRF host-safety check, failing closed on a private, special-use, or malformed host. | Gate any outbound fetch it performs through the same check. |
| connection-payload | Emit a `connection_request` that satisfies the strict schema and validate the `connection_response` it receives. | Validate an inbound `connection_request` against the strict schema, rejecting an unknown key, and emit a schema-valid `connection_response`. |
| first-contact-transcript | Drive the send side: fetch the card, select a mutually supported protocol version, sign the request, and verify the response. | Enforce the end-to-end accept rules, rejecting any transcript that fails a step or crosses a cross-field binding. |

A pure sender that never publishes a card is not required to serve `agent-card`,
and a pure receiver that never originates is not required to drive the send side
of `first-contact-transcript`; every other base obligation for the role applies.

## Capability-gated profiles

These categories are required only when an implementation advertises the
matching capability in its Agent Card. An implementation that does not advertise
the capability MUST NOT be expected to satisfy them, and MUST NOT advertise a
capability it does not fully implement.[^ck]

- **encryption** (`payload-encryption`) — required when the implementation sends
  or accepts encrypted payloads (`network.tulpa.encrypted`). Intents that the
  protocol marks confidential are sent encrypted, so an implementation that
  handles those intents MUST implement this profile.
- **audit** (`merkle-leaf`, `inclusion-receipt`, `audit-query-response`) —
  required when the implementation participates in the bilateral audit exchange:
  computing audit-event leaf hashes, verifying witness inclusion receipts, and
  verifying signed audit-query responses.
- **witness** (`merkle-inclusion`, `merkle-consistency`, `merkle-checkpoint`) —
  required when the implementation is a transparency-log witness service:
  inclusion and consistency proof verification and the checkpoint grammar.
- **containment** (`handshake-message`) — required when the implementation
  advertises the containment and governance extension: the signed challenge,
  rejection, and resolution handshake messages.
- **discovery** (`discovery-query-envelope`) — required when the implementation
  answers directory discovery queries: verifying a requester-signed discovery
  query envelope against the requester's key, its own identity, its clock and its
  burned-nonce state before matching, so a query addressed to another directory, a
  stale query or a replayed nonce is rejected rather than served. Opting in to
  being surfaced is the agent-card discovery descriptor (base profile); serving
  the query is this capability.
- **authorization** (`agent-authorization`, `authorization-grant`): required when
  the implementation issues or accepts "Sign in with INK" authorization
  challenges and grants. A relying party emits a challenge bound to its own
  origin and requested scope, and a service verifies the scoped, audience-bound,
  expiring grant against the issuer key and its own context (audience, clock,
  replay set, revocation list, owner status) before acting on it. Issuing a grant
  is the sender side of the same capability. An implementation that does not
  advertise authorization is not expected to accept grants.
- **delegation** (`authorization-chain`): required when the implementation accepts
  delegation chains, the post-1.0 extension on top of the grant. A verifier checks
  a presented chain of 2 to 4 grant-shaped links against its own context: parent
  hash and issuer-subject continuity, monotonic scope and window attenuation with
  the `delegation.extend` re-delegation gate, per-position lifetime ceilings,
  active-key-only per-link signatures, and the audience, presenter, window, replay,
  revocation and owner-verification checks. It is distinct from the `authorization`
  capability so a frozen surface stays frozen. An implementation that does not
  advertise delegation is not expected to accept chains.

## Staged profile

A category tagged `profile: "staged"` is **not** a conformance obligation. It
pins a rule that is already implemented in both implementations behind an
explicit, default-off flag, and that becomes required on a scheduled date. The
staged profile is `agent-card-signature-phase-c`[^ck], the Phase C receiver rule
of [`ink-agent-card-signature.md`](ink-agent-card-signature.md) §10.

Staging exists so that a dated rule enters the base profile as an
already-agreed contract rather than as a fresh negotiation on the day it takes
effect. A staged category is anchored in the manifest now, with its case count
and its SHA-256, so its content is fixed and reviewable in advance; the vectors
are exercised by both implementations in a dedicated flag-on job; and the flip
is a retag of the category from `staged` to `base` in the manifest and in the
two freeze tripwires, with no change to the vectors themselves.

An implementation MUST NOT be judged non-conforming for failing a staged
category before the flip. Until then the base profile above is the whole floor.

## Relationship to the compliance checklist

[`ink-compliance-checklist.md`](ink-compliance-checklist.md) is the
requirement-by-requirement implementation matrix for the Tulpa reference, keyed
to individual spec sections. This document is the narrower, normative statement
of the cross-implementation conformance floor, keyed to the `conformance/v1`
categories that a second implementation runs directly. Where the two overlap
they agree; this profile is authoritative for what the corpus requires of a
conforming implementation.

[^ck]: Machine-checked value, recomputed from the repository by `npm run check:facts`. Do not hand-edit it to match a document; change the source of truth and rerun the check.
