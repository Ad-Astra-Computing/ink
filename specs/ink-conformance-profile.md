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
the roles it performs. The base profile is the thirteen categories tagged
`profile: "base"` in the manifest:

`agent-card`, `agent-card-fetch`, `connection-payload`,
`first-contact-transcript`, `jcs-number`, `jcs-string-safety`, `key-rotation`,
`principal-normalization`, `private-hostname`, `replay-freshness`,
`signature-base`, `signed-body-utf8`, `timestamp-validity`.

| Category | Base sender MUST | Base receiver MUST |
|---|---|---|
| principal-normalization | Canonicalize its own and the peer's agentId before any identity comparison. | Canonicalize the sender's agentId the same way before authorizing it. |
| signature-base | Build the §3.3 signature base and produce the Ed25519 signature over its UTF-8 bytes. | Reconstruct the same base and verify the signature, failing closed on any mismatch. |
| jcs-number | Canonicalize signed bodies under RFC 8785 with the safe-integer number profile. | Canonicalize the body the same way before verifying, rejecting an unsafe number. |
| jcs-string-safety | Reject a lone UTF-16 surrogate in any body it signs. | Reject a lone UTF-16 surrogate in any signed body it verifies, scanning the raw text before parsing. |
| signed-body-utf8 | Emit a signed body whose raw bytes are valid UTF-8. | Reject a signed body whose raw bytes are not valid UTF-8, before parsing. |
| timestamp-validity | Emit timestamps in the strict INK RFC 3339 millisecond grammar. | Parse and validate inbound timestamps under the same grammar. |
| replay-freshness | Emit a fresh timestamp and a unique per-message nonce. | Enforce the freshness window and reject a replayed nonce, recording the nonce only after the other checks pass. |
| key-rotation | Sign with an active key and emit its `keyId`. | Verify against the peer's published key set, honoring active, retired, and revoked status, and accept a legacy single-key card. |
| agent-card | Parse a peer's Agent Card under the schema and the pinned endpoint URL grammar. | Publish a schema-valid Agent Card at the discovery path. |
| agent-card-fetch | Apply the discovery response contract (status, content type, size cap, identity binding) to every card it fetches. | Apply the same contract to any card it fetches (for owner or peer resolution). |
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
capability it does not fully implement.

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
  query envelope against the requester's key before matching. Opting in to being
  surfaced is the agent-card discovery descriptor (base profile); serving the
  query is this capability.

## Relationship to the compliance checklist

[`ink-compliance-checklist.md`](ink-compliance-checklist.md) is the
requirement-by-requirement implementation matrix for the Tulpa reference, keyed
to individual spec sections. This document is the narrower, normative statement
of the cross-implementation conformance floor, keyed to the `conformance/v1`
categories that a second implementation runs directly. Where the two overlap
they agree; this profile is authoritative for what the corpus requires of a
conforming implementation.
