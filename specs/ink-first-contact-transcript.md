# INK first-contact transcript

**Status:** Stable base-profile spec; formal 1.0 freeze pending governance sign-off (see [`../GOVERNANCE.md`](../GOVERNANCE.md), [`../governance/releases/1.0-readiness-evidence.md`](../governance/releases/1.0-readiness-evidence.md)).

This document pins the decision a receiver makes on a complete stranger
first-contact exchange: a sender discovers an agent, selects a protocol version
from the card, signs a `connection_request`, and the sender in turn verifies the
receiver's `connection_response`. It is verified by the `first-contact-transcript`
conformance category.

The individual primitives the transcript composes are each pinned by their own
category (agent-card-fetch, connection-payload, signature-base, replay-freshness).
This category pins that they compose in the right order, with the right
cross-field bindings between steps, so an implementation cannot accept a flow
that skips a step or crosses two messages that should not match.

## Scope

The decision is over a single self-contained transcript object. The two signing
keys (the sender's and the receiver's) are supplied as resolved hex bytes: in a
live flow the sender's key is resolved from the sender's own DID document and the
receiver's key from the fetched card, but key resolution from a DID is out of
scope here and pinned elsewhere. The receiver key in the transcript equals the
key the fetched card advertises in `publicKeyMultibase`, so a verifier that
decodes the card key instead reaches the same bytes.

Version negotiation is a sender-side selection, not a cryptographic check. The
transcript pins one negotiation rule (below) so both implementations select the
same version and agree on whether the messages were emitted under it.

## Transport

Each message is an INK message envelope carried over the §3.3 transport
signature base. A transcript carries:

- `cardFetch` — the discovery response the sender received for the receiver's
  agent card: `status`, `contentType`, `contentLength`, `bodyRaw`, and the
  `requestedAgentId` the sender bound the fetch to. This is the same shape the
  `agent-card-fetch` category pins.
- `clientSupportedVersions` — the message protocol versions the sender can emit,
  in descending preference order.
- `receiverClock` and `seenNonces` — the receiver's clock and its
  previously-seen nonce set, as the `replay-freshness` category pins.
- `request` — the signed `connection_request`: a `signInput`
  (`method`, `path`, `recipientDid`, `body`, `timestamp`) whose `body` is the
  request envelope, the base64url `signature`, and `senderPublicKeyHex`.
- `response` — the signed `connection_response`: the same `signInput` shape whose
  `body` is the response envelope, the `signature`, and `receiverPublicKeyHex`.

A message envelope (the signed `body`) is a complete §3.1 intent envelope: it
carries `protocol`, `id`, `correlationId`, `createdAt`, `from`, `to`, `intent`,
`payload` and `signature`, plus the `nonce` and `timestamp` the replay check of
§3.5 requires at receipt. All are strings except `payload`. `signature` is the
§3.6 body signature over the envelope with that member removed; the §3.3
transport base then covers the whole envelope, `signature` included.

A shortened envelope is not in scope for this category and MUST NOT appear in the
corpus. §3.1 makes `id`, `correlationId`, `createdAt` and `signature` MUSTs, so a
receiver that validates the envelope before verifying anything is conforming, and
a transcript built on a shortened envelope would make that receiver reject a
transcript this category expects it to accept.

## Decision

The transcript is accepted only if every step below accepts, in order. Any
failure rejects the whole transcript.

1. **Discovery.** `evaluateAgentCardFetch(cardFetch)` accepts, yielding the
   receiver's card. A non-200 status, a wrong content type, an over-cap body, a
   schema-invalid card, or an `agentId` that does not equal `requestedAgentId`
   rejects.
2. **Version selection.** Let `advertised` be the card's
   `supportedProtocolVersions`, defaulting to `["ink/0.1"]` when the field is
   absent or empty. The selected version is the first entry of
   `clientSupportedVersions` that `advertised` contains. If the two sets do not
   overlap, reject.
3. **Request envelope structure.** The request envelope satisfies §3.1: every
   MUST member is present and within its cap (UTF-16 code units), `protocol` and
   `intent` are values from their closed sets, and no unknown top-level member is
   present. This runs before any signature work, so a malformed envelope costs a
   schema walk rather than a curve operation.
4. **Request agreement.** The request envelope's `protocol` must equal the
   selected version (so a message emitted under a version the card does not
   advertise rejects), its `intent` must be `connection_request`, its `payload`
   must satisfy the `connection_request` payload schema, and the request
   `signInput.timestamp` must equal the envelope `timestamp` (the §3.3
   transport-to-body timestamp binding).
   **Endpoint binding.** The request `signInput.path` must equal the path
   component of the fetched card's `endpoint`. `PATH` is inside the frozen
   §3.3 signature base and INK reserves no fixed inbound path, so the card is
   the only thing that tells the two sides which path they are both committing
   to. A sender that signs any other path, including a plausible-looking one
   from a document rather than from the card it just fetched, produces a base
   the receiver cannot reproduce.
5. **Request signatures.** `verifyInkSignature(request.signInput,
   request.signature, senderPublicKeyHex)` is true (the §3.3 transport signature
   over the delivered body), and the envelope's own `signature` member verifies
   against the same sender key under §3.6 (the body signature, over the envelope
   with `signature` removed and the domain keyed on the signed `protocol`). Both
   are checked: a receiver that verifies only the transport signature accepts a
   body the named sender never signed under its own key.
6. **Replay.** `checkReplay` accepts the request envelope `nonce` and
   `timestamp` against `receiverClock` and `seenNonces`: a stale or future
   timestamp, or a nonce already in `seenNonces`, rejects.
7. **Response envelope structure.** The response envelope satisfies §3.1 on the
   same terms as step 3.
8. **Response agreement.** The response envelope's `protocol` must equal the
   selected version, its `intent` must be `connection_response`, its `payload`
   must satisfy the `connection_response` payload schema with `status`
   `accepted`, and the response `signInput.timestamp` must equal the envelope
   `timestamp`.
9. **Response signatures.** `verifyInkSignature(response.signInput,
   response.signature, receiverPublicKeyHex)` is true, and the response
   envelope's `signature` member verifies against the receiver key under §3.6.

An accepted transcript pins the selected version as its canonical string, so two
implementations that accept but negotiate different versions diverge.

## Determinism

The corpus is generated from fixed sender and receiver Ed25519 keys and fixed
timestamps and nonces, so re-running the generator produces byte-identical
envelopes and signatures that both implementations verify the same way.
