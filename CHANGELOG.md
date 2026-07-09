# Changelog

All notable changes to INK are recorded
here. Pre-1.0 releases follow `0.Y.Z` semantics, see
[`docs/maturity.md`](docs/maturity.md) for the versioning policy.

## Unreleased

### Additions

- Authenticated discovery query envelope. A requester signs a bounded query
  (optional `tags`, `scope`, and `limit`) addressed to a directory, and the
  directory verifies it against the requester's key. New
  `DiscoveryQueryEnvelopeSchema` and `DiscoveryQuerySchema`, a
  `buildDiscoveryQueryEnvelope` signer, and a `verifyDiscoveryQueryEnvelope`
  verifier that fails closed. The `type` accepts both the `network.tulpa.*` and
  `network.ink.*` spellings; the signature binds every field. This is a protocol
  primitive only: the directory service, ranking, response, and consent
  semantics are out of scope. See
  [`specs/ink-discovery-query.md`](specs/ink-discovery-query.md).

### Tooling

- The package builds cleanly against `@types/node` 26. Node 26 types `Uint8Array`
  as generic over `ArrayBufferLike`, which the WebCrypto `BufferSource` parameter
  no longer accepts; the AES-GCM envelope encrypt and decrypt paths now normalize
  their inputs to an `ArrayBuffer`-backed view at the WebCrypto boundary. The
  bytes are unchanged, so ciphertext, tags, and signatures are identical.

## 0.10.0, opt-in Agent Card discovery

### Additions

- Opt-in discovery descriptor on the Agent Card. A card MAY carry a `discovery`
  object (`enabled`, `scope`, optional `tags`, `queryable`, and `updatedAt`)
  that consents to being surfaced by a directory or index. It is additive and
  forward compatible: a card without it is not discoverable, and unknown
  descriptor keys are ignored. The descriptor can only narrow exposure, its
  `scope` reuses the card visibility enum and may not exceed the card's
  `visibility`. New `isDiscoverable` and `effectiveDiscoveryScope` helpers and
  the `DiscoveryDescriptorSchema` export. Covered by the `agent-card`
  conformance category in the TypeScript reference and the Go verifier. See
  [`specs/ink-discovery-descriptor.md`](specs/ink-discovery-descriptor.md). The
  authenticated query envelope and the directory service itself are out of
  scope and deferred.

### Tooling

- The static Go verifier now covers every wrappable conformance category on both
  the `ink` CLI and the `ink-verify-server` HTTP service: card, signature,
  receipt, audit-response, handshake, connection, checkpoint, inclusion, and
  consistency. Signed-artifact parsers reject raw invalid UTF-8 before decoding
  so a signature cannot verify over bytes that differ from the wire.

## 0.9.0, vendor-neutral message namespace

This release lets a receiver accept the vendor-neutral `network.ink.*` spelling
of the eligible message types alongside the legacy `network.tulpa.*` spelling.
The transition is receiver-first and backward compatible: senders keep emitting
`network.tulpa.*` by default, so a receiver that has not upgraded never sees the
new prefix. The two audit types whose detached signatures do not cover the
envelope type stay single-spelling, see the notes below. It is published on the
`next` dist-tag.

### Additions

- Receivers dual-accept both `network.tulpa.<suffix>` and `network.ink.<suffix>`
  for every message type they verify. The dual-accept is a pure receiver-side
  leniency and is independent of the signed `protocol` field, which continues to
  govern only the body-signature domain. Senders may opt in to emitting the
  neutral spelling per message (for example the `messageType` option on the
  payload encryption helper); the default emission is unchanged.
- New `network.ink.*` cases in the `handshake-message`, `payload-encryption`
  and `audit-query-response` conformance categories, including the
  relabel-rejection cases, so the TypeScript reference and the Go implementation
  make the same accept and reject decision on both spellings.

### Notes

- Every dual-accepted type binds its actual on-the-wire `type` into the material
  it authenticates, so changing `type` after a message is signed or encrypted
  fails verification. The `audit_response` and `audit_inclusion` types stay
  single-spelling because their detached signatures cover only a payload subset
  and not the envelope type. See the compatibility policy for the full
  transition rules.

## 0.8.0, first-contact transcript, the base conformance profile, and auth hardening

This release pins the end-to-end first-contact exchange as a single conformance
category, declares and freezes the mandatory base profile every conforming
sender and receiver must implement, and hardens the live-auth and payload
encryption paths following a focused review of the key, auth, and encryption
surface. It is published on the `next` dist-tag.

### Additions

- A `first-contact-transcript` conformance category that pins a full stranger
  first-contact flow: discover the Agent Card, select a protocol version, verify
  the signed connection request under the freshness and replay rule, and verify
  the accepted connection response. The TypeScript reference and the Go
  implementation make the same decision and select the same protocol version on
  every vector.
- A conformance profile for each category in `conformance/v1/manifest.json`. The
  `base` profile is the floor every conforming implementation must satisfy;
  `encryption`, `audit`, `witness`, and `containment` are capability gated. The
  per-category sender and receiver obligations are normative in
  [`specs/ink-conformance-profile.md`](specs/ink-conformance-profile.md), and the
  base set is frozen by drift tests in both implementations.
- An optional atomic `addIfAbsent` method on the `NonceStore` interface. When a
  store provides it, inbound verification uses it instead of the separate check
  and record calls, so two concurrent replays of one signed request cannot both
  pass on a distributed store.

### Changes

- Inbound transport verification rejects a retired key by default. A signature
  that only verifies against a retired key is refused for live auth unless the
  caller opts into a rotation grace window. Retired keys remain usable for
  historical-artifact verification through the key-set primitive.

### Breaking

- Encrypted payload envelopes bind the recipient's static encryption key into
  the additional authenticated data, and decryption requires the recipient
  identity. `decryptInkPayload` now takes a required recipient DID and rejects a
  missing or empty value, and a ciphertext is bound to one recipient identity so
  it cannot be accepted by another. Envelopes produced by an earlier release do
  not decrypt under this version. The `payload-encryption` conformance vectors
  are regenerated accordingly.

## 0.7.0, discovery conformance and a packaged vector corpus

This release extends the cross-implementation conformance contract to the
discovery and handshake surface and ships the corpus as a packaged, indexed
artifact. The Agent Card, connection request and response, handshake messages,
and the composite audit-query-response verifier are now pinned by shared vectors
that the TypeScript reference and the Go implementation both run. A
machine-readable manifest indexes every category so a second implementation can
enumerate the corpus and detect drift from a single file, and the corpus ships
in the npm tarball. Agent Card endpoint fields move to a pinned, parser-
independent URL grammar. It is published on the `next` dist-tag.

### Additions

- Conformance vector categories for the Agent Card, the connection request and
  response payloads, the challenge, rejection, and resolution handshake
  messages, and the composite audit-query-response verifier. Both
  implementations make the same accept or reject decision on every vector.
- `conformance/v1/manifest.json`, a machine-readable index of the corpus with
  each category's vector file, spec, summary, case count, and the SHA-256 of the
  vector bytes. The `conformance/` tree ships in the package and is resolvable as
  a subpath export.
- `isInkEndpointUrl(value)` exposes the Agent Card endpoint URL grammar so a
  caller can validate an endpoint with the same rule the schema applies.

### Potentially breaking validation tightenings

These reject inputs that `0.6.0` accepted. A well-formed Agent Card that already
advertised a plain `https` inbox endpoint is unaffected.

- Agent Card `endpoint`, `inboxEndpoint`, and `thirdPartyAudit` endpoint fields
  are validated against a narrow, deterministic URL grammar instead of a broad
  URL check. An endpoint must be an `https` URL with a host and no userinfo or
  fragment, at most 2048 bytes, free of control characters and whitespace, with
  well-formed percent escapes and a port in range when present. Endpoints using
  another scheme, a fragment, embedded credentials, or a malformed escape are
  now rejected. The grammar is validated by explicit string rules in both
  implementations rather than a runtime URL parser, so the decision is identical
  across them.

## 0.6.0, cross-implementation conformance contract

This release turns INK's wire behavior into a contract held by two independent
implementations rather than described by one. A new Go implementation runs a
shared conformance vector corpus alongside the TypeScript reference, so an
accept or reject decision is pinned by agreement between implementations reached
from different code. The release also tightens timestamp, key-window, string,
and number validation, and exports several verifier primitives. It is published
on the `next` dist-tag; the API is additive, with the validation tightenings
noted below.

### Additions

- A second, independent implementation in Go and a shared conformance vector
  corpus covering principal normalization, the signature base, JCS numbers and
  strings, key rotation, replay and freshness, the timestamp grammar, and the
  Merkle inclusion, consistency, checkpoint, and audit-leaf-hash rules. Both
  implementations make the same decision on every vector, so the spec is not
  accidentally shaped by one language.
- `parseInkTimestampMs`, `isInkTimestamp`, and `MAX_TIMESTAMP_LENGTH` for the
  strict RFC 3339 timestamp grammar.
- `containsLoneSurrogateEscape` and `hasUnpairedSurrogate` for detecting a lone
  UTF-16 surrogate in a signed string before it is parsed.
- `verifyInclusionProof(leafHash, proof, leafIndex, treeSize, rootHash)` as a
  low-level RFC 6962 inclusion-proof primitive. It attests only that a leaf
  walks to a root; use `verifyInclusionReceipt` for full receipt verification.
- Protocol specs for the timestamp grammar, key-rotation presence, signed-string
  safety, the JCS number profile, and the Merkle inclusion, consistency,
  checkpoint, and leaf-hash rules.

### Potentially breaking validation tightenings

These reject inputs that `0.5.0` accepted. Legitimate signer and receiver
traffic is unaffected; the rejected inputs are malformed or outside the
documented profile.

- A timestamp must be a strict RFC 3339 date-time at millisecond precision, with
  a `T` separator and a `Z` or numeric offset. Date-only, zoneless,
  space-separated, and other lenient forms are rejected.
- A present `validFrom`, `validUntil`, or `revokedAt` on a key now constrains
  that key even when empty, null, or non-string, rather than being ignored; a
  present but unparseable `revokedAt` fails closed and treats the key as revoked.
- A signed body that carries a `\uXXXX` escape for an unpaired UTF-16 surrogate
  is rejected at sign and verify, because a parser that rewrote it to U+FFFD
  would commit different bytes.
- A signed body number must be a safe integer (absolute value at most `2^53-1`,
  not negative zero); a fraction, an out-of-range magnitude, and a non-finite
  value are rejected so the canonical bytes are identical across implementations.

## 0.5.0, transparency-log consistency proofs

This release adds RFC 6962 consistency-proof verification, so a verifier can
confirm a transparency log only ever appended to its tree between two
checkpoints rather than forking its history. The size comparison alone cannot
detect a split view. It is published on the `next` dist-tag; this release is
additive, with no breaking changes.

### Additions

- `verifyConsistencyProof(first, firstRoot, second, secondRoot, proof)` verifies
  an RFC 6962 Section 2.1.2 consistency proof: that the tree of `first` leaves is
  an append-only prefix of the tree of `second` leaves. It returns false (never
  throws) for any malformed input or any proof that does not reconstruct both
  roots with every node consumed.
- The `verify-inclusion` CLI uses it: when `--origin` enables the checkpoint
  cross-check and the signature-verified checkpoint is newer than the receipt's
  tree, the CLI fetches a consistency proof and verifies the receipt's tree is an
  append-only prefix of the checkpoint. A witness that serves no proof has the
  step reported as skipped, not passed.

The reference witness serves these proofs at `GET /ink/v1/consistency?first=N&second=M`.

## 0.4.0, stricter verification, message-size bounds, checkpoint and receipt verification

This release tightens signature verification and input validation and adds
several verification helpers. It is published on the `next` dist-tag.

### Potentially breaking validation tightenings

These reject inputs that `0.3.0` accepted. Legitimate signer and receiver
traffic is unaffected; the rejected inputs are malformed, malicious, or outside
the documented profile.

- Ed25519 signatures are now verified in strict RFC 8032 mode at every
  verification site. Small-order public keys and non-canonical point encodings
  are rejected.
- Signed JSON numbers are constrained to the forms every canonicalizer
  serializes identically: non-finite values, negative zero, and values whose
  shortest form uses exponential notation are rejected at signing and
  verification.
- The agent card, audit, handshake, and discovery schemas now enforce maximum
  field lengths and array sizes.
- The `Authorization: INK-Ed25519` header is matched against single literal
  spaces; a tab, carriage return, or line feed in the separator is rejected.

### Additions

- `verifyCheckpoint(signed, witnessPublicKey, expectedOrigin)` verifies a signed
  C2SP checkpoint: the witness Ed25519 signature over the checkpoint body and the
  log origin. A checkpoint used for the inclusion-receipt cross-check must be
  verified this way first.
- `verifyReceipt({ receipt, senderPublicKey, expected })` binds a delivery
  receipt to the exact message it acknowledges: issuer key, `from`/`to`/
  `messageId`, the recomputed message hash, and an optional `disposition`.
- `verifyInclusionReceipt` accepts an `event` option that recomputes the leaf
  hash and binds it to `receipt.eventId`. The legacy `eventHash` is retained but
  does not provide that binding.
- `verifyInkAuth` returns a prefix-independent `principal` alongside the raw
  sender id; per-sender security state (blocks, rate limits) should key on
  `principal`. `canonicalAgentPrincipal(agentId)` is exported for the same use.

Per the pre-1.0 policy this release publishes under the `next` dist-tag; `latest`
is unchanged.

## 0.3.0, accept the ink: agentId alias for key extraction

`extractPublicKeyFromAgentId` now accepts either the canonical `tulpa:` prefix or the `ink:` alias introduced in ink/0.4. Both carry the identical multibase Ed25519 key, so the bootstrap verification key is byte-identical and a signature made with that key verifies regardless of which accepted prefix carried it. The prefix is identity syntax, not signing authority.

Emission is unchanged: `deriveAgentId` still returns `tulpa:` (accept both, emit one). The new `AGENT_ID_KEY_PREFIXES` export is frozen so a consumer cannot widen the accepted set at runtime. The change is additive and backward compatible. Existing `tulpa:` inputs behave exactly as before, and every previously rejected prefix other than `ink:` is still rejected. The wire protocol version is unchanged.

A receiver that keys per-sender security state (blocks, rate limits, duplicate-payload checks, cached verification keys, connection identity) MUST collapse the two spellings to one prefix-independent principal so a sender cannot switch prefix to dodge a block or split a rate-limit window. See [Identity](https://ink.tulpa.network/spec/identity/).

Per the pre-1.0 policy this release publishes under the `next` dist-tag.

## 0.2.0, version-keyed body-signature domain

Version-keyed body-signature domain. The body message signature is now domain-separated by protocol version. ink/0.1 messages, and any object with no explicit ink/0.2 protocol, keep the legacy `tulpa/sign` domain so every signature produced to date still verifies. ink/0.2 messages are signed and verified under the neutral `ink/sign` domain. The verifier selects exactly one domain from the signed `protocol` field and never tries an alternate, so a signature made under one version's domain cannot be replayed under another.

This change is receiver-first and backward compatible. Verifiers accept both versions and `MessageEnvelopeSchema` now accepts ink/0.1 and ink/0.2 as a strict enum, rejecting any unknown version. Senders still emit ink/0.1 by default. The HTTP transport-auth signature is unchanged.

New vectors in `test-vectors/body-signature.json` pin the version-keyed domain including the cross-version and tamper cases. The standalone Python interop client verifies them identically.

Per the pre-1.0 policy this release publishes under the `next` dist-tag.

## 0.1.7, expose per-intent payload schemas and getPayloadSchema from the package root

Pure additive release. Re-exports every per-intent Zod payload schema (`ScheduleMeetingPayloadSchema`, `IntroRequestPayloadSchema`, `OpportunityPayloadSchema`, `ConnectionRequestPayloadSchema`, `FollowUpPayloadSchema`, `AskPayloadSchema`, `PingPayloadSchema`, `RetractPayloadSchema`, `ContextSharePayloadSchema`, `MultiPartySyncPayloadSchema`, plus the matching `*ResponsePayloadSchema` variants) and the `getPayloadSchema(intent)` resolver from the package root. Adopters writing intent-aware receivers / handlers can now type their dispatch surface directly against the canonical payload shapes.

No wire-level changes. No behavior changes inside the existing functions. Receivers on 0.1.6 work unchanged on 0.1.7.

Per the pre-1.0 policy this release publishes under the `next` dist-tag.

## 0.1.6, expose intent + key-entry types and add optional inclusionProof to InkAuditInclusionSchema

Pure additive release. Two surface expansions and one backward-compatible schema addition:

- **Intent surface** — re-exports `IntentTypeSchema` constant and `IntentType` type from the package root. Adopters writing payload-aware receivers can now type their intent dispatch off the canonical Zod enum without reaching into a deep path.
- **Key-entry surface** — re-exports `KeyStatusSchema`, `KeyRoleSchema`, `KeyEntrySchema` constants and `KeyStatus`, `KeyRole`, `KeyEntry`, `StoredKey` types. Adopters wiring their own key-set storage and rotation can now type the persistence shapes without reaching into a deep path. `CandidateKey` was already root-exported.
- **InkAuditInclusionSchema** — adds an optional `inclusionProof: z.array(z.string()).optional()` field. Third-party auditor clients that verify Merkle inclusion proofs use this field; receivers that only check signatures can ignore it. Backward-compatible because the field is optional — receivers on 0.1.5 work unchanged on 0.1.6.

No wire-level changes. No behavior changes inside the existing functions.

Per the pre-1.0 policy this release publishes under the `next` dist-tag.

## 0.1.5, expose handshake type re-exports and InkTransportSchema from the package root

Pure additive release. Re-exports the `InkChallenge`, `InkRejection`, `InkResolution`, `InkTransport` types and the `InkTransportSchema` constant from the package root. Adopters writing handshake-aware receivers can now type their state-machine without reaching into a deep path. No wire-level changes. No behavior changes inside the existing functions. Receivers on 0.1.4 work unchanged on 0.1.5.

Per the pre-1.0 policy this release publishes under the `next` dist-tag.

## 0.1.4, expose receipts, transport-auth, discovery-gating, audit schemas and handshake schemas from the package root

Pure additive release. The implementation files have shipped in earlier releases under deep paths; this release brings them to the package root so adopters writing receivers, builders, or auditor clients can import everything they need from `@adastracomputing/ink` directly.

New root-level exports:

- **Receipts** (`./ink/receipts`): `buildReceipt`, `shouldSendReceipt`, `sendReceiptFireAndForget`. The canonical INK delivery-receipt builders, signing helpers and fire-and-forget transport. A receiver that wants to ack inbound envelopes per Auditability §6 can drop these in without rolling its own.
- **Transport-auth** (`./ink/transport-auth`): `resolveEffectiveTransports`, `checkTransportAllowed`. The token-level transport allowlist enforcement, including the "field absent vs empty array" semantics. Required for any extension token issuer.
- **Discovery-gating** (`./ink/discovery-gating`): `buildRedactedCard`, `shouldRedactOnGet`, `AgentCardQuerySchema`. Visibility-aware Agent Card responses (`public`, `network_only`, `capability_gated`, `private`).
- **Checkpoint parsing** (`./ink/checkpoint`): `parseCheckpoint`, `formatCheckpoint`, `CheckpointData`. For consumers of transparency-log signed checkpoints.
- **Audit event schemas + types** (`./models/ink-audit`): `InkAuditEventTypeSchema`, `InkAuditEventSchema`, `InkAuditInclusionSchema`, `InkReceiptSchema`, `InkAuditQuerySchema`, `InkIntroductionReceiptSchema`, plus matching types `InkAuditEventType`, `InkAuditEvent`, `InkAuditInclusion`, `InkReceipt`, `InkAuditQuery`, `InkAuditResponse`, `InkIntroductionReceiptStatus`.
- **Handshake message schemas** (`./models/ink-handshake`): `InkChallengeSchema`, `InkRejectionSchema`, `InkResolutionSchema`, type `AgentCardVisibility`.
- **Agent Card schema** (`./models/agent-card`): `AgentCardSchema` (the type was already exported).
- **Encryption key encoder** (`./crypto/keys`): `encodeEncryptionKeyMultibase` (the encoder companion to the already-exported `decodeEncryptionKeyMultibase` from 0.1.3).

No wire-level changes. No behavior changes inside the existing functions. Receivers on 0.1.3 work unchanged on 0.1.4.

Per the pre-1.0 policy this release publishes under the `next` dist-tag.

## 0.1.3, expose validateMessage and decodeEncryptionKeyMultibase from the package root

Pure additive release that re-exports two helpers from the package root so adopters no longer have to import them through a deep internal path:

- `validateMessage(raw)` runs the canonical `MessageEnvelopeSchema` parse plus the intent-specific payload schema. Receivers building from scratch were either re-implementing the schema check or pulling from `@adastracomputing/ink/dist/models/intent.js`, which is not a stable surface. The implementer-guide at https://ink.tulpa.network/guides/implementing-a-receiver/ documented this helper as if it were already exported; this release makes that documentation accurate.
- `decodeEncryptionKeyMultibase(multibase)` is the companion to the already-exported `decodePublicKeyMultibase`. The former handles X25519 keys (the Agent Card encryption-key prefix); the latter handles Ed25519. The encrypted-intents guide tells adopters to decode an Agent Card's `publicKeyMultibase` for use with `encryptInkPayload`, which expects hex; without the X25519 decoder exported, adopters had to inline the multicodec strip themselves.

Also re-exports the `MessageEnvelope` type and the `MessageEnvelopeSchema` constant so adopters can type their parser surface against the canonical schema. No wire-level changes. No behavior changes inside the existing functions. Receivers on 0.1.2 work unchanged on 0.1.3.

This release publishes under the npm `next` dist-tag per the pre-1.0 policy.

## 0.1.2, Python interop CLI emits canonical envelope

> **Maturity note.** v0.1.x is wire-compatible across patches (`ink/0.1` stays frozen) but the API surface and trust semantics remain alpha-quality. See [`docs/maturity.md`](docs/maturity.md). Starting with this release, pre-1.0 versions publish under npm's `next` dist-tag; `latest` only advances when a release is explicitly promoted. Adopters who want the current pre-1.0 line install with `npm install @adastracomputing/ink@next`; the bare `npm install @adastracomputing/ink` will resolve to the most recent release a maintainer has stamped adopter-grade.

Fixes the v0.1.1 erratum: the Python `examples/interop-cli/` shipped in v0.1.1 emitted a phantom envelope shape (`type`, `intentType`, `purpose`, `urgency` at top level, no `id`, no `correlationId`, no `createdAt`, no body-level `signature`) that no conforming receiver could accept. v0.1.2 rewrites the CLI's envelope builder to emit the canonical `MessageEnvelopeSchema` shape:

- `id` and `correlationId` are now generated as 26-char Crockford-base32 ULIDs.
- `createdAt` is the canonical envelope creation timestamp (ISO-8601 UTC); the body also carries a separate `timestamp` field that `verifyInkAuth()` uses for HTTP §3.3 freshness, distinct from `createdAt`.
- `intent` is the canonical enum value (`intro_request` for introductions); the legacy `intentType`/`purpose` flatten into `payload: { target, reason, urgency }` per `IntroRequestPayloadSchema`.
- Body-level `signature` is now produced by the canonical domain-separated signer (`Ed25519("tulpa/sign\n" + JCS(envelope-without-signature))`, base64url, no padding) — matches `src/crypto/sign.ts` byte-for-byte.
- `provenance` is omitted when absent (the field is `.optional()`; an explicit `null` would be rejected by Zod).
- HTTP §3.3 fields (`timestamp`, `nonce`) ride alongside the canonical fields so `verifyInkAuth()` still reads them.

**CLI now builds `connection_request` envelopes.** `ink-interop send/build --intent-type connection_request` (or the alias `connection`) constructs a `ConnectionRequestPayloadSchema`-conformant payload (`method`, `context`, `profileSnapshot`). This is the bootstrap intent for first contact between strangers: receivers that opt in to foreign senders verify the body signature against the inline key extracted from the sender's `did:key` (trust-on-first-use). Other intent types (`intro_request`, `ask`, `follow_up`) presume the sender is already a known contact and remain reserved for established relationships.

Verified end-to-end against `https://api.tulpa.network/ink/v1/<agentId>/intent`: a `did:key:` `connection_request` from `ink-interop send` lands as a pending action in the recipient's inbox (`status: 200`, `accepted: true`, `pendingActionId: 01KT…`). Coverage spans schema validation, body + transport signature verification, replay/freshness, identity resolution, routing, and the foreign-DID policy gate. Tests pinned to the canonical shape (`tests/test_envelope.py`) prevent regression. The npm library itself is unchanged from v0.1.1.

**Example-helper API break.** `examples/interop-cli/`'s Python helper `build_intent_envelope()` now requires `keypair`, replaces `intent_type`/`purpose`/`timestamp` with canonical args (`target`, `reason`, `created_at`, etc.), and removes the `extra=` kwarg. Adopters who imported the old helper directly will need to update their calls — the previous signature emitted invalid wire data so no callable interop existed there to preserve. This is an example-only change; the npm library (`@adastracomputing/ink`) exports are unchanged.

## 0.1.1, discovery rename and normative SSRF floor

> **Erratum, 2026-06-01:** the bundled Python interop CLI at
> `examples/interop-cli/` shipped with this tag emits an envelope
> shape that does not match the canonical `MessageEnvelopeSchema`
> (`id`, `correlationId`, `createdAt`, `intent` enum, payload,
> body-level `signature`). The npm library is unaffected. End-to-end
> sends from the Python CLI to a conforming receiver fail with
> `invalid_envelope`. Fixed in v0.1.2.

This release is **wire-compatible with v0.1.0**; the wire version stays `ink/0.1`. Every change below is additive and accepts the prior shape for the duration of the v0.1.x line — implementations that emit and consume v0.1.0 cards / service entries continue to interoperate. One observable library behavior changes: the runtime emit value of the redacted Agent Card `type` field flips from `"tulpa.agent.card"` to `"ink.agent.card"` (see below). Consumers that pinned to the literal must accept either string; the TypeScript union has been widened accordingly.

**Service entry rename.** The DID Document service entry for INK endpoints is now `type: "INKAgentEndpoint"`. The legacy `"TulpaAgentEndpoint"` is still accepted by consumers during v0.1.x; new publishers SHOULD emit `INKAgentEndpoint`. When both are present, `INKAgentEndpoint` takes precedence. Removed at the next wire-version bump.

**Service entry now points at the Agent Card URL.** `serviceEndpoint` is the URL of the Agent Card, not the inbound message endpoint. Inbound URL stays on the Card itself in the `endpoint` field. Per the spec update, `inboxEndpoint` is also accepted as a synonym for `endpoint`.

**Normative SSRF floor for discovery fetches.** The Discovery spec now mandates HTTPS-only, refusal of private/link-local/loopback/cloud-metadata hosts, bounded redirects with host re-checking on each hop, response size and time caps, and honoring `Cache-Control`. Detailed hardening stays implementer responsibility but the normative floor lives in the spec.

**Normative DID-binding of fetched cards.** Consumers MUST bind the card's `ownerDid` (when present) to the DID under resolution, and bind the card's `agentId` to the agent identifier being sent to. A mismatch on either field is a hard reject. This closes the substitution attack where a host that legitimately publishes one DID claims to publish another.

**Cache and refresh rules lifted into normative Discovery.** Refresh on signature/keyId miss, on observed `keySetVersion` increase, never fall back to bootstrap keys after a valid card has been observed.

**Redacted Agent Card type renamed.** The `type` field on a redacted Agent Card is now `"ink.agent.card"`. Consumers MUST also accept the legacy `"tulpa.agent.card"` during v0.1.x. The `network.tulpa.*` wire-message types are explicitly **frozen** for v0.x per the compatibility policy; rewriting them would break every deployed router.

**Wire version is `ink/0.1`.** All v0.1.x package releases emit `protocol: "ink/0.1"` on the wire. The next wire-version bump is `ink/0.2`.

## 0.1.0-alpha.5, ship compiled JS

Fixes a publish-time regression in `0.1.0-alpha.3` (and the unreleased
`alpha.4`) where the package shipped raw TypeScript under `main` and
`exports`. Node 24 refuses to strip types from anything under
`node_modules`, so any consumer following the quickstart hit
`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING` on the first `import`
and could not use the library at all.

### Changed

- `npm run build` compiles `src/` to `dist/` via `tsconfig.build.json`;
  `prepublishOnly` runs it automatically so the npm tarball always
  contains compiled JS plus declaration maps.
- `main`, `types` and `exports."."` now point at `./dist/index.js` and
  `./dist/index.d.ts`. The `files` array ships `dist/` instead of
  `src/`, so consumers no longer see raw TS in `node_modules`.
- Dev shell and `engines.node` move from Node 22 to Node 24 (the
  current Active LTS) to match CI.

End-to-end verified against `witness-demo.tulpa.network`: the
quickstart `submit.mjs` now returns a signed inclusion receipt on
Node 24 without modification.

## 0.1.0-alpha.3, signed audit-query response

Closes the last HIGH conformance-audit finding (witness audit-query
response missing signature, proofs and protocol envelope).

### Added

- `signAuditQueryResponse(payload, privateKey)` and `verifyAuditQueryResponseSignature(payload, signature, publicKey)` primitives. Canonical signed bytes are `ink/audit-query-response/v1\n` + JCS(payload without serviceSignature). The payload binds `serviceDid`, `messageId`, `requester`, `events`, `proofs`, `treeSize`, `rootHash`, `timestamp`, so a valid signature cannot be rebound to a different witness, message, requester, or root.
- `verifyAuditQueryResponse({response, witnessPublicKey, expectedRequester, expectedMessageId, verifyEventSignature, expectedServiceDid?, laterCheckpoint?})` is the recommended high-level verifier. `verifyEventSignature` is a REQUIRED callback that resolves the submitting agent's keys and validates each event's `agentSignature`. Without it, the verifier refuses to return valid, because Merkle inclusion alone does not prove agent provenance (§7.5). The function enforces envelope shape, requester binding, events/proofs strict one-to-one alignment, the §7.4 per-event scope rule, walks every Merkle proof via `computeAuditMerkleLeafHash` up to the response's `rootHash`, runs `verifyEventSignature` on every event and supports optional later-checkpoint cross-check. `verifyAuditQueryResponseSignature` alone is signature-only and is documented as a low-level primitive.
- `computeAuditMerkleLeafHash(event)` primitive: the RFC 6962 leaf-hash rule for inclusion proofs, `SHA-256(0x00 || JCS(event-without-agentSignature))`. Distinct from `computeEventHash` (unprefixed, used only for `previousEventHash` chain linkage). Verifiers walking an inclusion proof MUST use this function, not `computeEventHash`.
- Nix flake now exposes `apps.default`, so `nix run github:Ad-Astra-Computing/ink -- verify-inclusion --file r.json --witness URL` works without `npm install`.

### Security

- The §7.3 envelope now binds `requester`. Without this binding, a signed witness response generated for Alice could be replayed to Bob as Bob's authoritative view of the same `messageId`. Verifiers MUST check the response's `requester` equals their locally authenticated requester before accepting events as a complete view.
- Witnesses MUST fail closed when the requester's visible event set for a `messageId` exceeds the response cap, returning an unsigned HTTP 413 rather than silently signing a partial response. The reference and OSS witnesses query `LIMIT MAX_QUERY_EVENTS + 1`, detect overflow and refuse to sign.
- Witnesses MUST emit a deterministic, stable result-set order so signed bytes are reproducible. The reference and OSS witnesses use `ORDER BY event_id ASC`.
- Storage-integrity failures during proof construction (missing event_hash, hash mismatch, missing Merkle node, unprovable leaf, malformed event_json) now return HTTP 500 instead of silently omitting events from a signed response.
- All canonicalize-and-sign / canonicalize-and-verify paths now cap by UTF-8 byte length, not JS string length. With non-ASCII event data the prior cap could be undercounted and let oversized payloads through. Affects `buildSignatureBase`, `computeMessageHash`, `signAuditEvent` / `verifyAuditEventSignature`, `computeEventHash`, `signAuditResponse` / `verifyAuditResponseSignature`, `signAuditQueryResponse` / `verifyAuditQueryResponseSignature` and the witness `handleQuery` response-size guard.
- `verifyAuditEventSignature`, `verifyAuditResponseSignature`, `verifyAuditQueryResponseSignature` now wrap canonicalization inside the try/catch, so payloads that pass the complexity precheck but throw inside `jcsCanonicalize` (e.g. objects with `undefined` values) return `false` instead of propagating.

### Spec

- `specs/ink-auditability.md` §7.3 (audit-query response) now defines the full signed-envelope shape: `{protocol, type: "network.tulpa.audit_query_response", serviceDid, messageId, requester, events, proofs[{eventId, leafIndex, inclusionProof}], treeSize, rootHash, timestamp, serviceSignature}`. Previous text described a bare `{events}` shape with no signature, no protocol envelope and no per-event proofs.
- §7.3 leaf-hash text now references `computeAuditMerkleLeafHash` directly and warns implementers that `computeEventHash` (chain linkage) is NOT the leaf input.
- §7.3 now explicitly forbids witnesses from signing partial results: truncation MUST be an unsigned error. A signed response is a complete enumeration of the requester's visible events at `(treeSize, rootHash)`.
- §7.3 requires witnesses to emit `events` and `proofs` in a stable, deterministic order.

## 0.1.0-alpha.2, inclusion-receipt verifier

Adds a public verification path for INK Auditability Section 7
inclusion receipts, plus a CLI any third party can run without
trusting any specific operator's UI.

### Added

- `verifyInclusionReceipt({receipt, witnessPublicKey, eventHash?, laterCheckpoint?})` exported from the package root. Pure function. Returns `{valid, steps[]}` where each step explains pass/fail with detail. Always verifies structure + Ed25519 service signature against the canonical `ink/audit-inclusion/v1\n` + JCS format. Optionally walks the Merkle proof when `eventHash` is provided, and cross-checks against a `laterCheckpoint` for tree-grew-not-rewound + no-fork-at-same-treeSize.
- `ink` CLI dispatcher with a `verify-inclusion` subcommand. `npx @adastracomputing/ink verify-inclusion --file receipt.json --witness https://witness.example.com` fetches the witness DID document + current checkpoint and runs the full verification. Witness URL is validated (https-only by default, `--allow-http` opt-in, no credentials). Exit code 0 = valid, 1 = invalid, 2 = usage / network / validation error. Self-contained ESM JavaScript so it works on any Node 22+ install with no TypeScript toolchain.

## 0.1.0-alpha.1, spec clarification

Spec-only release. Library code in `src/` is
unchanged from `0.1.0-alpha.0`; the bundled spec text is updated.

### Spec changes

- `specs/ink-auditability.md` now pins the canonical
  inclusion-receipt signature format: `ink/audit-inclusion/v1\n` +
  JCS(`{eventId, leafIndex, treeSize, rootHash, timestamp}`).
  Previously the spec described the signature as "over (eventId +
  treeSize + rootHash + timestamp)" without specifying a separator
  or encoding, which caused interop drift between implementations.
  No code change in this package; downstream witness and verifier
  implementations should align with the canonical format.

## 0.1.0-alpha.0, first public alpha

Initial open-source release of the INK protocol library and specification.

### Protocol surface

- Ed25519-signed envelopes with JCS (RFC 8785) canonicalization.
- Domain-separated signing base: `ink/0.1\nMETHOD\nPATH\nrecipientDid\nJCS(body)\ntimestamp`.
- Agent Card schema with `keys.signing` and `keys.encryption`.
- Key rotation authority rule (see `docs/key-rotation-rule.md`).
- Timestamp freshness window: 5 minutes past, 30 seconds future.
- ECIES encryption envelopes with AAD bound to all security-relevant
  outer fields.
- Receipt and audit envelope structures.
- Optional containment extension: capability-gated visibility, handshake
  budgets, sender silent-drop after first rate-limit violation.

### Library

- Public API exported from the package root, see README for the export
  surface.
- Defense-in-depth SSRF protections in `fetchAgentCard`: https-only
  baseUrl, no userinfo, IANA special-use IPv4 and IPv6 blocklists,
  6to4-embedded-v4 extraction, manual redirect, body-size stream cap,
  Zod runtime card validation, recursive endpoint validation,
  integrator-supplied fetch hook for connect-time defenses.
- Length and format caps on every base64url/hex decode call site.
- Strict signature length and charset validation before any
  cryptographic operation.
- Authoritative empty-key-set semantics, once an Agent Card publishes
  a signing key set, callers must not fall back to bootstrap keys.
- `verifyInkAuth` requires an explicit `nonceStore: NonceStore | "deferred"`
  option: pass a `NonceStore` to have the middleware enforce single-use
  semantics on `body.nonce` within the freshness window, or `"deferred"`
  to acknowledge that `checkReplay` (or equivalent) will run elsewhere
  in the request pipeline. Omitting the option returns
  `nonce_handling_required`, so a misconfigured deployment fails
  loudly rather than silently accepting replays.
- `verifyAuditEventChain(events)` validates internal continuity of an
  audit response slice: strictly +1 sequence, `previousEventHash`
  linkage, duplicate-sequence fork detection. Consumers of
  audit-exchange responses MUST run this alongside
  `verifyAuditResponseSignature`.
- `checkReplay` standalone helper with explicit nonce + timestamp
  freshness; nonce backing storage is the integrator's choice.

### Test surface

- 430 unit and integration tests across crypto, middleware, discovery,
  containment, and security-regression suites.
- Interop test vectors in `test-vectors/` covering signing base, key
  rotation, replay, and Agent Card shapes.
