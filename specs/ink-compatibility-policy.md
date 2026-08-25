# INK Compatibility and Versioning Policy

**Status:** Draft, v1 stabilization
**Authors:** Ad Astra Computing
**Last updated:** 2026-05-24

## Purpose

This document defines how INK versions its wire protocol, when changes require version bumps, how optional capabilities are advertised, and how implementations handle unknown fields and message types.

This is the normative compatibility contract. Any change to the INK wire format MUST be evaluated against this policy before merging.

---

## 1. Protocol Version

INK uses a single protocol version string in every message envelope, receipt, audit event and handshake message.

Defined versions: `ink/0.1` (default) and `ink/0.2` (negotiated). See [§1.4](#14-defined-wire-versions).

The version string appears in the `protocol` field of every top-level INK object and in the first line of every signature base.

### 1.1 Version Format

`ink/<major>.<minor>`

- **Major**: incremented for incompatible wire changes
- **Minor**: incremented for backward-compatible additions

The `protocol` value is a closed enum and a value outside it is rejected outright, never inferred from its major. The accepted set is per-surface: the intent envelope accepts `ink/0.1` and `ink/0.2` (the body-signature minor of §1.4), while the handshake, Agent Card, receipt and audit objects accept `ink/0.1` only, so `ink/0.2` on those objects is rejected (`ink-protocol.md` §3.1; `handshake-message/wrong-protocol-rejects` and `agent-card/wrong-protocol-rejects`). A new minor version does not deploy by receivers ignoring it; it deploys receiver-first, the receiver advertising it in `supportedProtocolVersions` and the sender emitting it only after that advertisement, exactly as `ink/0.2` did (§1.4). "Ignore unknown optional fields" applies only to the tolerant surfaces of §3.1, not to the `protocol` value.

### 1.2 Audit Version

Audit events use a separate version string: `ink-audit/1`

This version follows the same policy but is independent of the transport protocol version. An audit version bump does not require a transport version bump or vice versa.

### 1.3 Wire-namespace prefix (`network.tulpa.*`)

Message `type` fields throughout INK v0.1 carry the prefix
`network.tulpa.*` (e.g. `network.tulpa.encrypted`, `network.tulpa.challenge`).
This is a **historical artifact** of INK's origin at Tulpa and is *not*
intended to imply Tulpa ownership of the protocol, Ad Astra Computing
stewards INK; Tulpa is one product built on it.

The vendor-neutral prefix `network.ink.*` is introduced as a
backward-compatible, receiver-first transition, the same shape as the `ink/0.2`
body-signature change:

- A conforming receiver MUST dual-accept both spellings of every message type
  that has both: `network.tulpa.<suffix>` and `network.ink.<suffix>` are
  equivalent on receipt (e.g. `network.ink.challenge` validates wherever
  `network.tulpa.challenge` does). A type the Protocol §6 registry marks
  **neutral-only** was allocated after this transition and has a single
  registered spelling, `network.ink.<suffix>`; its `network.tulpa.*` form is
  unregistered and rejected.
- A sender MUST continue to EMIT `network.tulpa.*` by default. Emitting the
  vendor-neutral spelling is opt-in and reserved for a future negotiated
  capability, so a receiver that has not yet upgraded never sees the new prefix.
- The dual-accept is a pure receiver-side leniency and is INDEPENDENT of the
  signed `protocol` field (which governs only the body-signature domain). It is
  not gated on `ink/0.2` or any wire version.
- A validated message keeps its actual `type` string. Every signature, hash,
  receipt, and AEAD binding is over the spelling on the wire, never a normalized
  one, so relabelling a message (changing its `type` after it was signed or
  encrypted) fails verification.

Two message types are excluded from dual-accept and stay `network.tulpa.*`
only: `audit_response` and `audit_inclusion`. Both carry a *detached* signature
that authenticates only a payload subset (`responseSignature` over `JCS(events)`,
`serviceSignature` over `{eventId, leafIndex, treeSize, rootHash, timestamp}`)
and not the envelope `type`. The relabel-rejection guarantee above therefore
cannot hold for them, so the vendor-neutral spelling is withheld until a future
wire change brings `type` under their signature. Every other type either signs
its full body (handshake, receipt, audit-query-response) or binds `type` into
its AEAD AAD (encrypted), so dual-accept is relabel-safe.

The `handshake-message`, `payload-encryption`, and `audit-query-response`
conformance categories pin both spellings, including the relabel-rejection
cases, so the two implementations agree.

### 1.4 Defined wire versions

Two wire versions are defined:

- `ink/0.1`, the original version. A sender emits it by default unless it has positively negotiated otherwise.
- `ink/0.2`, a backward-compatible minor that changes only the body-signature domain separator, from the legacy `tulpa/sign\n` to the neutral `ink/sign\n`. Everything else, the transport-auth signature base, the envelope shape, the encryption and audit sub-protocols and every `network.tulpa.*` type, is identical to `ink/0.1`.

`ink/0.2` is receiver-first. A receiver advertises the versions it verifies in its Agent Card `supportedProtocolVersions` array; when that field is absent a sender MUST assume `ink/0.1` only, and a sender MUST NOT emit `ink/0.2` to a receiver that has not advertised it. The negotiation is what keeps the change compatible: an `ink/0.1`-only receiver never receives `ink/0.2` traffic, so it is never asked to verify a domain it does not implement. An `ink/0.2` receiver selects the body-signature domain from the signed `protocol` field and verifies both versions, and because `protocol` is inside the signed body a relabelled message fails verification.

This satisfies §1.1. The minor bump adds a capability without breaking deployed `ink/0.1` implementations, because the body-signature domain is negotiated rather than assumed.

---

## 2. Compatibility Rules

### 2.1 Breaking Changes (Major Version Bump Required)

The following changes MUST trigger a major version bump:

| Change | Reason |
|--------|--------|
| Signature base format change | Breaks all existing verification |
| Required field added to existing message type | Old implementations reject new messages |
| Required field removed from existing message type | New implementations reject old messages |
| Field type changed (e.g. string → number) | Deserialization breaks |
| Cryptographic algorithm change (signing, encryption, hashing) | Interop breaks silently |
| JCS canonicalization behavior change | Signature verification breaks |
| Replay protection parameter change (window size, nonce format) | Messages rejected incorrectly |
| Auth header scheme change | Transport auth breaks |
| Key status semantics change | Verification behavior changes |
| Signed-body grammar narrowed (a byte sequence that used to be accepted is now rejected) | A body a conforming sender could previously emit stops verifying |

The last row is what the pre-1.0 window is for. A narrowing is a break in the
direction that costs least, because it only ever turns an accept into a reject:
a receiver on the new rule refuses something an old sender could produce, and no
signature over previously valid bytes becomes forgeable. Taking one after 1.0
would still require a major bump. Every narrowing taken before 1.0 MUST be
recorded here with its date, the byte sequences it removes, and the reason:

| Narrowing | Taken | Removes | Reason |
|---|---|---|---|
| Escaped object member names in a signed body ([`ink-signed-string-safety.md`](ink-signed-string-safety.md)) | 0.17.0 | A member name containing a quotation mark, a reverse solidus, or a character in `U+0000`–`U+001F`, and any member name spelled with a `\uXXXX` escape | V8 returns a wrong member name for such a name, so a receiver on Node 24+ or Cloudflare workerd canonicalizes bytes the signer never produced and disagrees with a Go receiver about which bytes a signature covers |

### 2.2 Backward-Compatible Changes (Minor Version Bump)

The following changes MAY be made under the same major version:

| Change | Constraint |
|--------|-----------|
| New optional field on a tolerance-pinned surface (§3.1) | Receivers ignore the unknown field. On a strict schema (intent envelope, intent payloads, auth-header parameters) a new field is not additive; it ships receiver-first, advertised then emitted, the same pattern as §2.4 |
| New intent type | Receivers respond with `unsupported_intent` rejection. The intent-type set is closed in both the envelope schema and the card capability arrays, so a new intent lands receiver-first via the enum-extension path of §7.1 |
| New receipt disposition | The disposition enum is closed under major 1 on both the receipt message (an unknown value is `malformed_receipt`) and the card `capabilities.receipts.dispositions` array (a card advertising a new value is rejected wholesale), so a new disposition takes the receiver-first enum-extension path on both |
| New audit event type | Processors MUST ignore unknown event types |
| New handshake challenge type | Receivers respond with appropriate rejection |
| Second cryptographic suite added additively (new optional top-level card member, receiver-first negotiation) | 1.0 receivers ignore the unknown top-level member; see §2.4 |
| New optional capability in Agent Card | Receivers ignore unknown capability blocks |

### 2.3 Non-Version Changes

The following changes do not require a version bump:

- Documentation clarifications that do not change wire behavior
- New test vectors for existing behavior
- Implementation bug fixes that bring behavior into spec compliance
- New optional Agent Card metadata fields outside `keys` and `capabilities`

### 2.4 Adding a Cryptographic Suite

The `algorithm` field on a `keys.signing` or `keys.encryption` entry is a closed
enum (`Ed25519`, `X25519`) for the lifetime of major 1. A key entry that carries
any other `algorithm` value does not skip; it rejects the whole Agent Card. This
is pinned by the base conformance vector `key-bad-algorithm-rejects` and enforced
in both reference implementations. So a second cryptographic suite MUST NOT be
introduced by adding new values to the `keys.*` `algorithm` enum, and second-suite
key material MUST NOT be placed in `keys.signing` or `keys.encryption` under major
1. A deployed 1.0 receiver would reject any card advertising such a key.

A second suite is instead introduced additively as a new optional top-level Agent
Card member (see the reserved `suites` seam in §3.3) plus receiver-first
negotiation, following the same pattern `ink/0.2` used: the receiver advertises
what it verifies and the sender emits the second suite only to a receiver that has
advertised it, while a 1.0 receiver that does not understand the new member ignores
it and continues on the base suite. Introduced this way, adding a negotiated
second suite is a minor change. This is consistent with §2.1: changing or
retiring the existing base suite remains a major change, because deployed
receivers verify only the base suite.

---

## 3. Unknown Fields and Types

### 3.1 Unknown Fields

Tolerance of an unknown field is per-surface, not blanket, and the two regimes are pinned by the frozen corpus.

Most INK schemas are strict: an unknown member is rejected outright. This holds for the intent envelope (`ink-protocol.md` §3.1 states a receiver MUST reject an unknown top-level key on the envelope), every intent payload including the connection payloads (`connection-payload/request-unknown-key-rejects`, `connection-payload/response-unknown-key-rejects`, `first-contact-transcript/response-payload-unknown-key`), the profile-snapshot object and its nested availability config wherever the snapshot is embedded, whether in a connection payload or the Agent Card `profileSnapshot` (`connection-payload/profile-unknown-key-rejects`, `connection-payload/availability-unknown-key-rejects`) and the Authorization-header parameters (`authorization-header/second-unknown-param-rejects`). A field added to any strict surface is not additive; it ships receiver-first, advertised then emitted, the same pattern as §2.4.

A small set of surfaces is tolerant and ignores an unknown member: the Agent Card top level, including its top-level `availability` member (`agent-card/card-unknown-top-level-key-ignored-accepts`), the nested `discovery` descriptor, which is a separate surface with its own case (`agent-card/discovery-unknown-key-ignored-accepts`), the encrypted-envelope outer object (`payload-encryption/unknown-outer-field-ignored`, where an ignored field is not AAD-bound), the handshake and receipt objects (accepted, not rejected; the reference validators strip unknown keys from the parsed object) and unknown audit event types in chain processing (§3.4). On a tolerant surface an implementation MUST NOT reject on an unknown field's presence.

### 3.2 Unknown Message Types

When a receiver encounters an unknown `type` value in a handshake or protocol message, it MUST respond with a `network.tulpa.rejection` with reason `unsupported_intent`.

When a receiver encounters an unknown `intent` in a message envelope, it MUST respond with a rejection and SHOULD send a `received` receipt if receipt support is advertised.

### 3.3 Key Algorithms

Within major 1 the key-entry `algorithm` set is closed (`Ed25519`, `X25519`).
An unrecognized `algorithm` value on a `keys.signing` or `keys.encryption` entry
is not skipped during verification; it is a whole-card reject (pinned by the base
vector `key-bad-algorithm-rejects`). A candidate key set built from a validated
card therefore never contains an unrecognized algorithm, so no skip rule is
reachable.

To reserve room for a future receiver-first suite negotiation without a
field-name collision, two names are reserved and MUST NOT be reused for any other
purpose under major 1: the top-level Agent Card member `suites` and the
auth-scheme-token pattern `INK-<Alg>` (for example a future transport scheme token
alongside the existing `INK-Ed25519`). A second suite is introduced
only additively and receiver-first (see §2.4). The one hard invariant: second-suite
key material MUST NOT be placed in `keys.signing` or `keys.encryption` under major 1.

### 3.4 Unknown Audit Event Types

Audit chain processors MUST NOT break on unknown event types. Unknown events MUST be included in hash chain computation to preserve chain integrity.

---

## 4. Capability Advertisement

### 4.1 Mechanism

Agent Cards are the canonical mechanism for capability advertisement. The `capabilities` block declares what an agent supports.

Implementations MUST NOT assume capabilities that are not advertised.

### 4.2 Required Capabilities

Every base INK v0.1 agent MUST support:
- Transport signing (`INK-Ed25519` auth header)
- Replay protection (timestamp + nonce)
- At least one intent type
- Agent Card discovery at the path pinned by [`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md)

### 4.3 Optional Capabilities

The following are advertised per-agent and MUST NOT be assumed:

| Capability | Agent Card field | Default if absent |
|-----------|-----------------|-------------------|
| Receipt support | `capabilities.receipts` | No receipts |
| Bilateral audit exchange | `capabilities.auditExchange` | Not supported |
| Third-party witness | `capabilities.thirdPartyAudit` | Not supported |
| Encryption | Presence of encryption keys in `keys.encryption` | Encryption not supported |
| Key rotation | Presence of `keys.signing` array | Legacy single-key mode |
| Handshake stages | Presence of `/challenge`, `/rejection`, `/resolution` endpoints | Not supported |

### 4.4 Capability Negotiation

INK does not use explicit capability negotiation handshakes. Capabilities are discovered by reading the Agent Card before first contact.

If a sender requires a capability the receiver does not advertise (e.g. encryption for `schedule_meeting`), the sender MUST NOT send the message. It MAY inform the user that the recipient does not support the required capability.

---

## 5. Wire Format Stability

### 5.1 Signature Base

The signature base format is the most stability-critical element of INK:

```
ink/0.1\n<METHOD>\n<PATH>\n<recipientDid>\n<JCS(body)>\n<timestamp>
```

The first line is the fixed literal `ink/0.1` for every message, including `ink/0.2` traffic; the transport base does not track the message `protocol` value. Version selection happens only in the body-signature domain (see [`ink-protocol.md`](ink-protocol.md) §3.6). Any change to this format, field order, separator, domain prefix, canonicalization algorithm, is a breaking change.

### 5.2 Auth Header

```
INK-Ed25519 <base64url(signature)> [keyId=<keyId>]
```

The `keyId` parameter is optional and was added in a backward-compatible way. The normative grammar is the strict one in [`ink-protocol.md`](ink-protocol.md) §3.3, `^INK-Ed25519 ([A-Za-z0-9_-]{86})(?: keyId=([A-Za-z0-9_:.-]{1,128}))?$`, with literal single spaces, an exact 86-character base64url signature and a bounded `keyId` charset. It is not the looser `\s+`/`\S+` form; the corpus rejects the inputs a loose regex would accept (double spaces, off-length or off-charset signatures, over-length or illegal-character key ids), pinned by the `authorization-header` category.

Future parameters would use the same `key=value` syntax after the signature, space-separated, but a deployed 1.0 receiver rejects any unrecognized parameter (pinned by `authorization-header/second-unknown-param-rejects`). A new parameter is therefore a reserved syntax slot, not an additively deployable change; it ships only behind a negotiated capability or a version gate.

### 5.3 Encoding Conventions

These conventions are fixed for the lifetime of INK v1:

| Data | Encoding |
|------|----------|
| Ed25519/X25519 signatures | base64url (no padding, RFC 4648 §5) |
| Public keys in Agent Card | multibase (base58btc with multicodec prefix) |
| Hashes (SHA-256) | lowercase hex |
| Timestamps | strict RFC 3339 profile (e.g. `2026-03-25T12:00:00Z`) |
| Nonces | `[A-Za-z0-9_-]{16,256}` |
| AES-GCM nonces | base64url |
| Body canonicalization | JCS (RFC 8785) |

The timestamp encoding is not full ISO 8601. INK enforces the narrower strict
RFC 3339 profile (an uppercase `T`, a `Z` or numeric `±HH:MM` zone, no leap
second, no space separator, no lowercase `t`/`z`) with whole-millisecond
precision. The grammar and its vectors are in
[`ink-timestamp-grammar.md`](ink-timestamp-grammar.md). That grammar governs the
signed-body timestamp only; the handshake message timestamp uses a distinct,
narrower grammar (literal `Z`, no numeric offset) pinned by
[`ink-handshake-message.md`](ink-handshake-message.md). The replay nonce is the
enforced `[A-Za-z0-9_-]{16,256}` charset (§3.5 of
[`ink-protocol.md`](ink-protocol.md)); a UUID without hyphens or a base64url
token both satisfy it, but the enforced grammar is the charset shown, not either
example form.

### 5.4 Multicodec Prefixes

| Algorithm | Prefix bytes |
|-----------|-------------|
| Ed25519 | `0xed 0x01` |
| X25519 | `0xec 0x01` |

---

## 6. Deprecation Policy

### 6.1 Feature Deprecation

A feature or field MAY be deprecated by:
1. Documenting it as deprecated in the spec
2. Adding a note to the compliance checklist
3. Continuing to support it for at least one major version

### 6.2 Version Sunset

A major version MAY be sunset after:
1. The successor version has been stable for at least 6 months
2. All known active implementations have been notified
3. A documented migration path exists

---

## 7. Extension Points

### 7.1 Intent Types

Under major 1 the intent-type set is a closed enum, in both the envelope `intent` field and the Agent Card `capabilities.intentsAccepted` and `capabilities.intentsSent` arrays. A card advertising an intent outside the enum is rejected wholesale (pinned by `agent-card/bad-intent-enum-rejects`), and both reference implementations enforce the same closed set. A new intent type therefore is not added freely; it lands via a spec revision that extends the enum, deployed receiver-first so a card carrying it is not rejected by peers that predate the revision.

Free-form reverse-domain extensibility belongs to the protocol-message `type` registry (`ink-protocol.md` §6), not the intent enum. `network.tulpa.custom_intent` appears there as the registry's naming example, a message `type` in a namespace distinct from the intent enum. It MUST NOT be placed in an envelope `intent` field or a card capability array under major 1.

### 7.2 Audit Event Types

New audit event types can be added without a version bump. They use the same `InkAuditEvent` envelope and chain mechanics.

### 7.3 Agent Card Extensions

Agent Cards MAY include additional top-level or nested fields. Unknown fields MUST be ignored by consumers.

---

## 8. Implementation Guidance

### 8.1 Version Checking

Implementations MUST check `protocol` on every inbound object against the closed set of wire versions accepted for that surface and reject any value outside it (§1.1). The check tests the full version string, not the major alone, so an unknown minor such as `ink/0.3` is rejected rather than accepted. The accepted set is per-surface: the intent envelope accepts `ink/0.1` and `ink/0.2`, while the handshake, Agent Card, receipt and audit objects accept `ink/0.1` only (`handshake-message/wrong-protocol-rejects`, `agent-card/wrong-protocol-rejects`):

```
// SUPPORTED_WIRE_VERSIONS is the closed set accepted on this surface,
// e.g. new Set(["ink/0.1", "ink/0.2"]) on the intent envelope,
// new Set(["ink/0.1"]) on the other top-level objects.
if (!SUPPORTED_WIRE_VERSIONS.has(protocol)) reject("unsupported_protocol_version");
```

A new wire version is deployed receiver-first (advertised in `supportedProtocolVersions`, emitted only after advertisement), not by senders assuming a receiver will tolerate an unknown value.

### 8.2 Forward Compatibility

Implementations SHOULD be written to tolerate:
- Unknown optional fields on the tolerant surfaces of §3.1 (the strict surfaces reject them, by design)
- Unknown intent types (reject gracefully)
- Unknown audit event types (include in chain, skip processing)
- Unknown top-level Agent Card members (ignore; see the reserved `suites` seam in §3.3)
- Unknown Agent Card fields (ignore)

### 8.3 Strict Validation

Implementations MUST strictly validate:
- Signature base construction (exact format)
- Timestamp freshness windows
- Required fields on all message types
- Key status semantics (active/retired/revoked)
- Hash chain integrity for audit events
