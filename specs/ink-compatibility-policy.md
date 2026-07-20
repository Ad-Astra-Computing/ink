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

Implementations MUST reject messages with an unrecognized major version. Implementations SHOULD accept messages with a recognized major version and an unrecognized minor version by ignoring unknown optional fields.

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

- A conforming receiver MUST dual-accept both spellings of every message type:
  `network.tulpa.<suffix>` and `network.ink.<suffix>` are equivalent on receipt
  (e.g. `network.ink.challenge` validates wherever `network.tulpa.challenge`
  does).
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

### 2.2 Backward-Compatible Changes (Minor Version Bump)

The following changes MAY be made under the same major version:

| Change | Constraint |
|--------|-----------|
| New optional field on existing message type | Receivers MUST ignore unknown fields |
| New intent type | Receivers respond with `unsupported_intent` rejection |
| New receipt disposition | Receivers MUST accept unknown dispositions gracefully |
| New audit event type | Processors MUST ignore unknown event types |
| New handshake challenge type | Receivers respond with appropriate rejection |
| New key algorithm added to Agent Card | Receivers skip keys with unknown algorithms |
| New optional capability in Agent Card | Receivers ignore unknown capability blocks |

### 2.3 Non-Version Changes

The following changes do not require a version bump:

- Documentation clarifications that do not change wire behavior
- New test vectors for existing behavior
- Implementation bug fixes that bring behavior into spec compliance
- New optional Agent Card metadata fields outside `keys` and `capabilities`

---

## 3. Unknown Fields and Types

### 3.1 Unknown Fields

Implementations MUST preserve unknown fields during canonicalization (JCS handles this correctly). Implementations MUST NOT reject messages containing unknown fields.

### 3.2 Unknown Message Types

When a receiver encounters an unknown `type` value in a handshake or protocol message, it MUST respond with a `network.tulpa.rejection` with reason `unsupported_intent`.

When a receiver encounters an unknown `intent` in a message envelope, it MUST respond with a rejection and SHOULD send a `received` receipt if receipt support is advertised.

### 3.3 Unknown Key Algorithms

When building a candidate key set for verification, implementations MUST skip keys with unrecognized `algorithm` values. Verification proceeds with the remaining candidates.

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
- Agent Card discovery at `GET /ink/v1/{agentId}/agent.json`

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

The `keyId` parameter is optional and was added in a backward-compatible way. The regex `/^INK-Ed25519\s+(\S+)(?:\s+keyId=(\S+))?$/` accepts both forms.

Future parameters MUST use the same `key=value` syntax after the signature, space-separated.

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

New intent types can be added without a version bump. They follow the same envelope format and signing rules.

Custom intent types SHOULD use reverse-domain naming (e.g. `network.tulpa.custom_intent`) to avoid collisions.

### 7.2 Audit Event Types

New audit event types can be added without a version bump. They use the same `InkAuditEvent` envelope and chain mechanics.

### 7.3 Agent Card Extensions

Agent Cards MAY include additional top-level or nested fields. Unknown fields MUST be ignored by consumers.

---

## 8. Implementation Guidance

### 8.1 Version Checking

Implementations MUST check `protocol` on every inbound message. The check SHOULD compare only the major version for forward compatibility, rejecting a major this build does not implement (§1.1) rather than testing against a single hardcoded value, so a build that later implements major 1 accepts it without an edit:

```
// SUPPORTED_MAJOR_VERSIONS is the set of majors this build implements,
// e.g. new Set(["0"]) today, new Set(["0", "1"]) once 1.0 ships.
const [major] = protocol.split("/")[1].split(".");
if (!SUPPORTED_MAJOR_VERSIONS.has(major)) reject("unsupported_protocol_version");
```

### 8.2 Forward Compatibility

Implementations SHOULD be written to tolerate:
- Unknown optional fields on any message type
- Unknown intent types (reject gracefully)
- Unknown audit event types (include in chain, skip processing)
- Unknown key algorithms (skip during verification)
- Unknown Agent Card fields (ignore)

### 8.3 Strict Validation

Implementations MUST strictly validate:
- Signature base construction (exact format)
- Timestamp freshness windows
- Required fields on all message types
- Key status semantics (active/retired/revoked)
- Hash chain integrity for audit events
