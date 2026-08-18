# INK Agent Card Specification v0.1

**Status:** Stable base-profile spec; formal 1.0 freeze pending governance sign-off (see [`../GOVERNANCE.md`](../GOVERNANCE.md), [`../governance/releases/1.0-readiness-evidence.md`](../governance/releases/1.0-readiness-evidence.md)).
**Authors:** Ad Astra Computing
**Last updated:** 2026-07-20

## Purpose

An agent publishes its discovery document, the Agent Card, at the path
[`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md) pins.
A peer reads it to learn how to reach the agent
(its inbound endpoint), how to verify its messages (its keys), and what it
accepts (its capabilities). For independent implementations to interoperate they
must accept and reject the same cards. This profile pins the card's schema
validation, including a deliberately narrow endpoint URL grammar.

## Endpoint URL grammar

The `endpoint`, `inboxEndpoint`, and `thirdPartyAudit.endpoint` fields use a
pinned INK endpoint URL grammar, not a general URL validator. An endpoint URL is:

- a non-empty string of at most 2048 UTF-8 bytes,
- with no ASCII control character (`U+0000`-`U+001F`, `U+007F`) and no ASCII
  whitespace (the string is not trimmed first),
- with scheme `https` (lowercase),
- a non-empty host (DNS name, IPv4 literal, or bracketed IPv6 literal),
- no userinfo (`user@` / `user:pass@`),
- an optional port that is a decimal `1`-`65535`,
- an optional path and query,
- and no fragment.

This is narrower than a general WHATWG URL: `javascript:`, `mailto:`, `ftp:`,
non-`https`, control-character-tainted, userinfo-bearing, and fragment-bearing
values are rejected even though a permissive URL validator accepts them. An
endpoint identifier should be a fetchable https URL, and pinning the grammar
keeps the decision identical across implementations and runtimes.

## Card shape

The card is an object (unknown keys are ignored) with:

- `protocol`: the literal `"ink/0.1"`.
- `agentId` (<=512), `handle` (<=256), `displayName` (<=200): required strings.
- `ownerDid` (<=512), `ownerHandle` (<=256), `atprotoRecordUri` (<=2048):
  optional strings.
- `endpoint`: a required endpoint URL.
- `inboxEndpoint`: an optional endpoint URL that, when present, MUST equal
  `endpoint` byte for byte (the alias exists for forward compatibility, not to
  publish two inbound URLs).
- `publicKeyMultibase`: a required string starting with `z`, at most 128 code
  units.
- `profileSnapshot`: an optional strict profile snapshot (see
  [`ink-connection-payload`](ink-connection-payload.md)).
- `capabilities`: required, with `intentsAccepted` and `intentsSent` (arrays of
  at most 32 intent-type values), and optional `receipts`, `auditExchange`, and
  `thirdPartyAudit`.
- `availability`: required, with a `timezone` (<=64) and optional `meetingHours`
  and `responseSla` (<=200).
- `keys`: optional, with `signing` and `encryption` arrays (<=32) of key
  entries. A key entry has a non-empty `keyId`, an `algorithm` (`Ed25519` or
  `X25519`), a `publicKeyMultibase` starting with `z`, a `status`, and key-window
  timestamps (`validFrom` required, `validUntil`/`revokedAt` optional) in the
  strict RFC 3339 profile (see [`ink-timestamp-grammar`](ink-timestamp-grammar.md)).
- `currentSigningKeyId` / `currentEncryptionKeyId` (<=128), `keySetVersion` (a
  positive integer), `supportedProtocolVersions` (up to 8 strings of <=16),
  `visibility`, and `governance`: optional.
- `discovery`: an optional opt-in discoverability descriptor whose `scope` may
  not exceed `visibility`; see [`ink-discovery-descriptor`](ink-discovery-descriptor.md).
- `cardSignature`: optional. The self-authenticating card proof (see
  [`ink-agent-card-signature`](ink-agent-card-signature.md) §3.1), an object with
  a `keyId` (<=128) and a `signature` (base64url no-padding, exactly 86
  characters `[A-Za-z0-9_-]`).
- `rotationChain`: optional. An array of at most 32 rotation links that root the
  card key against the identity (see [`ink-agent-card-signature`](ink-agent-card-signature.md)
  §4.1). Each link has a positive-integer `keySetVersion`, a `signing` array
  (1 to 32 of `{keyId, publicKeyMultibase, status}`, each `keyId` unique within
  the link), a `prevKeyId` (<=128), and a `signature` (86-char base64url). A link
  entry carries no `algorithm` (Ed25519 is pinned) and no key-window timestamps.
- `updatedAt`: optional. An informational strict RFC 3339 timestamp (see
  [`ink-timestamp-grammar`](ink-timestamp-grammar.md)); it carries no comparison
  rule.

The `cardSignature`, `rotationChain`, and `updatedAt` members are all optional
and backward-compatible: a card without them validates exactly as before, and a
consumer that predates the signature spec ignores them as unknown top-level
fields. A receiver that enforces the signature spec verifies a present proof and
roots it per [`ink-agent-card-signature`](ink-agent-card-signature.md) §5.

String length bounds are measured in UTF-16 code units, matching the reference
schema's `.max()`, except the endpoint byte length above.

## Reference and second-implementation behavior

In the TypeScript reference, `AgentCardSchema` (in
[`src/models/agent-card.ts`](../src/models/agent-card.ts)) is the validation
source; the endpoint grammar is `isInkEndpointUrl` (in
[`src/models/endpoint-url.ts`](../src/models/endpoint-url.ts)), applied to all
three endpoint fields. The Go implementation mirrors them in `ValidateAgentCard`
and `isInkEndpointUrl` (in [`go/ink/agentcard.go`](../go/ink/agentcard.go)),
reusing the strict timestamp parser for key windows and the strict profile
snapshot validator.

The `cardSignature` and `rotationChain` schemas and the card-proof verifier
`verifyAgentCardSignature` live in
[`src/crypto/agent-card-signature.ts`](../src/crypto/agent-card-signature.ts) in
the TypeScript reference; a Go parity implementation and the
`agent-card-signature` conformance vectors follow.

## Conformance

The `agent-card` category of the [`ink.conformance.v1`](../conformance/v1) corpus
pins this. Each vector supplies a `card`. The corpus covers a minimal and a full
card, and the rejection edges: a wrong protocol, a missing required field, the
endpoint URL grammar (the schemes and forms a permissive validator would accept),
an `inboxEndpoint` that differs from `endpoint`, a bad `publicKeyMultibase`, an
unknown or over-cap enum array, a bad third-party-audit endpoint, a key entry
with a bad timestamp, algorithm, or empty id, and a non-positive numeric field.
