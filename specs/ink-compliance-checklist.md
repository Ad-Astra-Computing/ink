# INK v0.1 Compliance Checklist and Implementation Matrix

**Status:** Draft, v0.1 alpha conformance
**Authors:** Ad Astra Computing
**Last updated:** 2026-05-27

## Purpose

This checklist lets an independent implementer verify INK conformance without reading Tulpa source code. Each requirement maps to a spec section, test vector family and implementation status.

For the normative cross-implementation floor keyed to the `conformance/v1` corpus, see [`ink-conformance-profile.md`](ink-conformance-profile.md): it freezes which conformance categories a base sender and base receiver MUST satisfy versus the capability-gated profiles. This checklist is the broader, Tulpa-specific implementation matrix; the profile document is authoritative for what the corpus requires of any conforming implementation.

**"Protocol §X" citations** in the Spec column resolve to [`ink-protocol.md`](ink-protocol.md), the in-repo normative core wire spec. Its sections are: §2 discovery and the Agent Card, §3.1 message envelope, §3.3 transport signing, §3.4 payload encryption, §3.5 replay and freshness, §4 rate limiting, §5 handshake messages, §6 message-type namespace. Other Spec-column names (Key Rotation, Auditability, Containment, Auth Chain, Compat Policy, Discovery Fetch) resolve to the matching `ink-*.md` spec in this directory; "Discovery Fetch" is [`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md).

---

## How to Read This Document

**Requirement levels** follow RFC 2119:
- **MUST**, absolute requirement for conformance
- **SHOULD**, recommended; deviations require justification
- **MAY**, truly optional; advertised via capability

**Status column** applies to the Tulpa implementation:
- **Required**, part of the v1 wire contract
- **Optional**, capability-gated, not assumed
- **Extension**, defined but not required for base interop
- **Future**, specified for later versions

**Vectors column** names the `conformance/v1` categories, by manifest id,
whose vectors pin the row for every implementation; the empty marker `,`
means no vector pins the row, so whatever evidence it has is in the Tests
column.
`npm run check:facts` rejects an id the manifest does not have and renders
§16 from this column. **Tests column** names the reference test files that
exercise the row.

---

## 1. Discovery

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| D1 | Agent Card served at the discovery path | MUST | Required | Discovery Fetch, Discovery path |, | `test/ink-discovery-gating.test.ts` |
| D2 | Agent Card includes `protocol`, `agentId`, `publicKeyMultibase`, `endpoint` | MUST | Required | Protocol §2 | `agent-card` | `test/ink-discovery-gating.test.ts` |
| D3 | Agent Card includes `capabilities.intentsAccepted` and `intentsSent` | MUST | Required | Protocol §2 | `agent-card` | `test/ink-discovery-gating.test.ts` |
| D4 | Agent Card includes `keys.signing[]` with key-set model | SHOULD | Required | Key Rotation §5 | `agent-card` | `test/ink-key-rotation.test.ts` |
| D5 | Agent Card includes `currentSigningKeyId` and `keySetVersion` | SHOULD | Required | Key Rotation §5 |, | `test/ink-key-rotation.test.ts` |
| D6 | Legacy single-key Agent Cards accepted (no `keys` block) | MUST | Required | Key Rotation §16 | `agent-card` | `test/ink-key-rotation.test.ts` |
| D7 | Agent Card includes receipt capability advertisement | MAY | Optional | Auditability §1 |, | `test/ink-discovery-gating.test.ts` |
| D8 | Agent Card includes third-party audit service advertisement | MAY | Optional | Auditability §7 |, | `test/ink-discovery-gating.test.ts` |

---

## 2. Transport Signing

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| S1 | Signature base: `ink/0.1\nMETHOD\nPATH\nrecipientDid\nJCS(body)\ntimestamp` | MUST | Required | Protocol §3.3 | `signature-base` | `test/security-fixes.test.ts` |
| S2 | Ed25519 signature over UTF-8 encoded signature base | MUST | Required | Protocol §3.3 | `signature-base` | `test/security-fixes.test.ts` |
| S3 | Auth header: `INK-Ed25519 <base64url(sig)>` | MUST | Required | Protocol §3.3 | `authorization-header` | `test/security-fixes.test.ts` |
| S4 | Auth header extended: `INK-Ed25519 <sig> keyId=<keyId>` (optional) | SHOULD | Required | Key Rotation §13 | `authorization-header`, `key-rotation` | `test/ink-auth-header.test.ts` |
| S5 | base64url encoding uses no-padding (RFC 4648 §5) | MUST | Required | Protocol §3.3 | `authorization-header` | `test/security-fixes.test.ts` |
| S6 | JCS canonicalization per RFC 8785 | MUST | Required | Protocol §3.3 | `jcs-number`, `jcs-string-safety` | `test/security-fixes.test.ts` |
| S7 | Verification fails on wrong path | MUST | Required | Protocol §3.3 | `signature-base` | `test/security-fixes.test.ts` |
| S8 | Verification fails on tampered body | MUST | Required | Protocol §3.3 | `signature-base` | `test/security-fixes.test.ts` |
| S9 | Transport auth returns the canonical, prefix-independent principal alongside the raw `from`, so a receiver can key its per-sender controls on it as Protocol §4 requires; the two spellings of one key map to one principal | MUST | Required | Protocol §4, §7 | `principal-normalization` | `test/canonical-principal.test.ts` |

---

## 3. Replay Protection

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| R1 | Reject timestamps older than 5 minutes | MUST | Required | Protocol §3.5 | `replay-freshness` | `test/security-fixes.test.ts` |
| R2 | Reject timestamps more than 30 seconds in the future | MUST | Required | Protocol §3.5 | `replay-freshness` | `test/security-fixes.test.ts` |
| R3 | Reject duplicate nonces within the freshness window | MUST | Required | Protocol §3.5 | `replay-freshness` | `test/security-fixes.test.ts` |
| R4 | Accept valid nonce + fresh timestamp | MUST | Required | Protocol §3.5 | `replay-freshness` | `test/security-fixes.test.ts` |
| R5 | Nonce recorded only after all rejection checks pass | SHOULD | Required | Auth Chain Audit |, | `test/security-fixes.test.ts` |

---

## 4. Encryption

> Capability-gated: the `encryption` conformance profile. Required only when the implementation sends or accepts encrypted payloads; see [ink-conformance-profile.md](ink-conformance-profile.md). Not part of the base profile.

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| E1 | ECIES: X25519 ECDH + HKDF-SHA256 + AES-256-GCM | MUST (if encryption supported) | Required | Protocol §3.4 | `payload-encryption` | `test/security-fixes.test.ts` |
| E2 | HKDF salt: `"ink/0.1"`, info: `"ink/0.1/encrypt"` | MUST | Required | Protocol §3.4 | `payload-encryption` | `test/security-fixes.test.ts` |
| E3 | AAD: `"ink/0.1:envelope\n"` + JCS(protocol, type, from, ephemeralKey, nonce, timestamp, messageNonce) | MUST | Required | Protocol §3.4 | `payload-encryption` | `test/security-fixes.test.ts` |
| E4 | Encrypted envelope type: `network.tulpa.encrypted` | MUST | Required | Protocol §3.4 | `payload-encryption` | `test/security-fixes.test.ts` |
| E5 | `schedule_meeting`, `context_share` and `multi_party_sync` require encryption[^ck] | MUST | Required | Protocol §3.4 |, | `test/encryption-policy.test.ts`, `examples/reference-receiver/test/inbound.test.ts` |
| E6 | Decryption validates inner/outer envelope consistency | MUST | Required | Protocol §3.4 | `payload-encryption` | `test/security-fixes.test.ts` |

---

## 5. Message Envelope

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| M1 | Intent envelope includes `protocol`, `id`, `correlationId`, `createdAt`, `from`, `to`, `intent`, `payload`, `signature`; `timestamp` and `nonce` are optional in the schema and required at receipt for the replay checks (§3.5). Intent messages carry `intent` and have no `type`; the reverse-domain `type` field is on protocol messages (encrypted, handshake, receipt, audit) in the `network.tulpa.*`/`network.ink.*` namespace (§6) | MUST | Required | Protocol §3.1, §6 | , | `test/security-fixes.test.ts` |
| M2 | `protocol` field is `"ink/0.1"` or `"ink/0.2"`; an unknown value is rejected, never inferred | MUST | Required | Protocol §3.1, §8 | , | `test/security-fixes.test.ts` |
| M3 | `signingKeyId` optional field for key rotation | SHOULD | Required | Key Rotation §13 | , | `test/ink-auth-header.test.ts` |
| M4 | Unknown fields preserved during canonicalization | MUST | Required | Compat Policy §3.1 | , | `test/security-fixes.test.ts` |

---

## 6. Handshake

> Containment-gated: the `containment` conformance profile (signed challenge, rejection, and resolution messages). Required only when the implementation advertises the containment and governance extension; see [ink-conformance-profile.md](ink-conformance-profile.md). Not part of the base profile.

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| H1 | Challenge: `network.tulpa.challenge` with INK-Ed25519 auth | MUST | Required | Protocol §5 | `handshake-message` | `test/ink-handshake-schemas.test.ts` |
| H2 | Rejection: `network.tulpa.rejection` with reason code | MUST | Required | Protocol §5 | `handshake-message` | `test/ink-handshake-schemas.test.ts` |
| H3 | Resolution: `network.tulpa.resolution` with outcome | MUST | Required | Protocol §5 | `handshake-message` | `test/ink-handshake-schemas.test.ts` |
| H4 | Resolution outcome: `accepted`, `declined`, `escalated_to_human`, `expired` | MUST | Required | Protocol §5 | `handshake-message` | `test/ink-handshake-schemas.test.ts` |
| H5 | Handshake messages signed with same signature base rules | MUST | Required | Protocol §3.3/§5 | , | `test/ink-handshake-schemas.test.ts` |
| H6 | Path binding: signature for `/challenge` rejects at `/rejection` | MUST | Required | Protocol §3.3 | , | `test/ink-handshake-schemas.test.ts` |

---

## 7. Receipts

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| RC1 | Receipt type: `network.tulpa.receipt` | MUST (if receipts supported) | Optional | Auditability §1 | , | `test/ink-receipt-generation.test.ts` |
| RC2 | Dispositions: `received`, `delivered`, `acted`, `rejected`, `expired` | MUST | Optional | Auditability §1 | , | `test/ink-receipt-generation.test.ts` |
| RC3 | `messageHash`: SHA-256 of JCS-canonicalized original message (hex) | MUST | Optional | Auditability §1 | , | `test/ink-receipt-generation.test.ts` |
| RC4 | Receipts are Ed25519 signed | MUST | Optional | Auditability §1 | , | `test/ink-receipt-generation.test.ts` |
| RC5 | No receipt sent for receipts (loop prevention) | MUST | Optional | Auditability §1 |, | `test/ink-receipt-generation.test.ts` |
| RC6 | Receipt transport uses INK-Ed25519 auth header | MUST | Optional | Auditability §1 | , | `test/ink-receipt-generation.test.ts` |

---

## 8. Bilateral Audit Exchange

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| A1 | Audit events: hash-chained with `previousEventHash` (SHA-256 hex) | MUST (if audit supported) | Optional | Auditability §2 | , | `test/ink-receipt-generation.test.ts` |
| A2 | Audit events: signed with `agentSignature` (Ed25519) | MUST | Optional | Auditability §2 | , | `test/ink-receipt-generation.test.ts` |
| A3 | Monotonic `sequence` per agent | MUST | Optional | Auditability §2 | , | `test/ink-receipt-generation.test.ts` |
| A4 | Audit query: `network.tulpa.audit_query` with INK auth | MUST | Optional | Auditability §3 | , | `test/ink-receipt-generation.test.ts` |
| A5 | Audit response: filtered to sender/recipient only | MUST | Optional | Auditability §3 |, | `test/ink-receipt-generation.test.ts` |
| A6 | Fork detection: same sequence + different hash = tampered | MUST | Optional | Auditability §2 | , | `test/security-round25.test.ts` |
| A7 | `signingKeyId` recorded as top-level `InkAuditEvent.signingKeyId` field | SHOULD | Required | Key Rotation Phase 3 | , | `test/ink-key-rotation.test.ts` |
| A8 | Response slices have strictly +1 sequence continuity (no gaps within a slice) | MUST | Required | Auditability §3 | , | `test/security-round25.test.ts` |
| A9 | `previousEventHash` MUST equal SHA-256(JCS(prior event without `agentSignature`)) for every event after the first in a slice | MUST | Required | Auditability §2 | , | `test/security-round25.test.ts` |
| A10 | Consumers run both `verifyAuditResponseSignature` and `verifyAuditEventChain` before treating events as authoritative | MUST | Required | Auditability §3 |, | `test/security-round25.test.ts` |

---

## 9. Third-Party Witness

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| W1 | Submit: `POST /ink/v1/audit/submit` with INK-Ed25519 + embedded event signature | MUST (if witness supported) | Optional | Auditability §7 | , | `test/security-fixes.test.ts`, `witness/witness/test/endpoints.test.ts (witness repo)` |
| W2 | Query: `POST /ink/v1/audit/query` with INK-Ed25519 | MUST | Optional | Auditability §7 | , | `test/security-fixes.test.ts`, `witness/witness/test/endpoints.test.ts (witness repo)` |
| W3 | Access control: requester must be event agent or counterparty | MUST | Optional | Auditability §7 | , | `witness/witness/test/endpoints.test.ts (witness repo)` |
| W4 | Merkle tree: RFC 6962-style binary tree | MUST | Optional | Auditability §7 | `merkle-inclusion`, `merkle-consistency` | `witness/witness/test/merkle.test.ts (witness repo)` |
| W5 | Inclusion receipt: signed by witness service | MUST | Optional | Auditability §7 | `inclusion-receipt` | `witness/witness/test/endpoints.test.ts (witness repo)` |
| W6 | Checkpoint body is the C2SP tlog-checkpoint format; the witness serves it at `GET /ink/v1/checkpoint` (the endpoint itself is covered by the witness repo tests, the format by the vectors) | SHOULD | Optional | Auditability §7 | `merkle-checkpoint` | `witness/witness/test/endpoints.test.ts (witness repo)` |
| W7 | Transport auth on submit: dual signature (transport + event) | MUST | Optional | Auditability §7 | , | `witness/witness/test/endpoints.test.ts (witness repo)` |
| W8 | Submit includes `signingKeyId` in transport auth | SHOULD | Required | Key Rotation Phase 3 |, | `test/ink-key-rotation.test.ts` |
| W9 | Query response is the signed `network.tulpa.audit_query_response` envelope binding `serviceDid`, `messageId`, `requester`, `events`, `proofs`, `treeSize`, `rootHash`, `timestamp` | MUST | Optional | Auditability §7.3 | `audit-query-response` | `test/audit-query-response.test.ts`, `test/verify-audit-query-response.test.ts` |
| W10 | Per-event Merkle proof rule: leaf = `SHA-256(0x00 \|\| JCS(event-without-agentSignature))` (RFC 6962) | MUST | Optional | `ink-merkle-leaf.md` | `merkle-leaf` | `test/merkle-leaf-hash.test.ts` |
| W11 | Per-event scope: `event.messageId == envelope.messageId` AND `envelope.requester ∈ {event.agentId, event.counterpartyId}` | MUST | Optional | Auditability §7.3, §7.4 | `audit-query-response` | `test/verify-audit-query-response.test.ts` |
| W12 | Deterministic result-set ordering so signed bytes are reproducible | MUST | Optional | Auditability §7.3 |, | `witness/witness/test/security-round12.test.ts (witness repo)` |
| W13 | Fail-closed on truncation: refuse to sign a partial result; return unsigned 413 | MUST | Optional | Auditability §7.3 |, | `witness/witness/test/security-round12.test.ts (witness repo)` |
| W14 | Fail-closed on storage integrity (event_hash mismatch, missing Merkle node, column-vs-event_json drift): HTTP 500, no signed response | MUST | Optional | Auditability §7.3 |, | `witness/witness/test/security-round12.test.ts (witness repo)` |
| W15 | Empty-log response: `treeSize == 0` MUST have empty `events`, empty `proofs` and canonical empty-tree `rootHash` | MUST | Optional | Auditability §7.3 | `audit-query-response` | `test/verify-audit-query-response.test.ts` |
| W16 | Every returned event MUST include `agentSignature`; verifiers MUST verify it against the agent's published keys (witness Merkle validity does not prove agent provenance) | MUST | Optional | Auditability §7.3, §7.5 | `audit-query-response` | `test/verify-audit-query-response.test.ts` |

---

## 10. Key Rotation

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| K1 | `agentId` stable across key rotation | MUST | Required | Key Rotation §4 |, | `test/ink-key-rotation-e2e.test.ts` |
| K2 | Agent Card key-set: `keys.signing[]` with `keyId`, `algorithm`, `publicKeyMultibase`, `status`, `validFrom` | MUST | Required | Key Rotation §5 | `agent-card` | `test/ink-key-rotation.test.ts` |
| K3 | Key statuses: `active`, `retired`, `revoked` | MUST | Required | Key Rotation §5.3 | `key-rotation` | `test/ink-key-rotation.test.ts` |
| K4 | Verification order: hinted key → active → retired → skip revoked | MUST | Required | Key Rotation §6.4 | `key-rotation` | `test/ink-key-rotation.test.ts` |
| K5 | Retired keys valid for historical verification | MUST | Required | Key Rotation §6.2 | `key-rotation` | `test/ink-key-rotation.test.ts` |
| K6 | Revoked keys rejected for signatures after `revokedAt` | MUST | Required | Key Rotation §6.3 | `key-rotation` | `test/ink-key-rotation.test.ts` |
| K7 | Cache refresh on verification miss (max 1 retry) | SHOULD | Required | Key Rotation §9.2 | , | `test/ink-key-rotation-e2e.test.ts` |
| K8 | `keyId` emitted on outbound messages (auth header + envelope) | SHOULD | Required | Key Rotation §13 | , | `test/ink-auth-header.test.ts` |
| K9 | `keyId` in auth header takes precedence over body `signingKeyId` | SHOULD | Required | Key Rotation §13 | , | `test/ink-key-rotation.test.ts` |
| K10 | Historical keys retained minimum 90 days | SHOULD | Required | Key Rotation §11.2 |, |, |
| K11 | `keySetVersion` monotonically incremented on rotation/revocation | MUST | Required | Key Rotation §5 |, | `test/ink-key-rotation-e2e.test.ts` |
| K12 | Rotation audit events: `key.rotated`, `key.revoked` | SHOULD | Required | Audit Bridge | , | `test/ink-key-rotation.test.ts` |
| K13 | Retired-key verification result includes `keyStatus` | SHOULD | Required | Multi-Key Verify |, | `test/ink-key-rotation.test.ts` |

---

## 11. Authorization Chains

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| AC1 | `provenance` field on message envelope | MAY | Extension | Auth Chain §1 |, | `test/security-fixes.test.ts` |
| AC2 | Delegation token: signed scope + expiry | MAY | Extension | Auth Chain §2 |, | `test/security-fixes.test.ts` |
| AC3 | Multi-hop chains: ordered hops with permission attenuation | MAY | Extension | Auth Chain §3 |, |, |
| AC4 | `allowedTransports` constraint on delegation hops | SHOULD | Required | Containment §7 |, | `test/ink-transport-auth.test.ts` |
| AC5 | Transport attenuation: child hops subset of parent transports | MUST | Required | Containment §7 |, | `test/ink-transport-auth.test.ts` |
| AC6 | Omitted `allowedTransports` defaults to `["ink_http"]` (v0.3+ tokens) | MUST | Required | Containment §7 |, | `test/ink-transport-auth.test.ts` |
| AC7 | Legacy tokens: version-gated migration with permissive default | MUST | Required | Containment §7 |, | `test/ink-transport-auth.test.ts` |

---

## 12. Error Semantics

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| ER1 | `missing_authorization`, no auth header | MUST | Required | Protocol §3.3 | `authorization-header` | `test/ink-handshake-schemas.test.ts` |
| ER2 | `invalid_auth_scheme`, wrong auth scheme | MUST | Required | Protocol §3.3 | `authorization-header` | `test/security-fixes.test.ts` |
| ER3 | `invalid_signature`, signature does not verify | MUST | Required | Protocol §3.3 | `signature-base` | `test/security-fixes.test.ts` |
| ER4 | `timestamp_expired`, older than 5 minutes | MUST | Required | Protocol §3.5 | `replay-freshness` | `test/security-fixes.test.ts` |
| ER5 | `timestamp_too_far_future`, more than 30s ahead | MUST | Required | Protocol §3.5 | `replay-freshness` | `test/security-fixes.test.ts` |
| ER6a | `nonce_handling_required`, `verifyInkAuth` invoked without a `nonceStore` (fail-closed default) | MUST | Required | Protocol §3.5 | , | `test/security-round25.test.ts` |
| ER6b | `missing_nonce`, body.nonce missing or out of `[16,256]` charset bounds when `nonceStore` is supplied | MUST | Required | Protocol §3.5 | , | `test/security-round25.test.ts` |
| ER6c | `nonce_replay`, `nonceStore.has(nonce)` returned true after successful signature verify | MUST | Required | Protocol §3.5 | , | `test/security-round25.test.ts` |
| ER6d | `nonce_store_error`, `nonceStore.has` or `.add` threw (fail-closed) | MUST | Required | Protocol §3.5 |, | `test/security-round25.test.ts` |
| ER6e | `duplicate_nonce`, returned by the standalone `checkReplay` helper when a nonce is in `previouslySeenNonces` | MUST | Required | Protocol §3.5 | `replay-freshness` | `test/security-fixes.test.ts` |
| ER7 | `unsupported_intent`, unknown intent type | MUST | Required | Protocol §3.1 |, | `test/ink-handshake-schemas.test.ts`, `examples/reference-receiver/test/inbound.test.ts` |
| ER8 | `encryption_required`, plaintext where encrypted required, ahead of the intent allowlist | MUST | Required | Protocol §3.4 |, | `test/encryption-policy.test.ts`, `examples/reference-receiver/test/inbound.test.ts` |
| ER9 | `rate_limited`, request rate exceeded. The library registers the code as a rejection reason; the limiter itself is receiver policy and has no library test | SHOULD | Required | Protocol §4 |, | receiver-side, none in the library |
| ER10 | `handshake_budget_exhausted`, per-correlation budget hit | SHOULD | Required | Containment §5 |, | `test/ink-handshake-budget.test.ts` |
| ER11 | `sender_rate_limited`, per-sender rate limit hit | SHOULD | Required | Containment §5 |, | `test/ink-handshake-budget.test.ts` |
| ER12 | `counterparty_cooldown`, recipient broadly rate-limiting | SHOULD | Required | Containment §5 |, | `test/ink-handshake-budget.test.ts` |
| ER13 | `delegation_budget_exhausted`, delegation issuance limit hit | SHOULD | Required | Containment §4 |, | `test/ink-transport-auth.test.ts` |
| ER14 | `transport_scope_violation`, invocation transport not in token | MUST | Required | Containment §7 |, | `test/ink-transport-auth.test.ts` |

---

## 13. Containment (Phase 1)

| # | Requirement | Level | Status | Spec | Vectors | Tests |
|---|-----------|-------|--------|------|---------|-------|
| CT1 | Agent Card `visibility` field: `public`, `network_only`, `capability_gated`, `private` | SHOULD | Required | Containment §6 |, | `test/ink-discovery-gating.test.ts` |
| CT2 | Unauthenticated GET returns redacted card for non-public visibility | MUST | Required | Containment §6 |, | `test/ink-discovery-gating.test.ts` |
| CT3 | Redacted card includes only: `agentId`, `displayName`, `supportsInk`, `discoveryMode` | MUST | Required | Containment §6 |, | `test/ink-discovery-gating.test.ts` |
| CT4 | `POST /ink/v1/{agentId}/agent-card-query` with INK-Ed25519 auth | MUST (if `capability_gated`) | Required | Containment §6 |, | `test/ink-discovery-gating.test.ts` |
| CT5 | Authenticated query denied for unknown requester | MUST | Required | Containment §6 |, | `test/ink-discovery-gating.test.ts` |
| CT6 | `private` visibility returns 404 on unauthenticated GET | MUST | Required | Containment §6 |, | `test/ink-discovery-gating.test.ts` |
| CT7 | Per-correlation handshake budget: max 3 challenges | SHOULD | Required | Containment §5 |, | `test/ink-handshake-budget.test.ts` |
| CT8 | Rejection and resolution are terminal per correlationId | MUST | Required | Containment §5 |, | `test/ink-handshake-budget.test.ts` |
| CT9 | Total state transitions capped at 5 per correlationId | SHOULD | Required | Containment §5 |, | `test/ink-handshake-budget.test.ts` |
| CT10 | Handshake TTL bounded by intent `expiresAt` or 24h | SHOULD | Required | Containment §5 |, | `test/ink-handshake-budget.test.ts` |
| CT11 | Per-sender intent rate limit: 10/minute | SHOULD | Required | Containment §5 |, | `test/ink-handshake-budget.test.ts` |
| CT12 | First budget violation returns typed rejection with backoff hint | MUST | Required | Containment §5 |, | `test/ink-handshake-budget.test.ts` |
| CT13 | Subsequent violations are silent drops (no amplification) | MUST | Required | Containment §5 |, | `test/ink-handshake-budget.test.ts` |
| CT14 | `backoffHint` optional on rejection: `retryAfterSeconds`, `cooldownUntil`, `backoffClass` | MAY | Required | Containment §5 |, | `test/ink-handshake-budget.test.ts` |
| CT15 | Agent Card `governance` block: `maxAcceptedDelegationDepth`, `supportedTransports`, `handshakeBudget` | MAY | Required | Containment §9 |, |, |
| CT16 | Containment audit events: `transport_scope_violation`, `handshake_rate_limited`, `handshake_budget_exhausted`, `discovery_query_*` | SHOULD | Required | Containment §9 |, | `test/ink-transport-auth.test.ts` |

---

## 14. Interoperability Profiles

> The normative cross-implementation profile freeze keyed to the `conformance/v1` corpus is [ink-conformance-profile.md](ink-conformance-profile.md). Under that freeze the signed handshake messages (section 6) are containment-gated and encryption (section 4) is capability-gated, not part of the base sender or receiver floor. The role groupings below are the Tulpa implementation's view; where they list handshake or encryption as a minimum, treat those as capability-gated per the freeze.

An implementation MAY conform to one or more of these profiles:

### 14.1 Sender-Only

Minimum requirements: S1–S8, R1–R4, M1–M4, D1–D3, ER1–ER6

Can send INK messages and verify responses but does not accept inbound messages.

### 14.2 Receiver-Only

Minimum requirements: S1–S8, R1–R5, M1–M4, D1–D3, ER1–ER9. The signed handshake messages (H1–H6) and encryption (E1–E6) are capability-gated, not part of the base receiver floor.

Can receive and verify INK messages but does not initiate.

### 14.3 Full Peer

All required items from sections 1–3, 5, 10–12, plus encryption (section 4) and handshake (section 6) when the matching capability is advertised.

### 14.4 Audit-Capable Peer

Full peer requirements plus sections 7–8.

### 14.5 Witness Service

Sections 2 (S1–S8) and 9 (W1–W8). Does not need to implement message envelope or handshake.

---

### 14.6 Containment-Hardened Peer

Full peer requirements plus section 13 (CT1–CT16). Adds transport scoping, discovery gating and handshake budgets.

---

## 16. Conformance Vector Coverage

The Vectors column of every row above names the `conformance/v1` categories whose vectors pin that row, by manifest id. A row with no category is pinned by tests only. `npm run check:facts` rejects a category id that is not in `conformance/v1/manifest.json`, and it regenerates this matrix, so the column and the matrix cannot drift from the corpus.

<!-- BEGIN GENERATED checklist-vector-matrix -->
*Generated from `conformance/v1/manifest.json` and the Vectors column of the rows above. Regenerate with `npm run check:facts -- --write`.*

| Category | Profile | Cases | Rows citing it |
|----------|---------|------:|----------------|
| `agent-authorization` | `authorization` | 68 | none |
| `agent-card` | `base` | 53 | D2, D3, D4, D6, K2 |
| `agent-card-evidence` | `evidence` | 19 | none |
| `agent-card-fetch` | `base` | 34 | none |
| `agent-card-signature` | `base` | 50 | none |
| `agent-card-signature-phase-c` | `staged` | 10 | none |
| `attestation` | `evidence` | 34 | none |
| `audit-query-response` | `audit` | 27 | W9, W11, W15, W16 |
| `authorization-chain` | `delegation` | 56 | none |
| `authorization-grant` | `authorization` | 55 | none |
| `authorization-header` | `base` | 23 | S3, S4, S5, ER1, ER2 |
| `connection-payload` | `base` | 22 | none |
| `discovery-query-envelope` | `discovery` | 33 | none |
| `evidence-refusal` | `evidence` | 13 | none |
| `first-contact-transcript` | `base` | 28 | none |
| `handshake-message` | `containment` | 32 | H1, H2, H3, H4 |
| `inclusion-receipt` | `audit` | 39 | W5 |
| `jcs-number` | `base` | 16 | S6 |
| `jcs-string-safety` | `base` | 10 | S6 |
| `key-rotation` | `base` | 32 | S4, K3, K4, K5, K6 |
| `merkle-checkpoint` | `witness` | 21 | W6 |
| `merkle-consistency` | `witness` | 19 | W4 |
| `merkle-inclusion` | `witness` | 14 | W4 |
| `merkle-leaf` | `audit` | 15 | W10 |
| `payload-encryption` | `encryption` | 22 | E1, E2, E3, E4, E6 |
| `principal-normalization` | `base` | 10 | S9 |
| `private-hostname` | `base` | 58 | none |
| `replay-freshness` | `base` | 10 | R1, R2, R3, R4, ER4, ER5, ER6e |
| `signature-base` | `base` | 15 | S1, S2, S7, S8, ER3 |
| `signed-body-member-name` | `base` | 18 | none |
| `signed-body-utf8` | `base` | 21 | none |
| `timestamp-validity` | `base` | 17 | none |

45 of 124 requirement rows cite at least one category; 16 of 32 categories are cited by at least one row; the corpus holds 894 cases.
<!-- END GENERATED checklist-vector-matrix -->

---

## 17. Implementation Status Summary

| Area | Required | Implemented | Tested |
|------|----------|------------|--------|
| Discovery | 8 | 8 | 8 |
| Transport Signing | 9 | 9 | 9 |
| Replay Protection | 5 | 5 | 5 |
| Encryption | 6 | 6 | 6 |
| Message Envelope | 4 | 4 | 4 |
| Handshake | 6 | 6 | 6 |
| Receipts | 6 | 6 | 6 |
| Bilateral Audit | 7 | 7 | 7 |
| Witness | 8 | 8 | 8 |
| Key Rotation | 13 | 13 | 12 |
| Auth Chains | 7 | 6 | 6 |
| Error Semantics | 14 | 14 | 14 |
| Containment | 16 | 16 | 15 |
| **Total** | **109** | **108** | **106** |

**Notes:**
- AC3 (multi-hop chains) is designed but not fully implemented, extension status
- K10 (90-day retention) is enforced by design (keys never deleted) but not explicitly tested with time simulation
- CT15 (governance block) is schema-defined but not yet tested with governance-specific assertions

[^ck]: Machine-checked value, recomputed from the repository by `npm run check:facts`. Do not hand-edit it to match a document; change the source of truth and rerun the check.
