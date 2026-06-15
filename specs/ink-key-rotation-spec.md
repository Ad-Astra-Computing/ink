# INK Key Rotation Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-05-24

## Purpose

This specification defines how INK agents rotate signing and encryption keys without breaking:
- active message exchange
- historical verification
- witness verification
- counterparty discovery

Core principle:

**An INK agent's identity must remain stable across key changes, while its active and historical keys remain verifiable.**

---

## 1. Problem

Today Tulpa implementations derive `agentId` from the signing public key.

That creates a protocol problem:
- rotating the signing key changes the apparent agent identity
- counterparties cannot safely distinguish key rotation from impersonation
- old receipts, audit events, and witness records still need verification

Therefore key rotation MUST be handled as a protocol concern, not a local storage concern.

---

## 2. Goals

INK key rotation SHALL:
- preserve a stable logical agent identity
- allow new transport/auth signatures to verify under a new key
- preserve verification of historical artifacts signed by prior keys
- let counterparties discover key changes safely
- support overlap, retirement, and emergency revocation

INK key rotation SHALL NOT:
- require breaking message history
- require rewriting old receipts or audit events
- rely on out-of-band manual key distribution

---

## 3. Non-Goals

This spec does not define:
- human DID key rotation for ATP itself
- extension delegation token rotation
- witness service key rotation beyond discovery advertisement

Those may reuse the same patterns later, but are not required here.

---

## 4. Identity Model

## 4.1 Stable Agent Identity

INK v1 SHALL treat `agentId` as a stable logical identifier, not as a direct encoding of the current signing key.

`agentId` MUST remain stable across key rotation.

## 4.2 Key Material

Each agent SHALL advertise one or more keys by role:
- signing keys
- encryption keys

Each key SHALL have:
- a stable `keyId`
- an algorithm
- a public key
- a lifecycle status
- validity timestamps

---

## 5. Agent Card Additions

## 5.1 Key Set Advertisement

The Agent Card SHALL advertise key sets explicitly.

Recommended shape:

```json
{
  "agentId": "did:plc:alice#agent/tulpa-main",
  "protocol": "ink/0.1",
  "keys": {
    "signing": [
      {
        "keyId": "sig-2026-03",
        "algorithm": "Ed25519",
        "publicKeyMultibase": "z...",
        "status": "active",
        "validFrom": "2026-03-25T00:00:00Z"
      },
      {
        "keyId": "sig-2025-11",
        "algorithm": "Ed25519",
        "publicKeyMultibase": "z...",
        "status": "retired",
        "validFrom": "2025-11-01T00:00:00Z",
        "validUntil": "2026-04-01T00:00:00Z"
      }
    ],
    "encryption": [
      {
        "keyId": "enc-2026-03",
        "algorithm": "X25519",
        "publicKeyMultibase": "z...",
        "status": "active",
        "validFrom": "2026-03-25T00:00:00Z"
      }
    ]
  },
  "currentSigningKeyId": "sig-2026-03",
  "currentEncryptionKeyId": "enc-2026-03",
  "keySetVersion": 7,
  "updatedAt": "2026-03-25T00:00:00Z"
}
```

## 5.2 Required Fields

Each key entry MUST include:
- `keyId`
- `algorithm`
- `publicKeyMultibase`
- `status`
- `validFrom`

Optional but recommended:
- `validUntil`
- `revokedAt`
- `revokeReason`

## 5.3 Status Values

Allowed statuses:
- `active`
- `retired`
- `revoked`

Meaning:
- `active`: valid for new outbound messages and inbound verification
- `retired`: not used for new outbound messages, but still valid for historical verification
- `revoked`: no longer trusted for new signatures after `revokedAt`

---

## 6. Signing Verification Rules

## 6.1 Current Messages

For current inbound messages, receivers MUST:
- resolve the sender's Agent Card
- attempt verification against active signing keys first

## 6.2 Historical Verification

For receipts, audit events, witness submissions, and previously stored messages, receivers MUST:
- permit verification against retired keys if the artifact timestamp falls within that key's validity window

## 6.3 Revoked Keys

Receivers MUST NOT verify signatures with a revoked key, even for artifacts whose timestamp predates `revokedAt`. Revocation is a trust statement: the key is compromised or must not be trusted, and pre-revocation artifacts cannot be distinguished from forgeries made after compromise.

This is the normative rule, see [`docs/key-rotation-rule.md`](../docs/key-rotation-rule.md). Retired is the correct status for keys that should remain verifiable for historical traffic.

## 6.4 Verification Order

Recommended verification order:
1. current active key by `currentSigningKeyId`
2. other active signing keys
3. retired signing keys
4. reject if no valid candidate verifies

## 6.5 Window Field Presence

The window fields `validFrom`, `validUntil`, and `revokedAt` are optional, but
their **presence is semantic**: a field that appears in a key entry at all
constrains the key, even when its value is empty, `null`, or not a string. This
removes any ambiguity between "no constraint" and "a constraint the producer
failed to express", which an attacker could otherwise exploit to make a revoked
or out-of-window key look usable.

For each candidate key, a receiver MUST apply:

- **Absent** field: no constraint from that field.
- **`revokedAt` present** with any value: the key is unusable.
- **`validFrom` / `validUntil` present**: the value MUST be a strict RFC 3339
  timestamp (see [INK Timestamp Grammar](./ink-timestamp-grammar.md)). A present
  value that is empty, `null`, non-string, or not a strict timestamp makes the
  key unusable.

A malformed window invalidates **only that candidate key**: verification skips
it and continues with the remaining keys, so one bad historical entry cannot
prevent a usable key from verifying.

---

## 7. Encryption Verification Rules

## 7.1 New Messages

Senders MUST encrypt to the recipient's current active encryption key.

## 7.2 Overlap Window

During rotation overlap, receivers SHOULD support decryption with:
- current active encryption key
- immediately previous retired encryption key

This allows delivery continuity during cache lag.

## 7.3 Retirement

An encryption key SHOULD NOT move to `revoked` until counterparties have had a documented overlap period to refresh the Agent Card.

Recommended minimum overlap:
- 7 days for planned rotation

Emergency revocation MAY be immediate.

---

## 8. Rotation Flow

## 8.1 Planned Rotation

Recommended planned rotation flow:

1. Generate new keypair(s)
2. Publish updated Agent Card with:
   - new key(s) marked `active`
   - previous current key(s) marked `retired`
   - incremented `keySetVersion`
3. Start signing new outbound messages with the new signing key
4. Start encrypting to the new encryption key
5. Accept verification/decryption with prior keys during overlap
6. After overlap, leave prior signing keys `retired` for historical verification
7. Revoke old encryption key if necessary

## 8.2 Emergency Rotation

For suspected compromise:

1. Publish updated Agent Card immediately
2. Mark compromised key `revoked`
3. Increment `keySetVersion`
4. Begin signing with new key immediately
5. Counterparties MUST refresh on verification miss or newer card version detection

Emergency revocation MAY break some in-flight encrypted delivery and this is acceptable.

---

## 9. Discovery and Cache Invalidation

## 9.1 Canonical Discovery Surface

The Agent Card SHALL be the canonical discovery surface for current and historical INK keys.

If ATP-linked identity records or DID-linked materials are also used, they MUST be consistent with the Agent Card.

## 9.2 Cache Behavior

Implementations SHOULD cache discovered key sets, but MUST refresh when:
- signature verification fails for all cached active keys
- a message references an unknown `keyId`
- a newer `keySetVersion` is observed
- encryption to the current key fails due to key mismatch

## 9.3 Refresh Policy

Recommended cache TTL:
- 1 hour default

Recommended forced refresh triggers:
- verification miss
- explicit rotation signal
- card version monotonic increase

---

## 10. Optional Rotation Signal

INK MAY define an advisory message type:
- `network.tulpa.key_rotation`

Purpose:
- accelerate counterparty refresh
- reduce verification misses after planned rotation

This message MUST NOT be the sole source of truth.

The Agent Card remains canonical.

Recommended fields:
- `from`
- `to`
- `newKeySetVersion`
- `rotatedSigningKeyIds`
- `rotatedEncryptionKeyIds`
- `timestamp`
- `nonce`

Receivers SHOULD treat it as a hint to refresh discovery state.

---

## 11. Historical Verification

## 11.1 Requirement

INK implementations MUST preserve the ability to verify:
- stored messages
- receipts
- bilateral audit events
- witness submissions
- witness inclusion references

## 11.2 Historical Key Retention

Historical keys used for verification SHOULD remain available for at least:
- 90 days minimum

Recommended:
- retain indefinitely while marking status appropriately

If a system cannot retain historical keys indefinitely in the live Agent Card, it MUST provide a documented verified history surface.

---

## 12. Witness Interaction

## 12.1 Submit Verification

Witness services MUST be able to verify audit submissions against:
- current active keys
- retired keys when validating older events or delayed submissions

## 12.2 Query Verification

Signed witness query verification MUST use the same rotation-aware signing-key lookup rules as other INK transport verification.

## 12.3 Retention

Witness implementations SHOULD cache or resolve historical keys in a way that preserves later verification of valid older events.

---

## 13. Key IDs

## 13.1 Requirement

New INK signed messages SHOULD include the signing `keyId`.

This avoids trial-verifying across many candidate keys.

Recommended location:
- transport metadata or signed body field, depending on final wire design

If omitted, verifiers MAY try all candidate keys.

## 13.2 Format

`keyId` MAY be any stable opaque string.

Recommended:
- `sig-YYYY-MM`
- `enc-YYYY-MM`
- or ULID-based identifiers

It MUST be unique within the agent's key set.

---

## 14. Data Model

Recommended local store:
- `agent_keys`

Recommended fields:
- `agent_id`
- `key_id`
- `role`
- `algorithm`
- `public_key_multibase`
- `private_key_encrypted`
- `status`
- `valid_from`
- `valid_until`
- `revoked_at`
- `created_at`
- `updated_at`

Recommended identity metadata:
- `current_signing_key_id`
- `current_encryption_key_id`
- `key_set_version`

---

## 15. API / Runtime Changes

Recommended runtime changes:
- key lookup by `agentId + role + status`
- verification helper that accepts candidate historical keys
- Agent Card generation from key set, not single key fields
- maintenance support for overlap transitions
- rotation admin/owner API

Recommended owner/admin APIs:
- `POST /api/tulpa/keys/rotate`
- `GET /api/tulpa/keys`
- `POST /api/tulpa/keys/:keyId/revoke`

These APIs are product/runtime concerns, not protocol requirements, but are strongly recommended.

---

## 16. Compatibility and Migration

## 16.1 Backward Compatibility

During migration from single-key agents:
- Agent Cards MAY advertise both legacy single-key fields and the new key-set structure
- receivers SHOULD support both during transition

## 16.2 Migration Path

1. add key-set fields to Agent Card
2. support rotation-aware verification in receivers
3. emit `keyId` on outbound messages
4. migrate storage from single current key to role-based key set
5. remove assumptions that `agentId` encodes current signing key

## 16.3 Legacy Agents

Receivers MUST continue to support legacy single-key agents during the migration window.

---

## 17. Security Considerations

## 17.1 Compromise

If a signing key is compromised:
- rotation MUST support immediate revocation
- counterparties MUST refresh discovery data on verification miss

## 17.2 Replay

Key rotation does not replace nonce/timestamp replay protections.

Those protections remain mandatory.

## 17.3 Historical Trust

Historical verification does not imply ongoing trust.

Retired-key acceptance MUST be scoped to historical artifact verification, not new live messages.

## 17.4 Drift

All key-role logic MUST remain consistent across:
- the primary INK runtime
- the witness/auditability runtime
- test vectors
- lexicons
- docs

---

## 18. Test Vectors

This spec requires new vector families for:
- active-key verification
- retired-key verification
- revoked-key rejection
- key-set version refresh behavior
- encrypted message decryption during overlap window

Minimum required cases:
- message signed by current key verifies
- message signed by retired key verifies as historical
- message signed by revoked key after `revokedAt` fails
- witness submit/query verifies against rotated key set
- stale cached key set refreshes successfully

---

## 19. Rollout Plan

## Phase 1 ✓ (implemented 2026-03-25)
- ✓ `KeyEntry`, `KeyStatus`, `CandidateKey` types + Zod schemas (`src/models/key-entry.ts`)
- ✓ `AgentCardSchema` extended with optional `keys`, `currentSigningKeyId`, `currentEncryptionKeyId`, `keySetVersion`
- ✓ `agent_keys` SQLite table with lifecycle status, `identity` table gains key-set tracking columns
- ✓ `KeyStore` equivalent for agent_keys CRUD (implementer-specific path)
- ✓ `verifyInkSignatureWithKeys()` multi-key verification helper (`src/crypto/multi-key-verify.ts`)
- ✓ `verifyInkAuth` gains `resolveKeySet` parameter for multi-key transport auth, and `nonceStore: NonceStore | "deferred"` (required, fail-closed) for single-use nonce enforcement
- ✓ `PipelineContext.resolveKeySet` for multi-key message signature verification
- ✓ Receipt verification uses candidate key lists with active → retired ordering
- ✓ `extractCandidateKeys()` for Agent Card key extraction (`src/discovery/agent-card.ts`)
- ✓ `getAgentCard()` builds `keys` block from `KeyStore`
- ✓ Auto-migration: `seedFromIdentity()` on first wake-up
- ✓ `initialize()` inserts key entries alongside identity row
- ✓ Witness `verifyInkTransportAuth` signature accepts `resolveKeySet` (not yet wired)
- ✓ Test coverage: key-set schema, KeyStore CRUD, multi-key verification, end-to-end rotation vectors (see `test/ink-key-rotation.test.ts`)

## Phase 2 ✓ (implemented 2026-03-25)
- ✓ Key rotation APIs: `POST /tulpa/keys/rotate`, `GET /tulpa/keys`, `POST /tulpa/keys/:keyId/revoke`
- ✓ `keyId` emitted on outbound INK messages (auth header `keyId=` param + envelope `signingKeyId`)
- ✓ `hintKeyId` verification: try hinted key first, fallback to active → retired scan
- ✓ Agent Card cache with SQLite-backed TTL (1 hour default) and refresh-on-miss
- ✓ Integration tests for full rotated-message paths (6 e2e tests)

## Phase 3 ✓ (implemented 2026-03-25)
- ✓ Witness integration: `signingKeyId` passed to transport auth on witness submit
- ✓ `signingKeyId` recorded as a top-level field on `InkAuditEventSchema` for historical verification
- ✓ keyId semantics: auth header takes precedence, unknown keyId falls through, revoked keyId rejected
- ✓ Rotation observability: `signature.verified_retired`, `signature.revoked_rejected`, `key.rotated`, `key.revoked` audit event types
- ✓ `keyStatus` in `MultiKeyVerifyResult` for retired-key observability
- ✓ Audit bridge mappings: `key_rotated` → `key.rotated`, `key_revoked` → `key.revoked`
- ✓ Interop test vectors: 8 scenarios in `test-vectors/key-rotation.json`
- ✓ Phase 3 test cases in `test/ink-key-rotation.test.ts` (covers historical verification, revoked rejection, audit-event types)

---

## 20. Open Questions

- Should `agentId` become DID-fragment-based, handle-based, or another stable logical identifier?
- Should historical keys live only in Agent Card, or also in ATP-linked records for verifiable history?
- Should `keyId` live in the signed JSON body or an authenticated transport header?
- What exact overlap duration should be mandatory for planned encryption-key rotation?
- Should retired signing keys remain indefinitely discoverable or move to a separate verified history surface?

---

## 21. Recommendation

The recommended v1 direction is:
- stable logical `agentId`
- explicit role-based key sets in the Agent Card
- current + retired + revoked key lifecycle states
- rotation-aware verification
- historical verification continuity

This is the main remaining protocol design required to make INK feel finished.
