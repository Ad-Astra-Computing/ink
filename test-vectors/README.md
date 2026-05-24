# INK v0.1 Test Vectors

Reference test vectors for INK v0.1 signing, encryption, replay protection, handshake flows, witness transport auth and key rotation. These vectors use fixed key material and deterministic inputs so that two independent implementations can verify byte-for-byte correctness.

## Files

| File | Covers | Vector count |
|------|--------|-------------|
| `keys.json` | Fixed Ed25519 and X25519 key pairs for Alice and Bob (hex-encoded) | — |
| `signing.json` | Signature generation and verification (§3.3) | 3 |
| `encryption.json` | ECIES encryption/decryption (§3.4) | 2 |
| `jcs.json` | JCS canonicalization (RFC 8785) | 4 |
| `replay.json` | Replay protection acceptance/rejection (§3.5) | 6 |
| `receipts-and-audit.json` | Receipt signatures, audit query signatures, hash-chained audit events and fork detection (Auditability §1–§3) | 4 |
| `handshake.json` | Challenge (Stage 2a), rejection (Stage 2b) and resolution (Stage 3) — valid signatures, path/recipient/body binding failures, replay protection | 22 |
| `witness.json` | Audit submit and query with INK transport auth, plus cross-service interop cases | 15 |
| `key-rotation.json` | Auth header keyId format, rotated-key verification, historical verification, revoked-key rejection, refresh-on-miss, keyId precedence, unknown keyId fallthrough, audit event signingKeyId tracking | 8 |

**Total: 64 deterministic vectors across 9 families**

## Vector categories

### Signing (`signing.json`)
Covers the INK Ed25519 signature base construction (`ink/0.1\nMETHOD\nPATH\nrecipientDid\nJCS(body)\ntimestamp`) and verification, including wrong-key and tampered-path negative cases.

### Handshake (`handshake.json`)
Each handshake message type (challenge, rejection, resolution) has:
- **Valid**: canonical body, signature base, signature — full round-trip
- **Invalid path**: same signature replayed against a different endpoint
- **Invalid recipient**: same body/signature but wrong recipient DID
- **Tampered body**: a field modified after signing
- **Expired timestamp**: >5 minutes old
- **Future timestamp**: >30 seconds ahead (challenge only)
- **Duplicate nonce**: nonce already in deduplication window

Resolution vectors include all four outcome variants: `accepted`, `declined`, `escalated_to_human`, `expired`.

### Witness (`witness.json`)
Covers the witness transport auth model (INK-Ed25519 on both submit and query):

**Submit** (`POST /ink/v1/audit/submit`):
- Transport signature over full body (which contains the signed audit event)
- Path binding, recipient binding, timestamp freshness, body tamper detection
- **Event signature vs transport signature separation**: transport auth valid but embedded event signature forged — witness must reject

**Query** (`POST /ink/v1/audit/query`):
- Signed POST body (not GET) — sender identity derived from verified auth, not caller input
- Path binding, body tamper detection, timestamp/nonce replay protection

**Interop cases**:
- Submit signature replayed against query path → fails (path binding)
- Query signature replayed against different witness DID → fails (recipient binding)
- Intent from main worker replayed as witness submit → fails (both path and recipient differ)

### Replay protection (`replay.json`)
Standalone timestamp freshness and nonce deduplication tests. The handshake and witness vectors also include replay cases inline.

## Usage

1. Load key material from `keys.json`
2. Run each test case: construct the expected output from the inputs and compare
3. All base64url values use no-padding encoding (RFC 4648 §5)
4. All hex values are lowercase

## Fixture shapes

### Signature vectors (handshake, witness submit/query)
```json
{
  "id": "challenge-valid",
  "input": {
    "method": "POST",
    "path": "/ink/v1/did:plc:bob456test/challenge",
    "recipientDid": "did:plc:bob456test",
    "body": { ... },
    "timestamp": "2026-03-25T12:00:00Z",
    "signerPrivateKeyHex": "..."
  },
  "expected": {
    "canonicalBody": "...",
    "signatureBase": "ink/0.1\nPOST\n/ink/v1/.../challenge\n...\n...\n...",
    "signatureBase64url": "...",
    "accepted": true
  }
}
```

### Negative signature vectors
```json
{
  "id": "challenge-invalid-path",
  "input": {
    "method": "POST",
    "path": "/ink/v1/did:plc:bob456test/rejection",
    "body": { ... },
    "originalSignatureBase64url": "..."
  },
  "expected": { "accepted": false, "reason": "..." }
}
```

### Replay vectors (inline in handshake/witness)
```json
{
  "id": "challenge-timestamp-expired",
  "input": {
    "messageTimestamp": "2026-03-25T11:50:00Z",
    "receiverClock": "2026-03-25T12:00:00Z",
    "nonce": "..."
  },
  "expected": { "accepted": false, "errorCode": "expired_message" }
}
```

### Key rotation (`key-rotation.json`)
Scenario-based vectors for key rotation behavior. Unlike other vector families, key rotation vectors use runtime-generated keys (not the fixed Alice/Bob keys) because they test lifecycle transitions. The companion test suite `test/ink-key-rotation-phase3.test.ts` exercises all 8 scenarios:

- **Auth header keyId format** — regex parsing of `INK-Ed25519 <sig> keyId=<keyId>` with and without keyId
- **Rotated-key verification** — new key signs, verifier with [old=retired, new=active] keyset accepts
- **Historical message verification** — messages signed before rotation still verify against retired key
- **Revoked-key rejection** — cryptographically valid signatures from revoked keys are rejected
- **Refresh-on-miss** — stale cache fails, refetch Agent Card, retry succeeds (max 1 retry)
- **keyId precedence** — auth header keyId takes precedence over body `signingKeyId`
- **Unknown keyId fallthrough** — unknown keyId hint skipped, normal iteration finds correct key
- **Audit event signingKeyId** — audit events record `signingKeyId` in data field for historical verification

## Key generation

The test keys were generated deterministically from fixed seeds. They are NOT suitable for production use. The seeds are included so implementations can verify key derivation if needed.
