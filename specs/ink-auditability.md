# INK Protocol-Level Auditability (draft extension)

**Status:** Draft
**Authors:** Ad Astra Computing
**Date:** 2026-03-19

## Problem

The current INK v0.1 model has strong internal audit capabilities (`AgentAuditStore` with 130+ event types, extension `AuditEntry` schema) but these are **application-layer**, they live inside each agent's host process and are not part of the wire protocol. This creates gaps:

1. **No delivery receipts**, the sender doesn't know if the recipient's agent received, queued, rejected or acted on the message. The HTTP 200 from the inbox endpoint only means "I got it."
2. **No cryptographic audit trail**, audit events are stored internally and could be modified. There's no tamper-evident log that both parties can reference.
3. **No cross-agent audit reconciliation**, if Alice says she sent a message and Bob says he never got it, there's no shared record to resolve the dispute.
4. **No standardized audit format**, each INK implementation would have to reverse-engineer tulpa's `AgentAuditStore` schema. The audit data isn't portable.

## Design

### 1. Message Receipts (Wire Protocol)

Receipts are a **new INK message type** (`network.tulpa.receipt`), not an intent type. INK v0.1 distinguishes message types (`network.tulpa.intent`, `network.tulpa.challenge`, `network.tulpa.resolution`, `network.tulpa.rejection`, `network.tulpa.encrypted`) from intent types (`scheduling`, `intro_request`, etc.) within `network.tulpa.intent` messages. Receipts are a distinct protocol-level concern and MUST NOT be shoehorned into the intent envelope.

```json
{
  "protocol": "ink/0.1",
  "type": "network.tulpa.receipt",
  "from": "did:plc:recipient",
  "to": "did:plc:sender",

  "messageId": "original-message-id",

  "disposition": "received | delivered | acted | rejected | expired",

  "dispositionAt": "2026-03-19T12:00:00Z",

  "note": "optional detail (rejection reason, action taken)",

  "messageHash": "<SHA-256 hash, see §1.1 for hash scope>",

  "nonce": "<base64url-encoded 128-bit nonce>",
  "timestamp": "2026-03-19T12:00:01Z"
}
```

**Disposition types:**

| Disposition | Meaning |
|-------------|---------|
| `received` | Envelope accepted, queued for processing |
| `delivered` | Message shown to owner or processed by rule |
| `acted` | Owner/agent took action (accepted, declined, etc.) |
| `rejected` | Message rejected by pipeline |
| `expired` | Message expired before processing |

#### 1.1 `messageHash` Scope

`messageHash` is always the SHA-256 of the **JCS-canonicalized plaintext message body**, regardless of transport encryption.

For **plaintext messages** (type `network.tulpa.intent`, `network.tulpa.challenge`, etc.):
- `messageHash` = SHA-256 of the JCS-canonicalized INK message body, excluding transport headers (the `Authorization` header carries the signature, it is not part of the JSON body).

For **encrypted messages** (type `network.tulpa.encrypted`):
- `messageHash` = SHA-256 of the **decrypted plaintext intent body**, not the outer `InkEncryptedPayload` envelope.
- Rationale: both sender and recipient possess the plaintext (sender before encryption, recipient after decryption). Hashing the plaintext binds the receipt to semantic content rather than transport encoding and avoids sensitivity to ciphertext non-determinism.

Implementations MUST use JCS canonicalization before hashing to ensure byte-level determinism.

**Receipt flow:**

```
Sender                              Recipient
  |-- POST /ink/v1/intent -------->|
  |<-- HTTP 200 { accepted } ------|
  |                                 | (processes message)
  |<-- POST /ink/v1/receipt -------|  (type: network.tulpa.receipt)
  |-- HTTP 200 ------------------->|
```

**Properties:**
- Receipts are full INK messages: signed per §3.3 (METHOD + PATH + recipientDid + JCS(body) + timestamp), with nonce and timestamp for replay protection per §3.5
- Receipts are delivered via `POST /ink/v1/receipt` (a new endpoint, separate from `/ink/v1/intent`)
- Receipts are **opt-in** per agent, advertised in the Agent Card capabilities
- Receipts for receipts are NOT sent (receiving a `network.tulpa.receipt` MUST NOT trigger a receipt response, loop prevention)
- The `from`/`to` fields are reversed relative to the original message (the recipient becomes the sender of the receipt)

**Agent Card capability:**

```typescript
capabilities: {
  receipts: {
    send: true,          // "I send receipts for messages I receive"
    dispositions: [      // which disposition types I report
      "received",
      "delivered",
      "acted",
      "rejected",
    ],
  }
}
```

### 2. Audit Event Envelope (Portable Format)

Define a standardized audit event format that any INK implementation can produce and consume.

```typescript
InkAuditEventSchema = z.object({
  // Event identity
  id: z.string(),                    // ULID
  version: z.literal("ink-audit/1"),

  // Who logged this event
  agentId: z.string(),
  agentSignature: z.string(),        // Ed25519 signature over the event (minus this field)

  // Chain position (inspired by SSB feed structure)
  sequence: z.number().int().positive(),  // monotonically increasing, starting at 1
  previousEventHash: z.string().nullable(),  // SHA-256 of the prior event; null for sequence=1

  // What happened
  eventType: z.enum([
    // Message lifecycle
    "message.sent",
    "message.received",
    "message.queued",
    "message.delivered",
    "message.acted",
    "message.rejected",
    "message.expired",
    "message.retracted",
    // Receipt lifecycle
    "receipt.sent",
    "receipt.received",
    // Delegation
    "delegation.granted",
    "delegation.used",
    "delegation.revoked",
    "delegation.expired",
    // Connection
    "connection.requested",
    "connection.accepted",
    "connection.declined",
    // Verification
    "signature.verified",
    "signature.verified_retired",
    "signature.failed",
    "signature.revoked_rejected",
    "replay.detected",
    // Key lifecycle
    "key.rotated",
    "key.revoked",
    // Introduction lifecycle
    "introduction.requested",
    "introduction.approved",
    "introduction.declined",
    "introduction.forwarded",
    "introduction.completed",
    "introduction.expired",
    "introduction.receipt_sent",
    "introduction.receipt_received",
    // Enclave lifecycle
    "enclave.requested",
    "enclave.authorized",
    "enclave.opened",
    "enclave.operation_submitted",
    "enclave.resolved",
    "enclave.expired",
    "enclave.aborted",
    "enclave.receipt_sent",
    "enclave.receipt_received",
    // Containment
    "transport_scope_violation",
    "handshake_rate_limited",
    "handshake_budget_exhausted",
    "discovery_query_received",
    "discovery_query_granted",
    "discovery_query_denied",
  ]),

  // Event timestamp
  timestamp: z.string().datetime(),

  // References
  messageId: z.string().optional(),
  correlationId: z.string().optional(),
  counterpartyId: z.string().optional(),  // the other agent involved
  signingKeyId: z.string().optional(),    // key used to sign this event, for historical verification

  // Event-specific data (schema varies by eventType)
  data: z.record(z.unknown()).optional(),
});
```

**Tamper evidence (hash chain + sequence numbers):**

The audit chain uses **both** a hash chain and a monotonic sequence number, following SSB's feed model:

- **`sequence`:** monotonically increasing integer starting at 1. Provides a human-readable position and makes gaps immediately detectable (if you see sequence 5 followed by 7, sequence 6 was deleted or suppressed).
- **`previousEventHash`:** SHA-256 of the JCS-canonicalized prior event (excluding `agentSignature`). Null for the first event (sequence=1). Provides cryptographic chain linkage, if any event is modified, all subsequent hashes break.
- **`agentSignature`:** Ed25519 signature over the JCS-canonicalized event (excluding the `agentSignature` field itself). Proves the agent attested to this event at this chain position.

**Fork detection (per SSB):**
- If an agent presents two different events with the same `sequence` number, the chain is forked. A forked chain SHOULD be treated as untrusted during reconciliation.
- During audit exchange (§3), both parties can compare sequence numbers and hashes. If Alice has sequence 1-10 for a message and Bob has sequence 1-8, the gap is immediately visible. If their hashes diverge at sequence 5, that's the point of tampering.

The chain is per-agent (not global), each agent maintains its own append-only log.

### 3. Audit Exchange Protocol

Agents can request audit records from each other for reconciliation.

**New endpoint:** `POST /ink/v1/audit`

Audit queries use **POST** (not GET) to fit INK's existing authentication model. INK v0.1 auth (§3.3) signs `METHOD + PATH + recipientDid + JCS(body) + timestamp`, which requires a request body for canonicalization. GET requests have no body, so they cannot be authenticated or replay-protected under the current INK auth scheme.

**Agent Card advertisement:**

```typescript
{
  endpoint: "https://agent.example.com/ink/v1",
  capabilities: {
    auditExchange: true,  // "I support the audit exchange protocol"
  }
}
```

**Request (signed per §3.3, replay-protected per §3.5):**

```json
POST /ink/v1/audit
Authorization: INK-Ed25519 <signature>

{
  "protocol": "ink/0.1",
  "type": "network.tulpa.audit_query",
  "from": "did:plc:alice",
  "to": "did:plc:bob",
  "messageId": "msg-123",
  "nonce": "<base64url-encoded 128-bit nonce>",
  "timestamp": "2026-03-19T12:00:00Z"
}
```

The signature base follows §3.3 exactly:
```
signatureBase = "ink/0.1\nPOST\n/ink/v1/audit\ndid:plc:bob\n{...JCS(body)...}\n2026-03-19T12:00:00Z"
```

**Response:**

```json
{
  "protocol": "ink/0.1",
  "type": "network.tulpa.audit_response",
  "messageId": "msg-123",
  "events": [ /* InkAuditEvent[] */ ],
  "responseSignature": "<Ed25519 signature over JCS(events array)>"
}
```

The `responseSignature` is the responder's Ed25519 signature over the JCS-canonicalized `events` array, allowing the requester to prove the responder attested to this specific audit slice. The signature alone does NOT prove the slice is internally consistent. Consumers MUST run two checks before treating the events as authoritative: `verifyAuditResponseSignature(events, signature, key)` (proves the responder produced this exact slice) AND `verifyAuditEventChain(events)` (proves the slice has no internal `sequence_gap`, `sequence_fork`, or `previous_hash_mismatch`). A slice that passes one and fails the other MUST be rejected.

**Access control:**
- The responder MUST verify (via its message store) that the requester's DID (`from`) is either the sender or recipient of the referenced `messageId`. If not, return error code `access_denied`.
- The request is authenticated and replay-protected using the standard INK auth flow, no special-case logic needed.
- Events are filtered to only include the specific message's lifecycle.

### 4. Dispute Resolution

When two agents disagree about a message's status, they perform mutual audit exchange via `POST /ink/v1/audit` (§3):

```
Alice                                          Bob
  |-- POST /ink/v1/audit (messageId=123) ----->|
  |<-- { events: [...], responseSignature } ---|
  |                                             |
  | Alice has her own events for msg-123        |
  | and Bob's signed events for msg-123         |
  |                                             |
  | Compare sequence numbers and hashes:        |
  |   - Matching hashes: agreement              |
  |   - Divergent hashes: flag for human review |
  |   - Sequence gaps: events were suppressed   |
  |   - Fork (same sequence, different hash):   |
  |     chain is untrusted                      |
```

**Reconciliation algorithm:**
1. Both agents exchange audit events for the disputed message via `POST /ink/v1/audit`
2. Each response is signed by the responder (`responseSignature`), creating non-repudiable evidence of what each party claims happened
3. Verify each response with `verifyAuditResponseSignature`. Reject slices that fail.
4. Run `verifyAuditEventChain(events)` on each verified slice. Reject slices that return `sequence_gap`, `sequence_fork`, or `previous_hash_mismatch`, a slice that fails this gate is internally inconsistent regardless of who signed it.
5. Compare `sequence` numbers and `previousEventHash` chains across the two slices to find the earliest point of divergence
6. If the recipient has `message.received` but not `message.delivered`, the message was lost internally
7. If the sender has `message.sent` but the recipient has no events, the message was lost in transit
8. Both parties' signed responses can be presented to a human mediator if automated reconciliation fails

### 5. Audit Retention and Export

**Retention policy (protocol-level recommendation):**
- Message lifecycle events: 12 months minimum
- Delegation events: lifetime of the delegation + 12 months
- Connection events: lifetime of the connection + 6 months

**Export format:**
- JSON Lines (one `InkAuditEvent` per line, newline-delimited)
- File naming: `ink-audit-{agentId}-{startDate}-{endDate}.jsonl`
- Includes a trailing line with the final hash chain value for integrity verification

### 6. Integration with Existing AgentAuditStore

The internal `AgentAuditStore` (130+ event types, rich metadata) remains the primary audit system for the tulpa application layer. The INK audit protocol is a **subset** designed for interoperability:

| Concern | AgentAuditStore | INK Audit Protocol |
|---------|----------------|--------------------|
| Scope | All agent activity | Cross-agent message lifecycle only |
| Event types | 130+ application-specific | ~20 protocol-standard |
| Audience | Owner dashboard | Other INK agents and dispute resolution |
| Tamper evidence | No (mutable SQL) | Yes (hash chain) |
| Signature | No | Yes (Ed25519 per event) |
| Portability | Tulpa-specific schema | Standard INK format |

**Bridge:** when the internal audit store logs a message event (e.g. `intent_received`, `intent_sent`), a corresponding INK audit event is generated and appended to the protocol-level hash chain.

## Migration Path

1. Add `network.tulpa.receipt` as a new INK message type with `POST /ink/v1/receipt` endpoint
2. Add `network.tulpa.audit_query` / `network.tulpa.audit_response` as new INK message types with `POST /ink/v1/audit` endpoint
3. Add receipt generation to `receiveMessage` pipeline (opt-in via agent config)
4. Add `InkAuditEvent` generation alongside existing `AgentAuditStore` logging, with sequence numbers and hash chain
5. Advertise receipt and audit capabilities in Agent Card
6. All new endpoints use the existing INK auth model (§3.3) and replay protection (§3.5), no special-case authentication
7. _(Future)_ Deploy a INK-native audit service (§7) for third-party witnessing of high-value interactions

## Prior Art and Research

This design was validated against established receipt and audit trail protocols.

### Message Disposition Notification (MDN, RFC 8098)
Email's receipt protocol. INK's disposition types are directly influenced by MDN's action/disposition model:
- MDN separates **action mode** (`manual-action` vs `automatic-action`) from **disposition type** (`displayed`, `deleted`, `processed`, `denied`, `failed`). INK simplifies this into a single `disposition` enum since INK agents always process programmatically.
- **Critical lesson: MDN is advisory and unreliable.** Receipts can be silently suppressed by intermediaries, spam filters or the recipient's MUA. You cannot distinguish "not read" from "MDN suppressed." INK addresses this by making receipts protocol-level intent messages (signed and delivered via the same inbox mechanism), not a separate transport.
- MDN's `denied` disposition lets a recipient refuse to send a receipt without revealing read status. INK adopts this via selective disposition reporting in the Agent Card.
- **MDN has no delivery receipt**, that's DSN (RFC 3461). INK's `received` disposition covers delivery; `delivered`/`acted` cover read/action. This is a deliberate consolidation.

### XMPP Receipts (XEP-0184) and Chat Markers (XEP-0333)
XMPP provides two relevant patterns:
- **Cumulative acknowledgment:** marking message N as `displayed` implicitly marks messages 1..N. This reduces bandwidth in catch-up scenarios. INK does NOT adopt this, INK messages are not linearly ordered (they span multiple conversations/correlationIds), so cumulative receipts would be ambiguous.
- **Disposition escalation:** XEP-0333 defines `received` → `displayed` → `acknowledged` as increasing levels of confirmation. INK's `received` → `delivered` → `acted` follows the same escalation pattern.
- **No tamper evidence.** XMPP receipts are plaintext XML within TLS. A malicious server can forge or suppress them. INK's receipts are Ed25519-signed by the recipient's key.

### Matrix Protocol Receipts
Matrix puts receipts outside the persistent DAG (as ephemeral EDUs). Key lessons:
- **Receipts as ephemeral vs. persistent is a core design choice.** Matrix chose ephemeral to avoid bloating the room DAG. INK puts receipts IN the audit hash chain (persistent) because they serve as evidence, not just UX signals. This is a deliberate tradeoff, more storage for stronger guarantees.
- **Federation receipt loss.** Matrix receipts can be lost during federation disruptions with no replay mechanism. INK mitigates this by treating receipts as regular intent messages with the same delivery guarantees.
- **Private read receipts.** Matrix added `m.read.private` because public receipts leaked too much. INK's selective disposition reporting (Agent Card `capabilities.receipts.dispositions`) achieves the same, an agent can report only `received` and `rejected` but not `delivered` or `acted`.

### Certificate Transparency (RFC 6962)
CT's Merkle tree approach is the gold standard for tamper-evident append-only logs:
- **Signed Certificate Timestamp (SCT) as receipt.** CT's SCT is a signed promise: "I will include this in my log within the Maximum Merge Delay." This is stronger than INK's receipts, CT receipts come from an independent third party (the log), not the recipient. INK's receipts are bilateral (between sender and recipient), which is simpler but has weaker trust properties.
- **Inclusion proofs and consistency proofs.** CT can prove a specific entry exists in the log (inclusion) and that the log is append-only (consistency). INK's hash chain provides append-only evidence but not efficient inclusion proofs. For INK's scale (50 messages/day per agent), the hash chain is sufficient, Merkle trees add complexity without proportional benefit.
- **The split-view attack.** A malicious CT log can show different views to different clients. INK has the same risk, a malicious agent can maintain two different hash chains. Mutual audit exchange (Section 4) is INK's mitigation, analogous to CT's gossip protocol.

### Secure Scuttlebutt (SSB)
SSB's single-writer append-only feed is the closest analog to INK's per-agent hash chain:
- **Hash chain structure.** Each SSB message contains `previous` (hash of prior message), `sequence` (monotonic counter), `author` (public key) and `signature`. INK's `InkAuditEvent` adopts the same pattern with `previousEventHash`.
- **Fork detection.** SSB detects when a feed owner publishes two messages with the same sequence number. The feed is permanently "poisoned." INK should adopt fork detection: if an agent presents two different events with the same sequence position, the chain is untrusted.
- **No editing or deletion.** SSB's immutability is a feature for audit but a problem for GDPR. INK addresses this with the `redact` capability in `AgentAuditStore`, the event remains in the chain but its content is replaced with `[redacted]`.
- **JSON canonicalization.** SSB's signature is over `JSON.stringify` with specific key ordering, which has caused interop bugs. INK uses JCS (RFC 8785) canonicalization, which is a proper standard.

### DIDComm Messaging v2
DIDComm's problem reports and trust ping provide patterns for cross-agent status signaling:
- **Problem reports** use structured error codes (`e.p.msg.not-understood`, `e.m.req.not-accepted`). INK's receipt `note` field is simpler, a free-text rejection reason. Consider adopting structured codes in a future version.
- **Deniability vs. non-repudiation.** DIDComm explicitly offers both modes (signed JWS for non-repudiation, authcrypt for deniability). INK receipts are always signed (non-repudiation). This is the right choice for audit trails, deniability and auditability are fundamentally at odds.
- **No built-in receipt protocol.** DIDComm v2 deliberately omits a core receipt protocol because its multi-transport model (HTTP, WebSocket, Bluetooth, QR) makes reliable delivery confirmation impossible. INK avoids this by standardizing on HTTP.

### COSE Receipts / SCITT (Supply Chain Integrity, Transparency and Trust)
SCITT applies CT concepts to arbitrary claims, not just certificates:
- **Access-controlled transparency.** Unlike CT (fully public), SCITT supports Merkle proofs over access-controlled logs. This is critical for agent protocols where message contents should not be publicly visible. INK's `/audit` endpoint with sender/recipient access control follows this model.
- **Multiple transparency services.** SCITT allows a single statement to accumulate receipts from multiple independent services. INK could adopt this for high-stakes messages, both agents publish audit events to an independent transparency service for stronger guarantees.
- **Separation of issuer and transparency service.** In SCITT, the entity making claims is separate from the entity recording them. INK currently has agents self-recording their own audit events. For stronger guarantees, INK could support optional third-party audit services.

### C2SP Witness Cosigning Protocol
The Community Cryptography Specification Project defines a witness protocol for transparency logs. Witnesses verify consistency proofs between checkpoints (signed tree heads) and return cosignatures, they never see log contents, only tree sizes and root hashes. Key properties:
- **Privacy by design.** A witness attests "this log is append-only" without knowing what's in it. Perfect for INK where message content is private.
- **Single honest witness sufficiency.** One non-colluding witness is enough to detect a split-view attack (a log presenting different histories to different clients).
- **Ed25519 native.** Checkpoints and cosignatures use Ed25519 note signatures, matching INK's key model exactly.
- **Lightweight.** One HTTP request per checkpoint, not per event. At INK's scale (~50 events/day), an agent might publish one checkpoint per hour, 24 witness requests/day.

The checkpoint format (`tlog-checkpoint`) is a simple text format: origin line, tree size, base64 root hash, followed by note signatures. INK's per-agent hash chain maps naturally to this, the agent is the "log" and publishes periodic checkpoints.

### Sigstore (Rekor, Fulcio, Cosign)
Sigstore provides a transparency log (Rekor) for software supply chain signatures. Rekor v2 (GA 2025) uses Trillian Tessera with integrated witness cosigning. Relevant patterns:
- **Hash notarization.** Rekor accepts `(artifact_hash, signature, public_key)` tuples. INK could submit `(audit_chain_hash, agent_signature, agent_public_key)` to get a free, independent timestamp proof. Content stays private, only the hash is public.
- **Rekor v2 tile-based architecture.** Static file serving for Merkle tree tiles, reducing infrastructure cost dramatically. If INK builds its own transparency service, this architecture is the model.
- **Public key visibility tradeoff.** Rekor entries expose the signer's public key. For INK, this means agent DIDs would be visible even though message content is not. Acceptable for agents that want public transparency; use witnesses instead for full privacy.

### OpenTimestamps
A Bitcoin-anchored timestamping protocol. Aggregates hashes into a Merkle tree and anchors the root in a Bitcoin transaction. Provides the strongest possible "this data existed at time T" proof (Bitcoin's security model) at the cost of 1–2 hour confirmation latency. Free calendar servers, no registration. Best suited as a periodic anchor (once/day) for the audit chain's latest hash, providing legally defensible timestamps for compliance scenarios.

### Design Decisions Informed by Research

| Decision | Rationale | Prior Art |
|----------|-----------|-----------|
| Receipts as signed intent messages | Stronger than advisory MDN/XMPP; same delivery path as regular messages | MDN lesson: advisory receipts are unreliable |
| Per-message receipts (not cumulative) | INK messages aren't linearly ordered across conversations | XMPP cumulative receipts assume linear order |
| Receipts in hash chain (persistent) | Audit evidence, not just UX | Matrix chose ephemeral; INK needs evidence |
| Per-agent hash chain (not Merkle tree) | Sufficient for INK's scale; simpler | SSB feeds vs. CT Merkle trees |
| Selective disposition reporting | Privacy control for recipients | Matrix `m.read.private`, MDN `denied` |
| JCS canonicalization for signing | Proper standard, avoids SSB's JSON.stringify bugs | SSB interop issues |
| Access-controlled audit endpoint | Messages are private; audit should be too | SCITT access-controlled transparency |
| Fork detection on hash chain | Detect malicious chain rebuilds | SSB fork poisoning |
| Witness cosigning over full transparency service | Privacy-preserving, minimal infrastructure | C2SP `tlog-witness`, CT gossip |
| Tiered approach (witnesses → SCITT → Tessera) | Match effort to threat model | Sigstore ecosystem layering |

### 7. Third-Party Audit Services (Optional)

Bilateral audit exchange (§3–§4) has a fundamental limitation: a malicious agent can maintain two different hash chains and show each counterparty a different history. This is the **split-view attack**, well-known from Certificate Transparency research. Mutual exchange detects inconsistencies only when both parties compare, it can't prevent a malicious agent from presenting a consistent-looking but fabricated chain to each party independently.

Third-party audit services solve this by introducing an independent witness that neither party controls.

#### 7.0 Service Identity and Auth Model

A third-party audit service is a **INK service role**, not a standard INK agent. It differs from the human-delegate model (§2) in several ways:

| Concern | INK Agent | Audit Service |
|---------|-----------|--------------|
| Identity | DID bound to a human via `agentLink` | `did:web` or `did:key`, self-sovereign, no human owner |
| Discovery | `TulpaAgentEndpoint` in DID document | Advertised in subscribing agents' Agent Card `capabilities.thirdPartyAudit.services` |
| Auth (inbound) | INK auth §3.3, verifies sender's `agentLink` delegation | INK auth §3.3, verifies sender's `agentLink` delegation (same as any INK endpoint) |
| Auth (outbound) | Signs with `agentLink.signingKeyMultibase` | Signs with its own Ed25519 key (published in subscribing agents' Agent Card) |
| Delegation proof | Required, must trace authority back to a human DID | Not applicable, the service is independently trusted by each subscribing agent |

**Key distinctions:**

1. **No `agentLink` verification.** When an agent receives a response from an audit service, it does NOT verify an `agentLink` delegation chain. Instead, it verifies the response signature against the service's public key as configured in the agent's own `capabilities.thirdPartyAudit.services[].publicKey`. Trust in the service is **configured, not discovered**, the agent operator chose to use this service.

2. **Inbound auth is standard INK.** When agents submit events TO the service, the service verifies the submitter's identity via standard INK auth (§3.3), resolve the sender's DID, find their `agentLink`, verify the signature. The service is a normal INK recipient in this direction.

3. **Service DID resolution.** The service's `did:web` (or `did:key`) is resolved normally for TLS binding and key discovery, but the service does NOT need a `TulpaAgentEndpoint` service entry in its DID document. Its endpoint is provided directly in the subscribing agent's Agent Card configuration.

4. **No inbox, no intents.** The audit service does not accept INK intents, challenges or resolutions. It exposes only the audit-specific endpoints (`/ink/v1/audit/submit`, `/ink/v1/audit/query`).

Implementations MUST treat the audit service as an external dependency, not a INK peer. If the service is unavailable, agents fall back to bilateral audit exchange (§3–§4).

#### 7.1 Architecture

```
Agent A                    Audit Service                    Agent B
  |                            |                               |
  |-- submit(event) --------→ |                               |
  |←- receipt(inclusion) ----- |                               |
  |                            |                               |
  |                            | ←------- submit(event) -------|
  |                            | -------- receipt(inclusion) -→ |
  |                            |                               |
  |-- query(messageId) -----→ |                               |
  |←- proof(events, merkle) -- |                               |
```

The audit service:
1. Accepts signed `InkAuditEvent` submissions from agents
2. Appends them to a **Merkle tree** (not just a hash chain, enables efficient inclusion proofs)
3. Returns a **signed inclusion receipt** proving the event was recorded at a specific tree position and timestamp
4. Serves **inclusion proofs** on demand (per-submission via the inclusion receipt and per-query via the signed `audit_query_response` envelope). **Consistency proofs** between two arbitrary checkpoints are not in scope for alpha.3; consistency-proof verification against external `tlog-witness` cosigners (§7.0) is the alpha.3 mitigation against split-view attacks.

The service CANNOT forge events that verifiers will accept, because every returned event carries the submitting agent's Ed25519 `agentSignature` and §7.3 verifiers re-check it against the agent's published keys. A witness that commits a fabricated event_json into its Merkle tree can produce a valid inclusion proof, but verifiers will reject the response when the agent signature fails to validate. (Verifiers that walk Merkle proofs without checking `agentSignature` lose this guarantee; see §7.5.) The service CAN prove:
- That a specific event was submitted at a specific time (inclusion)
- That the log is append-only and no events have been removed (consistency)
- That two parties submitted conflicting events for the same message (conflict detection)

#### 7.2 Submission Protocol

Agents submit audit events to the service alongside their normal hash chain maintenance. Submission is **asynchronous** and **non-blocking**, the agent does not wait for the service receipt before proceeding.

```json
POST /ink/v1/audit/submit
Authorization: INK-Ed25519 <signature>

{
  "protocol": "ink/0.1",
  "type": "network.tulpa.audit_submit",
  "from": "did:plc:agent",
  "to": "did:web:audit.example.com",
  "event": { /* InkAuditEvent */ },
  "nonce": "<base64url>",
  "timestamp": "2026-03-19T12:00:00Z"
}
```

**Response (Signed Inclusion Receipt):**

```json
{
  "protocol": "ink/0.1",
  "type": "network.tulpa.audit_inclusion",
  "eventId": "01JBTEST0001",
  "treeSize": 48291,
  "leafIndex": 48290,
  "rootHash": "<SHA-256 hex of Merkle tree root>",
  "timestamp": "2026-03-19T12:00:01Z",
  "serviceSignature": "<Ed25519 signature, see canonical format below>"
}
```

**Canonical signature format.** `serviceSignature` is an Ed25519 signature over the bytes:

```
"ink/audit-inclusion/v1\n" || JCS(receipt-fields-without-serviceSignature)
```

where `JCS` is the RFC 8785 canonical JSON serialization of the inclusion-receipt object with all top-level fields except `serviceSignature` itself. The receipt object's fields used for the signature MUST be exactly `{eventId, leafIndex, treeSize, rootHash, timestamp}`. `protocol` and `type` are envelope metadata, not part of the signed payload. Verifiers reconstruct the signed bytes from the response and check the signature against the witness's published Ed25519 public key.

The inclusion receipt is analogous to CT's Signed Certificate Timestamp (SCT). The agent stores it alongside the audit event and can present it as proof of timely submission.

#### 7.3 Verification Protocol

Any party to a message can request the service's view of the audit trail:

```json
POST /ink/v1/audit/query
Authorization: INK-Ed25519 <signature>

{
  "protocol": "ink/0.1",
  "type": "network.tulpa.audit_query",
  "from": "did:plc:requester",
  "to": "did:web:audit.example.com",
  "messageId": "msg-123",
  "nonce": "<base64url>",
  "timestamp": "2026-03-19T13:00:00Z"
}
```

**Response includes Merkle inclusion proofs and is signed by the witness:**

```json
{
  "protocol": "ink/0.1",
  "type": "network.tulpa.audit_query_response",
  "serviceDid": "did:web:witness.example.com",
  "messageId": "msg-123",
  "requester": "did:plc:requester",
  "events": [ /* InkAuditEvent[] visible to the requester */ ],
  "proofs": [
    {
      "eventId": "01JBTEST0001",
      "leafIndex": 48290,
      "inclusionProof": ["<hash>", "<hash>", "..."]
    }
  ],
  "treeSize": 48291,
  "rootHash": "<SHA-256 hex of Merkle tree root at response time>",
  "timestamp": "2026-03-19T13:00:01Z",
  "serviceSignature": "<Ed25519, see canonical format below>"
}
```

**Canonical signature format.** `serviceSignature` is an Ed25519 signature over the bytes:

```
"ink/audit-query-response/v1\n" || JCS(response-fields-without-serviceSignature)
```

The signed payload binds the witness's `serviceDid`, the `messageId` requested, the authenticated `requester` whose access-control scope produced the result, every returned event, every inclusion proof, the witness's `treeSize` and `rootHash` at response time and the `timestamp`. The `proofs` array has one entry per event, keyed by `eventId`; verifiers MUST reject if proofs do not match events one-to-one. `treeSize` and `rootHash` apply uniformly to every proof. The `requester` binding prevents cross-requester replay: a witness response generated for Alice cannot be presented to Bob as Bob's authoritative view of the same `messageId`. Verifiers MUST check `requester` equals the locally authenticated requester before treating the response as their own scoped view.

Per-event scope: a signed envelope binds `messageId` and `requester` but says nothing about the event objects until verifiers look inside them. To prevent a witness or a tampering intermediary from smuggling out-of-scope events into a signed response, verifiers MUST reject any response where, for any returned event, `event.messageId` differs from the envelope `messageId`, OR the envelope `requester` is neither `event.agentId` nor `event.counterpartyId`. Witnesses SHOULD reject the same conditions at signing time as defense in depth against storage corruption.

Empty-log responses: a witness that has not yet committed any leaves reports `treeSize: 0` and `rootHash` equal to SHA-256 of the empty string (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`). A signed response with `treeSize: 0` is legitimate but MUST also have empty `events`, empty `proofs` and the empty-tree `rootHash`. Verifiers MUST reject any `treeSize: 0` response that deviates from this shape.

Per-event agent signatures: Merkle validity alone does NOT prove a returned event was produced by the agent named in `event.agentId`. A witness could in principle commit a fabricated event_json that is not a real `InkAuditEvent`. Every returned event MUST therefore include its `agentSignature` field. Verifiers MUST resolve the submitting agent's published Ed25519 keys (via Agent Card §2) and verify `agentSignature` on every event in addition to walking the Merkle proof. A response that omits `agentSignature` on any event MUST be rejected as structurally invalid.

Truncation: witnesses MUST NOT silently sign a partial result. If the requester's visible event set for a `messageId` exceeds the witness's response cap, the witness MUST return an unsigned error response (HTTP 413). A signed response is, by definition, a complete enumeration of the requester's visible events for that `messageId` at `(treeSize, rootHash)`.

Determinism: witnesses MUST emit `events` and matching `proofs` in a stable, deterministic order so verifiers can reproduce the signed bytes from the underlying records.

Leaf hash: each event's Merkle leaf hash is `SHA-256(0x00 || JCS(event-without-agentSignature))`. The leading `0x00` byte is the RFC 6962 leaf-domain-separation tag; internal Merkle nodes use `0x01 || left || right`. Verifiers MUST rehash the returned `event` object themselves (stripping `agentSignature`, then JCS, then SHA-256 with the `0x00` prefix) and use that hash as the leaf input to `inclusionProof`. They MUST NOT trust any leaf-hash value supplied by the witness alongside the event. Walking the proof from this computed leaf hash up through `inclusionProof` MUST reach the top-level `rootHash` per the proof construction in §7.2. The INK library exposes this exact computation as `computeAuditMerkleLeafHash`; it is distinct from `computeEventHash`, which is the unprefixed SHA-256 used for `previousEventHash` chain linkage and MUST NOT be used as the Merkle leaf input.

#### 7.4 Access Control

The audit service operates under **access-controlled transparency** (per SCITT):
- Events are tagged with the `messageId` and the DIDs of sender/recipient
- Only the sender or recipient (i.e. an event's own `agentId` or `counterpartyId`) can query events for a given `messageId`. The witness MUST refuse to serve a row to any other requester
- The service verifies the requester's identity via INK auth (§3.3) before serving events
- The Merkle tree structure is public: anyone can verify inclusion proofs against signed checkpoints and, where consistency-proof endpoints are deployed, cross-check that checkpoints are append-only. Event contents remain access-controlled

Delegated queries (where a third-party agent queries events on behalf of a principal via an INK Authorization Chain) are not in scope for alpha.3. A future revision will define the additional envelope fields the witness signs to bind the effective principal alongside the immediate requester, and verifiers will be updated accordingly. Until then, conformant witnesses MUST treat the per-event scope rule in §7.3 as authoritative: a returned event's `agentId` or `counterpartyId` MUST equal the response `requester`.

This follows SCITT's model: the transparency guarantee (append-only, no suppression) is public, but the data itself is private.

#### 7.5 Trust Model

The audit service is a **semi-trusted witness**, not an arbiter:
- It CANNOT forge events that verifiers will accept, because verifiers re-check `event.agentSignature` against the agent's published Ed25519 keys (§7.3). A witness that commits a fabricated event_json into its Merkle tree can produce a valid inclusion proof, but the per-event agent-signature check fails and the response is rejected. Verifiers that walk the proof without checking `agentSignature` lose this guarantee.
- It CANNOT modify events without breaking Merkle proofs
- It CAN suppress events by refusing to include them (detectable via consistency proofs between submissions)
- It CAN be unavailable (agents fall back to bilateral exchange)
- It CAN collude with one party to suppress the other's events (mitigated by using multiple services)

**Multiple services:** For high-stakes interactions, agents MAY submit to multiple independent audit services. If any one service is compromised, the others still have the complete record. This mirrors CT's approach of requiring certificates to appear in multiple independent logs.

#### 7.6 Agent Card Advertisement

```typescript
capabilities: {
  auditExchange: true,
  thirdPartyAudit: {
    services: [
      {
        endpoint: "https://audit.example.com/ink/v1",
        did: "did:web:audit.example.com",
        publicKey: "<Ed25519 public key hex>"
      }
    ],
    submitPolicy: "all"  // "all" | "high_value" | "none"
  }
}
```

`submitPolicy` controls which events are submitted:
- `all`: every audit event is submitted to the service
- `high_value`: only events for messages with encryption or delegation chains
- `none`: advertised but not actively submitting (can still query)

#### 7.7 Implementation Options

INK does not mandate a specific transparency log implementation. The options fall into three tiers based on effort and guarantees:

**Tier 1, Lowest effort, highest immediate value:**

| Approach | How it works | Privacy | Cost |
|----------|-------------|---------|------|
| **Witness cosigning** (C2SP `tlog-witness`) | Agents publish periodic checkpoints of their hash chain. Independent witnesses verify consistency proofs and return cosignatures. Split-view attacks become detectable when clients compare cosigned roots or use multiple witnesses. | Inherent, witnesses see only tree size + root hash, never event content | Free (public witnesses exist) |
| **Rekor hash notary** (Sigstore) | Submit SHA-256 hashes of audit chain checkpoints to Rekor's public Merkle log. Provides an independent timestamp proof that a chain state existed at time T. | Hash-only, public key and timing are visible, content is not | Free (rekor.sigstore.dev) |

Witness cosigning is the **recommended starting point**. The C2SP witness protocol (`tlog-witness`, `tlog-cosignature`, `tlog-checkpoint`) uses Ed25519 natively and maps directly to INK's existing hash chain. Agents already compute sequential hashes, publishing a checkpoint is just exposing the latest `(sequence, rootHash)` pair. The checkpoint format:

```
ink-audit/<agentDid>
<sequence number>
<base64 root hash>

<Ed25519 note signature>
```

**Tier 2, Medium effort, stronger guarantees:**

| Approach | How it works | Privacy | Cost |
|----------|-------------|---------|------|
| **SCITT transparency service** | A hosted service accepts COSE_Sign1-wrapped audit events, applies registration policy (INK auth for access control) and returns Merkle inclusion receipts. Follows IETF draft-ietf-scitt-architecture. | Access-controlled, events stored with sender/recipient ACL | DataTrails (commercial) or self-hosted |
| **INK-native Merkle service** | A Tulpa-operated transparency service using the submission protocol from §7.2. Reuses INK auth (§3.3) and message format. | Full INK access control | Self-hosted |

SCITT is the best architectural fit for a full third-party audit service. The VeritasChain Protocol (draft-kamimura-scitt-vcp) demonstrates SCITT profiles for financial audit trails, a INK profile would follow the same pattern. However, SCITT is still a draft standard and the ecosystem is immature.

**Tier 3, Infrastructure investment:**

| Approach | How it works | Privacy | Cost |
|----------|-------------|---------|------|
| **Tessera-based log** (Google/transparency-dev) | Build a INK "personality" on top of Trillian Tessera. The Merkle tree is served as static tiles (any S3-compatible object store). Combined with external witnesses for independent attestation. | Full control, you build the personality | Self-hosted, significant engineering |
| **OpenTimestamps Bitcoin anchor** | Once per day, anchor the latest audit chain hash to Bitcoin. Provides the strongest "this data existed at time T" proof. 1–2 hour confirmation latency. | Hash-only, Bitcoin sees only the Merkle root | Free |

**Recommended deployment path:**

1. **Now:** Implement witness cosigning for per-agent hash chains (Tier 1). Minimal code, agents expose a checkpoint endpoint, collect cosignatures from public witnesses.
2. **When needed:** Add Rekor hash notarization for agents that want a public timestamp record (Tier 1).
3. **For high-value interactions:** Deploy a INK-native Merkle service or adopt a SCITT transparency service (Tier 2). Agents advertise this in their Agent Card `capabilities.thirdPartyAudit`.
4. **For compliance:** Add periodic OpenTimestamps Bitcoin anchoring (Tier 3) for legally defensible timestamps.

### Open Questions (Raised by Research)

1. **Should receipts be deniable?** DIDComm supports deniable messages. INK's current design makes all receipts non-repudiable (signed). For casual interactions, this may be overly formal. Consider an optional unsigned receipt mode for low-stakes messages.

2. **Structured error codes for rejections?** DIDComm's structured problem codes (`e.p.msg.*`) are more machine-parseable than INK's free-text `note`. Consider adopting a structured code scheme in a future version.

3. **Audit service federation:** should audit services be able to cross-replicate, similar to CT log mirroring? This would increase resilience but adds complexity.

4. **Audit service discovery:** should there be a well-known audit service registry, or is Agent Card advertisement sufficient?

## Security Considerations

- **Receipt spam:** receipts are rate-limited like regular messages. An agent can disable receipt sending. Receipts for receipts are never sent (loop prevention).
- **Audit data privacy:** audit events for a message are only available to the sender and recipient. Events are filtered before serving via the `/audit` endpoint access control.
- **Hash chain integrity:** the chain is only as trustworthy as the agent maintaining it. A malicious agent can rebuild the chain. The value is in **mutual** verification, both parties' chains must agree. Fork detection (per SSB) flags agents that present inconsistent chains.
- **Storage cost:** audit events are compact (~200 bytes each). At 50 messages/day, 12 months of audit = ~3.5 MB per agent. This is well within typical per-agent storage budgets.
- **Selective disclosure:** agents can choose which disposition types to report. A privacy-conscious agent might only send `received` and `rejected` but not `delivered` or `acted`. This follows Matrix's precedent with private read receipts.
- **Split-view attacks:** a malicious agent could show different audit histories to different parties. Mutual audit exchange (§4) detects inconsistencies after the fact. Third-party audit services (§7) make split-view attacks detectable under consistency checking, a single honest witness that compares roots will catch divergence, but a single access-controlled witness can still equivocate unless clients independently verify consistency proofs or multiple witnesses are used. For high-stakes interactions, agents SHOULD submit to at least two independent audit services.
