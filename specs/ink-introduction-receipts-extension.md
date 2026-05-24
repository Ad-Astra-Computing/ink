# INK Introduction Receipts Extension v0.1

## Status
Draft

## Last Updated
23 March 2026

## Purpose

This specification defines a protocol-level extension for verifiable introductions in INK.

It introduces a signed introduction artifact that allows agents to prove that:
- an introduction workflow occurred
- a specific introducer participated
- the introduction reached a defined outcome
- the artifact is linked to the underlying INK exchange

This extension is intended to strengthen Tulpa's warm-path and introduction flows without requiring private relationship context to be published publicly.

---

## 1. Problem

The core INK handshake and the message receipt extension provide strong evidence that messages were sent, received, and acted upon.

They do not yet provide a first-class artifact for the distinct social action of an introduction.

This creates several gaps:

1. A completed introduction is visible only as a series of lower-level intents, resolutions, and local UI actions.
2. There is no portable proof that a specific introducer approved or forwarded an introduction.
3. Trust-path explanations cannot rely on a standardized signed artifact.
4. Implementations cannot exchange or export introduction provenance in an interoperable way.

---

## 2. Design Goals

This extension aims to provide:
- a signed, portable proof of introduction workflow outcomes
- linkage to the original INK exchange
- clear role semantics for requester, introducer, and introduced parties
- local-first storage with optional selective sharing
- compatibility with INK auditability and authorization chains

This extension does not aim to:
- publish private introduction context by default
- replace generic INK delivery/disposition receipts
- create a public reputation or ranking layer
- encode arbitrary social-graph claims without underlying workflow evidence

---

## 3. Core Model

An introduction receipt is a distinct INK message type.

It is not:
- an `intentType`
- a replacement for `network.tulpa.receipt`
- a public ATP record by default

It is a signed artifact that attests to the outcome of an introduction-related workflow.

### 3.1 Roles

This specification uses the following roles:

- **requester**: the agent that asked for an introduction
- **introducer**: the agent representing the person deciding whether to bridge the parties
- **beneficiary**: the party the requester wants to meet
- **target**: the counterparty being introduced to the beneficiary

For the common case:
- requester = beneficiary
- target = person the beneficiary wants to meet

The model keeps these fields separate so future workflows can support assistant-mediated or delegated requests without changing the wire shape.

### 3.2 Receipt Trigger

An introduction receipt SHOULD be issued when an introduction workflow reaches one of these terminal states:
- approved
- declined
- forwarded
- completed
- expired

An introduction receipt MUST NOT be emitted for every intermediate step.
It is an outcome artifact, not a transcript replacement.

---

## 4. Wire Format

### 4.1 Message Type

This extension defines a new INK message type:

`network.tulpa.introduction_receipt`

### 4.2 Envelope

```json
{
  "protocol": "ink/0.1",
  "type": "network.tulpa.introduction_receipt",
  "id": "01JQ....",
  "correlationId": "01JQ....",
  "from": "did:plc:introducer",
  "to": "did:plc:requester",
  "requesterDid": "did:plc:requester",
  "introducerDid": "did:plc:introducer",
  "beneficiaryDid": "did:plc:beneficiary",
  "targetDid": "did:plc:target",
  "status": "forwarded",
  "purpose": "Warm introduction for hiring conversation",
  "relatedIntentId": "01JQ....",
  "relatedResolutionId": "01JQ....",
  "contextHash": "a4c8...",
  "nonce": "<base64url>",
  "timestamp": "2026-03-23T12:00:00Z"
}
```

### 4.3 Required Fields

| Field | Description |
|------|-------------|
| `protocol` | MUST be `ink/0.1` |
| `type` | MUST be `network.tulpa.introduction_receipt` |
| `id` | Unique ULID or equivalent globally unique identifier |
| `correlationId` | Correlates the receipt to the introduction workflow |
| `from` | Sender of the receipt |
| `to` | Primary recipient of the receipt |
| `requesterDid` | DID of the requesting agent |
| `introducerDid` | DID of the introducing agent |
| `beneficiaryDid` | DID of the party seeking the introduction |
| `targetDid` | DID of the party being introduced |
| `status` | Outcome of the introduction workflow |
| `purpose` | Short human-meaningful statement of purpose |
| `nonce` | Replay protection nonce |
| `timestamp` | Receipt creation time |

### 4.4 Optional Fields

| Field | Description |
|------|-------------|
| `relatedIntentId` | Stage 1 intent or application-layer intro request that triggered the workflow |
| `relatedResolutionId` | Final resolution identifier if one exists |
| `note` | Optional short note from the introducer or implementation |
| `contextHash` | SHA-256 hex digest of a locally stored private context bundle |
| `authorizationChainRef` | Reference to an authorization chain artifact if used |
| `expiresAt` | Optional expiry for the receipt's asserted relevance, not its validity |

### 4.5 Status Values

The `status` field MUST be one of:

| Status | Meaning |
|--------|---------|
| `approved` | Introducer approved the introduction request but forwarding may not yet have happened |
| `declined` | Introducer declined to make the introduction |
| `forwarded` | Introducer forwarded the intro to the target or otherwise initiated the bridge |
| `completed` | The introduction was accepted and the bridge was established |
| `expired` | The intro workflow expired without completion |

Implementations SHOULD use:
- `approved` when the introducer has given consent but delivery to the target is not yet complete
- `forwarded` when the introducer has actually sent the bridge
- `completed` only when the introduction reached the intended counterparties successfully

---

## 5. Delivery and Recipients

### 5.1 Delivery Path

Introduction receipts SHOULD be delivered over HTTP using a dedicated endpoint:

`POST /ink/v1/introduction-receipt`

This keeps them distinct from generic delivery/disposition receipts.

### 5.2 Recipients

At minimum, the receipt MUST be sent to the requester.

The receipt MAY also be sent to:
- the beneficiary, if different from the requester
- the target, when the status is `forwarded` or `completed`

Implementations MUST NOT send the receipt to unrelated third parties.

### 5.3 Loop Prevention

Receiving a `network.tulpa.introduction_receipt` MUST NOT trigger:
- a generic message receipt
- another introduction receipt

This follows the same loop-prevention principle as generic INK receipts.

---

## 6. Signature and Replay Protection

Introduction receipts are full INK messages.

They MUST:
- be signed using the standard INK Ed25519 request signing flow
- include a nonce
- include a timestamp
- be replay-checked under the same nonce window as other INK messages

The signature base SHOULD follow the same pattern as other INK endpoints:

```text
POST
/ink/v1/introduction-receipt
<recipientDid>
<JCS(body)>
<timestamp>
```

If a receipt is sent to multiple recipients, each HTTP request MUST be signed for the specific recipient DID.

---

## 7. Privacy Model

### 7.1 Local-First Storage

Introduction receipts MUST be treated as local application data by default.

They SHOULD be stored inside each relevant participant's local application state and SHOULD NOT be published to ATP by default.

### 7.2 Minimal Disclosure

The receipt SHOULD contain only the minimum information needed to prove that the introduction workflow occurred.

Sensitive framing, notes, or relationship context SHOULD remain local and MAY be referenced indirectly through `contextHash`.

### 7.3 Selective Sharing

Users MAY export or share introduction receipts selectively.

Any future ATP publication of introduction receipts MUST be:
- opt-in
- purpose-specific
- documented in a separate spec

### 7.4 Trust Distance and Graph Use

Introduction receipts MAY be used to explain warm paths or trust distance inside Tulpa.

They MUST NOT be used as a generic public popularity score or implicit endorsement outside the introduction workflow context.

---

## 8. Relationship to Existing INK Artifacts

### 8.1 Generic Message Receipts

`network.tulpa.receipt` answers:
"What happened to this message?"

`network.tulpa.introduction_receipt` answers:
"What happened to this introduction workflow?"

Implementations MUST keep these concepts separate.

### 8.2 Resolutions

Introduction receipts complement, but do not replace, `network.tulpa.resolution`.

Resolutions capture the final handshake outcome.
Introduction receipts capture the social trust artifact of a completed or declined introduction path.

### 8.3 Audit Events

Introduction receipt issuance SHOULD be mirrored into the audit chain with event types such as:
- `introduction.requested`
- `introduction.approved`
- `introduction.declined`
- `introduction.forwarded`
- `introduction.completed`
- `introduction.receipt_sent`
- `introduction.receipt_received`

These event types SHOULD be added in `specs/ink-auditability.md` if this extension is adopted.

### 8.4 Authorization Chains

If the introduction depends on delegated authority or multi-hop approval, the receipt MAY reference an authorization chain artifact.

The receipt itself does not replace authorization chains.

---

## 9. Access Control

An agent receiving an introduction receipt MUST verify that it is an intended participant in the workflow.

An implementation MUST reject the receipt with `access_denied` if:
- the recipient is not the requester
- the recipient is not the beneficiary when explicitly addressed
- the recipient is not the target when explicitly addressed

The implementation SHOULD also verify:
- that the signer matches `from`
- that `introducerDid` is consistent with the signer when the introducer is the sender
- that the receipt references a known or expected correlation when available

---

## 10. Lexicon Shape

Recommended lexicon ID:

`network.tulpa.ink.introductionReceipt`

Recommended required properties:

```ts
type InkIntroductionReceipt = {
  protocol: "ink/0.1"
  type: "network.tulpa.introduction_receipt"
  id: string
  correlationId: string
  from: string
  to: string
  requesterDid: string
  introducerDid: string
  beneficiaryDid: string
  targetDid: string
  status: "approved" | "declined" | "forwarded" | "completed" | "expired"
  purpose: string
  nonce: string
  timestamp: string
  relatedIntentId?: string
  relatedResolutionId?: string
  note?: string
  contextHash?: string
  authorizationChainRef?: string
  expiresAt?: string
}
```

---

## 11. Example Flows

### 11.1 Approved but Not Yet Forwarded

1. Requester sends intro-related intent
2. Introducer approves internally
3. Introducer emits `network.tulpa.introduction_receipt` with `status = approved`
4. Requester stores artifact and updates UI

### 11.2 Forwarded

1. Introducer sends the actual bridge message to target
2. Introducer emits introduction receipt with `status = forwarded`
3. Requester receives proof that the bridge was made

### 11.3 Completed

1. Target accepts or bridge is otherwise established
2. Introducer or receiving implementation emits introduction receipt with `status = completed`
3. Relevant parties store the final trust artifact

### 11.4 Declined

1. Introducer declines the request
2. Introducer emits receipt with `status = declined`
3. Requester receives a signed proof of decline and explanatory note if allowed

---

## 12. Storage and Export

Implementations SHOULD store introduction receipts in a dedicated local collection or table.

Suggested fields:
- receipt id
- correlation id
- participant DIDs
- status
- signed payload
- message hash
- created at
- received at

Implementations MUST support exporting introduction receipts in a portable JSON format on user request.

The export SHOULD include:
- the signed receipt payload
- transport metadata sufficient for verification
- any related resolution or authorization references that the user is allowed to export

---

## 13. UI / Product Requirements

Tulpa or other INK implementations adopting this extension SHOULD expose:
- a human-readable intro history
- clear explanation of who introduced whom
- the current intro status
- the reason or purpose statement
- the fact that the proof is signed and portable

The UI SHOULD avoid:
- gamified trust scores
- public leaderboards of introductions
- exposing hidden third-party context without consent

---

## 14. Error Handling

Implementations SHOULD use standard INK structured errors where possible.

Recommended error codes:
- `invalid_receipt`
- `access_denied`
- `unknown_correlation`
- `signature_failed`
- `replay_detected`
- `unsupported_extension`

If the receiver does not support this extension, it SHOULD return `unsupported_extension`.

---

## 15. Compatibility and Rollout

This extension is optional.

Agents SHOULD advertise support in Agent Card capabilities.

Recommended capability shape:

```json
{
  "capabilities": {
    "introductionReceipts": {
      "send": true,
      "receive": true,
      "statuses": ["approved", "declined", "forwarded", "completed", "expired"]
    }
  }
}
```

Senders MUST NOT assume support unless capability discovery or prior negotiation indicates it.

If the recipient does not support introduction receipts, the sender MAY:
- fall back to local-only receipt generation
- rely on generic message receipts and audit events only

---

## 16. Test Vectors and Compliance

If adopted, this extension SHOULD add:
- signed receipt test vectors
- replay-protection test vectors
- multi-recipient delivery examples
- correlation-link validation cases

Compliance checks SHOULD verify that an implementation:
- validates required fields
- verifies signatures
- enforces participant access control
- prevents receipt loops
- exports receipts portably

---

## 17. Recommended Follow-On Implementation Work

The Tulpa codebase SHOULD next implement:

1. a lexicon file for `network.tulpa.ink.introductionReceipt`
2. receipt verification and persistence utilities
3. a local store for introduction receipts
4. owner API endpoints for intro history and proof export
5. UI surfaces for warm-path trust explanation
6. audit event additions for introduction lifecycle states

---

## 18. Open Questions

1. Should `completed` be emitted only by the introducer, or may the beneficiary or target also finalize it?
2. Should `approved` be optional if `forwarded` follows immediately?
3. Should `contextHash` commit to a standardized canonical bundle shape?
4. Should there be a compact participant visibility field for cases where the target should not receive the full receipt?
5. Should future ATP publication support a redacted proof form derived from the local receipt?
