# INK Containment Phase 1, Implementation Spec

## Status
Draft

## Purpose

Narrow implementation spec for Phase 1 of the [Agent Containment and Governance Extension](ink-agent-containment-and-governance-extension-spec.md). Covers three slices:

1. **Transport-bound authorization**, delegation tokens scoped to specific transports
2. **Capability-gated Agent Card discovery**, redacted cards for unauthenticated peers
3. **Handshake flood resistance**, per-correlation budgets, typed rejections, backoff hints

These three were chosen because they are independently shippable, require no fleet infrastructure, and harden the protocol surface that already exists.

---

## Slice 1: Transport-Bound Authorization

### Problem

A delegation token issued for INK HTTP use can currently be replayed via extension callbacks, voice workflows, or other channels. The authorization chain spec defines `constraints` with `intentTypes`, `targetAgents`, `expiresAt`, and `maxMessages`, but not which transport the token is valid on.

### Wire Changes

#### 1.1 Add `allowedTransports` to delegation hop constraints

Extend `DelegationHopSchema.constraints`:

```typescript
constraints: z.object({
  intentTypes: z.array(IntentTypeSchema).optional(),
  targetAgents: z.array(z.string()).optional(),
  expiresAt: z.string().datetime(),
  maxMessages: z.number().int().positive().optional(),
  // NEW
  allowedTransports: z.array(InkTransportSchema).optional(),
}),
```

Transport identifiers:

```typescript
const InkTransportSchema = z.enum([
  "ink_http",       // Standard INK HTTP endpoints
  "ink_ws",         // WebSocket INK transport (future)
  "extension_api",  // Product API calls from extensions
  "voice",          // In-app voice (CF Calls / WebRTC)
  "line_phone",     // PSTN phone calls via Telnyx
  "human_review_queue",  // Escalation queue for human review
]);

type InkTransport = z.infer<typeof InkTransportSchema>;
```

#### 1.2 Default behavior and legacy migration

If `allowedTransports` is **omitted**, the effective default depends on a version gate:

- **Tokens issued after this spec ships (v0.3+):** omitted `allowedTransports` defaults to `["ink_http"]`. Implementations MUST NOT treat omission as "all transports allowed."
- **Legacy tokens (pre-v0.3, no `allowedTransports` field):** during the migration window (90 days from deploy), omitted `allowedTransports` defaults to `["ink_http", "extension_api", "voice", "line_phone"]`, matching the set of transports that existed before transport scoping was introduced. After the migration window closes, legacy tokens without `allowedTransports` fall back to `["ink_http"]` only.

**Version gate mechanism:** the delegation token issuance endpoint stamps a `tokenVersion` field (string, e.g. `"0.3"`) on newly issued tokens. Tokens without `tokenVersion` are legacy. The migration window end date is stored as a deployment config constant, not hardcoded in the protocol.

**Migration plan:**
1. Deploy transport scoping with the legacy-permissive default
2. Update all token issuance paths (extension install, delegation grant) to include `allowedTransports` explicitly
3. Monitor audit logs for `transport_scope_violation` events from legacy tokens
4. After 90 days (or when audit logs show zero legacy-token violations for 14 consecutive days), flip the default to `["ink_http"]` only

This avoids breaking existing extension, voice, and phone delegation flows on deploy day while providing a clear path to strict-by-default.

#### 1.3 Verification rule

When verifying a delegation chain, the verifier MUST:

1. Determine the current invocation transport (from request context, not from the message itself)
2. For each hop in the chain, check that the current transport is in that hop's `allowedTransports`
3. If any hop does not include the current transport, reject with reason `transport_scope_violation`

Each hop's `allowedTransports` MUST be a subset of the previous hop's (same attenuation rule as permissions and autonomy tiers). A child delegation cannot add transports the parent didn't allow.

#### 1.4 Rejection reason

Add to the typed rejection enum:

```typescript
"transport_scope_violation"
```

#### 1.5 Audit event

Add audit event type:

```typescript
"transport_scope_violation"
```

Event payload:

```typescript
{
  messageId: string;
  correlationId: string;
  fromDid: string;
  claimedTransport?: string;
  actualTransport: string;
  allowedTransports: string[];
}
```

### Implementation

#### Files modified

| File | Change |
|------|--------|
| `src/models/ink-handshake.ts` | Add `InkTransportSchema`, extend `constraints` |
| `src/crypto/ink.ts` | Chain validation: check transport attenuation |
| `src/middleware/ink-auth.ts` | Tag request context with transport identifier |
| `src/ink/chain-verifier.ts` | Add transport check to `verifyDelegationChain()` |
| `src/models/ink-audit.ts` | Add `transport_scope_violation` event type |
| Agent state/orchestration layer | Pass transport context through to chain verification |

#### Transport identification

The invocation transport is determined by the receiver, not claimed by the sender:

| Context | Transport value |
|---------|----------------|
| Request to `/ink/v1/*` endpoints | `ink_http` |
| Extension API call via product routes | `extension_api` |
| Voice session action | `voice` |
| PSTN call handler | `line_phone` |
| Human review queue resolution | `human_review_queue` |

This MUST be set by the routing layer before delegation chain verification runs. It is never parsed from the inbound message.

#### Backward compatibility

See §1.2 for the version-gated migration plan. During the 90-day migration window, legacy tokens without `allowedTransports` or `tokenVersion` are treated as `["ink_http", "extension_api", "voice", "line_phone"]` to avoid breaking existing flows. New tokens issued after deploy always include explicit `allowedTransports` and `tokenVersion: "0.3"`.

### Tests

| Test | Description |
|------|-------------|
| Token with `allowedTransports: ["ink_http"]` accepted on INK HTTP | Happy path |
| Token with `allowedTransports: ["ink_http"]` rejected on `extension_api` | Transport mismatch |
| v0.3 token with omitted `allowedTransports` defaults to `["ink_http"]` | Strict default for new tokens |
| Legacy token (no `tokenVersion`) defaults to permissive set during migration window | Legacy compat |
| Legacy token defaults to `["ink_http"]` only after migration window closes | Migration complete |
| Token with `["ink_http", "voice"]` accepted on voice | Multi-transport grant |
| Child hop cannot add transport parent didn't allow | Attenuation check |
| Child hop can narrow parent's transport list | Subset OK |
| New tokens include `tokenVersion: "0.3"` | Version stamping |
| Rejection includes `transport_scope_violation` reason | Typed error |
| Audit event emitted on transport violation | Observability |

---

## Slice 2: Capability-Gated Agent Card Discovery

### Problem

Agent Cards at `GET /ink/v1/{agentId}/agent.json` currently return full capability and endpoint details to any requester. This expands the probing surface: an attacker can enumerate capabilities, accepted intents, scheduling endpoints, delegation support, and extension hooks without authentication.

### Wire Changes

#### 2.1 Agent Card `visibility` field

Add to `TulpaAgentCard`:

```typescript
visibility: "public" | "network_only" | "capability_gated" | "private"
```

This replaces the existing `"public" | "network_only" | "private"` enum by adding `capability_gated`.

#### 2.2 Redacted Agent Card

When visibility is `capability_gated`, unauthenticated requests to the Agent Card endpoint receive a redacted response:

```typescript
interface RedactedAgentCard {
  type: "ink.agent.card";  // legacy "tulpa.agent.card" MUST also be accepted during v0.1.x
  version: "1.0";
  agentId: string;
  displayName?: string;
  visibility: "capability_gated";
  supportsInk: true;
  discoveryMode: "authenticate_for_details";
  updatedAt: string;
}
```

Fields NOT included in the redacted card:
- `capabilities`
- `openness`
- `communicationModes`
- `phoneCard`
- `voiceProfileSummary`
- `ownerLink` (if owner has restricted linkage visibility)
- Any governance fields from the containment spec

#### 2.3 Authenticated Agent Card query

New endpoint:

```
POST /ink/v1/{agentId}/agent-card-query
```

Request body:

```typescript
{
  protocol: "ink/0.1";
  type: "network.tulpa.agent_card_query";
  from: string;         // requester DID
  nonce: string;        // replay protection
  timestamp: string;    // freshness
  requestedFields?: string[];  // optional: specific fields requested
}
```

Authentication: standard INK `Authorization: INK-Ed25519 <sig>` header. Signature base follows the same format as all INK requests (protocol + method + path + recipientDid + JCS(body) + timestamp).

Response (if authorized):

```typescript
{
  protocol: "ink/0.1";
  type: "network.tulpa.agent_card_response";
  card: TulpaAgentCard;   // full or field-filtered
  grantedFields: string[];
  timestamp: string;
}
```

Response (if denied):

```typescript
{
  protocol: "ink/0.1";
  type: "network.tulpa.agent_card_denied";
  reason: "unknown_requester" | "insufficient_trust" | "not_connected";
  timestamp: string;
}
```

#### 2.4 Access policy

The agent owner configures which peers see which fields. Recommended tiers:

| Requester relationship | Card detail level |
|----------------------|------------------|
| Not connected, unknown | Redacted card only |
| Known peer (has exchanged at least one message) | Capabilities and openness |
| Connected (mutual connection) | Full card |
| Fleet-managed same-org peer | Full card + governance fields |

The exact policy is implementation-defined. The protocol defines the query mechanism and response shapes; the access decision is local.

#### 2.5 Audit events

Add event types:

```typescript
"discovery_query_received"
"discovery_query_granted"
"discovery_query_denied"
```

Payload:

```typescript
{
  requesterDid: string;
  grantedFields?: string[];
  denyReason?: string;
}
```

### Implementation

#### Files modified

| File | Change |
|------|--------|
| `src/models/ink-handshake.ts` | Add `AgentCardQuerySchema`, `AgentCardResponseSchema`, `AgentCardDeniedSchema` |
| `src/models/ink-audit.ts` | Add discovery audit event types |
| INK route handlers | Add `POST /ink/v1/:agentId/agent-card-query` handler |
| INK route handlers | Modify `GET /ink/v1/:agentId/agent.json` to return redacted card when `capability_gated` |
| Agent state/orchestration layer | Store and serve visibility setting, access policy evaluation |

#### Agent Card endpoint behavior by visibility

Since `GET /ink/v1/{agentId}/agent.json` is unauthenticated, "INK peers only" is not enforceable at the GET layer. The visibility modes therefore define what the unauthenticated GET returns and whether authenticated query is available:

| Visibility | `GET /ink/v1/{agentId}/agent.json` | `POST /ink/v1/{agentId}/agent-card-query` |
|-----------|-----------------------------------|------------------------------------------|
| `public` | Full card | Not needed, but MAY respond with full card |
| `network_only` | **Redacted card** (identity + `supportsInk` + displayName only) | Full card for any authenticated INK peer with valid signature |
| `capability_gated` | Redacted card | Full or filtered card based on access policy (connection tier) |
| `private` | 404 | Responds only to connected peers |

The key difference between `network_only` and `capability_gated`:
- `network_only`: any peer that can produce a valid INK signature gets the full card. The gate is "are you a real INK agent?", authentication only, no authorization.
- `capability_gated`: authenticated peers get filtered results based on relationship tier (unknown → known → connected → same-org). The gate is "what is your relationship to this agent?", authentication plus authorization.

Both modes return the same redacted card on unauthenticated GET. The difference is in the authenticated query's access policy.

#### Recommended default

Per the governance spec:
- Self-sovereign / public-network deployments: `network_only`
- Enterprise / internal deployments: `capability_gated`

The default for new Tulpa agents: `network_only`. This is a **behavior change** from current (which returns a full card on unauthenticated GET). The change is safe because:
- No external INK peers exist yet, there are no consumers of the unauthenticated full card
- The authenticated query endpoint ships in the same deploy, so any future peer can get full details by signing the request
- The redacted card still confirms the agent exists and supports INK, which is sufficient for initial discovery

### Tests

| Test | Description |
|------|-------------|
| `public` visibility returns full card on GET | Existing behavior preserved |
| `network_only` returns redacted card on unauthenticated GET | Probing surface closed |
| `network_only` returns full card on authenticated query from any INK peer | Auth-only gate |
| `capability_gated` returns redacted card on GET | Core redaction |
| `capability_gated` authenticated query from connected peer returns full card | Relationship-gated |
| `capability_gated` authenticated query from unknown peer returns denied | Access control |
| Redacted card includes only safe fields (no capabilities, openness, endpoints) | No capability/endpoint leak |
| Query with invalid/missing signature returns 401 | Auth enforcement |
| Query replay (same nonce) rejected | Replay protection |
| Audit events emitted for query granted/denied | Observability |
| `private` visibility returns 404 on GET | No discovery |

---

## Slice 3: Handshake Flood Resistance

### Problem

The INK handshake is deterministic: intent → challenge → resolution (or rejection). An attacker can:
- Send many valid challenges to exhaust processing budget
- Loop challenge/resolution cycles on the same correlationId
- Flood rejections to suppress legitimate handshakes
- Exploit predictable retry behavior

### Wire Changes

#### 3.1 Per-correlation handshake budgets

For each `correlationId`, recipients MUST enforce:

| Counter | Limit | Description |
|---------|-------|-------------|
| Challenges received | 3 | Max challenges from a single counterparty on one correlationId |
| Rejections received | 1 | Terminal, no further messages accepted |
| Resolutions received | 1 | Terminal, no further messages accepted |
| Total state transitions | 5 | Hard cap on all handshake messages per correlationId |
| Handshake TTL | Intent's `expiresAt` or 24h, whichever is shorter | After expiry, no further messages accepted |

When any limit is hit:
- **First violation** on a given correlationId/sender pair: return a typed rejection with the appropriate reason (`handshake_budget_exhausted`, `sender_rate_limited`) and an optional backoff hint. This tells a well-behaved sender what happened.
- **Subsequent violations** after a typed rejection has already been sent for that correlationId/sender pair: silent drop (no response). This prevents amplification from an attacker who keeps sending after being told to stop.

The budget tracker records whether a typed rejection has been sent per correlationId/sender pair. This is the canonical rule, there is no scenario where a first violation is silently dropped.

#### 3.2 Backoff hints

Add optional metadata to challenge and rejection responses:

```typescript
const InkBackoffHintSchema = z.object({
  retryAfterSeconds: z.number().int().positive().optional(),
  cooldownUntil: z.string().datetime().optional(),
  backoffClass: z.enum(["sender", "intent_ref", "counterparty"]).optional(),
});
```

Semantics:
- `retryAfterSeconds`: sender SHOULD wait at least this many seconds before retrying
- `cooldownUntil`: absolute timestamp after which sender MAY retry
- `backoffClass`:
  - `sender`: this sender is rate-limited (all intents)
  - `intent_ref`: this specific intent/correlationId is rate-limited
  - `counterparty`: the recipient is broadly rate-limiting (overloaded)

Backoff hints are advisory. A sender that ignores them risks harder rejection or silent drops.

#### 3.3 New typed rejection reasons

Add to the rejection reason enum:

```typescript
"handshake_budget_exhausted"  // per-correlation budget hit
"counterparty_cooldown"       // recipient is rate-limiting broadly
"sender_rate_limited"         // this sender is sending too much
"delegation_budget_exhausted" // delegation issuance limit hit
```

These are in addition to existing rejection reasons. The `proof_of_work_required` reason from the governance spec is intentionally NOT implemented in Phase 1.

#### 3.4 Per-sender rate limits

Beyond per-correlation budgets, recipients SHOULD enforce per-sender limits:

| Window | Limit | Scope |
|--------|-------|-------|
| Per minute | 10 new intents | Per sender DID |
| Per hour | 60 new intents | Per sender DID |
| Per minute | 30 handshake messages (all types) | Per sender DID |

These are recommended defaults. Implementations MAY adjust based on trust tier (connected peers get higher limits).

#### 3.5 Audit events

Add event types:

```typescript
"handshake_rate_limited"
"handshake_budget_exhausted"
```

Payload:

```typescript
{
  correlationId: string;
  fromDid: string;
  messageType: string;       // challenge, rejection, resolution
  limitType: "per_correlation" | "per_sender_minute" | "per_sender_hour";
  currentCount: number;
  limit: number;
}
```

### Implementation

#### Files modified

| File | Change |
|------|--------|
| `src/models/ink-handshake.ts` | Add `InkBackoffHintSchema`, new rejection reasons, budget constants |
| `src/models/ink-audit.ts` | Add rate-limit audit event types |
| `src/ink/handshake-budget.ts` | Per-correlation and per-sender budget tracking |
| `src/middleware/ink-auth.ts` | Wire budget checks before handshake processing |
| Agent state/orchestration layer | Initialize budget tracker, connect to handshake pipeline |

#### Budget tracker design

```typescript
interface HandshakeBudgetTracker {
  /** Check and record a handshake message. Returns null if allowed, rejection reason if blocked. */
  checkAndRecord(params: {
    correlationId: string;
    fromDid: string;
    messageType: "intent" | "challenge" | "rejection" | "resolution";
    intentExpiresAt?: string;
  }): {
    allowed: boolean;
    reason?: string;
    backoffHint?: InkBackoffHint;
  };

  /** Prune expired correlation state. Call from maintenance. */
  pruneExpired(): void;
}
```

Storage: in-memory within the per-agent state container. Correlation state is keyed by `correlationId` and tracks message counts and timestamps. Per-sender state is keyed by `fromDid` with sliding window counters.

Memory bounds: max 10,000 active correlations tracked. Oldest entries evicted on overflow (LRU). Per-sender windows use fixed-size circular buffers (60 slots for per-minute, 60 slots for per-hour).

#### Where budget checks run

Budget checks run **after** signature verification but **before** handshake processing:

1. Verify INK auth signature (existing)
2. Parse message type and correlationId
3. `budgetTracker.checkAndRecord(...)`, if rejected, return typed rejection with backoff hint
4. Proceed to handshake processing (existing)

This ordering ensures:
- Unsigned/forged messages never consume budget (no amplification)
- Valid but excessive messages get typed rejections
- Processing resources are protected

#### Silent drop vs. typed rejection

The canonical rule is defined in §3.1: first violation returns a typed rejection with backoff hint; subsequent violations are silent drops. The budget tracker maintains a `rejectionSent: Set<string>` keyed by `${correlationId}:${fromDid}` to distinguish first from subsequent violations.

### Tests

| Test | Description |
|------|-------------|
| 3 challenges on same correlationId accepted | Within budget |
| 4th challenge on same correlationId rejected | Budget exhausted |
| Rejection is terminal, no further messages accepted | Terminal state |
| Resolution is terminal, no further messages accepted | Terminal state |
| Total state transitions capped at 5 | Hard cap |
| Expired handshake rejects new messages | TTL enforcement |
| Per-sender minute rate limit triggers after 10 intents | Sender limit |
| Per-sender hour rate limit triggers after 60 intents | Sender limit |
| Backoff hint included in rejection response | Advisory signaling |
| Second violation after rejection is silent drop | No amplification |
| Budget tracker prunes expired correlations | Memory management |
| LRU eviction at 10k correlations | Memory bounds |
| Audit event emitted on rate limit | Observability |
| Connected peers get higher limits (if configured) | Trust-tier awareness |

---

## Cross-Cutting: Agent Card Governance Fields

All three slices benefit from advertising governance capabilities in the Agent Card. Add to the Agent Card schema:

```typescript
interface InkGovernanceCapabilities {
  maxAcceptedDelegationDepth?: number;
  supportedTransports?: InkTransport[];
  supportsCapabilityGatedDiscovery?: boolean;
  handshakeBudget?: {
    maxChallengesPerCorrelation?: number;
    maxIntentsPerMinute?: number;
  };
}
```

This is added as an optional `governance` field on `TulpaAgentCard`:

```typescript
interface TulpaAgentCard {
  // ... existing fields ...
  governance?: InkGovernanceCapabilities;
}
```

Senders can read the recipient's governance fields to pre-filter behavior (e.g., don't send a delegation chain deeper than `maxAcceptedDelegationDepth`, respect `supportedTransports`).

---

## Implementation Order

```
Step 1: Schema changes, add all new types, enums, audit events
Step 2: Transport-bound authorization (tests first)
  2a. InkTransportSchema, constraints extension
  2b. Transport context tagging in middleware
  2c. Chain verifier transport check
  2d. Audit event emission
Step 3: Handshake flood resistance (tests first)
  3a. HandshakeBudgetTracker with per-correlation and per-sender limits
  3b. Wire into handshake pipeline (after auth, before processing)
  3c. Typed rejections with backoff hints
  3d. Silent drop on repeated violations
  3e. Audit event emission
Step 4: Capability-gated Agent Card discovery (tests first)
  4a. Redacted card generation
  4b. GET endpoint conditional response
  4c. POST agent-card-query endpoint
  4d. Access policy evaluation
  4e. Audit event emission
Step 5: Agent Card governance fields
Step 6: Integration tests, all three slices together
```

Transport-bound authorization is first because it is the simplest wire change and immediately closes the confused-deputy gap. Handshake flood resistance is second because it protects the existing handshake surface. Discovery gating is third because it has more moving parts (new endpoint, access policy) but lower urgency.

---

## Verification

- `npx vitest run test/ink-transport-auth.test.ts`
- `npx vitest run test/ink-handshake-budget.test.ts`
- `npx vitest run test/ink-discovery-gating.test.ts`
- `npx vitest run`, all existing tests still pass
- `npx tsc --noEmit`, no new type errors
- Manual: issue delegation token with `allowedTransports: ["ink_http"]`, verify it is rejected on extension API call
- Manual: set agent visibility to `capability_gated`, verify GET returns redacted card, authenticated query returns full card
- Manual: send 4 challenges on same correlationId, verify 4th is rejected with `handshake_budget_exhausted`

---

## Dependencies

- No external dependencies required
- No new npm packages
- All crypto uses existing `@noble/ed25519` and JCS canonicalization
- Budget tracker is pure in-memory (per-agent state)
