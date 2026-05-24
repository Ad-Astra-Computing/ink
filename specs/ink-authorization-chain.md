# INK v0.3 — Authorization Chain

**Status:** Draft
**Authors:** tulpa core
**Date:** 2026-03-19

## Problem

INK v0.2 has single-hop delegation: a Tulpa issues a delegation token to an extension, and the extension can act on the Tulpa's behalf. The message envelope carries a `provenance` field that claims origin (`human`, `agent_approved`, `agent_autonomous`), but:

1. **No cryptographic proof of delegation** — the `provenance` field is a self-asserted claim. A malicious extension can forge `origin: "human"` on autonomous messages.
2. **No multi-hop chains** — if Extension A delegates to Service B which calls Service C, the recipient sees only the final hop. There's no way to trace the full authorization path.
3. **No recipient-verifiable authorization** — the recipient must trust the sender's provenance claim. The delegation token is between Tulpa↔Extension only; the recipient never sees it.

## Design

### 1. Delegation Proof (replaces self-asserted provenance)

Add a `delegationProof` field to the message envelope that cryptographically binds the delegation chain to the message.

```typescript
DelegationProofSchema = z.object({
  // The delegation token (existing format: payload.signature)
  delegationToken: z.string(),

  // The issuing Tulpa's public key (so recipient can verify the token signature)
  issuerPublicKey: z.string(),

  // Extension's signature over the message ID, binding this proof to this message
  //   signatureBase = messageId + "\n" + intent + "\n" + JCS(payload)
  extensionSignature: z.string(),

  // Extension's public key (from the installation record / manifest)
  extensionPublicKey: z.string(),

  // Origin assertion, now signed by the extension rather than self-asserted
  origin: ProvenanceOriginSchema,
});
```

**Verification by recipient:**

1. Decode the delegation token, verify its Ed25519 signature against `issuerPublicKey`
2. Check that `issuerPublicKey` matches the sender's known public key (from Agent Card or connection store)
3. Verify `extensionSignature` against `extensionPublicKey` to confirm the extension signed this specific message
4. Check that `extensionPublicKey` matches the `publicKeyMultibase` in the delegation token payload
5. Verify the delegation token hasn't expired and permissions/autonomy tier are sufficient for the intent

**Result:** the recipient now has cryptographic proof that:
- The Tulpa owner authorized this extension (delegation token)
- The extension actually produced this message (extension signature)
- The origin claim is bound to the extension's key (not forgeable)

### 2. Multi-Hop Delegation Chains

For cases where Extension A calls Service B which generates the message:

```typescript
DelegationChainSchema = z.object({
  // Ordered list of delegation hops, from Tulpa → final actor
  hops: z.array(DelegationHopSchema).min(1).max(5),
});

DelegationHopSchema = z.object({
  // Who delegated
  delegator: z.string(),  // did:key of delegator
  delegatorPublicKey: z.string(),

  // Who received delegation
  delegate: z.string(),  // did:key or extension ID
  delegatePublicKey: z.string(),

  // Scoped grant for this hop
  permissions: z.array(PermissionSchema),
  maxAutonomyTier: AutonomyTierSchema,
  constraints: z.object({
    intentTypes: z.array(IntentTypeSchema).optional(),
    targetAgents: z.array(z.string()).optional(),
    expiresAt: z.string().datetime(),
    maxMessages: z.number().int().positive().optional(),
    allowedTransports: z.array(z.enum([
      "ink_http", "ink_ws", "extension_api",
      "voice", "line_phone", "human_review_queue",
    ])).optional(),
  }),

  // Delegator's signature over (delegate + permissions + constraints)
  signature: z.string(),
});
```

**Chain validation rules:**
- Each hop's permissions must be a **subset** of the previous hop's permissions (no privilege escalation)
- Each hop's `maxAutonomyTier` must be **≤** the previous hop's tier
- Each hop's `expiresAt` must be **≤** the previous hop's expiration
- Each hop's `allowedTransports` must be a **subset** of the previous hop's transports (transport attenuation — see INK Containment §7)
- Maximum chain depth: 5 hops (prevents unbounded delegation)
- The first hop must be signed by the Tulpa owner's key

**Transport scoping (INK Containment §7):**
- If `allowedTransports` is omitted on a v0.3+ token, it defaults to `["ink_http"]` (least privilege)
- Legacy tokens (no `tokenVersion` field) receive a permissive default of `["ink_http", "extension_api", "voice", "line_phone"]` during a 90-day migration window
- Messages arriving on a transport not in the token's `allowedTransports` are rejected with `transport_scope_violation`

### 3. Envelope Changes

Update `MessageEnvelopeSchema` for v0.3:

```typescript
MessageEnvelopeSchema = z.object({
  protocol: z.literal("tulpa/0.2"),  // bump when implemented
  id: z.string(),
  correlationId: z.string(),
  createdAt: z.string(),
  expiresAt: z.string().optional(),
  from: z.string(),
  to: z.string(),
  intent: IntentTypeSchema,
  payload: z.unknown(),
  signature: z.string(),

  // v0.3: replaces the old `provenance` field
  delegationProof: DelegationProofSchema.optional(),
  delegationChain: DelegationChainSchema.optional(),

  // Deprecated — kept for backward compat during migration
  provenance: MessageProvenanceSchema,
});
```

**Backward compatibility:**
- Recipients that don't understand `delegationProof` fall back to `provenance` (existing behavior)
- Senders include both fields during the migration period
- After migration period, `provenance` becomes optional and `delegationProof` is required for extension-originated messages

### 4. Agent Card Capability Advertisement

Extensions that support chain verification advertise it:

```typescript
capabilities: {
  intentsAccepted: [...],
  intentsSent: [...],
  delegationProof: true,      // "I include delegation proofs on extension messages"
  delegationChainDepth: 2,    // "I support up to 2-hop chains"
}
```

### 5. Autonomy Tier Enforcement

The current `maxAutonomyTier` in the delegation token becomes **enforceable by the recipient**:

| Origin | Required Tier | Recipient Can Verify? |
|--------|--------------|----------------------|
| `human` | any | Yes — extension signature proves the extension saw user input |
| `agent_approved` | `social` or lower | Yes — delegation token tier checked |
| `agent_autonomous` | `transactional` only | Yes — delegation token tier checked |

If the delegation proof shows `origin: agent_autonomous` but the delegation token's `maxAutonomyTier` is `personal`, the recipient rejects the message.

### 6. Revocation

Existing revocation (token hash stored in installation, checked on each request) works for the Tulpa↔Extension hop. For multi-hop chains:

- Each delegator maintains a revocation list (set of revoked delegate keys)
- The `delegationChain` includes a `revocationEndpoint` per hop
- Recipients can optionally check revocation endpoints (non-blocking, cached)
- Revocation is **eventually consistent** — a revoked chain may be accepted for up to the cache TTL (default: 5 min, matching the replay window)

## Migration Path

1. Ship `delegationProof` generation in the extension middleware
2. Ship `delegationProof` verification in `runPipeline` (optional — don't reject messages without it yet)
3. After adoption threshold (e.g. 90% of messages include proofs), make `delegationProof` required for extension-originated messages
4. Deprecate `provenance` field

## Prior Art and Research

This design was validated against established delegation protocols. Key influences:

### UCAN (User Controlled Authorization Networks)
UCAN is the closest analog to INK's delegation model. Both use DID-based identities with Ed25519 signatures and chained capability tokens. Key lessons adopted:

- **Separate delegation from invocation.** UCAN 1.0 distinguishes "I was granted this capability" from "I am now exercising it." INK adopts this: the `delegationToken` is the grant; the `extensionSignature` over the specific message is the invocation. This prevents confused deputy attacks where a delegation token is accidentally replayed as an action.
- **Capability attenuation via partial ordering.** UCAN defines a partial order on capabilities where each hop can only narrow scope. INK uses the same approach: permission-subset checking and autonomy tier ≤ comparison. Given INK already has a flat permission enum (`PermissionSchema`), subset checking is straightforward.
- **CID-referenced vs. inlined proofs.** Early UCANs inlined parent tokens, causing exponential growth. INK avoids this by having each hop carry only its own signature and constraints — the chain is a flat array, not nested tokens.
- **No built-in revocation.** UCAN relies on short-lived tokens rather than revocation infrastructure. INK should adopt the same stance (see Revocation section update below).

### ZCAP-LD (Authorization Capabilities for Linked Data)
W3C CCG's capability system uses additive caveats instead of UCAN's partial order. Each delegation can only ADD restrictions, never remove them. This is simpler to implement but less expressive. INK's permission-subset model is more aligned with UCAN's approach, which better fits the structured permission enum.

### OAuth 2.0 Token Exchange (RFC 8693)
The `act` (actor) and `may_act` (pre-authorization) claims provide a clean representation of "who is acting on behalf of whom." INK adopts this pattern:
- The delegation proof's `origin` + `extensionPublicKey` serves as the `act` claim
- The delegation token itself serves as the `may_act` pre-authorization
- RFC 8693 supports nested `act` claims for multi-hop, which maps to INK's `hops` array

Key difference: RFC 8693 requires a centralized STS (Security Token Service). INK is decentralized — verification is self-contained using the chain signatures.

### SPIFFE/SPIRE
SPIFFE separates identity from authorization entirely. Relevant pattern: **short-lived credentials with automatic rotation** avoid the revocation problem. SPIFFE SVIDs typically expire in hours, not days. INK should adopt this for delegation tokens (see updated recommendation below).

### W3C DID + Verifiable Credentials
INK already uses `did:key` for agent identity, which is the right choice — self-certifying, no resolution infrastructure needed. The DID Document's `capabilityDelegation` verification relationship was designed to support exactly this kind of delegation. INK could optionally reference it for interop with the broader DID ecosystem.

### ActivityPub / AT Protocol
Neither has meaningful delegation chains. ActivityPub bots are independent actors with no protocol-level delegation proof. AT Protocol has scoped app passwords and PDS-mediated service auth (single-hop). INK's delegation chain is a significant advancement over both.

### Design Decisions Informed by Research

| Decision | Rationale | Prior Art |
|----------|-----------|-----------|
| Flat hop array (not nested tokens) | Avoids exponential size growth | UCAN 1.0 CID-referenced proofs |
| Permission subset checking | Fits INK's flat enum model | UCAN partial order |
| Separate delegation from invocation | Prevents confused deputy | UCAN 1.0 delegation/invocation split |
| `origin` bound to extension signature | Prevents origin forgery | RFC 8693 `act` claim binding |
| Short-lived tokens over revocation lists | Simpler, more reliable in decentralized systems | SPIFFE short-lived SVIDs |
| Max 5 hops | 2-3 is typical in practice; 5 allows headroom | No protocol sets a hard limit |

## Updated Recommendations (Post-Research)

### Shorter Token TTLs
Based on SPIFFE's approach and UCAN's lesson that revocation is unsolved in pure capability models:
- **Default TTL: 1-4 hours** (not 48 hours as currently allowed)
- Extensions should auto-renew tokens before expiry
- The `ttlHours` parameter in the token endpoint should cap at 24 hours for standard extensions
- 48-hour tokens should require elevated review status

### Invocation Binding
Adopt UCAN 1.0's delegation/invocation separation explicitly:
- The `delegationToken` proves "I was granted this capability"
- The `extensionSignature` over `messageId + intent + JCS(payload)` proves "I am now exercising it on this specific message"
- Recipients MUST verify both — a valid delegation token alone is not sufficient

## Security Considerations

- **Key rotation:** if a Tulpa rotates keys, outstanding delegation tokens become invalid. Extensions must re-request tokens after key rotation.
- **Stolen extension keys:** the delegation token is scoped (permissions, layers, expiry). A stolen key can only act within the granted scope until the token expires or is revoked. With the recommended 1-4 hour TTL, the exposure window is small.
- **Chain depth attacks:** capped at 5 hops. Each hop strictly narrows scope. No established protocol requires more than 3 in practice.
- **Clock skew:** delegation token expiry uses the same ±5 min window as INK replay protection.
- **Confused deputy:** the delegation/invocation separation (per UCAN 1.0) prevents a delegation token from being misused as a direct action. The extension must produce a fresh signature for each message.
- **Replay of delegation proofs:** the `extensionSignature` binds to a specific `messageId`, so replaying a delegation proof on a different message fails verification.
