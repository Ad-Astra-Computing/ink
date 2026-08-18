# INK Agent Containment and Governance Extension v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-05-24

## Purpose

This specification extends INK with controls for:
- agent containment
- delegation-chain abuse prevention
- handshake flood resistance
- discovery minimization
- transport-bound authorization
- optional fleet-managed enterprise deployments

The goal is to preserve INK’s self-sovereign trust model while addressing operational risks common in agentic systems:
- runaway delegation
- uncontrolled agent spawning
- predictable workflow abuse
- excessive visibility of agent endpoints and capabilities
- ambiguous authorization across multiple transports

This specification complements, but does not replace, the authorization chain framing in [`ink-authorization-chain.md`](./ink-authorization-chain.md) and the auditability surface in [`ink-auditability.md`](./ink-auditability.md).

Core principle:

**INK should remain open enough for trustworthy coordination, while making delegation, visibility, and automation budgets explicit and enforceable.**

---

## 1. Motivation

INK already covers core identity, transport signing, auditability, receipts, authorization chains, and key rotation well.

However, agentic systems are often compromised by failures in operational basics:
- over-broad delegation
- unbounded automation
- ambiguous ownership of spawned agents
- exposure of machine-readable surfaces to unnecessary probing
- weak separation between transports and permission scopes

Recent zero-trust guidance for AI systems continues to emphasize:
- explicit verification
- least privilege
- assume breach
- containment of blast radius
- strong visibility and governance for autonomous actors

INK should therefore strengthen not just identity and audit, but containment and governance.

---

## 2. Design Goals

This extension adds:

1. explicit delegation-depth and issuance-budget controls
2. protocol-level anti-flood rules for handshake and challenge flows
3. optional fleet-managed governance for enterprise deployments
4. discovery minimization and capability-gated Agent Card exposure
5. explicit transport binding for delegation tokens and chain hops

This extension does not attempt to:
- replace Tulpa’s broader abuse-prevention product controls
- require centralized identity for all INK deployments
- make proof-of-work mandatory
- turn INK into an enterprise-only protocol

---

## 3. Threat Model Additions

### 3.1 Runaway delegation
An agent or extension repeatedly delegates or spawns child actors that continue acting within inherited scope.

### 3.2 Handshake flooding
An attacker sends large volumes of validly signed challenges, rejections, or low-value handshake loops to consume resources or suppress legitimate traffic.

### 3.3 Discovery probing
An attacker enumerates Agent Cards, capabilities, endpoints, or public-facing metadata to map the network or plan exploitation.

### 3.4 Cross-transport confused deputy
A token intended only for INK HTTP use is replayed or reused in another channel such as a product API, extension callback, voice workflow, or fleet broker.

### 3.5 Fleet compromise blast radius
In enterprise or managed deployments, a central provisioning layer is compromised or misconfigured, causing broad misissuance or delayed revocation.

---

## 4. Containment Model

### 4.1 Delegation depth
INK already limits authorization-chain hop count. This extension adds explicit issuer and recipient policy signals for delegation depth.

Add the following optional Agent Card fields:

```ts
interface InkGovernanceCapabilities {
  maxIssuedDelegationDepth?: number
  maxAcceptedDelegationDepth?: number
  maxDelegationIssuancePerHour?: number
  supportsCapabilityGatedDiscovery?: boolean
  supportsFleetManagement?: boolean
  supportedTransports?: InkTransport[]
}

type InkTransport =
  | "ink_http"
  | "ink_ws"
  | "extension_api"
  | "voice"
  | "line_phone"
  | "human_review_queue"
```

Semantics:
- `maxIssuedDelegationDepth`: maximum downstream depth this agent will issue
- `maxAcceptedDelegationDepth`: deepest chain this agent will accept
- `maxDelegationIssuancePerHour`: optional self-advertised issuance budget

Recipients MUST apply the lower of:
- protocol global maximum
- local recipient policy
- sender-advertised accepted maximum when relevant

### 4.2 Delegation issuance budgets
Delegation issuance SHOULD be rate-limited both locally and, when present, by fleet policy.

Recommended defaults:
- low-trust agents: 5 issuances/hour
- standard trusted agents: 30 issuances/hour
- reviewed enterprise agents: deployment-specific

These are not mere implementation hints. The protocol should support communicating budget exhaustion via typed rejection.

Add new rejection reason:
- `delegation_budget_exhausted`

### 4.3 Child-agent containment
If an implementation allows an agent to provision or invoke a subordinate agent or service actor, that actor MUST NOT implicitly inherit the parent’s full authority.

Any spawned actor MUST receive:
- its own identity
- its own scoped authorization proof or token
- an explicit transport list
- its own expiry
- auditable linkage to the parent actor

Implicit credential copying or silent credential inheritance is prohibited.

---

## 5. Handshake Flood Resistance

### 5.1 Rationale
The INK handshake is intentionally structured and predictable. That is desirable for interop, but it also means attackers can target deterministic flows.

INK should therefore define protocol-level flood resistance rather than leaving it entirely to per-implementation heuristics.

### 5.2 Per-correlation budget
For a given `intentRef` or `correlationId`, recipients SHOULD enforce:
- maximum challenge count
- maximum rejection count
- maximum total state transitions
- expiry window after which no more handshake messages are accepted

Recommended defaults:
- max 3 challenges per `intentRef`
- max 1 rejection terminal event
- max 1 resolution terminal event
- handshake TTL no longer than the original intent expiry

### 5.3 Retry-after signaling
Add optional rejection metadata:

```ts
interface InkBackoffHint {
  retryAfterSeconds?: number
  cooldownUntil?: string
  backoffClass?: "sender" | "intent_ref" | "counterparty"
}
```

This metadata MAY appear in challenge or rejection responses where the recipient wants the sender to pause.

### 5.4 New rejection reasons
Add the following standardized reasons:
- `handshake_budget_exhausted`
- `counterparty_cooldown`
- `sender_rate_limited`
- `proof_of_work_required`

### 5.5 Proof-of-work
Proof-of-work MAY be supported as an optional extension in hostile or public-open deployments, but MUST NOT be mandatory for baseline INK interoperability.

Reason:
- it increases implementation complexity
- it complicates mobile and low-power clients
- it is unnecessary for many trusted-network deployments

The preferred baseline defenses are:
- stateful budgets
- cooldowns
- rate limits
- typed backoff
- trust-tier gating

---

## 6. Discovery Minimization

### 6.1 Problem
Publicly discoverable Agent Cards are useful, but they also expand the probing surface.

INK should support more granular discoverability than simply public vs private.

### 6.2 Agent Card visibility classes
Add optional Agent Card visibility states:

- `public`
- `network_only`
- `private`
- `capability_gated`

`capability_gated` means:
- the existence of the agent may be known
- detailed capabilities, endpoints, and accepted intents are only revealed to authenticated peers meeting local policy

### 6.3 Redacted Agent Card
For capability-gated discovery, implementations SHOULD support a redacted card variant.

Example:

```ts
interface RedactedAgentCard {
  id: string
  displayName?: string
  visibility: "capability_gated"
  publicHandle?: string
  supportsInk: true
  discoveryMode: "authenticate_for_details"
}
```

Detailed fields such as:
- intents accepted
- transports
- scheduling endpoints
- delegation/gov capabilities
- extension hooks

SHOULD only be disclosed after authenticated discovery.

### 6.4 Authenticated discovery
Capability-gated discovery SHOULD use a signed authenticated request.

Endpoint:
- `POST /ink/v1/{agentId}/agent-card-query`, the path pinned by
  [`ink-containment-phase1-implementation-spec.md`](ink-containment-phase1-implementation-spec.md)

Request body:
- requester DID
- nonce
- timestamp
- requested fields or capabilities

The response MAY:
- deny
- return a redacted card
- return a scoped detailed card

### 6.5 Privacy defaults
Recommended defaults:
- self-sovereign/public-network deployments: `network_only`
- enterprise-managed/internal deployments: `capability_gated`

---

## 7. Transport-Bound Authorization

### 7.1 Problem
Delegation tokens and authorization proofs should not be reusable across arbitrary channels.

### 7.2 Transport constraints
Extend authorization-chain hop constraints with `allowedTransports`.

```ts
constraints: {
  intentTypes?: string[]
  targetAgents?: string[]
  expiresAt: string
  maxMessages?: number
  allowedTransports?: InkTransport[]
}
```

Verification rule:
- if the current invocation transport is not in `allowedTransports`, the message MUST be rejected

### 7.3 Transport identifiers
The following transport identifiers are standardized:
- `ink_http`
- `ink_ws`
- `extension_api`
- `voice`
- `line_phone`
- `human_review_queue`

Future transports MUST define:
- a stable identifier
- invocation semantics
- audit expectations

### 7.4 Defaults
If `allowedTransports` is omitted:
- the default MUST be `["ink_http"]` for INK-native delegation
- implementations MUST NOT interpret omission as “all transports allowed”

This is intentionally strict.

### 7.5 Audit requirements
Audit records SHOULD include the invocation transport for delegated actions.

This helps distinguish:
- INK-native actions
- extension callbacks
- voice-triggered actions
- human-review-queue escalations

---

## 8. Fleet-Managed Enterprise Mode

### 8.1 Purpose
Some deployments need a central lifecycle layer for:
- agent provisioning
- policy enforcement
- offboarding
- org-wide revocation

INK SHOULD support this without making self-sovereign mode second-class.

### 8.2 Fleet management descriptor
Add optional Agent Card section:

```ts
interface FleetManagementInfo {
  mode: "self_sovereign" | "fleet_managed"
  orgId?: string
  brokerDid?: string
  revocationEndpoint?: string
  policyEndpoint?: string
}
```

### 8.3 Fleet broker responsibilities
A fleet broker MAY:
- issue managed agent cards
- publish org-level policies
- revoke agent participation
- publish org-scoped trust metadata
- require stricter transport/channel controls

A fleet broker MUST NOT silently rewrite historical signed artifacts.

### 8.4 Offboarding
For fleet-managed mode, offboarding SHOULD support:
- immediate key revocation or retirement
- revocation of outstanding delegation grants
- publication of agent inactive state
- optional org-signed deprovision receipt

### 8.5 Recipient policy
Recipients MAY treat fleet-managed peers differently, for example:
- requiring fleet metadata for enterprise-only workflows
- honoring org revocation feeds
- applying org-scoped trust rules

---

## 9. Wire and Schema Changes

### 9.1 Agent Card
Extend Agent Card governance/capability sections with:
- `maxIssuedDelegationDepth`
- `maxAcceptedDelegationDepth`
- `maxDelegationIssuancePerHour`
- `supportedTransports`
- `visibility`
- `supportsCapabilityGatedDiscovery`
- `fleetManagement`

### 9.2 Rejection schema
Extend typed rejections with:
- `delegation_budget_exhausted`
- `handshake_budget_exhausted`
- `counterparty_cooldown`
- `sender_rate_limited`
- `proof_of_work_required`

and optional:
- `retryAfterSeconds`
- `cooldownUntil`
- `backoffClass`

### 9.3 Authorization chain constraints
Add:
- `allowedTransports`

### 9.4 Audit events
Recommended new audit event types:
- `delegation_issued`
- `delegation_budget_exhausted`
- `handshake_rate_limited`
- `discovery_query_denied`
- `discovery_query_granted`
- `transport_scope_violation`
- `fleet_deprovisioned`

---

## 10. Verification Rules

Recipients implementing this extension SHOULD verify:

1. delegation chain depth <= recipient policy
2. delegation chain depth <= any sender-issued maximum if relevant
3. issuance budget not exceeded for governed flows
4. handshake per-correlation budgets not exceeded
5. invocation transport is allowed by the delegation chain
6. requested Agent Card details are allowed for the authenticated requester
7. fleet metadata, if required by local policy, is present and valid

Failures SHOULD map to typed, auditable rejection reasons rather than silent drops when safe to do so.

---

## 11. Rollout Plan

### 11.1 Phase 1: Advisory signals
- add Agent Card governance fields
- add transport constraint field
- add typed rejection reasons
- emit audit events

### 11.2 Phase 2: Local enforcement
- enforce `allowedTransports`
- enforce handshake budgets
- enforce capability-gated discovery for opted-in agents

### 11.3 Phase 3: Enterprise mode
- add fleet broker descriptors
- support org-wide deprovision and revocation feeds
- add enterprise policy docs and examples

### 11.4 Phase 4: Interop hardening
- add test vectors
- add compliance checklist entries
- run self-sovereign vs fleet-managed interop tests

---

## 12. Security Considerations

### 12.1 Delegation budgets are containment, not identity
These controls reduce blast radius but do not replace strong identity verification.

### 12.2 Discovery minimization is not secrecy
Capability-gated discovery reduces unnecessary exposure, but a determined peer may still infer the existence of an agent through other means.

### 12.3 Fleet management increases central leverage
Enterprise mode adds governance power, but also concentrates risk. Implementations SHOULD treat fleet brokers as high-value security boundaries.

### 12.4 Rate limits must not create easy reflection attacks
Backoff hints SHOULD be modest and auditable. Implementations SHOULD avoid letting an attacker cause broad counterparty suppression through spoofed or unauthenticated messages.

### 12.5 Transport scoping must be strict by default
If transport omission is interpreted loosely, this extension fails. Omission must resolve to narrow default scope, not broad scope.

---

## 13. Open Questions

- Should `capability_gated` discovery become the default for Agent Cards, or remain opt-in?
- Should proof-of-work ever be standardized beyond an optional extension?
- Should enterprise revocation feeds be pull-only, push-capable, or both?
- Should delegation issuance budgets be discoverable publicly, privately, or not at all?
- Should fleet-managed mode define an org-level Agent Card schema, or remain a per-agent add-on?

---

## Appendix A: Research Notes

The following external sources informed this extension:

- Techzine, “Securing agentic AI is still about getting the basics right”  
  Link: https://www.techzine.eu/blogs/security/140064/securing-agentic-ai-is-still-about-getting-the-basics-right
- Microsoft Security, Zero Trust strategy overview  
  Link: https://www.microsoft.com/en-us/security/business/zero-trust
- Microsoft Security Blog, “New tools and guidance: Announcing Zero Trust for AI”  
  Link: https://www.microsoft.com/en-us/security/blog/2026/03/19/new-tools-and-guidance-announcing-zero-trust-for-ai/
- Microsoft Security Blog, “Microsoft extends Zero Trust to secure the agentic workforce”  
  Link: https://www.microsoft.com/en-us/security/blog/2025/05/19/microsoft-extends-zero-trust-to-secure-the-agentic-workforce/

Summary:
- agentic systems still fail on ordinary access-control and containment mistakes
- identity and signing are necessary but not sufficient
- least privilege must include transport, lifecycle, and visibility controls
- enterprise deployments often need stronger lifecycle and offboarding governance than purely self-sovereign mode provides
