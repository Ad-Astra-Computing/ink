# Threat Model

This document describes what INK v0.1 aims to protect against and what it
does not. It is deliberately conservative. Treat every "not protected"
statement as a real limit of the current design.

## In-scope protections

### 1. Request authenticity
A signed INK message cannot be forged without one of the sender's currently
accepted signing keys under the key-rotation authority rule: any `active`
or `retired` key inside the validity window verifies, revoked keys never
verify. Endpoints that require a still-trusted key (writes, capability
grants) can pass `requireActiveKey: true` to `verifyInkAuth` to reject
retired-key signatures. The signing base covers method, path, recipient
DID, canonical JSON of the body, and timestamp; an attacker who can
replay body bytes but mutate any of those fields cannot produce a valid
signature.

### 2. Replay protection (narrow window)
Each INK message body carries a `nonce` and `timestamp` (the latter is
also covered by the signing base). Receivers reject any timestamp more
than 5 minutes old or more than 30 seconds in the future (clock-skew
tolerance). Within that window, nonces are single-use per (sender,
receiver), a nonce that was already accepted is rejected. This means a
captured message can only be replayed within ~5 minutes on a receiver
that has not seen its nonce. Two enforcement paths are available:
`verifyInkAuth` enforces nonce single-use after signature verification
when passed a `NonceStore`; passing `"deferred"` is an explicit
acknowledgement that the caller will run `checkReplay` (or an
equivalent gate) elsewhere in the pipeline. Omitting `nonceStore`
returns `nonce_handling_required` so misconfigured deployments fail
loudly. Nonce backing storage and TTL policy are the integrator's
choice.

### 3. Key rotation authority
See [`key-rotation-rule.md`](./key-rotation-rule.md). Revoked keys can
never verify. Retired keys can verify only during grace periods. The Card
signing set wins over locally-cached copies. Bootstrap keys are
first-contact only.

### 4. Authorization chain integrity
A delegation from agent A to agent B is signed by A over A's identity,
B's identity, and the allowed scope. B cannot invent authorization B was
not given. See
[`../specs/ink-authorization-chain.md`](../specs/ink-authorization-chain.md).

### 5. Receipt / audit envelope integrity
Delivery and read receipts are Ed25519-signed by the agent that issued
them. A receiver that stores receipts for audit can later prove the
counterparty acknowledged delivery without needing to trust INK itself.
Receipts do not verify using `revoked` keys.

### 6. Capability-gated Agent Card discovery
An agent whose Card visibility is `network_only` or `capability_gated`
returns a redacted Card to anonymous queries. The redacted Card preserves
public signing keys (so rotation discovery still works) but hides
capabilities, endpoints, availability and profile.

### 7. Handshake-budget DoS resistance
Per-sender and per-recipient budgets throttle how many failing handshakes
an unknown sender can force a recipient to process. Over-budget senders
receive a signed backoff hint; persistently abusive senders are
rate-limited at the transport layer.

## Out of scope (known limits)

### Identity proof
INK does not prove *who* an agent is in the real world. Identity-system
compromise (a malicious PDS returning a fabricated DID document, a
compromised registration service) is the identity system's problem.
Receivers authenticate *the cryptographic continuity* of a senderId ↔
Agent Card binding; they cannot authenticate that the human behind the
agent is who they claim.

### Compromised endpoints
If a sender's private keys are exfiltrated, an attacker can sign anything
the legitimate sender could until the key is revoked. INK's rotation rule
bounds the damage window but does not eliminate it. Key custody is out of
scope.

### Malicious marketplace extensions (if you integrate one)
The library does not include an extension/marketplace
layer. A product that integrates INK and adds a delegation-token layer
(for third-party agents to act on behalf of users) must design its own
trust model for the marketplace, manifest review, and capability
attenuation. INK v0.1 deliberately excludes this surface.

### Timing side-channels
`@noble/ed25519` is believed to be constant-time, but this has not been
independently audited in the INK context. Attacks that rely on very
precise timing of verification against a candidate key set are not
currently mitigated beyond what the underlying library provides.

### Traffic analysis
INK messages reveal their type, sender, recipient, and approximate size
even when the payload is encrypted (`ink_encrypted`). A passive observer
on the network path can enumerate agent relationships over time. Mixnets,
onion routing, and other unlinkability mechanisms are not part of INK.

### Side-channels in the agent itself
An agent that signs an INK message has seen the full plaintext. If the
agent is compromised, no amount of INK-layer protection helps. This is
especially important for agents that delegate to LLMs, prompt-injection
attacks against the agent's model can result in INK messages that are
cryptographically valid but semantically wrong (the model sent what the
attacker coaxed, not what the user wanted). INK does not address this.

### Audit finality
INK supports witness submission for tamper-evident audit logs (see
[`../specs/ink-auditability.md`](../specs/ink-auditability.md)), but
does not by itself provide consensus or finality. Two honest receivers
that disagree about a message's receipt status cannot be reconciled by
INK alone.

### Denial of service at the TCP/IP layer
INK's handshake budget protects against L7 DoS from known-pending senders.
It does not protect against L3/L4 floods, resource-exhaustion attacks on
the HTTP stack, or amplification attacks. Those remain the transport
operator's responsibility.

### Cryptographic primitives
Ed25519 signatures, X25519 key exchange, AES-GCM for payload encryption.
If any of those primitives fails (future quantum attacks, implementation
flaws in `@noble/*` libraries), INK v0.1 has no fallback. A v1.0 might
specify algorithm agility.

## Assumptions the protocol relies on

- TLS to the transport endpoint is correctly configured. INK signs at
  the application layer but assumes confidentiality during transport.
- Server clocks are within 5 minutes of real time. Both the ±5-minute
  timestamp window and the nonce TTL depend on this.
- The identity-system `senderId → Agent Card` resolution returns the
  current Card within acceptable latency (receivers may cache with a
  reasonable TTL, typically minutes).
- Receivers persist nonces durably enough to enforce the no-replay
  window. A receiver that loses its nonce cache during a restart MAY see
  duplicate accepts, this is a transient failure, not a protocol break.

## Recommended receiver defaults

| Setting                          | Default                |
|----------------------------------|------------------------|
| Timestamp max age                | 5 minutes              |
| Timestamp future skew tolerance  | 30 seconds             |
| Nonce TTL                        | 10 minutes             |
| Agent Card cache TTL             | 5 minutes              |
| Unknown-sender handshake budget  | 20 per hour per sender |
| Retired-key acceptance grace     | Up to 30 days          |
