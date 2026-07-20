# Threat Model

This document describes what INK aims to protect against and what it does not.
It is deliberately conservative. Treat every "not protected" statement as a real
limit of the current design.

INK has not undergone an independent security audit. It has been through
structured internal review. Do not describe or adopt INK as "audited" or
"hardened" on that basis (see [`../SECURITY.md`](../SECURITY.md) and
[`maturity.md`](./maturity.md)).

## Scope

This model covers the current wire, `ink/0.2`, a backward-compatible minor over
`ink/0.1`. Both are major version 0. `ink/0.2` changes only the body-signature
domain separator, from the legacy `tulpa/sign` to the neutral `ink/sign`, and is
receiver-first: a sender emits `ink/0.1` unless the receiver has advertised
`ink/0.2` in its Agent Card `supportedProtocolVersions`. Everything else, the
transport-auth signature base, the envelope shape, encryption, receipts and
audit, is identical across the two. See
[`../specs/ink-compatibility-policy.md`](../specs/ink-compatibility-policy.md).

The surfaces in scope:

- Transport authentication and replay protection (core INK auth).
- Key rotation authority ([`key-rotation-rule.md`](./key-rotation-rule.md),
  [`../specs/ink-key-rotation-spec.md`](../specs/ink-key-rotation-spec.md)).
- Payload encryption
  ([`../specs/ink-payload-encryption.md`](../specs/ink-payload-encryption.md)).
- Signed-string canonicalization safety
  ([`../specs/ink-signed-string-safety.md`](../specs/ink-signed-string-safety.md)).
- Agent Card discovery, the SSRF gate on card fetch
  ([`../specs/ink-private-hostname.md`](../specs/ink-private-hostname.md)) and
  capability-gated visibility.
- Receipts, bilateral auditability and third-party witnessing
  ([`../specs/ink-auditability.md`](../specs/ink-auditability.md)).
- Authorization grants and Sign in with INK, added since v0.1
  ([`../specs/ink-authorization-grant.md`](../specs/ink-authorization-grant.md),
  [`../specs/ink-agent-authorization.md`](../specs/ink-agent-authorization.md)).
- Multi-hop delegation chains, a draft extension
  ([`../specs/ink-authorization-chain.md`](../specs/ink-authorization-chain.md)).
- Containment, governance and the fleet-broker profile, a draft extension
  ([`../specs/ink-agent-containment-and-governance-extension-spec.md`](../specs/ink-agent-containment-and-governance-extension-spec.md)).
- Version and wire-namespace negotiation (`ink/0.1` to `ink/0.2`,
  `network.tulpa.*` to `network.ink.*`).

## Assets

These are the things INK is trying to keep sound. Each in-scope protection and
each known limit below is best read as "what happens to one of these assets".

1. **Agent signing private keys.** The Ed25519 keys that authenticate transport
   requests, receipts, audit events, delegation grants and challenges. Their
   compromise lets an attacker sign as the agent.
2. **Agent encryption private keys.** The static X25519 keys that decrypt
   `network.tulpa.encrypted` payloads. See the forward-secrecy limit below:
   these are static, so their compromise is more damaging than a signing-key
   compromise.
3. **The `agentId` to Agent Card key binding.** The claim that a given logical
   agent identity is authoritatively represented by the signing and encryption
   keys published in its Card. Every verification decision rests on this binding
   being honest.
4. **Audit-chain integrity.** The per-agent hash chain (`previousEventHash` plus
   monotonic `sequence`) and the receipts and witness inclusion proofs that hang
   off it. The asset is the property that a recorded history cannot be silently
   rewritten or forked without detection.
5. **Authorization grants and delegation grants.** Signed, scoped, short-lived
   capability artifacts. Inside their window they are bearer artifacts, so the
   asset is their confidentiality in transit and their binding to one audience,
   one subject and (for sign-in) one nonce-bound context.
6. **The replay state (nonce cache and grant seen-set).** The receiver-side
   record of `(sender, receiver)` nonces and `(issuer, grantId)` pairs that
   makes a message or a grant single-use. This is receiver state, not a signed
   field, so its atomicity and durability are the asset.
7. **Discovery minimization.** For capability-gated agents, the non-public Card
   fields (capabilities, endpoints, availability, profile) that a redacted Card
   withholds from anonymous queries.
8. **The witness Merkle tree.** For deployments that use a third-party audit
   service, the append-only tree whose inclusion and consistency proofs the
   witness signs.

## Trust boundaries

INK verifies at the application layer but depends on parties it does not fully
control. Each boundary is a place where a compromise moves an attacker inside
one or more assets above.

- **The registry / PDS / identity system.** Resolves `senderId` to a DID
  document and, transitively, to an Agent Card. INK authenticates the
  cryptographic continuity of the `agentId` to Card binding, it does not
  authenticate the resolver. A malicious or compromised resolver is out of scope
  and can substitute keys (see the unsigned-card limit below).
- **The TLS terminator.** INK signs at the application layer but assumes
  transport confidentiality and integrity from TLS. The SSRF gate
  ([`../specs/ink-private-hostname.md`](../specs/ink-private-hostname.md)) is a
  static-literal classifier only, so the terminator and the connecting platform
  also own connect-time IP pinning against DNS rebinding.
- **The witness / third-party audit service.** A semi-trusted party, not an
  arbiter. It cannot forge events that verifiers accept (per-event
  `agentSignature` is re-checked) and cannot modify events without breaking
  Merkle proofs, but it can suppress events, be unavailable and equivocate to a
  single access-controlled requester. See §7 of
  [`../specs/ink-auditability.md`](../specs/ink-auditability.md).
- **The fleet broker.** In fleet-managed deployments a central provisioning
  layer issues managed Cards, publishes policy and revokes participation. It
  concentrates risk: a compromised broker can misissue broadly or delay
  revocation. It MUST NOT silently rewrite historical signed artifacts. Treat it
  as a high-value security boundary. See
  [`../specs/ink-agent-containment-and-governance-extension-spec.md`](../specs/ink-agent-containment-and-governance-extension-spec.md)
  §8 and §12.3.
- **The relying-party sign-in context.** For Sign in with INK over an
  unauthenticated carrier (a browser redirect) there is no authenticated
  presenter, so the RP's binding of a nonce to a browser session or carrier
  context is the boundary that stops a stolen grant from being replayed. See
  [`../specs/ink-agent-authorization.md`](../specs/ink-agent-authorization.md).

## Adversaries

- **Passive network observer.** Sees message type, sender, recipient and
  approximate size even under payload encryption, and can enumerate agent
  relationships over time. Not defended against (traffic analysis, below).
- **Active MITM / hostile resolver.** Can substitute an Agent Card over the
  identity path or a compromised TLS terminator, swapping keys and silently
  downgrading version negotiation. Bounded only by TLS and registry honesty
  (unsigned-card limit, below).
- **Malicious counterparty agent.** A legitimate peer that lies: forges
  self-asserted provenance, maintains split-view audit chains or presents a
  fabricated but internally consistent history.
- **Compromised endpoint.** An attacker holding an agent's private keys signs
  anything the agent could until revocation. Key custody is out of scope.
- **Unknown-sender flooder.** Drives failing handshakes, challenge floods or
  delegation-issuance abuse to exhaust a recipient or suppress legitimate
  traffic.
- **Curious or malicious witness.** Tries to suppress, equivocate or fabricate
  audit entries.
- **Compromised fleet broker.** Misissues managed identity or delays org-wide
  revocation.
- **Phishing relying party.** Impersonates a legitimate RP to collect a sign-in
  or coax a capability grant.
- **Grant thief.** Captures grant bytes inside their short validity window and
  tries to present them.
- **Future cryptanalytic adversary.** A quantum attacker or a party with a
  SHA-256 or Ed25519 break. INK has no migration path (agility limit, below).

## In-scope protections

### 1. Request authenticity

A signed INK message cannot be forged without one of the sender's currently
accepted signing keys. The key-rotation authority rule (at the
`verifyInkSignatureWithKeys` primitive) accepts any `active` or `retired` key
inside its validity window and never accepts a revoked key, so retired keys
remain usable for historical-artifact verification. Live transport auth is
stricter: `verifyInkAuth` rejects retired-key signatures by default
(`retired_key_for_live_auth`), so a stolen retired key (which the authority rule
would otherwise let verify within its window, and indefinitely when it has no
`validUntil`) cannot authenticate fresh requests. A caller that wants a rotation
grace window for live traffic opts out with `requireActiveKey: false`. The
signing base covers method, path, recipient DID, canonical JSON of the body and
timestamp; an attacker who can replay body bytes but mutate any of those fields
cannot produce a valid signature. Replay of an unmodified signed request is
bounded by the freshness window and a single-use nonce; the `NonceStore` SHOULD
implement the atomic `addIfAbsent` so two concurrent replays cannot both pass on
a distributed store.

Under `ink/0.2` the body-signature domain (`ink/sign`) is selected from the
signed `protocol` field. Because `protocol` is inside the signed body, a
relabelled message fails verification, and an `ink/0.1`-only receiver never
receives `ink/0.2` traffic because the change is receiver-first.

### 2. Replay protection (narrow window)

Each INK message body carries a `nonce` and `timestamp` (the latter is also
covered by the signing base). Receivers reject any timestamp more than 5 minutes
old or more than 30 seconds in the future (clock-skew tolerance). Within that
window, nonces are single-use per `(sender, receiver)`, a nonce that was already
accepted is rejected. This means a captured message can only be replayed within
~5 minutes on a receiver that has not seen its nonce. Two enforcement paths are
available: `verifyInkAuth` enforces nonce single-use after signature
verification when passed a `NonceStore`; passing `"deferred"` is an explicit
acknowledgement that the caller will run `checkReplay` (or an equivalent gate)
elsewhere in the pipeline. Omitting `nonceStore` returns
`nonce_handling_required` so misconfigured deployments fail loudly. Nonce
backing storage and TTL policy are the integrator's choice.

### 3. Key rotation authority

See [`key-rotation-rule.md`](./key-rotation-rule.md) and
[`../specs/ink-key-rotation-spec.md`](../specs/ink-key-rotation-spec.md). Revoked
keys can never verify, even for artifacts whose timestamp predates `revokedAt`,
because a pre-revocation artifact cannot be distinguished from a forgery made
after compromise. Retired keys verify only for historical artifacts inside their
window, never for live auth. The Card signing set wins over locally-cached
copies. Bootstrap keys are first-contact only, and once a `keys.signing` set is
published the legacy top-level `publicKeyMultibase` is not a verification
fallback. Window-field presence is semantic: a `validFrom`, `validUntil` or
`revokedAt` that appears at all constrains the key even when its value is empty
or malformed, which removes the "no constraint versus a constraint the producer
failed to express" ambiguity an attacker could otherwise exploit. A malformed
window invalidates only that candidate key, so one bad historical entry cannot
block a usable key.

### 4. Canonicalization safety

A signed body is canonicalized with JCS (RFC 8785) and the canonical bytes are
signed, so two implementations that canonicalize the same body to different
bytes disagree on the signature, which is a consensus failure. INK closes the
two known divergences before the JSON is parsed: a lone UTF-16 surrogate escape
and any raw bytes that are not valid UTF-8 are both rejected on the raw body,
before parse, canonicalization or verification, because a parser that has
already rewritten either to `U+FFFD` cannot recover the original. See
[`../specs/ink-signed-string-safety.md`](../specs/ink-signed-string-safety.md).
The JCS number profile bans values whose canonical form is ambiguous across
serializers.

### 5. Payload encryption integrity

`network.tulpa.encrypted` payloads use ECIES: an ephemeral X25519 agreement,
HKDF-SHA256 and AES-256-GCM with the outer envelope bound as AAD. A ciphertext
is rejected on an all-zero shared secret (a low-order ephemeral key that would
derive a publicly known AES key), on any tamper of an AAD-bound field and when
the AAD-recomputed `recipientKey` does not match, so a ciphertext encrypted for
a different recipient fails the tag. The decrypted inner `from` must equal the
outer `from`, and a recipient DID is mandatory and must equal the inner `to`,
which binds the message when one X25519 key backs more than one alias. See
[`../specs/ink-payload-encryption.md`](../specs/ink-payload-encryption.md).
Confidentiality only, not forward secrecy: see the limit below.

### 6. Authorization-chain integrity

A delegation from agent A to agent B is signed by A over A's identity, B's
identity and the allowed scope. B cannot invent authorization it was not given.
The multi-hop draft
([`../specs/ink-authorization-chain.md`](../specs/ink-authorization-chain.md))
adds recipient-verifiable rules a reader of this document should not
under-count:

- Each hop's permissions MUST be a subset of the previous hop's, its
  `maxAutonomyTier` MUST be less than or equal to the previous tier, its
  `expiresAt` MUST be less than or equal to the previous expiry and its
  `allowedTransports` MUST be a subset of the previous hop's. No hop can escalate.
- Chain depth is capped at 5 hops, and the first hop MUST be signed by the
  owner's key.
- Delegation and invocation are separated (per UCAN 1.0): the delegation token
  proves the grant, a fresh `extensionSignature` over `messageId + intent +
  JCS(payload)` proves this specific message, and a recipient MUST verify both.
  This is the confused-deputy defense and makes a delegation proof
  non-replayable onto a different message.
- Origin (`human`, `agent_approved`, `agent_autonomous`) is bound to the
  extension signature rather than self-asserted, so it is not forgeable, and the
  recipient enforces the required autonomy tier.
- Transport is bound: a message arriving on a transport not in the token's
  `allowedTransports` is rejected with `transport_scope_violation`, and omission
  defaults to least privilege, never "all transports".
- Revocation is eventually consistent (short-TTL tokens plus per-hop revocation
  endpoints), so the recommended defense is short 1-to-4-hour token lifetimes
  rather than a revocation list.

### 7. Authorization grants and Sign in with INK

The grant primitive
([`../specs/ink-authorization-grant.md`](../specs/ink-authorization-grant.md))
is a scoped, signed, short-lived capability. Its signature binds `audience`,
`subject`, `scope`, `grantId`, `issuedAt` and `expiresAt`, so a tampered,
broadened or redirected grant fails the signature, not a later context check.
The protections a reader should not under-count:

- **Audience binding** is the confused-deputy defense: a grant minted for one
  service is not presentable at another.
- **Presentation binding.** Within its window a grant is a bearer artifact.
  Where the transport authenticates the presenter, a presenter that is not the
  signed `subject` is rejected. Over an unauthenticated carrier the audience
  MUST bind presentation out of band, and grant bytes MUST stay confidential in
  transit, exposed only to the subject and issuer.
- **Short window is the primary revocation control**, capped normatively at ten
  minutes. Explicit revocation is a receiver-side denylist keyed by
  `(issuer, grantId)`, the same shape as the replay seen-set. Keying on the pair
  rather than `grantId` alone keeps one issuer's ids from colliding with
  another's.
- **Replay** is receiver state: the accepted `(issuer, grantId)` pair MUST be
  recorded atomically with acceptance as a single check-and-insert, so two
  concurrent presentations cannot both pass.
- **Scope is opaque and default-deny.** An unknown token grants nothing, and a
  token minted for one audience carries no authority at another.

Sign in with INK
([`../specs/ink-agent-authorization.md`](../specs/ink-agent-authorization.md))
composes the grant under a signed challenge and adds:

- The challenge signature MUST verify against an active key of the Card resolved
  from the RP's bare-host `did:web`, and that card fetch MUST pass the
  private-hostname SSRF gate with connect-time IP pinning and MUST refuse
  redirects, because the fetch happens on unauthenticated attacker-supplied
  bytes before any signature check.
- `redirectUri` MUST be a literal prefix of the RP's own derived origin, MUST
  NOT carry a fragment, backslash, control character or whitespace, and the
  completion endpoint MUST consume the grant and forward nothing cross-origin.
  Together this closes open-redirect and cross-origin exfiltration of a sign-in.
- The identity assertion's `grantId` is derived deterministically from the
  verified challenge (`SHA-256` over `rp`, `nonce` and window), so a replayed
  challenge maps to the same `(issuer, grantId)` pair and both the issuer's
  mint-once rule and the RP's seen-set reject a second acceptance. The two
  layers do not depend on each other.
- Over an unauthenticated carrier, nonce-to-context binding stands in for
  presentation binding: the RP accepts a sign-in's grants only in the context
  that owns the nonce, and expires that context at the challenge `expiresAt`.
- Consent naming the RP and scope is required before minting any grant,
  including bare `identity.assert`, because even bare sign-in discloses a stable
  principal.

### 8. Containment and governance

The containment draft
([`../specs/ink-agent-containment-and-governance-extension-spec.md`](../specs/ink-agent-containment-and-governance-extension-spec.md))
adds blast-radius controls that map to typed, auditable rejections rather than
silent drops:

- **Delegation-depth and issuance budgets.** Recipients apply the lower of the
  protocol maximum, local policy and any sender-advertised accepted maximum, and
  signal exhaustion with `delegation_budget_exhausted`.
- **Child-agent containment.** A spawned actor MUST receive its own identity,
  its own scoped token, its own transport list and its own expiry. Silent
  credential inheritance is prohibited.
- **Handshake-flood resistance.** Per-sender and per-recipient handshake budgets
  and per-`correlationId` state-transition budgets throttle unknown senders,
  with signed backoff hints (`handshake_budget_exhausted`, `counterparty_cooldown`,
  `sender_rate_limited`). Backoff hints MUST be modest and auditable so they
  cannot be turned into a reflection attack that suppresses a spoofed
  counterparty. Proof-of-work is optional and never mandatory for baseline
  interop.
- **Discovery minimization.** A `network_only` or `capability_gated` agent
  returns a redacted Card to anonymous queries, preserving public signing keys
  (so rotation discovery still works) but hiding capabilities, endpoints,
  availability and profile.

### 9. Receipt and audit-chain integrity

Delivery and read receipts are Ed25519-signed by the issuing agent and do not
verify with revoked keys, so a receiver that stores them can later prove the
counterparty acknowledged delivery without trusting INK itself. The per-agent
audit chain combines a hash chain (`previousEventHash`) and a monotonic
`sequence`, so any modification breaks all later hashes and any gap or fork is
immediately visible. During bilateral audit exchange a responder signs the exact
slice (`responseSignature`), and a consumer MUST run both
`verifyAuditResponseSignature` and `verifyAuditEventChain`: a slice that passes
one and fails the other is rejected. Where a witness is used, verifiers MUST
recompute each Merkle leaf hash themselves and MUST re-check every returned
event's `agentSignature`, so a witness that commits a fabricated event still
produces a rejected response. See
[`../specs/ink-auditability.md`](../specs/ink-auditability.md).

## Known limits and out of scope

Treat this section as first-class. Several of these are durability limits that
do not soften with time.

### No forward secrecy

Payload encryption is ephemeral-sender against **static-recipient** X25519: the
sender uses a fresh ephemeral key, but the recipient's X25519 key is the
long-lived static key published in its Agent Card. There is no ratchet and no
per-session recipient key. A passive adversary who records ciphertext today and
later compromises a recipient's static encryption key can decrypt **all** past
captured traffic to that recipient, not just future traffic. Forward secrecy
would require an ephemeral-ephemeral agreement or a ratchet, which INK does not
specify. This makes the encryption private key (asset 2) a higher-value target
than a signing key: a signing-key compromise forges future messages, a static
encryption-key compromise retroactively decrypts the past. Rotating the static
X25519 encryption key and destroying the old private key bounds the
retroactive-decryption window to traffic sent under the retired key but does not
eliminate it, and it is not forward secrecy and must not be called that.

### No cryptographic agility or migration path

The suite is effectively pinned: Ed25519 signatures, X25519 key agreement,
HKDF-SHA256, AES-256-GCM and SHA-256 for hashing, the audit chain and the
witness Merkle tree. The compatibility policy classifies a signing, encryption
or hashing algorithm change as a major-version break, and no negotiation exists
to run a second suite alongside the first. There is no post-quantum path and no
hash-break path: if Ed25519 or X25519 falls to a quantum attack, or SHA-256 is
broken, there is no in-band way to migrate. The SHA-256 transparency log is the
sharpest case, an append-only log has no story for rehashing history under a new
function, so a hash break means a parallel per-suite log lineage and historical
proofs stay bound to SHA-256. The designated path for adding a second suite is
an additive minor under major 1: a new optional top-level Agent Card member that
1.0 receivers ignore, plus receiver-first negotiation of the kind `ink/0.2` used,
so a second suite runs alongside the first without breaking deployed receivers.
Only retiring the existing suite or restructuring the transparency log needs a
major version. The current wire does not yet ship a second suite; the additive
seam is reserved but unpopulated.

### The Agent Card is unsigned

The Agent Card is served over TLS and is not itself signed by the agent. Key
authority and version negotiation therefore rest entirely on TLS plus registry
and identity-system honesty. An adversary who controls the identity resolution
path or the TLS terminator (see the registry/PDS and TLS boundaries above) can
substitute signing and encryption keys and can silently strip or downgrade
`supportedProtocolVersions` to force `ink/0.1`, and a verifier has no in-band
cryptographic signal that the Card was tampered. Sign in with INK narrows this
for the RP-card and issuer-card fetch by pinning the fetch (SSRF gate,
connect-time pinning, redirect refusal) and requiring `agentId` to equal the
resolved principal, but it does not add a Card signature: the trust still
reduces to TLS and the resolver. This is the single largest trust assumption in
the model.

### No recovery from full signing-key loss

INK has no protocol-level recovery from the total loss of an agent's signing
keys. Rotation assumes the agent still holds a currently trusted key with which
to sign the Card update that introduces the new key. An agent that loses every
signing key cannot authenticate a rotation and cannot prove continuity of its
`agentId` under INK alone. Recovery is pushed to the DID / identity layer (the
resolver that maps `agentId` to key material), which is out of scope here and is
itself a trust boundary.

### Identity proof

INK does not prove *who* an agent is in the real world. Identity-system
compromise (a malicious PDS returning a fabricated DID document, a compromised
registration service) is the identity system's problem. Receivers authenticate
the cryptographic continuity of a `senderId` to Agent Card binding; they cannot
authenticate that the human behind the agent is who they claim.

### Compromised endpoints

If a sender's private keys are exfiltrated, an attacker can sign anything the
legitimate sender could until the key is revoked. INK's rotation rule bounds the
damage window but does not eliminate it. Key custody is out of scope.

### Split-view audit

A malicious agent can maintain two different hash chains and show each
counterparty a different consistent-looking history. Bilateral audit exchange
detects the divergence only after the fact and only when both parties compare.
A third-party witness makes split-view detectable, but a single access-controlled
witness can still equivocate unless clients independently verify consistency
proofs or submit to multiple witnesses. INK provides no consensus or finality:
two honest receivers that disagree about a receipt cannot be reconciled by INK
alone. For high-stakes interactions, submit to at least two independent audit
services. See §7 and the Security Considerations of
[`../specs/ink-auditability.md`](../specs/ink-auditability.md).

### Stolen grant inside its window

A grant or delegation token is a bearer artifact for the duration of its short
window. Presentation binding stops a thief over authenticated delivery, and
nonce-to-context binding stops one over a browser redirect, but a thief who owns
their own sign-in context and lures a user through consent is bounded only by
the completion-endpoint consumption rule and the short window, not by a
cryptographic tie to one challenge. The delegated-capability binding pins
principals, delivery context and mint window but is not cryptographic to a
single challenge.

### Cross-site tracking via stable principals

Because a user signs in under a stable principal, colluding relying parties can
correlate that the same principal signed in to each of them. The profile
acknowledges this rather than hiding it; the consent rule gates the disclosure
but does not prevent correlation. Pairwise or per-RP principals are a possible
later refinement and are out of scope.

### Malicious extensions and marketplace layers

The library does not include an extension or marketplace layer. A product that
adds a delegation-token layer for third-party agents must design its own trust
model for the marketplace, manifest review and capability attenuation.

### Prompt injection and side-channels in the agent

An agent that signs an INK message has seen the full plaintext. If the agent is
compromised, no INK-layer protection helps. This matters most for agents that
delegate to LLMs: prompt-injection against the model can produce INK messages
that are cryptographically valid but semantically wrong. INK does not address
this.

### Traffic analysis

INK messages reveal type, sender, recipient and approximate size even when the
payload is encrypted. A passive observer can enumerate agent relationships over
time. Mixnets, onion routing and other unlinkability mechanisms are not part of
INK.

### DNS rebinding on card fetch

The private-hostname classifier
([`../specs/ink-private-hostname.md`](../specs/ink-private-hostname.md)) is a
static-literal gate. It does not defend against DNS rebinding: a public hostname
that resolves to a private address at connect time still requires connect-time
IP pinning at the platform or TLS layer. The Sign in with INK card fetch
mandates that pinning; a general card fetch depends on the integrator applying
it.

### Timing side-channels

`@noble/ed25519` is believed to be constant-time, but this has not been
independently audited in the INK context. Attacks that rely on very precise
timing of verification against a candidate key set are not mitigated beyond what
the underlying library provides.

### Denial of service at the TCP/IP layer

INK's handshake and delegation-issuance budgets protect against L7 abuse from
known senders. They do not protect against L3/L4 floods, resource-exhaustion
attacks on the HTTP stack or amplification attacks. Those remain the transport
operator's responsibility.

### Fleet-broker central leverage

Fleet-managed mode adds governance power and concentrates risk in the broker. A
compromised broker can misissue identity or delay org-wide revocation. It MUST
NOT silently rewrite historical signed artifacts, and implementations SHOULD
treat brokers as high-value security boundaries. See
[`../specs/ink-agent-containment-and-governance-extension-spec.md`](../specs/ink-agent-containment-and-governance-extension-spec.md)
§12.

## Assumptions the protocol relies on

- TLS to the transport endpoint is correctly configured. INK signs at the
  application layer but assumes confidentiality and integrity during transport,
  and the Agent Card's authority reduces to this assumption plus resolver
  honesty.
- Server clocks are within 5 minutes of real time. Both the plus-or-minus
  5-minute timestamp window and the nonce TTL depend on this.
- The identity-system `senderId` to Agent Card resolution returns the current
  Card within acceptable latency (receivers may cache with a reasonable TTL,
  typically minutes).
- Receivers persist nonces and grant seen-sets durably enough to enforce the
  no-replay window. A receiver that loses its nonce cache during a restart MAY
  see duplicate accepts, a transient failure, not a protocol break.

## Recommended receiver defaults

| Setting                          | Default                |
|----------------------------------|------------------------|
| Timestamp max age                | 5 minutes              |
| Timestamp future skew tolerance  | 30 seconds             |
| Nonce TTL                        | 10 minutes             |
| Agent Card cache TTL             | 5 minutes              |
| Unknown-sender handshake budget  | 20 per hour per sender |
| Retired-key acceptance grace     | Up to 30 days          |
| Grant maximum lifetime           | 10 minutes             |
| Delegation token TTL             | 1 to 4 hours           |
| Delegation chain max depth       | 5 hops                 |
