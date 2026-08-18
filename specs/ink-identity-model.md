# INK Identity Model Specification

**Status:** Draft, 1.0 stabilization. This document is an index and a closure
document. It states the identity facts that had no normative home and cites the
single home of every fact that already had one; it does not restate a rule
another spec owns.
**Authors:** Ad Astra Computing
**Last updated:** 2026-08-16

Requirement keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** are used per RFC 2119.

## 1. Purpose

INK's identity concepts are load-bearing in every other spec: the principal
grammar sits under the signature base, the key lifecycle sits under the
authority rule and the card proof roots itself differently for each kind of
principal. Until now those concepts were only stated where they were used. An
implementer who wanted to know what an INK identity IS had to reconstruct it
from a grammar section, a rotation taxonomy, a card-proof rooting rule and a
threat model.

This document is that missing center. It defines what each INK principal
identifies, how it is derived or resolved, when two of them are the same, what
keys mean and what binds each of those things to the next. Where a rule is
already normative elsewhere this document states the edge and cites the owning
spec rather than repeating its text, because a duplicated normative sentence is
a drift source. Where a behavior was implemented but unwritten this document is
its normative home.

This document adds no wire format, no field and no message type. It is a
statement of the model the existing wire already carries.

## 2. Principal taxonomy

An INK **principal** is the value that appears as an `agentId`, as a message
`from` or `to`, as a grant `issuer`, `subject` or `audience` and as the
`recipientDid` line of the transport signature base. The grammar of that value
is pinned by [`ink-protocol.md`](ink-protocol.md) §7 and is not restated here.
This section says what each admissible form IDENTIFIES.

### 2.1 Key-derived principals

A key-derived principal is `tulpa:<multibase>` or `ink:<multibase>`, where the
multibase tail decodes to a 32-byte Ed25519 public key under the `0xed01`
multicodec (Protocol §7).

A key-derived principal is **self-certifying**: it identifies exactly the party
that holds the private half of the embedded key, and it carries no other claim.
There is no directory, registry or issuer behind it. Creating one requires no
permission from anyone, and no party can revoke one.

The embedded key is the identity's **genesis** key. It is NOT the identity's
current signing key. The demotion of the embedded key from current key to
genesis root, the rotation chain that carries trust forward from it and the
rule that holding it authorizes attesting rotations but not signing live
messages, are specified by
[`ink-agent-card-signature.md`](ink-agent-card-signature.md) §4.1 and stated in
[`ink-key-rotation-spec.md`](ink-key-rotation-spec.md) §4.1. A verifier MUST NOT
read a key-derived principal as an assertion about which key currently signs for
that identity.

A key-derived principal is therefore permanent and unrecoverable in exactly the
way its key material is. Loss of every chain-capable key is identity loss
(`ink-key-rotation-spec.md` §4.1).

### 2.2 The `ink:` alias

`ink:<multibase>` is an inbound alias for `tulpa:<multibase>` carrying the
identical multibase tail. The two spellings denote the SAME actor. The alias
exists so the protocol can reach a vendor-neutral namespace without a breaking
rename.

The accept-both-emit-one rule, the collapse to a single prefix-independent
principal and the escape of a literal `key:` input are pinned by Protocol §7 and
by the `principal-normalization` conformance category. Two obligations follow
and are stated here because they are identity obligations rather than grammar
obligations:

- A receiver MUST NOT treat the prefix as authority. Both prefixes decode their
  tail identically, so a signature made with the embedded key verifies whichever
  prefix carried it (Protocol §7).
- A receiver MUST NOT maintain two records for the two spellings of one key. The
  prefix is a spelling of an identity, not an identity.

The message-type namespace carries its own, separate `network.tulpa.*` and
`network.ink.*` dual-accept rule (Protocol §6). The two dual-accepts are
unrelated: the namespace rule is receiver-side leniency over a `type` string,
and the principal rule is an identity equality. An implementation MUST NOT gate
one on the other.

### 2.3 Foreign principals

Any principal that is not key-derived is a **foreign principal**: a
`did:web:<host>` identifier, a `did:plc:` identifier or any other stable
identifier an external identity system publishes. Protocol §7 carries it through
unchanged.

A foreign principal is **not** self-certifying. It identifies whatever the
identity system behind it says it identifies, and INK depends on that system for
the principal-to-key link. INK pins the resolution procedure for exactly one
foreign form, `did:web`. The general walk from a `did:web` identifier to a
verified card is [`ink-resolver.md`](ink-resolver.md), which owns the base
derivation, the request side of the fetch and the outcomes. The bare-host
grammar and its deterministic origin derivation for a relying party and a grant
issuer are pinned for that surface by
[`ink-agent-authorization.md`](ink-agent-authorization.md). No resolution
procedure is pinned in this repository for any other foreign form.

Consequently:

- A verifier presented with a foreign principal it cannot resolve to a key by
  its own policy MUST reject, and MUST NOT fall back to any weaker path. A
  key-derived principal has a bootstrap path because its identifier carries a
  key; a foreign principal has none.
- The DID-document anchoring requirement for a `did:web` card
  (`ink-agent-card-signature.md` §4.2) is a requirement on the RESOLVED
  document. The resolution of a `did:web` identifier to that document is the
  W3C did:web method's business and is not pinned by INK. An implementation MUST
  apply the SSRF host-safety gate of
  [`ink-private-hostname.md`](ink-private-hostname.md) to that resolution, the
  same as to any other outbound INK fetch.
- A `did:web` identifier MAY carry a port as a `%3A`-encoded separator. An
  implementation that resolves one MUST carry that port into the URL it fetches.
  Discarding it silently retargets the fetch at the default port, which is a
  different origin and therefore a different document, so an implementation that
  cannot carry the port MUST reject the identifier rather than resolve it
  without one. `did:web:host` and `did:web:host%3A443` are DISTINCT principals
  under the no-folding rule of §3.1 even though both resolve to the same origin:
  a spelling that resolves identically is still a different identifier, and an
  implementation MUST NOT fold one onto the other. A profile that needs a single
  spelling MUST pin a grammar admitting only one, as the sign-in profile does by
  refusing an explicit `443` for a relying party
  ([`ink-agent-authorization.md`](ink-agent-authorization.md)); that refusal is
  profile-local and MUST NOT be applied to general `did:web` resolution, where
  an explicit `443` is a method-legal identifier.
- A foreign principal MAY be recoverable where a key-derived one is not, because
  its root document can name a fresh key out of band
  (`ink-key-rotation-spec.md` §4.1).

### 2.4 The owner DID

An Agent Card MAY carry `ownerDid`, `ownerHandle` and `atprotoRecordUri`
([`ink-agent-card.md`](ink-agent-card.md)). These name the human or organization
on whose behalf the agent acts.

**INK defines no proof that binds an owner to an agent.** `ownerDid`,
`ownerHandle` and `atprotoRecordUri` are self-asserted strings inside a document
the agent itself publishes. A card signature (§5.2) proves that the agent's own
key asserted them; it proves nothing about the owner. Accordingly:

- A verifier MUST NOT treat `ownerDid`, `ownerHandle` or `atprotoRecordUri` as
  authenticated, whether or not the card carrying them is signed.
- A verifier MUST NOT make an authorization decision on `ownerDid` alone. An
  implementation that authorizes on owner identity MUST obtain the owner binding
  from the identity system that issued the owner DID, out of band of INK, under
  its own policy.
- An owner-status input to a grant verifier is exactly that, an input. The
  `requireVerifiedOwner` field of
  [`ink-authorization-grant.md`](ink-authorization-grant.md) and the chain rule
  in [`ink-authorization-chain.md`](ink-authorization-chain.md) consume a status
  the service supplies. Neither computes it, and this document does not define
  it either. Producing that status and its freshness are the service's policy.

The anti-substitution check of
[`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md) step 9
is not an exception to any of this. That step compares a card's `ownerDid`
against the DID the resolution went through, so a host that legitimately
publishes one DID's card cannot serve it in answer to another. It is an equality
check on a self-asserted field at the moment of resolution, not a proof that the
named owner exists or consented; a card that passes it is exactly as
unauthenticated in its owner fields as one fetched without a DID in the path.

An owner-binding proof would be a wire addition and is out of scope here. §7
records it as a non-goal for 1.0. Where another INK document names an
owner-record construct, an owner-link record or a named owner-verification
routine, it is describing a deployment's own pipeline and not an INK-defined
artifact. No such record or routine is specified by this repository, and an
implementation MUST NOT require one of a counterparty.

### 2.5 The handle

An Agent Card carries a required `handle` and a `displayName`
(`ink-agent-card.md`). Neither is an identifier.

A `handle` is a display affordance. It carries NO uniqueness guarantee, no
registry and no resolution procedure. A verifier MUST NOT resolve a principal
from a `handle`, MUST NOT key per-sender security state on one and MUST NOT
treat two cards bearing the same `handle` as related. Two unrelated agents MAY
publish the same `handle`, and nothing in INK prevents it or detects it. A
`handle` is inside the bytes a card proof covers, so it is self-asserted under
signature rather than mutable in transit; that is an integrity property of the
card and not an identity claim.

Handle-based identity was considered and rejected. `agentId` is the stable
logical identifier (`ink-key-rotation-spec.md` §20).

## 3. Equality and canonicalization

Identity bugs are equality bugs. This section states which comparison rule
applies where. It introduces no new algorithm.

### 3.1 The canonical principal

The canonicalization from a raw `agentId` to a prefix-independent principal is
pinned by Protocol §7 and by the `principal-normalization` conformance category.
Its properties matter to this model and are restated as properties, not as an
algorithm:

- it is applied EXACTLY ONCE, to the raw `agentId`, at the storage boundary. It
  is not idempotent (Protocol §7);
- it collapses the two method prefixes for one key onto one string, so a change
  of prefix cannot split one identity into two or evade state keyed on the
  other;
- it is TOTAL: a well-formed input canonicalizes and every other input escapes,
  so a caller does not have to handle a rejection on the security path;
- it performs NO case folding, NO percent-decoding and NO host normalization on
  a foreign principal. A foreign principal is returned unchanged.

The last property is the one an implementer most often gets wrong, so it is
stated normatively here: `did:web:Example.com` and `did:web:example.com` are
DIFFERENT principals under INK canonicalization, even though the hosts they name
are the same under DNS. An implementation MUST NOT fold them, because folding
one identifier family and not another produces two implementations that disagree
on identity. A profile that needs a single spelling MUST pin a grammar that
admits only one, as the sign-in profile does for a relying party
(`ink-agent-authorization.md`).

The cost of that choice is case splitting, and it is named here rather than left
for a deployment to discover: because a foreign principal passes through
canonicalization unchanged, a `did:web` sender can re-case its host to present as
a principal a receiver holds no state for, evading a block list entry or opening
a fresh rate-limit window per spelling. The identity rule does not bend for this.
A receiver MAY additionally key an abuse-control input on a coarser derived value
of its own, for example a case-folded host, as defense in depth, provided that
value is used only for throttling, blocking and similar policy decisions and that
no identity decision folds: canonical equality, key resolution, replay state and
every comparison of §3.3 stay on the unfolded principal.

The escaped output forms are reserved. A principal beginning `key:` or `raw:` is
never a legitimate `agentId` (Protocol §7), and an implementation MUST NOT emit
one as an `agentId`, a message `from` or `to` or a grant principal. A verifier
MAY reject such a value outright on receipt.

### 3.2 Where canonical equality applies

Every per-sender security decision MUST key on the canonical principal, never on
the raw spelling. Protocol §7 owns this rule and the `principal-normalization`
category pins it. It covers block lists, rate limits, duplicate-payload checks,
cached verification keys and connection identity.

"Per-sender" means every layer that RETAINS state about a sender, not only the
outermost one. A key-resolution cache, a burned-nonce or replay set and a
connection record are each per-sender state and, where scoped per sender, each
MUST be keyed on the canonical principal. An implementation that canonicalizes
at one layer and keys another on the raw spelling has not satisfied the rule:
the unkeyed layer is where the two spellings of one key split, and splitting a
replay set is enough to let one presentation be accepted twice. A store a
receiver keeps globally rather than per sender has no scope key to get wrong and
is outside this rule; Protocol §3.5 states that choice for the nonce store.

### 3.3 Where exact equality applies

Signed and bound fields are compared BYTE FOR BYTE, never canonicalized, because
canonicalizing before comparison would let one spelling stand in for another
inside a signature. This is already the rule at each of these surfaces and this
document collects the list rather than restating each rule:

- the card identity binding: a fetched card's `agentId` against the requested
  one ([`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md)
  step 8), and its `ownerDid` against the DID under resolution (step 9 of the
  same contract, an anti-substitution check and not owner authentication, §2.4);
- the encrypted envelope's inner and outer `from` and the inner `to` against
  the recipient's own bound identity
  ([`ink-payload-encryption.md`](ink-payload-encryption.md) step 10);
- a discovery directory's audience against the signed `to`, which
  [`ink-discovery-query.md`](ink-discovery-query.md) states as exact with no
  case folding, no trailing-slash normalization and no deriving one spelling
  from another;
- a relying party's derived origin against a `redirectUri` prefix
  (`ink-agent-authorization.md`).

The two rules do not conflict, because they answer different questions.
Canonical equality answers "is this the same actor as the one I have state for".
Exact equality answers "is this the string the signer signed". An implementation
MUST NOT substitute one for the other in either direction.

### 3.4 Key equality

Two keys are the same key when their RAW DECODED BYTES are equal. Comparison of
encoded strings is forbidden. `ink-agent-card-signature.md` §3.5 owns this rule,
including the multicodec-prefix requirement and the exact-32-byte requirement,
and it applies to every key comparison in this model, not only to card proofs.

## 4. Keys and their roles

### 4.1 Roles

An INK agent advertises keys by role: signing keys and encryption keys
(`ink-key-rotation-spec.md` §4.2). The roles are disjoint and the multicodec
enforces it. A signing key is Ed25519 under `0xed01` and verifies transport
signatures (Protocol §3.3), body signatures (Protocol §3.6), card proofs and
rotation links. An encryption key is X25519 under `0xec01` and is an ECDH input
only (Protocol §3.4).

A key MUST NOT be used in the role its multicodec does not name. An
implementation MUST reject a signing-key slot whose decode does not yield
`0xed01` plus 32 bytes and an encryption-key slot whose decode does not yield
`0xec01` plus 32 bytes. A key-derived principal always embeds a SIGNING key;
there is no encryption-key-derived principal, and an agent's encryption key is
discoverable only from its card.

### 4.2 Encodings

Public keys travel as multibase base58btc over the multicodec-prefixed key
(Protocol §7), signatures as base64url with no padding (Protocol §3.3). Both are
frozen for 1.0 under Protocol §1.1. A key is never carried as bare hex or bare
base64 on the wire.

### 4.3 Lifecycle

A key entry carries exactly one of `active`, `retired` or `revoked`, with the
meanings pinned by `ink-key-rotation-spec.md` §5.3 and the receiver behavior
pinned by [`docs/key-rotation-rule.md`](../docs/key-rotation-rule.md). The
window fields and the semantics of their PRESENCE are pinned by
`ink-key-rotation-spec.md` §6.5.

Three lifecycle consequences are identity statements rather than verification
statements, and are collected here:

- Rotation does NOT change the identity. The `agentId` is frozen at genesis and
  MUST NOT change when keys rotate (`ink-key-rotation-spec.md` §4.1).
- Revocation does NOT end the identity. It ends a key. A revoked signing key
  never verifies again, even for artifacts that predate its `revokedAt`
  (`ink-key-rotation-spec.md` §6.3), but the principal survives and continues
  under its remaining keys.
- A `retired` key is the identity's own past. Retirement is a rotation state and
  carries no trust statement; revocation is a trust statement
  (`docs/key-rotation-rule.md`).

### 4.4 The retired-key default

Live transport auth rejects a signature that only verifies against a `retired`
key unless the deployment opts into a rotation grace window (Protocol §3.3,
error `retired_key_for_live_auth`). This default NARROWS step 1 of
[`docs/key-rotation-rule.md`](../docs/key-rotation-rule.md), whose
active-then-retired iteration is written for verification in general; that
iteration survives unnarrowed only for historical verification, and the
narrowing is stated at the verification algorithm there. A reader who takes the
two documents together should read the authority rule as the shape of the search
and Protocol §3.3 as the live-auth restriction on which entries that search may
accept.

The observable consequence for the identity model is stated here because it is
the part an adopter reasons about: a retired key still speaks for the identity's
HISTORY and no longer speaks for it in the PRESENT. Historical verification of
receipts, audit events and stored messages against a retired key inside its
window remains a MUST (`ink-key-rotation-spec.md` §6.2).

The rationale for making the strict behavior the default is that a retired key
is, by construction, a key the identity has already replaced. The set of retired
keys only grows, and each one remains a live-authentication credential for as
long as a deployment accepts it, so accepting them by default would make the
attack surface of an identity monotonically increase with its rotation count.

A deployment that needs a grace window for cache lag opts into it explicitly,
and a receiver that opts in MUST bound the window, either by an explicit
wall-clock duration or by the retirement window fields
(`ink-key-rotation-spec.md` §6.5). An unbounded window is not a grace window. It
is a policy change that restores every retired key as a live credential for the
life of the identity, which is the behavior the default exists to prevent, and a
receiver MUST NOT describe or configure it as a grace window.

### 4.5 Rotation and recovery as observable behavior

An adopter cannot see another agent's key management. What it CAN observe is the
protocol behavior, and that is what this model pins:

- a rotation is observable as a card whose `keySetVersion` increased and whose
  `keys.signing` set changed, reachable from the previously observed set
  (`ink-agent-card-signature.md` §6);
- a recovery is NOT distinguishable from a rotation on the wire, and MUST NOT be
  expected to be. Recovery is expressed as an ordinary rotation-chain link,
  `keySetVersion` N+1 signed by a key from version N or by a pre-declared
  offline recovery key, and it MUST NOT derive a new `agentId`
  (`ink-key-rotation-spec.md` §4.1, `ink-agent-card-signature.md` §9);
- an identity loss is observable only as silence. Nothing on the wire announces
  it.

A verifier MUST NOT infer intent from a rotation. A rotation whose links verify
is a rotation, whatever caused it.

## 5. The binding graph

Everything above is a node. This section is the edges. Each edge names the fact
it carries, the spec that owns it and what a verifier MUST check to traverse it.
No edge is defined twice. One row of the summary table has no subsection of its
own, card key set to message, because its entire definition is the authority rule
of [`docs/key-rotation-rule.md`](../docs/key-rotation-rule.md) as narrowed for
live transport auth by §4.4, and this document adds nothing to it.

### 5.1 agentId to key

**Key-derived.** The edge is the identifier itself: the embedded key IS the
genesis root, with no lookup and no third party. A verifier traverses it by
decoding the multibase tail under Protocol §7 and MUST reject a decode that
lacks the `0xed01` prefix or does not yield exactly 32 bytes
(`ink-agent-card-signature.md` §3.5).

**Foreign.** INK pins the edge for `did:web` and for no other form. A verifier
traverses a `did:web` edge by the walk of [`ink-resolver.md`](ink-resolver.md),
or by `ink-agent-authorization.md`'s own construction on the sign-in surface
that profile governs. For every other foreign form there is no edge inside INK:
the verifier resolves under the identity system's own rules and MUST reject when
it cannot (§2.3).

### 5.2 key to card

The edge is `cardSignature`, and
[`ink-agent-card-signature.md`](ink-agent-card-signature.md) owns it entirely:
the signed bytes (§3.2), the signer resolution (§3.3), the rooting by principal
kind (§4) and the verifier order (§5). A verifier MUST run that order. This
document adds nothing to it.

Two properties of this edge are identity facts and are worth naming as such: an
invalid proof REJECTS the card and is never demoted to unsigned (§3.4), and a
card becomes the authoritative key set only AFTER the proof and its rooting pass
(§5 step 5).

### 5.3 card to agentId

The edge is the discovery identity binding: the fetched card's `agentId` MUST
equal the `agentId` the fetch was made for, compared exactly
(`ink-agent-card-discovery-fetch.md` step 8). Without it a host could serve
another principal's card and speak for it.

This edge is independent of §5.2 and both are required. §5.2 proves a key signed
the card. §5.3 proves the card is the one asked for. A card that satisfies one
and not the other MUST be rejected.

### 5.4 agent to owner

There is no verifiable edge. §2.4 is the whole of it: the card's owner fields
are self-asserted, INK defines no proof over them, and a verifier MUST NOT
authorize on them. This is stated as an edge so that a reader looking for one
finds the answer rather than an omission.

### 5.5 principal to delegation chain

The edge is a chain of grant-shaped links, and
[`ink-authorization-chain.md`](ink-authorization-chain.md) owns it: the parent
hash, the issuer-to-subject continuity across each seam, the monotonic scope and
window attenuation, the per-position lifetime ceilings, the active-key-only
per-link signature rule and the three-pass verify order. A single hop is the
grant primitive of [`ink-authorization-grant.md`](ink-authorization-grant.md).

The identity-model statement about this edge is only this: a chain conveys
AUTHORITY between principals; it never conveys IDENTITY. A verifier that accepts
a chain learns that the presenter holds an attenuated capability traceable to an
origin issuer it can root. It does not thereby learn that the presenter is the
origin issuer, and it MUST NOT collapse the two. Delegation is a capability-gated
extension and is not part of the 1.0 base profile
([`ink-conformance-profile.md`](ink-conformance-profile.md)).

### 5.6 Summary

| Edge | Carrier | Owning spec | Verifier MUST |
|---|---|---|---|
| agentId to key, key-derived | The identifier | Protocol §7 | Decode under the `0xed01` multicodec to exactly 32 bytes, else reject |
| agentId to key, foreign | External identity system | `ink-resolver.md` for the general `did:web` walk and `ink-agent-authorization.md` for the sign-in profile; not pinned by INK for any other form | Resolve under the pinned walk where one applies and under its own policy otherwise, reject when it cannot, gate the fetch through `ink-private-hostname.md` |
| key to card | `cardSignature`, `rotationChain` | `ink-agent-card-signature.md` | Run the §5 verifier order, reject an invalid proof outright |
| card to agentId | Discovery response | `ink-agent-card-discovery-fetch.md` | Compare `agentId` to the requested id exactly |
| card key set to message | Authority rule | `docs/key-rotation-rule.md` | Verify against the observed signing set only, never fall through |
| owner to agent | None | None | Treat owner fields as unauthenticated, never authorize on them |
| principal to capability | Grant, chain | `ink-authorization-grant.md`, `ink-authorization-chain.md` | Verify the presented artifact, never read authority as identity |

## 6. Trust establishment

### 6.1 First contact

A verifier meeting a principal for the first time holds no state about it. What
it may do in that window, and when the window closes, is pinned by
`docs/key-rotation-rule.md`: a bootstrap key derived from the identifier or a
key stored from an earlier first-contact handshake MAY be used only while no
Agent Card signing set has been observed, and bootstrap extraction MUST be
disabled the moment one has (invariant 4). For a receiver enforcing the card
proof the boundary tightens from a valid card to an AUTHENTICATED card
(`ink-agent-card-signature.md` §5 step 5).

Trust on first use is a real, bounded assumption and this document names it
plainly: on first contact a verifier accepts that the key it can see is the key
the identity intends. Nothing in the base protocol corroborates that. What
bounds the assumption is that it is made ONCE and then ratcheted: after the
first observation, key changes must be justified by the rotation chain and the
continuity rules (`ink-agent-card-signature.md` §6), and an unsigned card from a
principal previously seen with a signed one is rejected permanently (§7 of that
spec).

A key-derived principal narrows the assumption further. Its identifier carries
its own genesis key, so a cold verifier is trusting the identifier it was
GIVEN rather than a key it fetched. A foreign principal does not have this
property, and this is the substantive trust difference between the two families.

### 6.2 What a card signature proves

A valid `cardSignature`, rooted per `ink-agent-card-signature.md` §4, proves:

- the named key signed the exact card bytes, so no field of the card was
  altered after signing;
- the named key is reachable from the identity's root, the embedded genesis key
  for a key-derived principal or the DID document for a `did:web` principal.

It does NOT prove:

- that the card is the agent's CURRENT card. For a cold verifier the guarantee
  is reachability, not currency, and a leaked ever-active chain-era key permits
  full card fabrication at a fabricated `keySetVersion`
  (`ink-agent-card-signature.md` §6);
- anything about the owner (§2.4);
- anything about the agent's conduct, its capabilities being genuine or its
  endpoint being live. A signature is an integrity statement over a
  self-description.

Closing the currency gap requires external observation of card heads, which the
witness log provides ([`ink-merkle-consistency.md`](ink-merkle-consistency.md))
and which `ink-agent-card-signature.md` §6 keeps a SHOULD.

### 6.3 Phase posture

The rollout of producer signing and receiver enforcement is three phases and
`ink-agent-card-signature.md` §10 owns the schedule, the Phase C decision points
and the enforcement-switch rules. This document does not restate the phase
state, the dates or the switch names, because a phase state transcribed into a
second document is a fact that goes stale. A reader determining what a
conforming receiver must enforce today reads §10 and
`ink-conformance-profile.md`, which is the authority on which categories are
base and which are staged.

The identity-model consequence of the phases is stable across all three: the
direction of travel is that a key-derived identity's authority over its own card
moves from advisory to mandatory, and TLS plus registry honesty moves from
load-bearing to defense in depth.

## 7. Non-goals

These are outside the identity model by decision, not by omission. An
implementation MUST NOT depend on INK to provide them.

**Human identity.** INK identifies agents. It does not identify people, does not
verify that a person exists and defines no proof binding an agent to a human
(§2.4). Where a deployment needs one it obtains it from the identity system that
issued the owner DID, under that system's rules.

**Global uniqueness beyond key possession.** A key-derived principal is unique
only in the sense that finding a second holder of one Ed25519 private key is
computationally infeasible. There is no namespace, no registry, no first-come
allocation and no dispute procedure. Nothing prevents two agents from publishing
the same `handle`, the same `displayName` or the same claimed `ownerDid` (§2.5).
An implementation MUST NOT present any INK identifier other than the principal
itself as unique.

**Revocation transparency beyond the witness.** INK's revocation is a status on
a key entry in a document the agent itself publishes. A verifier learns of a
revocation only by fetching the card, so an agent that withholds a revoking
update from one counterparty simply is not seen to have revoked. INK provides no
revocation list, no OCSP-shaped responder and no push. The only mechanism that
converts this into detectable equivocation is external observation of card
heads through the RFC 6962 witness log, and that is a SHOULD, not a MUST
(`ink-agent-card-signature.md` §6).

**Identity resolution for foreign principals.** INK does not define how to get
from a `did:plc:` or any other foreign identifier to a key. `did:web` is the one
exception: its general walk to a verified card is
[`ink-resolver.md`](ink-resolver.md), and the sign-in surface
`ink-agent-authorization.md` pins its own construction on top of that (§2.3).
Adopters bringing their own identity system supply this and are the ones who
must get it right.

**Cross-identity linkage.** INK defines no way to prove that two principals are
the same actor, no key-continuity claim across identifier families and no
migration path from one principal to another. An agent that changes principal is
a new agent to every counterparty.

## 8. Relationship to other specs

Each row is the single home of the facts named. This document cites them and
does not duplicate them.

| Spec | Owns |
|---|---|
| [`ink-protocol.md`](ink-protocol.md) | The principal grammar, the multicodec prefixes, canonicalization to a prefix-independent principal, the key resolution order at a receiver and the retired-key live-auth default (§3.3, §7) |
| [`ink-agent-card.md`](ink-agent-card.md) | The card schema, including the owner fields, `handle`, the key-set members and the endpoint grammar |
| [`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md) | The discovery path, the discovery response contract, the card-to-agentId identity binding and the `ownerDid` anti-substitution check |
| [`ink-resolver.md`](ink-resolver.md) | The walk from a principal to a verified card: admissible inputs, the general `did:web` base derivation, the request side of discovery, the cache obligations and the resolution outcomes |
| [`ink-agent-card-signature.md`](ink-agent-card-signature.md) | The card proof, the rotation chain, rooting by principal kind, key-byte comparison, continuity and rollback and the phase rollout |
| [`ink-key-rotation-spec.md`](ink-key-rotation-spec.md) | The stable-agentId model, key roles, the status taxonomy, window-field semantics, historical verification and recovery |
| [`docs/key-rotation-rule.md`](../docs/key-rotation-rule.md) | The authority rule, the no-fallback invariants and the bootstrap window |
| [`ink-agent-authorization.md`](ink-agent-authorization.md) | The bare-host `did:web` grammar, the deterministic origin derivation and the pinned key resolution for a relying party and a sign-in issuer |
| [`ink-authorization-grant.md`](ink-authorization-grant.md) | The single-hop grant, its bindings and the owner-status hook |
| [`ink-authorization-chain.md`](ink-authorization-chain.md) | Delegation chains and attenuation |
| [`ink-payload-encryption.md`](ink-payload-encryption.md) | Recipient binding on decrypt |
| [`ink-discovery-query.md`](ink-discovery-query.md) | Exact audience comparison at a directory |
| [`ink-private-hostname.md`](ink-private-hostname.md) | The SSRF host-safety gate every identity-bearing fetch passes |
| [`ink-conformance-profile.md`](ink-conformance-profile.md) | Which categories a conforming implementation MUST satisfy |
| [`ink-merkle-consistency.md`](ink-merkle-consistency.md) | The consistency proof that converts a card-head fork into detectable equivocation |

## 9. Conformance

Most of this document's mechanical content is already pinned by the
`principal-normalization`, `agent-card`, `agent-card-fetch`,
`agent-card-signature`, `key-rotation` and `payload-encryption` categories of
`conformance/v1`, including the equality and role rules of §3 and §4.1, which are
consequences of decisions those categories already carry. An implementation that
passes them satisfies that part of the model.

Three rules stated here are testable and are not pinned by an existing vector.
They are recorded as candidate conformance categories rather than left implicit,
so that a later pass can pin them without rediscovering them:

- the emit side of the reserved escape forms (§3.1): a producer MUST NOT emit a
  principal beginning `key:` or `raw:` as an `agentId`, a message `from` or `to`
  or a grant principal. The existing category covers what a receiver does with
  such a value, not what a producer is forbidden to write;
- the pass-through of a `raw:`-shaped INPUT (§3.1): canonicalization applied once
  to an input that already begins with an escape prefix has a defined result, and
  an implementation that re-escapes or strips it splits one identity in two;
- the `did:web` port rule (§2.3): an implementation that resolves a `did:web`
  identifier carrying a `%3A`-encoded port MUST carry that port into the URL it
  fetches, and MUST reject the identifier rather than resolve it at the default
  port.

The statements this document adds that no category could pin are the negative
ones: that owner fields are unauthenticated (§2.4), that a `handle` is not an
identifier (§2.5) and the non-goals of §7. They are unpinnable by construction,
because each says that INK provides nothing where an adopter might assume it
provides something. They are enforced by review, not by vectors.

