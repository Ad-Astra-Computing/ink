# INK Attestation Specification v0.1

**Status:** Draft, proposed under the 1.0 accountability decision (shape in 1.0, policy out)
**Authors:** Ad Astra Computing
**Last updated:** 2026-09-03

## Purpose

Minting an INK identity is permissionless and stays permissionless. An
`agentId` authenticates exactly two things: possession of a private key at the
moment of signing, and continuity of that key across interactions. It does not
authenticate a human, an organization, a legal entity, a handle, a domain or
any form of accountability. That boundary is a feature of the identity model,
not a gap in it, and no receiver may be forced to pretend otherwise.

What a receiver can be given is a way to ask for more. This specification pins
the smallest artifact that request needs: a signed **attestation**, in which one
principal (the issuer) makes a bounded, typed claim about another (the
subject), valid for a fixed window, verifiable against the issuer's key. It
also pins the receiver's side: how a service states that transport-valid
traffic is refused or degraded for lack of evidence, without that refusal ever
being confused with a signature failure.

The precedent is deliberate. SMTP never verified who a sender was;
accountability arrived later as evidence layered on top, and whether anyone
accepted your mail was always a separate question from whether your message
parsed. INK freezes the evidence *shape* before 1.0 because shapes are
expensive to retrofit. Everything judgmental — which issuers to believe, what
claims are worth, how reputation accrues — is receiver policy and stays out of
the wire contract.

## What is in 1.0 scope and what is not

In scope, because it is shape:

- the attestation object, its bounds, its signature and its verification order;
- the separation of transport validity from receiver acceptance, including the
  structured refusal a receiver returns;
- the optional Agent Card member a receiver uses to advertise its evidence
  expectations before a sender transmits;
- the security statement above, restated normatively in
  [`ink-identity-model.md`](ink-identity-model.md).

Out of scope, deliberately: claim-type registries beyond grammar, issuer
accreditation, trust or reputation algorithms, revocation transparency,
payment or stake mechanics, and any binding to a specific owner-linkage system.
An attestation whose `claimType` a receiver does not recognize is simply not
evidence for that receiver.

## Attestation

An attestation is a JSON object with exactly these fields and no others. Every
field is required.

- `protocol`: the string `ink/0.1`.
- `type`: the wire type, `network.ink.attestation`. There is no legacy
  `network.tulpa.*` spelling: the object postdates the namespace migration, so
  it is born vendor-neutral and single-spelling.
- `issuer`: the attesting principal's DID or agent id, a non-empty string of at
  most 512 UTF-16 code units. The issuer key signs the attestation. Nothing in
  this specification makes any issuer authoritative.
- `subject`: the `agentId` the claim is about, same bound as `issuer`. An
  attestation whose subject is the issuer is well-formed; self-attestation is a
  claim like any other and is worth whatever the receiver decides the issuer's
  word is worth.
- `claimType`: a namespaced claim identifier, 3 to 128 UTF-16 code units,
  matching `[a-z0-9]+(\.[a-z0-9_]+)+` — a reverse-DNS-style dotted name in
  lowercase. The grammar is normative; the vocabulary is not. Issuers mint
  claim types under names they control; collisions are the namespace owner's
  problem, exactly as with message intents.
- `claim`: a JSON object carrying the claim-type-specific payload. The base
  verifier treats it as opaque: it is bounds-checked and canonicalized but
  never interpreted. It may be empty (`{}`). Its meaning belongs to the
  claim type.
- `attestationId`: an issuer-chosen unique id, 16 to 256 UTF-16 code units,
  matching the nonce grammar `[A-Za-z0-9_-]+`. It is the deduplication and
  revocation key: an issuer that wants to withdraw a claim publishes the id
  through whatever channel it maintains, and a receiver that caches
  attestations keys the cache on the pair of the issuer's **canonical
  principal** ([`ink-identity-model.md`](ink-identity-model.md) §3.1) and
  `attestationId`. The signature is always over the raw `issuer` spelling as
  signed; the canonical form is only the state key, so an alias spelling of
  the same key-derived issuer cannot split cache or revocation state.
- `issuedAt`: a strict INK timestamp ([`ink-timestamp-grammar.md`](ink-timestamp-grammar.md)).
  The attestation is not valid before this instant.
- `expiresAt`: a strict INK timestamp, strictly after `issuedAt`. The
  attestation is not valid at or after this instant. Unlike an authorization
  grant, no maximum lifetime is imposed: a claim about a subject is not a
  capability, and an issuer that wants to stand behind a claim for a year says
  so. Receivers are free to discount long windows as policy.
- `signature`: the Ed25519 body signature over every other field, base64url
  without padding, exactly 86 characters.

### Raw body

An attestation is a signed body. A verifier MUST apply the raw-body gate and
enforcement order of [`ink-signed-string-safety.md`](ink-signed-string-safety.md)
— the size cap, raw UTF-8 validity, the lone-surrogate escape scan, the
out-of-range number-literal scan and the escaped-member-name scan, in that
specification's enforcement order, all on the bytes, before parsing. The size cap is 65536 bytes. Verification takes the raw
bytes, never a value someone else parsed; the accept-versus-reject splits that
motivate this are the same as for grants and are not restated here.

The `claim` object is included in the bounds: the node and depth caps of the
signed-body profile apply to the whole document, so a claim payload cannot be
used to smuggle unbounded structure past the gate.

Every raw-body failure is a structural rejection, reported as `schema`.

## Signature

The signature covers every field except `signature` itself, computed over the
domain-separated JCS canonicalization of the unsigned object — the same body
signature scheme as every other INK signed body (`ink/0.1` keeps the
`tulpa/sign` domain). A verifier resolves `issuer` to a public key by its own
policy and the resolver rules of [`ink-resolver.md`](ink-resolver.md); key
resolution is not part of the attestation.

## Verification

Verification takes the raw bytes, the resolved issuer public key and a context
`{ now }`. Check order, first failure wins, each with its stable reason:

1. byte cap, raw-body gate, JSON parse → `schema`
2. structural bounds and field grammar → `schema`
3. signature over the canonical unsigned object → `signature`
4. validity window, lower bound inclusive, upper bound exclusive → `not_yet_valid` | `expired`

That is the whole base verification. Deliberately absent: audience (an
attestation is a public statement, not a capability, and binds no presenter),
scope, replay (presenting the same true claim twice is not an attack; caching
dedupes on `(issuer, attestationId)`), and any judgment about the issuer or the
claim. A verified attestation means one thing: this issuer's key signed this
claim about this subject for this window. Whether that means anything is the
receiver's decision, made after verification, never during it.

## Transport validity and receiver acceptance

These are different questions and the wire keeps them different.

A message is **transport-valid** when it passes the §3.3 transport signature,
the freshness and nonce rules, the body checks and the schema. Transport
validity is not negotiable and not a matter of policy: an implementation that
rejects a transport-valid message MUST NOT report the rejection with an
`auth:*` or `schema` code, and an implementation that accepts a
transport-invalid message is nonconformant no matter what evidence accompanied
it. Evidence never compensates for a bad signature.

**Acceptance** is what the receiver does next, and it is entirely the
receiver's. A receiver MAY refuse, sandbox, defer or rate-limit a
transport-valid message for any reason, including insufficient evidence. When
the reason is evidence, the refusal is structured:

- error code `policy:evidence_required`, HTTP 403;
- a `requiredClaimTypes` member: an array of 1 to 32 claim-type strings under
  the `claimType` grammar. The semantics are conjunctive and residual: the
  array names the claim types still missing after the receiver evaluated
  whatever evidence was presented, and all of them are required. Disjunctive
  policy ("any one of these") is not expressible in this shape and is deferred
  with the rest of policy vocabulary; a receiver holding an OR policy
  advertises the branch it prefers.

The refusal names types, never issuers: which issuers a receiver believes is
policy it is free to keep private, and naming them would invite issuer
enumeration. That privacy has a cost the sender must be able to terminate on:
a presented attestation of a listed type that the receiver does not credit —
untrusted issuer, discounted window, unconvincing claim payload — leaves the
type in `requiredClaimTypes`, and the refusal is indistinguishable from the
type never having been presented. So the termination rule is the sender's: a
sender that receives the same claim type in `requiredClaimTypes` after
presenting a verified attestation of that type MUST conclude that its evidence
was not credited, MUST NOT retry with the same attestation, and either obtains
the type from a different issuer or stops. A sender that can obtain a named
attestation retries with it; how attestations travel with a message is the
presentation binding below.

Receivers SHOULD prefer sandboxing to refusal where their product allows it:
accept the message, hold it out of privileged flows and say so. The early
network will contain agents with no history and no evidence, and a network
where the default answer is a closed door selects against exactly the adopters
the protocol exists for. This is guidance, not conformance: honesty about the
trade is the point, and a receiver that default-denies is conformant.

## Presentation

An attestation about a sender travels in the sender's Agent Card, in a new
optional top-level member:

- `attestations`: an array of 1 to 16 attestation objects, each independently
  verifiable under this specification.

The standalone 65536-byte attestation cap does not compose across the array:
the card itself is fetched under the 65536-byte body cap of
[`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md), so
every carried attestation shares that one budget with the rest of the card.
The practical consequence is intended: card-carried attestations are small,
and a claim whose payload wants serious size belongs in an out-of-band
artifact the claim payload references, not inline.

The card is the right carrier because it is already the sender's public,
signed, cacheable self-description, and because attestations are statements
about the agent, not about any single message. A receiver that requires
evidence resolves the sender's card exactly as it already does for keys, then
verifies whichever presented attestations carry claim types it cares about.
Attestations MUST NOT be carried inside message envelopes; a per-message
evidence channel invites per-message identity churn, and the card carrier makes
evidence a property of the identity instead.

**Subject binding.** A presented attestation satisfies evidence for a sender
only when its `subject` and the authenticated sender's `agentId` (equivalently,
the `agentId` of the card carrying it) are equal under the canonical principal
equality of [`ink-identity-model.md`](ink-identity-model.md) §3. A receiver
MUST enforce this before treating an attestation as evidence: base
verification proves the issuer signed a claim about `subject` and nothing about
who presents it, so without the binding any card could carry a valid
attestation copied from someone else's. An attestation whose subject is a
different principal is not malformed and not a protocol error; it is simply
not evidence for this sender.

A receiver advertises its expectations in its own card, in a second optional
member:

- `evidencePolicy`: an object with two optional members, `required` and
  `preferred`, each an array of 1 to 32 claim-type strings. `required` means
  transport-valid messages without a verified attestation of a listed type get
  the structured refusal above. `preferred` means such messages may be
  sandboxed or degraded. An absent member means nothing is required or
  preferred; an absent `evidencePolicy` means the receiver makes no advance
  statement, and the refusal code remains the authoritative signal.

Every claim-type array in this specification — `requiredClaimTypes`,
`evidencePolicy.required` and `evidencePolicy.preferred` — is a set: entries
MUST be distinct, a duplicate makes the carrying document malformed, and a
listed type is satisfied by one credited attestation of that type, never by a
count. Unknown members inside `evidencePolicy` follow the card's own
unknown-member rule: ignored for interpretation, covered by the card proof
when present.

Both members are additive optional card members under the compatibility
policy: a card without them is exactly as valid as today, and an
implementation that does not understand them ignores them for interpretation.
Signed cards stay compatible because of how
[`ink-agent-card-signature.md`](ink-agent-card-signature.md) defines the proof:
the signature is computed over the fetched document with `cardSignature`
removed **and nothing else removed**, so a verifier operates on the document as
served, unknown members included, and a consumer that strips unknown members
before verifying was already nonconformant under that rule. The consequence is
deliberate: because the proof covers them, an intermediary that strips
`attestations` from a signed card breaks the proof rather than silently
downgrading the sender's evidence.

**Activation and rollout, receiver-first.** This section is
**specified-inactive**: it takes effect only when the implementing change
lands, and until then no producer may publish either member in a signed card.
The implementing change is one release and carries, together: the Agent Card
spec and schema additions for bounded `attestations` and `evidencePolicy`
members, the fetch-path fix this paragraph describes, the conformance vectors that pin both and
the conformance-profile anchoring described under *Conformance*. The reason
for the gate is a defect this draft records: at the time of writing the
TypeScript reference's fetch path validates the card schema first and
verifies the proof over the schema's output, so an unknown member is stripped
before the proof is recomputed and a signed card carrying one reads
`invalid_signature`. Implementations MUST verify the proof over the fetched
document before any schema-driven stripping. Until consumers with the fix are
deployed, a producer publishing `attestations` in a signed card would be
rejected by consumers with the defect, so producers ship after receivers —
the same receiver-first order every other INK transition has used.

## Sybil resistance, stated plainly

Minting is free, so an attacker can present a fresh `agentId` per message, and
nothing at the transport layer prevents it — by design, and permanently. The
enforceable line is receiver policy, and before any history exists a receiver
can key on exactly three things: evidence presented under this specification
from issuers it chooses to believe, the operational cost controls it already
runs (rate limits, first-contact intent restrictions, sandboxing), and nothing
else. This specification adds the first; it does not and cannot add a
mechanism that makes fresh identities expensive, and claims that a future
reputation layer will are out of scope until such a layer exists to be
specified. A receiver whose threat model cannot tolerate free identities
requires evidence; that is the honest shape of the guarantee.

## Security considerations

- **An attestation is not authorization.** It grants nothing and binds no
  audience. A service that gates actions on attestations is composing policy
  on top of verification, and the composition is its own responsibility.
- **Issuer key rotation.** An attestation verifies against the issuer's key
  under the same rotation rules as any other signed body. A claim signed by a
  key later revoked for compromise is exactly as suspect as any other artifact
  of that key; receivers that cache verified attestations SHOULD re-verify on
  issuer key-set changes.
- **Claim payloads are untrusted input.** `claim` is opaque to the base
  verifier but not to whatever policy code reads it. Everything that reads a
  claim payload applies the same input discipline as any other
  counterparty-supplied JSON.
- **Enumeration.** `evidencePolicy` is public by construction. A receiver that
  considers its full policy sensitive advertises a subset or nothing and relies
  on the refusal code.

## Conformance

This section reserves names; it anchors nothing by itself. The `attestation`
conformance category pins the accept and reject decisions of this
specification — shape bounds, grammar, raw-body gate placement, signature,
window edges and the single-spelling wire type — and the
`policy:evidence_required` refusal shape is pinned alongside it. Both are
capability-gated: an implementation that neither produces nor consumes
attestations does not advertise the capability and is not bound by either.
The category, the capability name and its Agent Card advertisement are
anchored in [`ink-conformance-profile.md`](ink-conformance-profile.md) by the
implementing change named under *Activation and rollout*; until that change
lands, no implementation is bound by this section and no receiver may
advertise `evidencePolicy` while claiming conformance.
