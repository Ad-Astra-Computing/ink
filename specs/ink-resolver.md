# INK Resolver Specification

**Status:** Draft, 1.0 stabilization. This document pins the walk from an
identifier to verified key material. It states the resolution facts that had no
normative home and cites the single home of every fact that already had one; it
does not restate a rule another spec owns.
**Authors:** Ad Astra Computing
**Last updated:** 2026-08-17

Requirement keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** are used per RFC 2119.

## 1. Purpose

Every INK verification begins with key material, and every INK document that
consumes key material assumes the reader already has it. The authority rule
opens with a card the receiver has somehow obtained
([`../docs/key-rotation-rule.md`](../docs/key-rotation-rule.md)), the card proof
begins with a card someone fetched
([`ink-agent-card-signature.md`](ink-agent-card-signature.md) §5) and the fetch
contract begins after the request has already been made
([`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md)). The
step before all of them, from an `agentId` on the wire to a fetched and verified
card, was distributed across a discovery paragraph, a response contract, an
SSRF classifier, one profile's origin derivation and the two implementations'
code. An adopter reconstructing it read five documents and guessed at the seams.

This document is that step. It defines what a **resolver** accepts as input,
what it does for each admissible input, what it MUST refuse, how its result may
be cached and what outcomes it reports. Where a rule is already normative
elsewhere this document names the edge and cites the owning spec, because a
duplicated normative sentence is a drift source. Where a behavior was
implemented but unwritten this document is its normative home.

This document adds no wire format, no field and no message type. The identity
model ([`ink-identity-model.md`](ink-identity-model.md)) says what an INK
identity IS; this document says how a party GETS to one. The two are companions
and neither restates the other.

A resolver's job ends at a verified card and the key set inside it. What a
relying party then does with that key set is the authority rule's business, and
whether it wants to talk to the party at all is policy this document does not
touch (§7).

## 2. Resolution inputs

A resolver takes one principal, in the grammar
[`ink-protocol.md`](ink-protocol.md) §7 pins, and nothing else. It MUST NOT
accept a `handle`, a `displayName` or an `ownerDid` as an input; none of them is
an identifier (`ink-identity-model.md` §2.4, §2.5). It MUST NOT accept a bare
URL as a substitute for a principal, because a URL names a document and the
identity binding of §3.4 exists precisely to check that the document at a URL is
the one a principal asked for.

The input determines everything that follows, so a resolver MUST classify it
before doing any network work, and MUST fail closed on a classification it does
not recognize.

### 2.1 Key-derived principals

A `tulpa:<multibase>` or `ink:<multibase>` principal is resolvable to a key
WITHOUT any resolution: the identifier carries its own genesis key
(`ink-identity-model.md` §2.1). That key is a bootstrap credential and not the
identity's current signing key, and its use is bounded by the trust-on-first-use
window of `docs/key-rotation-rule.md` invariant 4.

A key-derived principal is NOT self-locating. Nothing in the identifier names a
host, and INK defines no derivation from one to a discovery base: no DNS record,
no default registry and no well-known origin. Resolving a key-derived principal
to a card therefore requires a discovery base the resolver already holds. §3.1
states the consequences.

The two spellings denote one actor (`ink-identity-model.md` §2.2), so a resolver
MUST NOT resolve them separately or hold two cache entries for them (§4).

### 2.2 `did:web` principals

A `did:web` principal is resolvable, because the identifier names a host and the
host is the discovery base. This is the only foreign principal form for which
INK pins any part of the walk, and the identity model records that scope and
names this document as the general procedure's home
(`ink-identity-model.md` §2.3, §5.1). §3.1 gives the base derivation and §3.4
the verification order.

### 2.3 Unresolvable inputs

The following inputs are NOT resolvable by this specification. For each, a
resolver MUST return the `unresolvable-input` outcome of §6 without performing
any network request, and MUST NOT substitute a weaker path. The rule the
identity model states for foreign principals generally, that a verifier which
cannot resolve MUST reject and MUST NOT fall back (`ink-identity-model.md`
§2.3), is what each of these cases instantiates.

- **An escape form.** A value beginning `key:` or `raw:` is a canonicalization
  output, never a legitimate `agentId` (Protocol §7,
  `ink-identity-model.md` §3.1). A resolver presented with one has been handed a
  canonicalized value where a raw one belongs, which is a caller defect, and it
  MUST NOT attempt to reverse the escape.
- **`did:key`.** A `did:key` identifier embeds a key and no location. It has no
  discovery surface, so there is no card to fetch, and
  `ink-agent-card-signature.md` §4 roots a card proof only for a key-derived id
  and for `did:web`. A resolver therefore cannot produce a verified card for
  one. A deployment MAY separately accept a `did:key` counterparty by decoding
  the embedded key, but that is a key-supply path outside this specification and
  the key it yields is a bootstrap key that no rotation can ever update; a
  deployment taking it MUST NOT present the result as a resolved card, and MUST
  NOT let it satisfy any rule this document states.
- **Any other method or unknown form.** A `did:plc`, a `did:ion`, a bare string
  or a method a resolver does not implement resolves under the issuing identity
  system's own rules, out of band of INK, and a resolver that does not implement
  those rules MUST fail rather than approximate them.

### 2.4 Input hygiene

Before deriving any URL from a principal a resolver MUST reject an input that
could steer the derived URL away from the target the principal names. At
minimum it MUST reject a non-string input, an empty input, an input longer than
the bound its URL construction can carry, and an input containing `/`, `\` or a
dot segment. These are path-traversal primitives against §3.2, not identity
rules, and they apply whatever the principal kind.

A resolver MUST perform this check on the RAW principal, before any
canonicalization. Canonicalization is applied exactly once at the storage
boundary (Protocol §7) and its output is not a resolution input (§2.3).

## 3. The resolution algorithm

A resolver evaluates in this order. The first failing step ends the resolution
with the outcome §6 assigns it.

### 3.1 Base derivation

**`did:web`.** The base is the origin the identifier names. For a bare-host
`did:web` identifier the derivation is pinned, by explicit string rules and
never by a URL parser, in
[`ink-agent-authorization.md`](ink-agent-authorization.md), and it yields
`https://` plus the host plus `:` and the decimal port when the identifier
carries one. A resolver MUST carry a `%3A`-encoded port into the derived origin
and MUST reject the identifier rather than resolve it at the default port
(`ink-identity-model.md` §2.3). Dropping the port silently retargets the fetch
at a different origin, which is a different document.

A resolver MAY additionally accept the path form `did:web:<host>:<seg>:<seg>`
under the W3C did:web method's own rules. INK pins no grammar for it, so a
resolver that accepts one MUST apply every other rule of this section to the
result unchanged, and MUST reject a segment that is `.` or `..` or that carries
a character outside an unreserved set.

**Key-derived.** There is no derivation. A resolver MUST NOT synthesize a base
for a key-derived principal, and MUST resolve one only against a base it holds
out of band: a base configured by the operator, a base recorded from an earlier
verified interaction with that same principal or a base a directory supplied
which the resolver's own policy trusts. This is a real bootstrap dependency and
it is named here rather than left for an adopter to discover: INK is
point-resolution, and a peer fetches a card only when it already knows where to
look (`ink-discovery-descriptor.md`).

A base a resolver did not already trust does not become trustworthy by being
used. A resolver MUST NOT treat a base supplied by an unauthenticated
counterparty, including one carried in the same message whose signature it is
trying to verify, as authoritative for that counterparty's own principal:
accepting one lets a sender nominate the host that will vouch for it, which
defeats the identity binding of §3.4 by making the attacker both the question
and the answer. The rule binds for a key-derived principal too, where the
identity binding cannot carry that argument on its own because the identifier
names no host: a nominated base lets an attacker steer a cold verifier to a
stale card that is validly signed and correctly bound, and a verifier meeting
the principal for the first time holds no prior card for the rollback rule of
`ink-agent-card-signature.md` §6 to bite on, so it adopts a superseded key set
as authoritative. A resolver MAY fetch such a base only when the result is used
for nothing but a first-contact record its own policy separately gates.

**Base URL form.** Whatever its origin, a base MUST be an `https` URL with no
userinfo. A resolver MUST reject a base with any other scheme, and MUST reject
a base carrying a username or a password, before §5 and before any request.

### 3.2 URL construction

A resolver constructs the discovery URL by joining the base to the versioned
card path, which `ink-agent-card-discovery-fetch.md` owns and this document does
not restate, with the `agentId` percent-encoded as a single path segment. That
versioned path is the sole normative discovery surface.

Construction MUST be performed against a PARSED base, not by string
concatenation on the raw base, and the resolver MUST confirm that the
constructed path still ends in the segment it intended. A URL serializer
normalizes dot segments and re-encodes escapes, so a base that passed validation
as a string can still serialize to a different path; checking the suffix after
construction is what closes that gap, and it is cheap.

An implementation MAY serve the same card at `/.well-known/ink/agent.json`, and
a resolver MUST NOT depend on that path: a peer that serves only the versioned
path is conforming, so a resolver that reaches for the alias first, or falls
back to it on a failure, is resolving outside this document. A resolver that
does accept the alias MUST treat it as nothing but a second URL for the same
document and MUST NOT relax any other rule of this document for it. In
particular the identity binding of §3.4 applies unchanged: a card served at a
well-known path is not thereby entitled to speak for whatever principal asked
for it. Where a profile pins its own card URL, that profile's
construction governs for that profile and this one does not; the INK Agent
Authorization profile does so for a relying party's card and for a sign-in
issuer's card, and states which parts of the fetch contract it reuses
(`ink-agent-authorization.md`).

### 3.3 The fetch

The response-evaluation contract is pinned in one place and this document does
not restate it: `ink-agent-card-discovery-fetch.md` owns the status rule, the
declared-length rule, the content-type rule, the body-size cap, the JSON parse,
the schema check, the protocol literal, the identity binding and the `ownerDid`
anti-substitution check, in that order. A resolver MUST run those steps
unchanged and MUST NOT accept a response that fails any of them. A resolver that
began at an owner's DID document and followed it to the card MUST supply that
owner's DID as the contract's `resolutionDid` input. Every other resolver MUST
supply null, including one that reached the card through the agent's own DID
document, which is the shape §3.1 describes: the input names an owner, so
passing an agent identifier there refuses every card whose owner and agent
differ. A wrong value either weakens the check or rejects a conforming card.

The request side is what that contract deliberately leaves out, and it is
specified here.

- **Redirects.** A resolver MUST NOT follow a redirect. Discovery is served at a
  fixed path, so a redirect is not a card; a followed redirect also escapes
  every check §3.1 and §5 made against the original base, which is exactly the
  SSRF primitive those checks exist to remove. Refusal MUST be at the transport
  layer, so that the response contract's status rule is a second line of defense
  and not the only one.
- **Body reading.** A resolver MUST bound the bytes it reads BEFORE it has a
  complete body, by aborting a read that crosses the cap, so that a chunked
  response carrying no declared length cannot force unbounded buffering. The cap
  is the one the fetch contract pins. Enforcing it only on an already-read body
  satisfies the response contract and not this rule.
- **Timeouts.** A resolver MUST bound the time it will wait for a discovery
  response, and SHOULD keep that bound short enough that a slow or hostile host
  cannot occupy a verification path. INK pins no duration: a bound is a
  liveness property of the resolver, not an interoperability property of the
  wire, and two resolvers with different bounds still accept and reject the same
  cards.
- **Request shape.** A resolver MUST NOT attach any credential, cookie or
  ambient authorization to a discovery request. Discovery is an unauthenticated
  read of a public document, and a request that carries a credential to an
  attacker-influenced origin is a credential disclosure whatever the response
  contains.

### 3.4 Post-fetch verification order

A resolver MUST NOT return key material from a card until the card has passed,
in this order:

1. **The response contract.** Steps 1 through 8 of
   `ink-agent-card-discovery-fetch.md`, which include the schema check and the
   identity binding of the fetched `agentId` against the requested one, compared
   byte for byte (`ink-identity-model.md` §3.3).
2. **The card proof, per phase posture.** The proof, its rooting by principal
   kind, the continuity and rollback rules against any cached prior card and
   the adoption step after which the card becomes the authoritative key set, are
   the verifier algorithm of `ink-agent-card-signature.md` §5, run unchanged.
   Which of its rules a conforming receiver MUST enforce today is the rollout
   schedule of that spec's §10 together with
   [`ink-conformance-profile.md`](ink-conformance-profile.md); this document
   does not transcribe a phase state, because a phase state copied into a second
   document goes stale.
3. **Key extraction.** Candidate keys come from the card's published signing
   set, under the authority rule of `docs/key-rotation-rule.md` as narrowed for
   live transport authentication (`ink-identity-model.md` §4.4). A resolver MUST
   NOT reorder these steps and MUST NOT extract keys from a card that failed an
   earlier one. A card that fails the proof is rejected outright and is never
   demoted to unsigned (`ink-agent-card-signature.md` §3.4).

The two identity checks in this order are independent and both are required:
the card proof shows a key signed the card, the identity binding shows the card
is the one asked for (`ink-identity-model.md` §5.3).

### 3.5 Card-content vetting

A card carries URL-shaped fields that a downstream caller will fetch or post to,
beginning with `endpoint`. Those fields arrive from the network, so a resolver
MUST apply the host-safety gate of §5 to every URL-shaped field of a card it
returns, and MUST reject the card when any of them fails, rather than returning
the card with a field a caller is expected to re-check. A resolver that returns
an unvetted `endpoint` has moved an SSRF decision to whichever caller forgets to
make it.

The field grammar itself, including the `https` scheme, the userinfo ban, the
control-character ban and the fragment ban, is the endpoint URL grammar of
[`ink-agent-card.md`](ink-agent-card.md) and is checked by the schema step of
§3.4. §5 is the additional host check the grammar does not make.

## 4. Caching and revalidation

Neither reference implementation carries a card cache today, so every rule in
this section binds whatever cache an adopter builds rather than describing one
that exists.

A resolver's cache is not a performance detail. Once a card has been observed,
the continuity, rollback and signature-stripping rules of
`ink-agent-card-signature.md` §6 and §7 compare every later card against it, and
the bootstrap window of `docs/key-rotation-rule.md` invariant 4 closes on it.
The cache is therefore security state, and this section states the obligations
that follow.

**What MAY be cached.** A resolver MAY cache a card that passed §3.4 in full,
and the key set extracted from it. It MUST NOT cache a card that failed any
step, and MUST NOT cache a card at an intermediate stage of §3.4: a card the
proof has not yet accepted is not a card, and a cache that holds one will
eventually be read by something that assumes it is.

**Cache key.** An entry MUST be keyed on the canonical principal, never on the
raw spelling and never on the URL it was fetched from. A key-resolution cache is
per-sender security state and the canonical-principal rule covers it explicitly
(`ink-identity-model.md` §3.2). Keying on the raw spelling splits one identity
into two entries, which is the split the canonicalization exists to prevent.

**Lifetime.** A resolver MAY serve a cached card without revalidating for a
bounded period of its own choosing. INK pins no duration and defines no
freshness field on the card: `updatedAt` carries no comparison rule by design
and `keySetVersion` is the sole monotonic quantity
(`ink-agent-card-signature.md` §6), so neither is a lifetime. A resolver MUST
NOT derive one from an HTTP cache header either, since the header is supplied by
the same host the card is, and MUST NOT treat any cached card as current: a
valid proof shows reachability, not currency (`ink-identity-model.md` §6.2).

**What invalidates.** A resolver MUST discard or replace a cached entry when it
observes a later card for the same principal that passes §3.4, and the
replacement MUST satisfy the continuity and rollback rules against the entry it
replaces before it takes effect. A verification failure against a cached key set
MUST NOT silently invalidate the entry: the authority rule forbids falling
through to another key source when the observed set has spoken
(`docs/key-rotation-rule.md` invariant 3), so a resolver that treats a failed
signature as a cache miss and refetches has built the fallback the rule forbids.
A resolver MAY refetch on a schedule, on a rotation it learns of out of band or
on operator action, and it MUST apply §3.4 to the result exactly as to a first
fetch.

**What MUST NOT be evicted.** The record that an authenticated card has been
observed for a principal outlives any individual cached card. Evicting it
reopens the bootstrap window that invariant 4 closed and re-admits an unsigned
card that §7 of the card-signature spec rejects permanently. A resolver MUST
retain that record at least as long as it retains any other per-sender security
state for the principal, and MUST NOT let ordinary cache pressure clear it.

**Negative caching.** A resolver MUST NOT cache a failed resolution as an
authoritative negative: a fetch failure is a statement about a moment, not about
an identity, and a cached one converts a transient outage into a durable refusal
an attacker can induce. A resolver MAY rate-limit or back off retries for a
principal that recently failed, provided the backoff decays and provided it
never turns into a rule that the principal is unresolvable.

## 5. Host safety

Every outbound request a resolver makes MUST pass the host-safety
classification of [`ink-private-hostname.md`](ink-private-hostname.md), failing
closed on a loopback, private, link-local, IANA special-use or malformed
IP-shaped host. This is a MUST for any resolver reachable from untrusted input,
which is every resolver that resolves a principal it read off the wire. The gate
applies to the discovery fetch of §3.3, to a DID-document fetch performed under
§3.1 (`ink-identity-model.md` §2.3) and to the card-content vetting of §3.5.

The classifier is a static-literal gate and its own spec says so: it does not
defend against DNS rebinding, and a public hostname that resolves to a private
address at connect time still reaches that address. A resolver MUST therefore
also apply the check at connect time, rejecting a resolved address in a private
or special-use range and pinning the connection to the address it checked, so
that a name which re-resolves between the check and the connect gains nothing.
A resolver that cannot pin the connect address in its runtime MUST fail closed
rather than proceed with the literal check alone, and MUST NOT describe the
literal check as an SSRF defense on its own. The Agent Authorization profile
already states this pairing for its own fetch; this section is the general rule
for every resolver fetch.

A deployment MAY disable the gate for a base it configured itself, for an
intentional intranet target or for a test. It MUST NOT disable it for a base or
a principal that reached it from the network, and the switch MUST be off by
default.

## 6. Outcomes

An implementation reports one of a closed set, so that two implementations
describing the same resolution describe it the same way. A resolver MUST
classify every resolution into exactly one of these values internally, because
the disclosure rule at the end of this section is a rule about a distinction the
resolver has already drawn and cannot be satisfied by a resolver that never drew
it. A resolver MAY collapse the classification at its caller-facing API: a
library that returns one failure value for every non-`resolved` outcome is
conformant on this point, and the TypeScript reference implementation's
`fetchAgentCard`, which returns `null` for every failure alike, collapses in
exactly that way. The set is deliberately small and draws no distinction finer
than the rules of this document require.

| Outcome | Meaning |
|---|---|
| `resolved` | A card passed §3.4 in full and its key set is available. |
| `unresolvable-input` | This resolver cannot get from what it was given to a discovery request at all, so the resolution ends before the fetch step of §3.3. |
| `fetch-failed` | The resolution reached the fetch step and no response reached the response contract: a transport error, a timeout, a refused redirect or a host the gate of §5 rejected before the request went out. |
| `verification-failed` | A response reached the response contract or the verification order of §3.4 and was rejected by it. |

Three failure classes are assigned here rather than left for an implementation
to place, because each sits near a boundary between two of the values:

- **A key-derived principal for which the resolver holds no base (§3.1).** The
  outcome is `unresolvable-input`. The input is well formed and the missing
  thing is the resolver's own knowledge, which reads against the name, but the
  discriminator this section uses is which side of the fetch step the resolution
  ends on, and this one ends before URL construction: with no base there is no
  URL to construct and no request to attempt, so `fetch-failed` would report a
  fetch step the resolution never reached. `unresolvable-input` is the value for
  a resolution that ends before any request, and its meaning above is
  resolver-relative for exactly this case.
- **A base that fails the base-URL form rule of §3.1**, by carrying a scheme
  other than `https` or by carrying userinfo. The outcome is
  `unresolvable-input`. That rule is checked during base derivation, before §5
  and before any request, so the resolution ends on the same side of the fetch
  step as the case above.
- **A `did:web` identifier whose `%3A`-encoded port the resolver cannot carry
  (§3.1).** The outcome is `unresolvable-input`. The identifier is rejected
  rather than resolved at the default port, and the rejection is a statement
  that this resolver cannot resolve this identifier, made before any request.

The `unresolvable-input` value therefore covers both a defective input and an
admissible input this resolver cannot act on. Nothing distinguishes them to a
counterparty, and the disclosure rule below constrains only the other two.

Only `resolved` yields key material. A resolver MUST NOT return partial results
with any other outcome, MUST NOT return a card alongside a non-`resolved`
outcome, and MUST NOT let a caller convert a non-`resolved` outcome into key
material by supplying a default.

The four values are grounded in two things and nothing wider. The Go
implementation already separates a bad input from a clean rejection at its
command layer, where the two reach a caller as different exit codes, and that
separation is what `unresolvable-input` names against the two failure outcomes.
The split between `fetch-failed` and `verification-failed` is required by the
disclosure rule below on its own terms: a resolver cannot decline to reveal
which of the two occurred unless it has already told them apart internally. The
TypeScript library makes neither distinction at its API today, where every
failure returns `null`, so this table is a classification the implementations
grow into rather than a report of one they both already make. A resolver MAY
carry richer internal diagnostics and SHOULD log them; this set is the
reportable classification, not a limit on what an operator may see.

An outcome is internal. A resolver MUST NOT convey which of `fetch-failed` and
`verification-failed` occurred to the counterparty whose principal it resolved,
and MUST NOT vary an externally observable response by it, because the
difference between them is an oracle over what the resolver's network can reach.
The wire-visible outcome of a failed resolution is that the message is rejected,
and the rejection reason belongs to whatever surface the message arrived on.

## 7. Non-goals

These are outside the resolver by decision, not by omission. An implementation
MUST NOT depend on this document to provide them.

**Finding an agent.** Resolution starts from a principal a party already has. It
does not search, it does not list and it does not rank. A directory is a
separate surface: an agent opts into being surfaced by the descriptor of
[`ink-discovery-descriptor.md`](ink-discovery-descriptor.md), and a request to a
directory is the envelope of [`ink-discovery-query.md`](ink-discovery-query.md).
Neither is part of resolution, and a resolver MUST NOT accept a directory result
as a substitute for §3.4.

**Deciding whether to trust the resolved party.** A resolver answers whether the
key material is authentically the principal's. It does not answer whether the
principal should be talked to. Block lists, rate limits, reputation, owner
status and every other policy input sit above the resolver, and the identity
model states what the resolved artifacts do and do not prove
(`ink-identity-model.md` §6.2, §2.4).

**Carrying intents.** Resolution is a read of a discovery document. It sends no
message, establishes no connection and creates no state with the counterparty.
The message contract, its signatures and its replay rules are Protocol §3.

**Resolving foreign identity systems.** Except for the `did:web` base derivation
of §3.1, INK defines no procedure from a foreign identifier to a key
(`ink-identity-model.md` §7). An adopter bringing its own identity system
supplies that procedure and is the party that must get it right, and this
document's obligations, the host-safety gate above all, apply to whatever it
supplies.

**Owner and handle lookup.** There is no resolution from a `handle`, an
`ownerHandle` or an `ownerDid` to a principal, in this document or anywhere in
INK (`ink-identity-model.md` §2.4, §2.5).

## 8. Relationship to other specs

Each row is the single home of the facts named. This document cites them and
does not duplicate them.

| Spec | Owns |
|---|---|
| [`ink-protocol.md`](ink-protocol.md) | The principal grammar, the versioned discovery path and canonicalization to a prefix-independent principal (§2, §7) |
| [`ink-identity-model.md`](ink-identity-model.md) | What each principal identifies, the equality rules, the key roles and what a resolved card does and does not prove |
| [`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md) | The discovery response-evaluation contract, its ordered steps and the identity binding |
| [`ink-agent-card.md`](ink-agent-card.md) | The card schema and the endpoint URL grammar applied to URL-shaped fields |
| [`ink-agent-card-signature.md`](ink-agent-card-signature.md) | The card proof, its rooting by principal kind, the verifier order, continuity and rollback and the phase rollout |
| [`../docs/key-rotation-rule.md`](../docs/key-rotation-rule.md) | The authority rule, the no-fallback invariants and the bootstrap window |
| [`ink-private-hostname.md`](ink-private-hostname.md) | The host-safety classification every resolver fetch passes |
| [`ink-agent-authorization.md`](ink-agent-authorization.md) | The bare-host `did:web` grammar, the deterministic origin derivation and that profile's own card URL construction |
| [`ink-discovery-descriptor.md`](ink-discovery-descriptor.md) | The opt-in declaration that an agent consents to being surfaced |
| [`ink-discovery-query.md`](ink-discovery-query.md) | The authenticated request to a directory |
| [`ink-conformance-profile.md`](ink-conformance-profile.md) | Which categories a conforming implementation MUST satisfy |

## 9. Conformance

The response-evaluation half of §3 is already pinned by the `agent-card-fetch`
category of `conformance/v1`, the host classification of §5 by
`private-hostname`, the cache-key rule of §4 by `principal-normalization` and
the verification order of §3.4 by `agent-card-signature` and `key-rotation`. An
implementation that passes those satisfies that part of this document.

The rules this document states that no existing vector pins are the request-side
and lifecycle ones, and they are recorded here as candidate categories rather
than left implicit:

- URL construction from a base and a principal (§3.2): the joined path, the
  single-segment encoding of the `agentId` and the post-construction suffix
  check are a pure function of two strings and are vector-shaped, as is the
  input hygiene of §2.4;
- the base-derivation refusals (§3.1): a non-`https` base, a base carrying
  userinfo and a `did:web` identifier whose port cannot be carried each have one
  correct answer;
- the outcome classification (§6): which of the four outcomes a given failure
  produces is comparable across implementations only if it is pinned.

Three parts of this document are not vector-shaped and are enforced by review.
The connect-time pinning requirement of §5 is a property of a runtime's socket
layer, not of a decision over strings. The cache obligations of §4 are
statements about state held across resolutions, which a single-shot vector
cannot express. The outcome-disclosure rule of §6 is a negative about what a
resolver does not tell a counterparty, and a negative of that shape is
unpinnable by construction.
