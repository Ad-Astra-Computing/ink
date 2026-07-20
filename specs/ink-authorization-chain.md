# INK Authorization Chain Extension Specification v0.1

**Status:** Draft. A post-1.0 named extension, not part of the 1.0 core. It
builds on the merged authorization-grant primitive
([`ink-authorization-grant.md`](ink-authorization-grant.md)) and Agent Card
signature rooting ([`ink-agent-card-signature.md`](ink-agent-card-signature.md)),
and it blocks nothing in 1.0.
**Authors:** Ad Astra Computing
**Last updated:** 2026-07-20

Requirement keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and
**MAY** are used per RFC 2119, consistent with the grant spec.

## Purpose

The [`ink-authorization-grant.md`](ink-authorization-grant.md) primitive pins a
single signed hop: one issuer grants one subject a bounded capability to present
to one named audience inside a short window. That primitive is deliberately not a
delegation framework. This extension adds exactly one thing on top of it: a
linear chain of those same grants, each hop narrowing the last, so a service can
verify that a presenter holds authority that traces back through a bounded number
of re-delegations to an origin issuer it can root.

A chain is not a new credential. Every link is the grant field model, signed over
the same bytes with the same discipline, so an implementation that already
verifies a grant reuses its schema, its canonicalization and its signature check
unchanged. The chain adds a parent hash that binds each link to the one above it,
a continuity rule that ties issuer to subject across the seam, a monotonic
attenuation rule decided on signed bytes and a three-pass verify order that fails
closed. It changes no field of the grant and it defines no capability algebra: a
`scope` entry stays an opaque audience-local token, exactly as the grant leaves
it.

For independent implementations to interoperate they MUST accept and reject the
same chains and verify the same signatures over the same bytes.

## Relationship to the grant and the sign-in profile

This extension composes two frozen surfaces without perturbing either. The grant
primitive is the field model and the signature scheme every link reuses. The
Agent Card signature machinery
([`ink-agent-card-signature.md`](ink-agent-card-signature.md)) is how a verifier
resolves and roots each link issuer's signing key. Neither the 1.0 base profile
nor the sign-in `authorization` capability
([`ink-agent-authorization.md`](ink-agent-authorization.md)) is amended here: this
extension ships additively under its own `delegation` capability (see *Capability
gate and conformance*).

A delegated capability minted by the sign-in profile can be the origin of a
chain: the authority the sign-in flow's delegated-capability grant conveys is the
authority the root link of a chain carries. Where the sign-in profile presents
that authority as a single grant, this extension re-expresses it as the root link
of a chain and adds bounded onward delegation below it.

## Delegation link

A delegation link is the grant field model with exactly two changes and nothing
else. Every field of the grant carries its meaning, its bound and its role from
[`ink-authorization-grant.md`](ink-authorization-grant.md) unchanged. The two
changes are:

1. **`type`** is the single string `network.ink.delegation_link`. This is a new
   type, so there is no legacy dual-accept alias to carry and a receiver accepts
   only this one spelling. The signed bytes bind it and it is never normalized.
2. **`parent`** is added: the base64url-no-padding SHA-256 digest of the parent
   link (see *The `parent` hash*). It is present on every link EXCEPT the root,
   and the root link MUST NOT carry it.

So a delegation link is a JSON object with exactly these fields and no others,
every field required except `requireVerifiedOwner` and except `parent` on the
root:

- `protocol`: the string `ink/0.1`, the same value and role as in the grant. It
  selects the body-signature domain (see *Signature*).
- `type`: the string `network.ink.delegation_link`.
- `issuer`: the delegating principal for this link, a non-empty string of at most
  512 UTF-16 code units. The issuer key signs the link.
- `subject`: the principal this link delegates to, the same bound. On any
  non-final link, this subject is the `issuer` of the link directly beneath it
  (see *Chain continuity*); on the final link the subject is the principal the
  whole chain is delegated to, bound to the authenticated presenter at pass 3.
- `audience`: the DID or service id the chain may be presented to, the same
  bound. It is fixed by the origin issuer and MUST be identical on every link (see
  *Confused deputy and multi-hop safety*).
- `scope`: an array of 1 to 64 distinct strings, each 1 to 128 UTF-16 code units,
  the same bounds and distinctness rule as a grant `scope`. A child link's scope
  MUST be a subset of its parent's (see *Attenuation*).
- `grantId`: an issuer-chosen unique id, 16 to 256 UTF-16 code units. It is the
  replay and revocation key for this link, keyed with `issuer` as the pair
  `(issuer, grantId)`.
- `issuedAt`: a strict INK timestamp (see
  [`ink-timestamp-grammar.md`](ink-timestamp-grammar.md)). The link is not valid
  before this instant, and it MUST NOT precede its parent's `issuedAt` (see
  *Attenuation*).
- `expiresAt`: a strict INK timestamp, strictly after `issuedAt`. The link is not
  valid at or after this instant, its window MUST fall inside its parent's window
  and its lifetime MUST NOT exceed the ceiling for its position (see *Attenuation*
  and *Lifetime ceilings*).
- `requireVerifiedOwner`: optional boolean, the same meaning as in the grant. Its
  effect over a chain is a conjunction (see *Verification*, pass 3).
- `parent`: on every non-root link, exactly 43 characters of the base64url
  alphabet `[A-Za-z0-9_-]`, the base64url-no-padding encoding of a 32-byte digest
  (see *The `parent` hash*). Absent on the root.
- `signature`: the Ed25519 body signature, base64url without padding.

A delegation link is not an authorization grant and is never handed to the grant
verifier. Its `type` differs, its lifetime ceilings differ by position (see
*Lifetime ceilings*) and it is only meaningful inside a chain. A verifier MUST NOT
accept a `network.ink.delegation_link` through the grant verifier, and MUST NOT
accept a `network.ink.authorization_grant` or `network.tulpa.authorization_grant`
as a chain link.

### The `parent` hash

`parent` binds a link to the exact bytes of the link above it. On every non-root
link it is the base64url encoding without padding of the SHA-256 digest of these
bytes, UTF-8 throughout:

1. the bytes of the domain string `ink/delegation-link`,
2. then a single newline (`U+000A`), the same domain-then-newline pattern the
   body-signature scheme uses,
3. then the JCS (RFC 8785) canonicalization of the FULL parent link object
   INCLUDING its `signature` field.

The encoded result is 43 characters, the value of the child's `parent` field. The
parent link is canonicalized with every member present, `signature` included,
because the child commits to the parent as it was actually signed and presented,
not to an unsigned skeleton of it.

Because each link's own signature covers its `parent` field (the signature covers
every field except `signature`, see *Signature*), the chain is hash-linked in one
direction: altering any ancestor changes that ancestor's canonical bytes, so (a)
the `parent` digest recomputed over those bytes no longer equals the value in the
child's signed `parent` field, which fails the pass 1 continuity check with reason
`chain`, and (b) the altered ancestor's OWN signature no longer verifies over its
changed bytes. The child's signed `parent` field is what pins the exact parent
bytes, so an attacker cannot splice a different parent under a signed child, and
cannot edit a parent without re-signing that parent and re-deriving every
descendant's `parent` field. This is the same anti-splice property the card
rotation chain gets from committing each link's full prior context, applied here
to a delegation chain.

## Chain continuity

For every non-root link, its `issuer` MUST byte-equal the `subject` of the link
directly above it. Indexing the presentation array root-first as links 0 through
n, this is: for i in 1..n, `issuer` of link i equals `subject` of link i-1.

The comparison is over the signed string values as they appear in each link,
byte for byte, with no verifier-side case-folding or transformation. INK
principals are already in a normalized form when signed (the did:web grammar the
sign-in profile pins, for example, is lowercase and punycode-encoded precisely so
comparison is bytewise), so continuity is a bytewise equality of the two signed
principal strings. A chain whose issuer-subject seam does not match at any hop
rejects with reason `chain`.

Continuity and the `parent` hash are complementary: the hash binds a child to the
byte identity of its parent, and continuity binds the child's `issuer` to the
parent's `subject`, so a link can only extend a link that actually delegated TO
its issuer.

## Presentation wrapper

A chain is presented as an unsigned wrapper object with exactly these fields:

- `protocol`: the string `ink/0.1`.
- `type`: the single string `network.ink.authorization_chain`.
- `links`: an array of 2 to 4 delegation links, root first.

The wrapper is UNSIGNED. It carries no signature of its own and none is expected:
integrity comes entirely from the per-link signatures and the `parent` hash chain,
and presentation binding and replay are decided by the final-link rules in
*Verification*. The wrapper is a transport container, not a signed statement.

A chain has a minimum of 2 links. A one-link "chain" is not a chain: it is a plain
grant and is verified by the grant verifier under
[`ink-authorization-grant.md`](ink-authorization-grant.md), not by this
extension. A wrapper carrying fewer than 2 links rejects as `schema`.

## Bounds

- **Depth.** A chain has at most 4 links: the origin (root) link plus at most
  three re-delegations. A wrapper carrying more than 4 links rejects as `schema`,
  the same structural reason as the fewer-than-2 case. Each link is
  per-presentation and may cost a network Agent Card fetch to resolve its issuer's
  key, so the depth cap bounds fetch amplification: a presented chain can force at
  most four card resolutions.
- **Raw byte cap.** A chain presented as raw bytes MUST be rejected as `schema`
  when it is longer than 65536 bytes, before it is decoded. The bound is generous:
  the largest well-formed four-link chain is far under it, so a presentation
  padded past 65536 bytes is not legitimate and need not be decoded to be refused.
  A verifier handed an already-decoded wrapper applies the structural bounds
  instead, so the byte cap is then the responsibility of whatever layer received
  the bytes and decoded them, the same split the grant draws.
- **Card resolution safety.** A verifier resolving an issuer's Agent Card to check
  a link signature MUST gate every resolution through the private-hostname
  classification and connect-time pinning rules of
  [`ink-private-hostname.md`](ink-private-hostname.md), rejecting a loopback,
  private, link-local, IANA special-use or malformed IP-shaped host and pinning
  the connection to the resolved address it checked. A verifier SHOULD cache
  resolved cards so a chain re-presented, and a prefix shared across sibling
  chains, does not re-fetch.

## Re-delegation opt-in

Onward re-delegation is opt-in and the scope machinery carries the opt-in: no new
boolean field exists. The reserved registry token `delegation.extend` (see
*Reserved scope tokens*) authorizes one further hop.

The origin issuer's own delegation is always permitted, but that is a statement
about the root link's own validity, not about its ability to seat a child. A root
link (link 0) is a valid link on its own with no `delegation.extend` in it: the
origin delegating to the first delegate is baseline delegation, not re-delegation,
and the origin needs no incoming token for its own link to stand. For the root to
seat a child, that is for the first delegate to re-delegate onward, the root link
MUST carry `delegation.extend`. Every re-delegation is gated: every non-root link,
a link at index i for i >= 1, is valid ONLY IF its parent link i-1's `scope`
contains `delegation.extend`. A non-root link (i >= 1) whose parent link i-1 does
not carry `delegation.extend` rejects with reason `attenuation`.

The token grants no service capability by itself. It authorizes one further hop
and nothing else: an audience MUST NOT read `delegation.extend` as conferring any
read, write or message authority, and it falls under the grant's default-deny like
any unrecognized service token when a service tries to act on it.

Because `delegation.extend` is an ordinary `scope` token, the attenuation subset
rule (below) governs it like any other. A child link cannot introduce
`delegation.extend` that its parent lacks, so the ability to re-delegate can only
narrow down a chain, never appear from nowhere. The practical consequence is that
a two-link chain requires `delegation.extend` in the root link, since link 1 is the
first re-delegation and its parent is the root; the plain one-link grant, which is
not a chain at all, is the only tokenless baseline. A chain of three or more links
requires `delegation.extend` in the root and in every intermediate link that a
re-delegation extends, carried down by subset at each hop. The gate at pass 1
checks the immediate parent (i-1) for every non-root link (i >= 1), and the subset
rule enforces the rest transitively.

## Attenuation

Every child link MUST narrow, and never widen, its parent. Attenuation is decided
entirely on signed bytes, so it is a structural verdict independent of the
verifier clock, and any widening rejects the WHOLE chain with the reason
`attenuation`. Three conditions hold at every parent-child seam (parent = link
i-1, child = link i, for i in 1..n):

1. **Scope subset.** The child's `scope` MUST be a subset of the parent's `scope`
   by exact string-set inclusion: every string in the child set MUST appear
   verbatim in the parent set. There are no wildcards, no hierarchy and no
   semantic ordering. A scope token in the child that is absent from the parent is
   a widening and rejects the chain as `attenuation`.
2. **Window nesting.** The child's window MUST nest inside the parent's:
   `parent.issuedAt <= child.issuedAt` AND `child.expiresAt <= parent.expiresAt`.
   A child that starts before its parent or expires after it escapes the parent
   window and rejects as `attenuation`.
3. **Delegability.** For every non-root child (index i >= 1) the parent MUST carry
   `delegation.extend` in its `scope`, per *Re-delegation opt-in*. This holds at
   every parent-child seam, uniform with the scope-subset and window-nesting
   conditions above: any non-root link whose parent lacks the token rejects as
   `attenuation`.

`audience` is not an attenuable field. It is fixed by the origin issuer and MUST
be identical on every link; attenuation can never re-point it (see *Confused
deputy and multi-hop safety*). `scope` and the validity window are the only fields
that narrow.

## Lifetime ceilings

A delegation link is a short-lived bootstrap artifact and its window is the
primary revocation control, so the window is bounded and the bound depends on the
link's position. These are MUST bounds, each checked structurally in pass 1 on the
link's signed `issuedAt` and `expiresAt`, clock-independent like the rest of the
window constraints:

- **Intermediate links** (every link that is not the final link of the chain,
  including the root when the chain is longer than 2 links): the lifetime
  `expiresAt - issuedAt` MUST NOT exceed 24 hours.
- **Final link** (the last element of `links`, the head the presenter holds): the
  lifetime MUST NOT exceed 10 minutes, the same short login-and-bootstrap ceiling
  the grant applies to a single grant.

A link whose lifetime exceeds the ceiling for its position rejects as `schema`, on
the signed bytes alone, the same disposition the grant gives a window over its
maximum lifetime.
The final link is the credential actually exercised at the audience, so it carries
the tight 10-minute ceiling, while an intermediate link only authorizes further
delegation within a broader day-scale window. Because the window-nesting rule of
*Attenuation* already forces each child window inside its parent's, the ceilings
compound downward: a chain cannot use an intermediate 24-hour window to grant a
final link more than its own 10 minutes.

## Signature

Each link's `signature` covers every field of that link except `signature`
itself, `parent` and `type` included. It is computed over the domain-separated JCS
canonicalization of the unsigned link object, the same body-signature scheme the
grant uses: for `protocol` value `ink/0.1` the domain is `tulpa/sign\n` (Protocol
§3.6), so the signed bytes are the UTF-8 concatenation of `tulpa/sign`, a single
`U+000A`, and the JCS (RFC 8785) canonicalization of the link with `signature`
removed. The signature is Ed25519, base64url without padding, verified under RFC
8032 strict rules.

This is the identical construction the grant spec pins, over the identical bytes
discipline, so a link is a grant-shaped object signed the grant's way. Because the
signature binds `audience`, `subject`, `scope`, `grantId`, `issuedAt`,
`expiresAt`, `type` and `parent`, a verifier can reject a link that was tampered,
broadened, re-pointed or re-parented: relabeling any of these after signing fails
the signature check, not a later context check.

Each link is signed by its own `issuer`, so a chain of n+1 links carries n+1
independent signatures, each resolved to its own issuer key. There is no chain-wide
signature and the wrapper is never signed.

## Verification

A verifier evaluates a presented chain against a context: the verifying service's
own identity (its `audience`), its clock `now` (a strict INK timestamp), the
authenticated presenting principal when one exists, its seen set of
`(issuer, grantId)` pairs, its revocation predicate and an optional owner status.
Verification runs three passes in order, fails closed at the first failure with a
stable reason and never throws. First failure wins, and each pass is evaluated over
a stable reason so two implementations reject in the same place for the same
reason.

The raw byte cap of *Bounds* is applied before any decode. A malformed verifier
clock `now` is a verifier input error and fails closed as `schema` wherever it is
consulted, exactly as the grant spec treats it.

### Pass 1: structure, on signed bytes

Decided entirely on the presented bytes, independent of the verifier clock and of
any key resolution:

- **Schema** (`schema`). The raw bytes MUST be valid UTF-8 with no lone UTF-16
  surrogate escape (see [`ink-signed-string-safety.md`](ink-signed-string-safety.md)).
  The wrapper MUST satisfy its shape (`protocol`, `type`,
  `network.ink.authorization_chain`, a `links` array of 2 to 4 links). Every link
  MUST satisfy the delegation-link schema: the exact field set, the
  `network.ink.delegation_link` type, the distinct-scope rule, the positive-window
  rule, the per-position lifetime ceiling (each link's `expiresAt - issuedAt` MUST
  NOT exceed 24 hours for any non-final link and 10 minutes for the final link, see
  *Lifetime ceilings*), the base64url signature shape, `parent` present and 43
  base64url characters on every non-root link and absent on the root. A chain
  shorter than 2 or longer than 4 links, and any per-link schema violation
  including a link over its position ceiling, rejects here as `schema`.
- **Continuity** (`chain`). For every non-root link, `issuer` MUST byte-equal the
  parent's `subject` (see *Chain continuity*), and each non-root link's `parent`
  MUST equal the base64url SHA-256 digest of its parent link computed per *The
  `parent` hash*. A mismatch at any seam rejects as `chain`.
- **Attenuation** (`attenuation`). At every seam the scope-subset, window-nesting
  and delegability conditions of *Attenuation* MUST hold. Any widening rejects the
  whole chain as `attenuation`.

### Pass 2: signatures, root to head

Walked root to head. For each link, the verifier resolves the link's `issuer` to a
signing key through the authenticated Agent Card machinery
([`ink-agent-card-signature.md`](ink-agent-card-signature.md)): it fetches and
authenticates the issuer's card under that spec's full construction (proof,
rooting by principal kind and the fetch safety of *Bounds*), then takes the active
signing key the authenticated card binds. Each link's `signature` MUST verify
against that key under RFC 8032 strict rules. Every signing key MUST be active at
the verifier's `now` under the key-rotation window rules
([`ink-key-rotation-spec.md`](ink-key-rotation-spec.md)): a retired or a revoked
key MUST NOT verify a link. A malformed `now` encountered while evaluating key
activity is a verifier input error and fails closed as `schema`, exactly as
everywhere `now` is consulted, NOT as `signature`; the `signature` reason is
reserved only for a genuine key-resolution or signature-verification failure under
a well-formed clock. Any failure to resolve a usable active key, or any signature
that does not verify, rejects the chain as `signature`.

Evaluating key status at `now` means rotating a delegate's key invalidates that
delegate's outstanding links: a link signed by a key the issuer has since retired
or revoked no longer verifies. This is intended, the SPIFFE short-lived-credential
stance, and it is the chain's fastest revocation lever for a compromised delegate.
Resolution failure fails closed: a verifier that cannot authenticate an issuer's
card to a usable active key MUST reject the chain rather than skip the check.

### Pass 3: context

Decided against the verifier's context and clock, after structure and signatures
have passed:

- **Audience** (`audience`). Every link's `audience` MUST equal the verifying
  service's own identity. Because all links must equal the one service, they are
  necessarily identical; a chain any of whose links names a different audience
  rejects as `audience`. This is the confused-deputy defense carried across the
  whole chain.
- **Presentation binding** (`subject`). When the caller supplies the authenticated
  presenting principal, it MUST equal the FINAL link's `subject`. A presenter that
  is not the final subject rejects as `subject`. When no presenter is supplied the
  check is skipped and the chain is a bearer artifact the audience MUST bind out of
  band, the same rule and the same empty-string equivalence the grant spec pins in
  its presentation-binding section.
- **Validity window** (`not_yet_valid`, `expired`). For every link, `now` MUST
  fall in `[issuedAt, expiresAt)`: at or after `issuedAt` and strictly before
  `expiresAt`. A link not yet valid rejects as `not_yet_valid`, an expired link as
  `expired`.
- **Replay** (`replay`). The verifier READS the seen set here and rejects the
  FINAL link as `replay` if its `(issuer, grantId)` pair is already present. It
  does NOT insert at this step: the head is recorded only on final acceptance of
  the whole chain, after every pass 3 check has passed, as a single
  check-and-insert under one guard, the same atomicity the grant spec requires
  (see *Replay*). Intermediate links are NOT replay-checked.
- **Revocation** (`revoked`). EVERY link's `(issuer, grantId)` pair is checked
  against the revocation predicate. A revoked pair anywhere in the chain rejects
  the whole chain as `revoked`, even inside its window (see *Revocation*).
- **Owner verification** (`owner_unverified`). The requirement is a conjunction:
  if ANY link sets `requireVerifiedOwner: true`, the whole chain requires verified
  owner binding, and the supplied owner status MUST be `verified`. An absent status
  is unverified and rejects as `owner_unverified`. A chain no link of which requires
  it ignores the status.

### Orthogonality to key rotation

The delegation-chain walk and the key-rotation chain walk are orthogonal. The
delegation chain is a chain of distinct principals, each delegating to the next,
walked in pass 1 for continuity and attenuation. The key-rotation chain is a
chain of key sets for a SINGLE principal, walked inside Agent Card signature
verification to root that one principal's current signing key. They compose at
exactly ONE seam: key resolution in pass 2, where resolving each delegation link's
issuer to a usable active key runs the full card-signature and rotation machinery
for that issuer. Nowhere else do the two interact, and neither cap bounds the
other: the 4-link delegation depth and the 32-link rotation-chain cap are
independent.

## Revocation

Revocation in v1 is a receiver-side denylist keyed by `(issuer, grantId)`,
consulted for EVERY link at verify time (pass 3). This is the same shape the grant
uses: receiver state, not a signed field, checked by the pair. Keying on the pair
rather than `grantId` alone keeps one issuer's revoked ids from colliding with
another's, because `grantId` is issuer-chosen. A revoked pair anywhere in the
chain rejects the whole chain.

There are no revocation endpoints, no push and no tombstones in v1. The honest
residual is worth stating plainly: a verifier that never learned of a revocation
accepts the chain until its window closes. The short window is the guarantee and
the denylist is an accelerant, not a completeness promise. A key rotation is the
other lever: because pass 2 requires every signing key to be active at `now`,
retiring or revoking a delegate's signing key invalidates that delegate's
outstanding links immediately for any verifier that resolves the fresh card.

## Replay

Replay protection covers the FINAL link only. At pass 3 the verifier READS the
seen set and rejects the head as `replay` if its `(issuer, grantId)` pair is
already present, but nothing in the chain records that a presentation happened and
the read alone inserts nothing. Recording the head is the service's job and it
MUST be atomic with acceptance: the accepted final-link pair is inserted only
after the whole chain is accepted, under the same guard that admits it, as a
single check-and-insert that checks the pair is absent and inserts it in one step.
A chain rejected for ANY reason MUST NOT insert anything into the seen set, so a
head that passes the replay read but then fails revocation or owner verification
never poisons the seen set against a later legitimate presentation of the same
head. Two concurrent presentations of the same head MUST NOT both be accepted; a
service that scans and inserts in separate steps leaves a window where both pass
the scan before either inserts, which defeats the control. Intermediate links are
deliberately NOT replay-checked, and this asymmetry is intentional and normative:
a chain prefix is legitimately reusable, because one parent link can seat many
different child chains, so replay-checking an intermediate link would refuse a
second, legitimately distinct chain that shares the same prefix. Intermediate
links ARE revocation-checked, so a compromised intermediate is still stoppable by
the denylist and by key rotation; only the seen-set insert is confined to the
head.

## Confused deputy and multi-hop safety

Two properties keep a chain from being re-pointed or presented by the wrong party.

**Fixed audience.** `audience` is set by the origin issuer, is not attenuable and
MUST be identical on every link and equal to the verifying service. Attenuation
narrows scope and the window, never the audience, so no re-delegation down the
chain can re-target the authority at a different service. A link minted for one
audience fails the audience check at any other, exactly as a grant does.

**Presenter equals final subject.** The party presenting the chain MUST be the
final link's `subject` when an authenticated presenter exists. A chain is
authority delegated to that final subject, so anyone else presenting it is
rejected at pass 3. Bearer-artifact semantics, where authority travels with the
bytes and the audience binds presentation out of band, are off-INK and out of
scope for this extension; over INK the audience binds the authenticated envelope
sender to the final subject, the same way the grant binds a presenter to its
subject.

## Reserved scope tokens

This extension defines its own reserved scope registry, and it is a short one.
Outside this extension a `scope` token stays opaque and audience-local, exactly as
the grant requires. This registry assigns meaning to one token and only under this
extension.

- `delegation.extend`: a delegability token. Its presence in a link's `scope`
  authorizes exactly one further re-delegation below it (see *Re-delegation
  opt-in*). It confers no service capability of its own: an audience MUST NOT read
  it as any read, write or message authority, and it attenuates like any other
  token under the subset rule.

This registry is this extension's own. It is NOT an amendment to the sign-in
profile's frozen closed scope registry
([`ink-agent-authorization.md`](ink-agent-authorization.md)): that registry, its
`identity.assert`, `profile.read` and `agent.message.send` tokens, and its
closed default-deny discipline, is untouched here. `delegation.extend` is a
delegation-layer token, not a sign-in scope, and a sign-in challenge does not
request it.

## Capability gate and conformance

This extension is gated by a NEW capability, `delegation`, distinct from the
sign-in `authorization` capability. The rationale is containment: the 1.0 base
profile and the sign-in `authorization` capability are frozen, so a post-1.0
extension ships additively under its own capability rather than by widening a
frozen one. An implementation advertises `delegation` in its Agent Card only when
it accepts delegation chains, and MUST NOT advertise it without fully implementing
this spec.

The `authorization-chain` conformance category, under the `delegation` profile,
pins these decisions. Each vector carries a presented chain plus the verification
context (the verifying service identity, the clock, the candidate issuer keys, the
presenter, the seen set, the revocation predicate and any owner status), and both
the TypeScript reference and the Go implementation MUST make the same accept or
reject decision. Each reject vector pins the typed reason so the two agree on
verify order. The stable reasons are `schema`, `chain`, `attenuation`,
`signature`, `audience`, `subject`, `not_yet_valid`, `expired`, `replay`,
`revoked` and `owner_unverified`. Of these only `chain` and `attenuation` are new;
every other reason is reused verbatim from the grant. The
category is capability-gated on `delegation`, required only when an implementation
accepts chains, and it does not perturb the frozen `base` set or the
`authorization` capability's `authorization-grant` and `agent-authorization`
categories.

## Scope and out of scope

In scope for v1:

- Linear chains of 2 to 4 links.
- A single fixed audience shared by every link.
- Syntactic subset scopes, exact string-set inclusion with no algebra.
- One conformance category, `authorization-chain`, under the new `delegation`
  capability.

Deferred or out of scope:

- Cross-audience re-delegation. Every link shares one audience; a chain that
  re-points authority at a second service is a later design, not this one.
- Semantic or caveat scopes. Scopes stay opaque syntactic tokens; a caveat
  algebra or a hierarchy is out of scope.
- Standing capabilities beyond the ceiling. Every link lives inside its
  position's window; a durable credential is not this extension.
- Issuer-published revocation artifacts. Revocation is the receiver-side denylist
  above; a signed revocation object, a shared log or issuer tombstones are later
  additions.
- Threshold or group delegates. A link delegates from one principal to one
  principal.
- Detached CID references. Each link carries its own bytes inline; there are no
  content-addressed detached proofs.
- An envelope `delegationProof` field. This extension is a presentation wrapper,
  not a message-envelope field, and it adds no member to the message envelope.
- DAG or multi-parent chains. The chain is a linear array with one parent per
  link; a graph is out of scope.

## Prior art

This extension was mapped against established delegation designs and diverges
deliberately.

- **UCAN.** The delegation-and-invocation split, attenuation-only narrowing and
  flat-array proof carriage are ADOPTED. The divergences are three: `audience` is
  the presentation TARGET, the service the chain is exercised at, not the next
  delegate down the chain; there is no semantic capability algebra, only exact
  string-set subset; and links carry their own bytes inline with a hash `parent`
  rather than CID-referenced proofs.
- **ZCAP.** The additive-caveat model, where each delegation only ADDS
  restrictions, is REJECTED in favor of monotonic scope subtraction over a flat
  token set, which fits INK's opaque-token grant model.
- **RFC 8693.** The actor-chain concept (`act` and nested actors) maps onto the
  root-to-head link chain, but its centralized Security Token Service is REJECTED:
  verification here is self-contained over the presented links and the issuers'
  Agent Cards.
- **SPIFFE.** The short-lived-credential-over-revocation stance is RATIFIED. Short
  windows and active-key-at-`now` verification are the primary controls, and the
  denylist is an accelerant.

## Witness logging

v1 delegation carries NO normative witness requirement. Revocation is the
receiver-side denylist and the short window is the guarantee; nothing in this
extension mandates submitting revocations or chain heads to a transparency log.

Witness-logging of revocations or chain heads is OPTIONAL and explicitly
DEFERRED. It is the same open question the Agent Card signature spec leaves for
the 1.0 profile's cold-verification path (see
[`ink-agent-card-signature.md`](ink-agent-card-signature.md) §6), and it is to be
revisited alongside it rather than pinned here. It is kept off the normative
surface on purpose to keep v1 minimal.

## Acceptance

A conformant verifier accepts a presented chain if and only if: the raw bytes are
within the byte cap and the wrapper and every link are structurally valid
(including the 2-to-4-link depth, the delegation-link schema, each link being
within its position's lifetime ceiling and the `parent` shape); chain continuity
holds at every seam by both the issuer-subject rule and the `parent` hash;
attenuation holds at every seam by scope subset, window nesting and the
re-delegation delegability gate; every link's signature verifies against a usable
active issuer key resolved through the authenticated Agent Card; every link's
`audience` equals the verifying service; the authenticated presenter, when
supplied, equals the final link's `subject`; `now` falls in every link's window;
the final link's `(issuer, grantId)` pair is neither replayed nor revoked and no
link's pair is revoked; and, when any link requires it, the supplied owner status
is `verified`. Every other case is a rejection with one of the reasons `schema`,
`chain`, `attenuation`, `signature`, `audience`, `subject`, `not_yet_valid`,
`expired`, `replay`, `revoked` or `owner_unverified`. Verification fails closed and
never throws.
