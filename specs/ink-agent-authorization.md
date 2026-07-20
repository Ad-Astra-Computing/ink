# INK Agent Authorization Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-07-16

## Purpose

INK advertises "Sign in with INK". The
[`ink-authorization-grant.md`](ink-authorization-grant.md) primitive pins the
artifact that claim mints, a scoped signed grant, but a grant alone does not say
how a service asks for one or how the two sides bind a single sign-in together.
This profile pins that flow: how a relying party requests sign-in with a signed
challenge, and how the existing authorization grant answers it. It composes the
grant; it does not extend or reinterpret it, beyond one named specialization of
the issuer-chosen `grantId`, the issuer's adoption of the id derived from the
verified challenge (see *Nonce binding*).

This is a flow profile, not a new credential. Every grant presented for
authority is still a plain authorization grant checked by the grant verifier
against the same bytes and the same rules; the delegated grant at sign-in is
accepted into custody under the procedure in *Binding patterns* and is verified
for authority by its audience at presentation. The only artifact this profile
adds is the challenge,
a request the relying party signs so the user's agent knows who is asking and
what for. The grant schema is untouched, and the multi-hop delegation design in
[`ink-authorization-chain.md`](ink-authorization-chain.md) stays a separate,
later extension and is out of scope here, the same as it is for the grant.

For independent implementations to interoperate they must accept and reject the
same challenges and verify the same grants over the same bytes.

## Roles

Three principals take part. The **relying party** (the RP) is the service that
wants to sign a user in; it issues the challenge and later verifies the grant it
receives. The **user's agent** is the principal that answers, minting the grant
after obtaining the user's consent. The **user** is the human the agent acts for,
whose consent gates any capability the agent grants beyond bare sign-in.

The RP and the user's agent are both ordinary INK principals with published
Agent Cards (see [`ink-agent-card.md`](ink-agent-card.md)). How each side
resolves the other's signing key is pinned rather than assumed: the agent
resolves the RP card under *Relying party requirements* and the RP resolves the
assertion issuer's key under the rules in *Binding patterns*. No shared
platform, directory or identity provider sits between them.

## Challenge

A challenge is a JSON object with exactly these fields and no others. Every
field is required:

- `protocol`: the string `ink/0.1`.
- `type`: the wire type `network.ink.authorization_challenge`. This is a single
  spelling. It is a new type, so there is no legacy dual-accept to carry and a
  receiver accepts only this one string.
- `rp`: the relying party's principal, a non-empty string of at most 512 UTF-16
  code units, the same bound as a grant principal. Under this profile `rp` MUST
  be a bare-host `did:web` identifier with no path segments (a path-bearing
  `did:web` has no unambiguous origin): `did:web:` followed by a host and an
  optional percent-encoded port. The host is one or more dot-separated labels,
  each 1 to 63 characters of lowercase `a`-`z`, digits and hyphens, not starting
  or ending with a hyphen, with no trailing dot, and its final label MUST NOT
  consist only of digits, which excludes every dotted-quad IPv4 literal
  structurally and matches the standard hostname rule that a top-level label is
  never all-numeric; an internationalized name MUST be pre-encoded as punycode
  A-labels so comparison is bytewise; an IPv6 literal needs no separate
  exclusion, because a bracketed literal already fails the label grammar. The
  optional port is `%3A` (uppercase) followed
  by a decimal 1 to 65535 with no leading zeros; an explicit port 443 is out of
  profile because the derived origin would collide with the default and origin
  equality must stay exact string comparison. Anything outside this grammar
  rejects as `schema` on the signed bytes alone, before the signature. The
  grammar is exact because the origin derived from it (see *Relying party
  requirements*) gates redirect acceptance before the signature, so two
  implementations must never disagree on it. The RP key signs the challenge.
- `nonce`: an RP-chosen string, 16 to 256 UTF-16 code units. It is the entropy
  source of the binding between this challenge and the identity assertion that
  answers it (see *Nonce binding*).
- `requestedScope`: an array of 1 to 64 distinct strings, each 1 to 128 UTF-16
  code units, the same bounds and distinctness rule as a grant `scope`. It names
  the scope tokens the RP asks the user to grant. Entries must be distinct so two
  implementations count the same set. Every entry MUST be a token in this
  profile's registry (see *Scope registry*): a challenge carrying any
  unregistered entry rejects as `schema`. It MUST also include
  `identity.assert`: a challenge that does not request it is not a sign-in
  request under this profile and rejects as `schema`.
- `redirectUri`: the completion URL, at most 2048 UTF-16 code units. It MUST
  consist of the RP origin derived from `rp` (the exact string *Relying party
  requirements* pins), followed immediately by `/`, followed by an optional path
  and query; the check is a literal string prefix match against the derived
  origin plus `/`, and no URL parsing is performed. It MUST NOT contain `#`,
  because a fragment never reaches the completion endpoint, so a
  fragment-bearing redirect target is malformed, and it MUST NOT contain `\`.
  It MUST NOT contain any ASCII control character (`U+0000`-`U+001F`, `U+007F`)
  and MUST NOT contain ASCII whitespace (the string is not trimmed first), the
  same ban the Agent Card endpoint URL grammar applies (see *Relying party
  requirements* for the rationale).
- `issuedAt`: a strict INK timestamp (see
  [`ink-timestamp-grammar.md`](ink-timestamp-grammar.md)). The challenge is not
  valid before this instant.
- `expiresAt`: a strict INK timestamp, strictly after `issuedAt`. The challenge
  is not valid at or after this instant. A zero or negative window is malformed,
  and a window longer than ten minutes is out of profile. The ceiling is the
  same one the grant applies and for the same reason: a challenge is a short-lived
  bootstrap request, so its window is short enough that it expires on its own
  well before any denylist would matter and long enough to absorb clock skew and
  a slow user consent.
- `signature`: the Ed25519 body signature, base64url without padding.

### Byte bound

A challenge presented as raw bytes MUST be rejected as `schema` when it is longer
than 65536 bytes, before it is decoded. The bound is generous, well past the size
of any well-formed challenge, so a challenge padded past 65536 bytes with
whitespace or other padding is not a legitimate request and need not be decoded to
be refused. A verifier handed an already-decoded object applies the structural
bounds instead, so the byte bound is then the responsibility of whatever layer
received the bytes and decoded them, the same split the grant draws.

### Signature

The signature covers every field except `signature` itself. It is computed over
the domain-separated JCS canonicalization of the unsigned object, the same body
signature scheme INK uses elsewhere (`ink/0.1` keeps the `tulpa/sign` domain),
the same scheme the grant uses. Because the signature binds `rp`, `nonce`,
`requestedScope`, `redirectUri`, `issuedAt` and `expiresAt`, the user's agent can
reject a challenge that was tampered, rescoped or redirected. Relabeling `rp` or
widening `requestedScope` after signing does not help an attacker: the signature
bound the original values, so the altered challenge fails the signature check.

### Verification

The user's agent verifies a challenge before minting a grant, running these
checks in order and rejecting at the first failure with a stable reason for each,
the same order and style the grant verifier uses:

1. **Structure and byte safety** (`schema`). The raw bytes must be valid UTF-8
   with no lone UTF-16 surrogate escape, and the object must satisfy the schema
   above, including the distinct-scope rule, the registry-membership rule for
   every `requestedScope` entry, the required `identity.assert` entry, the
   bare-host `did:web` grammar for `rp`, the positive-window rule, the
   ten-minute ceiling and the base64url signature shape. String safety is
   structural: a challenge carrying a lone surrogate rejects as `schema` before
   the signature check, not as a signature failure (see
   [`ink-signed-string-safety.md`](ink-signed-string-safety.md)). The redirect
   prefix rule is checked here too, on the signed bytes alone: a challenge
   rejects as `schema` before the signature when its `rp` is not a bare-host
   `did:web` identifier, when its `redirectUri` is not the derived RP origin
   followed immediately by `/` and an optional path and query under a literal
   string prefix match with no URL parsing or when its `redirectUri` contains
   `#`, `\`, an ASCII control character or ASCII whitespace, because in each
   case it is malformed under this profile
   regardless of who signed it. A window over ten minutes rejects here as well,
   on the signed bytes alone, independent of the verifier clock.
2. **RP signature** (`signature`). The Ed25519 signature must verify against an
   active signing key of the RP's Agent Card, resolved from `rp` (see *Relying
   party requirements*), under RFC 8032 strict rules and the key rotation spec's
   verification rules ([`ink-key-rotation-spec.md`](ink-key-rotation-spec.md)).
   A revoked key MUST NOT verify a challenge, and a retired key MUST NOT verify
   one either: retired keys exist for historical verification and a live
   challenge is never historical. Key usability, the active status and the
   `validFrom` and `validUntil` window under the rotation spec's window rules,
   is evaluated at the verifier's clock `now`, the same instant the validity
   window in step 3 uses, never at the challenge's `issuedAt`. The reasons are
   two: a challenge is a live artifact, so the rotation spec's historical
   artifact-timestamp rule never applies, and `issuedAt` is RP-chosen, so
   evaluating key windows at it would let an RP backdate a challenge into an
   old key's window. A malformed verifier clock `now` rejects as `schema`
   wherever it is consulted, including the key-window evaluation here, because
   a verifier input error is a `schema` failure exactly as the grant spec
   treats it; `signature` remains the reason only for an actual signature or
   key-usability failure under a well-formed clock. The signature is checked
   before the window, so a rejected challenge never reveals whether its window
   would have passed.
3. **Validity window** (`not_yet_valid`, `expired`). The agent's clock `now` must
   fall in `[issuedAt, expiresAt)`: at or after `issuedAt` and strictly before
   `expiresAt`. A `now` that is not a strict INK timestamp is a verifier input
   error and fails closed as `schema`, not as a window verdict the verifier never
   computed.

The stable reasons are `schema`, `signature`, `not_yet_valid` and `expired`.
Verification fails closed and never throws.

## Nonce binding

The identity assertion that answers a challenge MUST derive its `grantId` from
the verified challenge rather than carrying the nonce verbatim, because a raw
nonce is not issuer-unique: two RPs can send the same nonce and one RP can
reuse a nonce in a fresh window, and no window-bounded issuer state could stop
the resulting `(issuer, grantId)` collision the base grant's unique id rule
forbids. The `grantId` is the base64url encoding without padding of the
SHA-256 digest of these bytes, UTF-8 throughout: the bytes of the domain
string `ink/challenge-id`, then a single newline (`U+000A`), the same
domain-then-newline pattern the body-signature scheme uses, then the JCS
canonicalization of the JSON object with exactly the members `rp`, `nonce`,
`issuedAt` and `expiresAt` copied from the verified challenge. The encoded
result is 43 characters, inside the grant's 16 to 256 code unit `grantId`
bound, so the grant schema does not change. The nonce remains the entropy
source of the id, and the derivation gives nonce binding, replay defense and
revocation one shared key, the grant's existing `(issuer, grantId)` pair.

The derivation carries every property the flow needs. It is deterministic and
RP-verifiable: the RP holds the challenge it minted, so it recomputes the id
and matches it against its outstanding sign-in context, and the nonce-binding
property survives as a derived-id equality. It is issuer-unique structurally:
challenges that differ in `rp`, in `nonce` or in window derive distinct ids,
so the same nonce at two RPs or reused by one RP in a fresh window yields
different ids without any issuer-lifetime state. Two verified challenges
sharing the four binding fields derive the same id whatever their other
fields, so the mint-once rule below admits only the first of them; keying the
mint-once record by anything finer than the derived id, exact challenge bytes
included, is non-conformant, because it can mint two assertions with one
`(issuer, grantId)` pair. It is
replay-stable: identical challenge bytes derive
the identical id, so a replayed challenge still maps to the same
`(issuer, grantId)` pair and the RP's seen set still rejects a second
acceptance. And it makes window-bounded issuer state sound: after `expiresAt`
the only challenge that derives a given id is itself expired and can never
validly mint again, and any later challenge, same nonce or not, derives a new
id.

This specializes the grant's issuer-chosen id rule rather than conflicting with
it. The inputs originate with the RP, but the issuer adopts the deterministic
id derived from the verified challenge: the adoption is the issuer's own act,
performed only after the challenge verified, and the id remains issuer-signed
and issuer-unique, structurally by the derivation and operationally under the
mint-once rule below.

Mint-once is normative, not assumed. The user's agent MUST mint at most one
identity assertion per derived id, recording the id atomically with minting,
the derived id and nothing finer being the record's key, as a single
check-and-insert under
one guard, the same atomicity stance the grant spec's replay section takes for
acceptance, and it MUST refuse a challenge whose id it has already recorded.
The record need only live as long as the challenge window plus clock skew, and
the bound is structural: after `expiresAt` the only challenge deriving that id
is expired and any later challenge derives a new id, so the state expires with
the window it protects.

The binding covers the identity assertion only. A delegated capability grant
minted in the same flow MUST use a fresh issuer-chosen unique `grantId` that
MUST NOT equal the assertion's derived id: two grants from one issuer sharing
a `grantId` would break the grant's rule that the id is unique, and the
`(issuer, grantId)` replay and revocation key would be ambiguous between them.
The fresh id is sound because the delegated grant does not need the derived id
to be tied to the sign-in: its replay and revocation run on its own id, and
the acceptance rules in *Binding patterns* pin its principals, its delivery
context and its mint window to the sign-in it arrived with.

The consequences are worth stating plainly, because they are the whole reason
the binding is a derived id and not a new schema field:

- A challenge replayed to the same issuer is refused at the issuer by the
  mint-once rule, and an issuer that lost the record still cannot buy a second
  acceptance, because identical challenge bytes derive the identical id, so a
  second assertion carries the same `(issuer, grantId)` pair and the RP's seen
  set rejects the repeated pair. The two defenses layer rather than depending
  on each other: an attacker cannot get two accepted sign-ins out of one
  challenge.
- The same nonce sent to two different users yields two assertions with
  distinct issuers, and the same nonce sent by two different RPs or reused by
  one RP in a fresh window derives distinct ids, so the `(issuer, grantId)`
  pairs differ in every case and there is no collision across users or across
  RPs.
- An RP MUST mint each `nonce` with at least 128 bits of entropy. The nonce is
  the entropy source of the derived id and of the RP's outstanding-context
  mapping, so a guessable nonce would let an attacker predict or pre-seed
  derived ids; 128 bits keeps them unguessable.

The nonce also binds the sign-in to the context that asked for it. An RP MUST
associate each nonce with the sign-in context that initiated the challenge (the
browser session or the carrier's equivalent) and MUST accept the answering
grants, the identity assertion and any delegated capability minted with it, only
in that same context; a grant that verifies but arrives in a context that does
not own the sign-in's nonce is rejected. This is the presentation control for
carriers that authenticate nothing: over a browser redirect there is no
authenticated presenter, so the grant verifier's presentation binding never
fires, and without context binding a stolen grant would be a pure bearer
artifact inside its window. The context has a lifetime of its own: an RP MUST
expire the sign-in context at the challenge's `expiresAt`, so a completion
arriving after expiry finds no context that owns the derived id, whatever the
grant's own window says. The context lifetime and the signed mint-window
checks in *Binding patterns* are independent layers, receiver state on one
side and a signed field on the other.

## Binding patterns

This profile uses the one grant primitive in two shapes. Only the first is
required.

Both shapes share one field rule: a grant minted under this profile, identity
assertion and delegated capability alike, MUST omit `requireVerifiedOwner`.
The base grant treats an absent field as no owner requirement, so omission is
the deterministic spelling, and an RP MUST treat a sign-in grant that carries
the field, whatever its value, as not a grant under this profile and refuse
it, an RP-local acceptance rule like the rest of the checklists, with no new
wire reason. This profile's completion runs where no owner-status input
exists; owner verification composes with INK delivery pipelines instead, and a
later revision can define an owner-status input if a use case appears.

**Identity assertion** is the sign-in core and is mandatory for the profile. The
user's agent mints a grant whose `issuer` and `subject` are both the user's agent
principal, whose `audience` is the challenge `rp`, whose `scope` is
`identity.assert` plus whichever identity-assertion tokens from `requestedScope`
the user consented to and whose `grantId` is the id derived from the verified
challenge (see *Nonce binding*). A
delegated-capability token never rides in the assertion: it belongs to the other
grant shape (see *Scope registry*). The grant schema requires at least one scope
entry and `identity.assert` is that entry: when the user declines every
capability the minted scope is exactly `["identity.assert"]`, so a bare sign-in
never needs an empty scope the grant schema would reject. This grant
asserts "this principal signed in to that RP for this scope". It is delivered to
the RP, which verifies it with the ordinary grant verifier against its own
identity as the audience. When delivery is authenticated the RP passes the
authenticated presenter to the verifier and the grant's presentation binding
rejects a grant presented by anyone other than its `subject`, per the grant
spec's presentation-binding section.

The base verifier does not know this profile's shape, so the RP runs a profile
acceptance checklist in addition to it: `issuer` MUST equal `subject`;
`grantId` MUST equal the id the RP derives from the challenge whose sign-in
context received the completion, which is the context binding of *Nonce
binding* stated as a derived-id equality check; the assertion's `issuedAt`
MUST fall within the challenge's own `[issuedAt, expiresAt)` window, the same
mint-window rule the delegated path carries, satisfiable by construction the
same way; `scope` MUST contain `identity.assert`; and every `scope` entry
MUST be an identity-assertion token from this profile's registry that appeared
in the challenge's `requestedScope`. A grant failing any of these is not an
identity assertion under this profile and the sign-in is rejected, whatever the
base verifier said. These are RP-local acceptance rules and need no new wire
reason.

Verifying the assertion needs the issuer's key, and the base grant leaves key
resolution to policy, so this profile pins it. When the assertion's `issuer` is
a bare-host `did:web` identifier, the RP MUST resolve its Agent Card at the
derived origin's well-known path under exactly the rules this profile pins for
the RP card in *Relying party requirements*: the same grammar and origin
derivation, the private-hostname gate with connect-time pinning, the transport
refusal of redirects, the response-evaluation reuse with the card's `agentId`
equal to the issuer and an active signing key only under the rotation and
key-material rules evaluated at the RP's clock `now`. An issuer principal of
any other form is resolvable only where the RP already holds a trusted card or
key for that principal through a prior relationship or its own policy. Either
way an RP that cannot resolve the issuer to a usable key MUST reject the
sign-in rather than skip signature verification: resolution failure fails
closed.

**Delegated capability** is optional and consent-gated. When the user grants the
RP a capability to use later, the agent mints a second grant whose `issuer` is
the user's agent principal, whose `subject` is the RP principal, whose `audience`
is the user's agent principal, whose `scope` is the consented
delegated-capability tokens and whose `grantId` is a fresh issuer-chosen unique
id, never the assertion's derived id (see *Nonce binding*), so the RP can
present it
back to the agent over INK. Over
INK the audience verifies that the authenticated envelope sender equals the grant
`subject` before acting, and the grant bytes are confidential in transit, both per
the grant spec.

A delegated capability is pinned to its sign-in by acceptance rules the RP
enforces, since the fresh `grantId` carries no challenge binding of its own. A
delegated capability accepted as part of a sign-in MUST have its `issuer` equal
to the identity assertion's `issuer`, its `subject` equal to the RP, its
`audience` equal to that same issuer and its `issuedAt` within the challenge's
own `[issuedAt, expiresAt)` window, and it MUST be delivered in the same
nonce-bound completion as the assertion. Its scope carries the sibling rule to
the assertion checklist: every `scope` entry of a delegated capability accepted
at sign-in MUST be a delegated-capability token from this profile's registry
and MUST have appeared in the challenge's `requestedScope`; a grant carrying
any other entry is not a delegated capability under this profile and custody is
refused. The mint-window rule is verifiable at
custody, because `issuedAt` is a signed grant field and the RP holds the
challenge it minted, and it is satisfiable by construction: the agent verifies
the challenge window at its clock `now` before minting and stamps the delegated
grant's `issuedAt` at mint time, so a grant minted for this sign-in always
passes. What it buys is temporal confinement: a delegated grant minted for an
earlier sign-in whose challenge window has closed can no longer be presented in
a later completion. A delegated grant arriving outside such a completion, with
principals that do not match the assertion it arrived with or with an
`issuedAt` outside the challenge window is rejected.

These rules pin the principals, the delivery context and the mint window; they
do not make the binding to one specific challenge cryptographic. What remains
possible is confined to a grant the same user consented to for the same RP
inside a concurrently open challenge window, delivered through a context-bound
completion, and the agent's replay state at presentation still admits each
delegated grant only once.

What the RP runs at completion is an acceptance procedure, not the base grant
verifier, because the delegated grant's `audience` is the user's agent and the
verifier's audience-matches-self check could never pass at the RP. On receiving
a delegated capability in a sign-in completion the RP verifies structure and
byte safety, the issuer signature over the same bytes the grant spec signs, the
principal bindings above, the mint-window rule and the validity window. It MUST
NOT run the
audience-matches-self check, because the grant is not being presented to the RP
for authority, and it does not consult replay or revocation state, which belong
to the grant's audience. The distinction is custody against authority:
acceptance takes the grant into custody and nothing more, and authorization
happens only when the RP later presents the grant to the user's agent, whose
ordinary grant verifier then applies every check, audience, replay and
revocation included.

A delegated capability inherits the grant's ten-minute lifetime
ceiling, so it is a bootstrap artifact, not a standing credential: the RP
typically presents it promptly to establish a durable relationship through the
agent's ordinary pipeline, for example a connection the agent's own policy then
governs, and anything that outlives the window lives in that pipeline, not in
the grant.

Sign-in requires only the identity assertion. An RP MUST function when the user
declines every delegated capability: a grant whose scope is exactly
`["identity.assert"]` is a complete and valid sign-in, and an RP that refuses a
user who granted nothing beyond identity is not conformant.

## Scope registry

The grant primitive keeps scope tokens opaque and that stays normative: outside
this profile a token means only what the audience's own policy says it means. This
profile assigns meaning to tokens only under this registry and only when the
audience has opted into the profile. An audience that has not opted in reads every
token as opaque, exactly as the grant requires.

Every registry token has a shape, the grant shape it is valid in, because the
two shapes point in opposite directions: an identity assertion has the RP as its
audience, so it can carry only authority the RP exercises for itself, and
authority exercised against the user's agent can ride only in a
delegated-capability grant whose audience is the agent.

The initial registry is deliberately minimal:

- `identity.assert`: an identity-assertion token. It asserts only that the
  issuer signed in to the audience and grants nothing else: no read, no write,
  no message access. Every identity assertion MUST include it, and a challenge's
  `requestedScope` MUST include it (see *Binding patterns* and *Challenge*).
- `profile.read`: an identity-assertion token. The RP may read the public
  profile fields the issuer's Agent Card exposes, and nothing else. It grants no
  write and no message access.
- `agent.message.send`: a delegated-capability token, valid only in a grant
  whose `audience` is the user's agent and whose `subject` is the RP. The RP may
  send INK messages to the user's agent, subject to the agent's own acceptance
  pipeline. The token authorizes delivery for consideration, not acceptance; the
  agent's normal intake rules still decide what it acts on.

Unknown tokens grant nothing. A token outside this registry falls back to the
grant's default-deny rule: the audience MUST NOT read it as implying any
authority. A token carried in a grant of the wrong shape also grants nothing and
falls to the same default-deny: an `agent.message.send` inside an identity
assertion authorizes no messages, because that grant's audience is the RP and
nothing about it is presentable back to the agent. New tokens are added by a
revision of this spec, never invented ad hoc by an RP, and a free-form string is
out of profile. An agent MUST refuse to mint an unregistered token under this
profile.

On the request side the rule is stricter than default-deny: every
`requestedScope` entry MUST be a registry token, and a challenge carrying any
unregistered entry rejects as `schema` in verification step 1. By sending the
challenge type the RP opted into the profile, so an out-of-registry request is
malformed, not merely unminted. The version-skew consequence is deliberate: a
token added by a future revision of this registry is unknown to an older agent
and rejects, so an RP that wants broad compatibility requests only tokens it can
expect agents to know, and a rejected challenge is visible to the RP rather than
silently narrowed.

## Relying party requirements

An RP's principal is a bare-host `did:web` identifier under the grammar the
Challenge section pins for `rp`. The RP origin is derived from it
deterministically: `https://` plus the host, plus `:` and the decimal port when
one is present. Every admissible identifier derives exactly one spelling of its
origin, which is why an explicit port 443 and an undecoded internationalized
host are out of profile: the derived string feeds the literal prefix match
below, where two spellings of one origin would make equal origins compare
unequal.

The RP's Agent Card URL is that origin joined with the well-known card path the
Agent Card spec defines, `/.well-known/ink/agent.json` (see
[`ink-agent-card.md`](ink-agent-card.md)). An RP MUST publish its card there,
and the challenge signature MUST verify against an active signing key of that
card under the key rotation spec's verification rules: a revoked key MUST NOT
verify a challenge, and a retired key MUST NOT verify one either, because
retired keys exist for historical verification and a live challenge is never
historical. Which key material supplies the candidates is pinned with it: when
the card carries a `keys.signing` set the key MUST come from that set under
the rotation rules and the legacy top-level `publicKeyMultibase` MUST NOT be
used as a fallback, so a rotated-away bootstrap key can never verify a
challenge after a key set is published; when the card has no `keys.signing`
set the legacy `publicKeyMultibase` is the sole active signing key; and a card
whose key material cannot yield a usable active signing key, a malformed or
empty set included, rejects the challenge as `signature`, one deterministic
outcome. The same key-material rule applies to the issuer card resolved in
*Binding patterns*. The fetched card's `agentId` MUST equal `rp`: a card whose `agentId`
differs is rejected and no key from it is used, because a host serving another
principal's card must not be able to speak for it. The fetch of the card MUST
pass the private-hostname classification in
[`ink-private-hostname.md`](ink-private-hostname.md), rejecting a loopback,
private, link-local, IANA special-use or malformed IP-shaped host, and MUST
refuse redirects at the transport layer, because challenge verification fetches
the card before any signature check, so unauthenticated attacker-supplied bytes
can steer the fetch and the gate must not be local policy. The classification
is a static-literal gate: its own spec states that it does not defend against
DNS rebinding and that a public hostname resolving to a private address at
connect time still requires connect-time IP pinning at the platform layer. The
fetch MUST therefore also apply those connect-time rules, rejecting a resolved
address that falls in a private or special-use range and pinning the connection
to the resolved address it checked, so a hostname that re-resolves between
check and connect gains nothing. Of the card discovery-fetch contract (see
[`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md)) this
profile reuses only the response-evaluation steps, its status, declared-length,
content-type, body-size, JSON, schema, protocol and identity-binding checks,
with the requested agent id being `rp`. The URL the response came from is this
profile's well-known construction above, never that contract's URL
construction, which fetches a different path. This is what lets the user's
agent learn who is asking without a shared directory: it resolves `rp` to a
card and checks the signature against a key the card publishes.

The `redirectUri` MUST consist of the RP origin derived above, the exact pinned
string, followed immediately by `/`, followed by an optional path and query.
The check is a literal string prefix match against the derived origin plus `/`,
and no URL parsing is performed. `redirectUri` MUST NOT contain `#`, because a
fragment never reaches the completion endpoint, so a fragment-bearing redirect
target is malformed, and it MUST NOT contain `\`. It MUST NOT contain any ASCII
control character (`U+0000`-`U+001F`, `U+007F`) and MUST NOT contain ASCII
whitespace (the string is not trimmed first), the same ban the Agent Card
endpoint URL grammar applies to URL-shaped fields: the value is placed into a
redirect by the completion flow, so a control character that survives into a
Location header is an injection primitive, and the ban keeps acceptance exact
and parser-independent. A `redirectUri` that fails
any of these rules rejects as `schema` before the signature. The prefix rule
makes userinfo, host case tricks, percent-encoded host confusion and
default-port aliasing structurally impossible: nothing between the scheme and
the first `/` can differ from the pinned origin string.

The completion endpoint `redirectUri` names MUST itself consume the grant: it
MUST NOT be or chain a redirect and MUST NOT forward the grant bytes
cross-origin in any form (URL, fragment, body or header). The prefix rule
narrows delivery to the RP's own origin and the consumption rule closes what
remains: an open redirect or a forwarding endpoint inside that origin would
otherwise hand the grant to wherever it points, which is the classic hook for
collecting another party's sign-in.

The user's agent MUST obtain a consent decision that names the RP identity and
the requested scope tokens before minting any grant, including a bare
`identity.assert` assertion, because even bare sign-in discloses the user's
stable principal to the RP. How the decision is presented stays product surface;
the normative rule is consent before mint. The agent MUST NOT silently mint any
grant, and never a capability grant as a default.

## Threats

**Phishing relying party.** A site that impersonates a legitimate RP is bounded
by three composed checks: the challenge signature must verify against a key in the
card resolved from `rp`, so an impostor cannot borrow another RP's identity
without its key; the `redirectUri` must extend the RP's own pinned origin under
the prefix rule and its completion endpoint must consume the grant rather than
forward it, so a stolen challenge cannot deliver the sign-in anywhere but the
RP's own consuming endpoint; and the agent obtains a consent decision naming the
RP identity and
scope before it mints anything, so the user sees who is asking before the
sign-in exists.

**Capability creep.** An RP cannot widen what sign-in means over time, because the
scope registry is closed and default-deny. A challenge requesting an unregistered
token rejects as `schema`, a token carried in a grant of the wrong shape grants
nothing and new tokens arrive only by spec revision, so the set of things a grant
can authorize does not drift with individual RPs.

**Replay of grants.** The identity assertion that answers a challenge carries
the id derived from that challenge as its `grantId`, so replay is covered on
both sides. The issuer's
mint-once rule in *Nonce binding* refuses a replayed challenge before an
assertion exists, and the RP records the accepted `(issuer, grantId)` pair
atomically with acceptance and rejects a second presentation of the same pair,
so even an issuer that lost its record cannot buy a second sign-in. The two
layers do not depend on each other.

**Stolen grant inside its window.** A grant is short-lived but a thief who grabs
the bytes inside the window must still present them somewhere. Over authenticated
delivery the grant's presentation binding stops the thief: the verifier rejects a
presenter that is not the signed `subject`, and over INK the audience checks the
envelope sender against `subject`. Over an unauthenticated carrier such as a
browser redirect no presenter exists and presentation binding never fires, so the
context binding in *Nonce binding* takes over: the RP accepts a sign-in's grants
only in the context that owns its nonce, and stolen bytes presented from the
thief's own context are rejected. Context binding alone does not cover a thief
who owns a context, so the completion rules in *Relying party requirements*
close that channel: the endpoint `redirectUri` names consumes the grant and
forwards nothing cross-origin, so an attacker who initiates a sign-in context
and lures the user through consent cannot collect the grant off a forwarding
endpoint and replay it into the context it owns. The bindings and the
consumption rule, together with the short window and the grant's
confidentiality in transit, are the defense.

**Cross-site tracking via stable principals.** Because a user signs in under a
stable principal, colluding RPs can correlate that the same principal signed in to
each of them. This profile acknowledges the linkability rather than hiding it,
and the consent rule gates the disclosure: even a bare sign-in is minted only
against a consent decision that names the RP, so the principal is never revealed
without the user deciding to reveal it. Pairwise or per-RP principals are a
possible later refinement and are out of scope here.

## Conformance

The `agent-authorization` category of the
[`ink.conformance.v1`](../conformance/v1) corpus pins the challenge artifact and
its verification. It is a capability-gated profile (`authorization`), the same
profile the grant carries, required only when an implementation accepts
challenges (see [`ink-conformance-profile.md`](ink-conformance-profile.md)). Each
verify vector carries the challenge, the RP card's candidate signing keys, and
the verifier clock; both the TypeScript reference and the Go implementation must
make the same accept or reject decision, and each reject vector pins the typed
reason (`schema`, `signature`, `not_yet_valid`, `expired`) so the two agree on
verify order. The corpus covers the happy path, a bare-host `did:web` with a
non-default port, an active in-window key, and the negative cases: a retired,
revoked, out-of-window, wrong, or absent signing key (each `signature`, pinning
the active-key-only rule and that key usability is evaluated at the verifier
clock); a tampered body; a non-bare-host `rp` (path segment, uppercase host,
all-digit final label, IPv4 literal, explicit port 443, lowercase `%3a` marker);
a `requestedScope` missing `identity.assert`, carrying an unregistered token, or
otherwise malformed; a `redirectUri` that is not the derived origin plus `/` or
that carries a fragment, backslash, control character, or whitespace; an inverted
or over-ceiling window; a malformed or missing signature; and the window verdicts
at the inclusive lower and exclusive upper bounds. A separate set of derive-only
vectors pins the exact challenge-derived `grantId` for fixed inputs, so both
implementations compute the identical id, and pins its determinism, its
independence from non-binding fields, and its distinctness across `rp`, `nonce`,
and window. The grant that answers a challenge is pinned separately by the
`authorization-grant` category.

## Out of scope

- Multi-hop delegation. Chaining a grant through more than one hop is the separate
  draft in [`ink-authorization-chain.md`](ink-authorization-chain.md) and is not
  part of this profile.
- Durable standing capabilities. Every grant this profile mints lives inside the
  grant's ten-minute window; a capability that outlives that window is a later
  extension, not this profile.
- Grant introspection endpoints. This profile pins the artifacts and their
  verification, not a service an RP calls to ask about a grant's live state.
- Identity-provider product UX. Consent screens, account linking and session
  management are the RP's and the agent's product surface, not protocol.
- The challenge transport. A redirect, a QR code and an INK envelope are all valid
  carriers; this profile pins the challenge artifact and its verification, not how
  the bytes travel, the same stance the grant takes on revocation state and the
  discovery query takes on freshness. A carrier that delivers the exact signed
  bytes is conformant.
