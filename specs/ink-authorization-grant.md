# INK Authorization Grant Specification v0.1

**Status:** Draft
**Authors:** Ad Astra Computing
**Last updated:** 2026-07-12

## Purpose

INK advertises "Sign in with INK". This profile pins the smallest artifact that
claim needs: a scoped, signed authorization grant. An issuer signs a bounded
capability for one subject to present to one named service, valid for a fixed
window. A service verifies the grant against the issuer key and its own context
before acting on it.

This is a primitive, not a permissions framework. There is no delegation chain,
no capability algebra, and no policy language. A `scope` entry is an opaque token
the service interprets by its own policy; this profile does not define what any
token means, only that the set is signed and bounded. The multi-hop delegation
design in [`ink-authorization-chain.md`](ink-authorization-chain.md) is a
separate, later extension and is out of scope here.

For independent implementations to interoperate they must accept and reject the
same grants and verify the same signature over the same bytes.

## Grant

A grant is a JSON object with exactly these fields and no others. Every field is
required except `requireVerifiedOwner`:

- `protocol`: the string `ink/0.1`.
- `type`: the wire type, either `network.tulpa.authorization_grant` (legacy) or
  `network.ink.authorization_grant` (vendor-neutral). A receiver accepts both.
  The signed bytes bind whichever spelling was sent; it is never normalized.
- `issuer`: the granting principal's DID or agent id, a non-empty string of at
  most 512 UTF-16 code units. The issuer key signs the grant.
- `subject`: the principal the grant is for (the bearer), same bound as `issuer`.
- `audience`: the DID or service id the grant may be presented to, same bound.
- `scope`: an array of 1 to 64 distinct strings, each 1 to 128 UTF-16 code
  units. Entries must be distinct so two implementations count the same set.
- `grantId`: an issuer-chosen unique id, 16 to 256 UTF-16 code units. It is the
  replay and revocation key.
- `issuedAt`: a strict INK timestamp (RFC 3339 date-time, uppercase `T`, seconds
  required, `Z` or numeric offset). The grant is not valid before this instant.
- `expiresAt`: a strict INK timestamp, strictly after `issuedAt`. The grant is
  not valid at or after this instant. A zero or negative window is malformed.
- `requireVerifiedOwner`: optional boolean. When `true`, the verifier requires
  the service to supply a verified owner status (see *Owner verification*).
  Absent means the grant does not require owner verification.
- `signature`: the Ed25519 body signature, base64url without padding.

## Signature

The signature covers every field except `signature` itself. It is computed over
the domain-separated JCS canonicalization of the unsigned object, the same body
signature scheme INK uses elsewhere (`ink/0.1` keeps the `tulpa/sign` domain). A
verifier resolves `issuer` to a public key by its own policy, then checks the
signature; key resolution is not part of this grant.

Because the signature binds `audience`, `subject`, `scope`, `grantId`,
`issuedAt`, and `expiresAt`, a service can reject a grant that was tampered,
broadened, or redirected. Relabeling `audience` after signing does not help an
attacker: the signature bound the original value, so the relabeled grant fails
the signature check, not the audience check.

## Verification

A service verifies a grant against the issuer public key and a context: the
service's own `audience`, its clock `now` (a strict INK timestamp), an optional
set of already-seen grant ids, an optional revocation predicate, and an optional
owner status. Verification runs these checks in order and rejects at the first
failure, with a stable reason for each:

1. **Structure and byte safety** (`schema`). The raw bytes must be valid UTF-8
   with no lone UTF-16 surrogate escape, and the object must satisfy the schema
   above, including the distinct-scope and positive-window rules. See
   [`ink-signed-string-safety.md`](ink-signed-string-safety.md).
2. **Issuer signature** (`signature`). The Ed25519 signature must verify against
   the issuer key under RFC 8032 strict rules (small-order and non-canonical
   keys rejected). The signature is checked before any context decision, so a
   rejected grant never reveals whether its audience or window would have passed.
3. **Audience binding** (`audience`). The signed `audience` must equal the
   verifying service's own identity. This is the confused-deputy defense: a
   grant minted for one service must not be presentable at another.
4. **Validity window** (`not_yet_valid`, `expired`). `now` must be in
   `[issuedAt, expiresAt)`: at or after `issuedAt` and strictly before
   `expiresAt`. A `now` that is not a strict INK timestamp fails closed.
5. **Replay** (`replay`). A `grantId` already in the service's seen set is a
   replay.
6. **Revocation** (`revoked`). A `grantId` the service's revocation predicate
   reports as revoked is rejected even inside its window.
7. **Owner verification** (`owner_unverified`). Consulted only when the grant
   sets `requireVerifiedOwner: true`: the supplied owner status must be
   `verified`. An absent status is unverified.

Verification fails closed and never throws. A reference caller may instead throw
an `AuthorizationGrantError` carrying the same reason.

## Owner verification

A grant may require that the subject's human ownership has been verified, by
setting `requireVerifiedOwner: true`. This profile does not compute the owner
signal; it composes with the receiver's existing owner-verification pipeline
(the advisory `verifyOwnerDelegation` outcome). The verifier exposes only the
hook: the service passes in a `{ status: "verified" | "unverified" }` value, and
a grant that requires verification is rejected unless that status is `verified`.
How the service produces the status, and its freshness or caching, are the
service's policy and are out of scope here.

## Revocation

INK grants are point artifacts with no global state, so there is no revocation
list baked into the protocol and no revocation endpoint two implementations must
agree on. The revocation story is deliberately the simplest defensible one
consistent with the rest of INK:

- **Short windows are the primary control.** A grant is only valid inside
  `[issuedAt, expiresAt)`. An issuer keeps the window short (minutes, not days,
  the same short-TTL stance the authorization-chain note records for delegation
  tokens), so the window a revocation must cover is small and every grant
  expires on its own.
- **Explicit revocation is a receiver-side denylist keyed by `grantId`.** A
  service that wants to revoke a specific grant before it expires records its
  `grantId` and supplies a revocation predicate at verify time. A revoked
  `grantId` is rejected even inside its window. This reuses the same shape as the
  replay seen-set: receiver state, not a signed field, checked by id.

This mirrors how the discovery query envelope leaves freshness and replay windows
to directory policy: the protocol pins the artifact and the accept/reject
decision, and the receiver owns the state those decisions read. An issuer-signed
revocation object, a shared revocation log, or issuer-published tombstones are
possible later additions but are not required for the primitive and are not
specified here.

## Audit hooks

An authorization event (a grant issued, a grant accepted, a grant rejected with
its reason) is an ordinary INK audit event: it can be recorded through the
existing hash-chained audit and witness path
([`ink-auditability.md`](ink-auditability.md)) with no new envelope. This
profile does not mandate audit; it notes that the `grantId`, `issuer`,
`audience`, and rejection reason are the fields a service logs when it does.

## Acceptance

A conformant verifier accepts a grant if and only if it is structurally valid
under the schema above, its signature verifies against the issuer key, its
`audience` matches the verifying service, `now` falls in `[issuedAt, expiresAt)`,
its `grantId` is neither replayed nor revoked, and, when the grant requires it,
the supplied owner status is `verified`. Every other case is a rejection with the
reason named above. Verification fails closed and never throws.

## Conformance

The `authorization-grant` category of the
[`ink.conformance.v1`](../conformance/v1) corpus pins these decisions. It is a
capability-gated profile (`authorization`), required only when an implementation
accepts grants (see
[`ink-conformance-profile.md`](ink-conformance-profile.md)). Each vector carries
the full grant plus the verification context, and both the TypeScript reference
and the Go implementation must make the same accept or reject decision. The
corpus covers the scoped happy path, both wire spellings, the inclusive lower and
exclusive upper window bounds, a required-owner accept, and the negative cases: a
wrong issuer key, a tampered scope or subject, a confused-deputy audience, a
relabeled audience, an expired or not-yet-valid grant, a replayed or revoked
`grantId`, an unverified or absent owner where required, an unknown key, an
empty, duplicate, overbroad, or non-string scope, an inverted window, a malformed
timestamp, a malformed or missing signature, a short `grantId`, and a malformed
verifier clock.
