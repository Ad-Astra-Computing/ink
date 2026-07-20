# INK Agent Card Signature Specification

**Status:** Stable in the 0.14 conformance corpus. Phase A has shipped; Phases B and C are staged for a later minor.
**Authors:** Ad Astra Computing
**Last updated:** 2026-07-20

Requirement keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** are used per RFC 2119.

## 1. Purpose

An INK Agent Card carries the material a counterparty needs to trust an agent:
its signing and encryption keys, its `currentSigningKeyId` and `keySetVersion`,
its `endpoint`, its `capabilities` and its `supportedProtocolVersions`. Today
that card is not self-authenticating. A consumer fetches it over TLS from a
discovery surface (see [`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md))
and then treats its contents as authoritative under the key-rotation rule (see
[`docs/key-rotation-rule.md`](../docs/key-rotation-rule.md)). Key authority and
version negotiation therefore rest entirely on TLS plus registry honesty. A
registry compromise or a man-in-the-middle can substitute keys or silently strip
a `supportedProtocolVersions` entry to force a downgrade, and nothing in the card
itself detects it.

This specification closes that gap. It defines an OPTIONAL card proof,
`cardSignature`, that binds the full card under a fixed domain, and it defines how
that proof is rooted for each principal kind so a cold verifier can decide card
authenticity from the identity alone. Once a card is authenticated, and only
then, it becomes the authoritative key set of the key-rotation rule.

This document assumes the wire contract of
[`ink-protocol.md`](ink-protocol.md): JCS (RFC 8785) canonicalization with the
safe-integer number profile and lone-surrogate rejection (Protocol §3.2), the
domain-separation family (`ink/sign\n`, `tulpa/sign\n`, `ink/audit-event\n`,
Protocol §3.6), base64url no-padding 86-character Ed25519 signatures under RFC
8032 strict verification (Protocol §3.3) and the principal grammar with the
`0xed01` Ed25519 and `0xec01` X25519 multicodecs (Protocol §7).

## 2. Design position

The card proof commits the **full card object**, never a field-selected subset.
A partial-coverage design that signs only the keys, or only the keys and the
version list, is REJECTED: it recreates the strip attack field by field, letting
an attacker mutate any uncovered member (`endpoint`, `capabilities`, `discovery`)
while a valid signature still verifies. Full-card coverage is the only design that
makes the whole card a single signed statement.

The proof does not replace the identity system. INK still assumes the identity
system resolves a principal to a discovery surface. What the proof adds is that
the key set, the version list and every other card field carry an integrity
guarantee anchored in the identity itself, so TLS and registry honesty drop from
load-bearing to defense-in-depth.

## 3. The `cardSignature` member

### 3.1 Shape

A card MAY carry an OPTIONAL top-level member `cardSignature`, an object:

| Member | Required | Type | Notes |
|---|---|---|---|
| `keyId` | MUST | string | Names the signing key, resolved under §3.3. |
| `signature` | MUST | string | base64url no-padding, exactly 86 characters `[A-Za-z0-9_-]`. |

`cardSignature` is a single top-level member. Because the card schema already
requires consumers to ignore unknown top-level fields (Protocol §2,
[`ink-agent-card.md`](ink-agent-card.md)), a peer that does not implement this
spec skips `cardSignature` and `rotationChain` (§5) and validates the card
exactly as before. Deployment is therefore schema-safe today.

### 3.2 Signed bytes

The signature is Ed25519 over the UTF-8 bytes of:

```
ink/agent-card\n<JCS(card)>
```

where:

1. the first line is the fixed domain-separation string `ink/agent-card`
   followed by a single U+000A. This domain joins the existing INK
   domain-separation family (Protocol §3.6). It is **not** version-keyed: card
   format evolution is governed by the card's own `protocol` field, which is
   inside the signed bytes, so the domain never needs to track a version.
2. `<JCS(card)>` is the RFC 8785 canonicalization (Protocol §3.2) of the full
   card object with the `cardSignature` member removed and **nothing else
   stripped**. Every other member is covered: `supportedProtocolVersions`,
   `keys`, `currentSigningKeyId`, `keySetVersion`, `endpoint`, `capabilities`,
   `discovery` and any member the schema permits. Only `cardSignature` is
   removed, because it cannot commit to itself.

A signer MUST refuse, and a verifier MUST reject, a card whose canonical form
violates the §3.2 canonicalization constraints of the protocol (an unsafe
number, a lone surrogate, an over-cap walk).

### 3.3 Signer resolution

The key named by `cardSignature.keyId` MUST authenticate the card under exactly
one of two forms.

**Key-set card.** When the card carries a `keys.signing` set, `currentSigningKeyId`
MUST be present, `cardSignature.keyId` MUST name an entry in that set with status
`active`, and `cardSignature.keyId` MUST equal `currentSigningKeyId`
UNCONDITIONALLY. A card signed by a `retired` or a `revoked` key is invalid. A
card is a live statement, re-signed on every update; a retired or revoked signer
contradicts that. A `keyId` that is absent from `keys.signing`, or a signed
key-set card with no `currentSigningKeyId`, is invalid.

**Legacy single-key card.** When the card carries no `keys.signing` set,
`cardSignature.keyId` MUST be the literal string `bootstrap`, and the verifying
key is the multibase decode of the card's top-level `publicKeyMultibase`. This
mirrors the bootstrap keyId used for legacy message verification, without
amending it.

### 3.4 Verification of the proof

A verifier decodes the 86-character `signature`, reconstructs the signed bytes of
§3.2 from the received card, resolves the verifying key under §3.3 and checks
the Ed25519 signature under RFC 8032 strict rules (small-order points and
non-canonical public keys rejected, Protocol §3.3).

An invalid signature REJECTS the card outright. An invalid-signed card is
**never** demoted to an unsigned card, and never falls through to a weaker path.
The only cards this spec treats as unsigned are those that carry no
`cardSignature` at all.

### 3.5 Key comparison

Every key comparison in this spec (a `cardSignature.keyId` resolved against a
signing set, a `prevKeyId` matched against the prior link, a head link matched
against `keys.signing`, a `cardSignature` key matched against the embedded
genesis key or a DID-document verification method) is a comparison of RAW KEY
BYTES, never of encoded strings. A verifier MUST multibase-decode each
`publicKeyMultibase`, MUST require the `0xed01` Ed25519 multicodec prefix
(Protocol §7), and MUST compare the trailing 32-byte raw Ed25519 key. A
comparison MUST NOT be made on the multibase string. Two non-canonical
encodings of the same 32-byte key are the SAME key and MUST NOT be allowed to
split one identity into two; a decode that lacks the `0xed01` prefix or does not
yield exactly 32 raw bytes REJECTS the card.

## 4. Rooting the signing key by principal kind

A valid proof shows that the named key signed the card. It does not by itself
show that the named key has authority over the identity. Rooting supplies that
link, and it is partitioned by principal kind. Both partitions apply; this is not
an either-or choice.

### 4.1 Key-derived agentIds (`tulpa:zKEY`, `ink:zKEY`)

For a key-derived principal (Protocol §7) the Ed25519 key embedded in the
`agentId` is the permanent **genesis** key: the root of card-authentication trust
for that identity, for the life of the identity.

This is a distinct role from the message-verification bootstrap rule of the
key-rotation authority rule, and it does **not** amend that rule. The bootstrap
key stays disabled for MESSAGE verification once a card has been observed
(`docs/key-rotation-rule.md`, invariant 4). The genesis key retains CARD-chain
authority forever. Holding the genesis key authorizes attesting rotations of the
card key set; it does not authorize signing messages after the key set has
rotated away from it.

**Rotation chain.** A card MAY carry an OPTIONAL top-level member
`rotationChain`, an array of at most 32 links. Link `i` is an object:

| Member | Required | Type | Notes |
|---|---|---|---|
| `keySetVersion` | MUST | integer | The key-set version this link commits. |
| `signing` | MUST | array | The COMPLETE signing key set at `keySetVersion`, each `{keyId, publicKeyMultibase, status}`. |
| `prevKeyId` | MUST | string | The key that signs this link (see below). |
| `signature` | MUST | string | base64url no-padding, exactly 86 characters. |

The link signature is Ed25519 over the UTF-8 bytes of:

```
ink/card-rotation\n<JCS(link without signature)>
```

Each link commits the **complete** signing key set at its `keySetVersion`, not a
delta. A delta representation invites set-splicing, where an attacker replays one
add or remove out of context; committing the whole set at each version forecloses
it. Each `signing` entry is `{keyId, publicKeyMultibase, status}`, where `status`
is one of `active`, `retired` or `revoked` per the key-rotation taxonomy
([`ink-key-rotation-spec.md`](ink-key-rotation-spec.md)). A link entry carries NO
`algorithm`: Ed25519 is pinned for chain-capable keys, and an `algorithm` member
MAY be added additively in a later minor without breaking these vectors. Within any
committed link `signing` set every `keyId` MUST be unique, and the card's own
`keys.signing` set is likewise keyId-unique, so the keyed set correspondence of
§4.1 step 3b is unambiguous; a link or card with a duplicate `keyId` is REJECTED.

`keySetVersion` MUST be strictly increasing and contiguous across the chain (no
gaps, no repeats, no reordering). Contiguity constrains CONSECUTIVE links only:
the FIRST link MAY commit ANY `keySetVersion`. The genesis holder MAY therefore
re-root a compressed single-link chain at any version, publishing one
genesis-signed link that commits the current set at the current
`keySetVersion`. This is deliberate and is the escape hatch for the 32-link cap:
a long history collapses to a single genesis-signed link at the head version
rather than requiring an out-of-scope rollup checkpoint.

**Link-signer rule.** `prevKeyId` names the key that signs link `i`. For link 1,
`prevKeyId` MUST be the genesis key embedded in the `agentId` (§3.5). For every
link after the first, the signer identified by `prevKeyId` MUST appear in link
`i-1`'s committed `signing` set with status `active`; a link whose signer is
`retired` or `revoked` in the prior link's set fails the whole chain. This
subsumes the revoked-in-history rule: a key marked `revoked` in the set that
would authorize it can never sign the next link, so a compromise announced on the
chain cannot mint further links. Legitimate links published before a key's
revocation stay valid, because the prior link's set recorded that key as `active`
at the time it signed. It also excludes `retired` keys from attesting rotations,
consistent with the active-signer-only rule of §3.3.

A never-rotated agent needs no chain. Its `cardSignature.keyId` names a key that
equals the embedded genesis key, and §4.1's cold verifier resolves directly to
the `agentId`.

**Cold verifier for a key-derived id.** A verifier with no prior state:

1. decodes the embedded Ed25519 key from the `agentId` (Protocol §7);
2. if `rotationChain` is present, walks it genesis-to-head, verifying every link
   under `ink/card-rotation\n`, checking the strictly-increasing contiguous
   `keySetVersion` and applying the link-signer rule to each `prevKeyId` against
   the prior link's committed set (the genesis key for the first link);
3. binds the head link to the card. Both of the following MUST hold, or the chain
   fails: (a) the head link's `keySetVersion` EQUALS the card's top-level
   `keySetVersion`; and (b) the head link's committed `signing` set CORRESPONDS
   EXACTLY to the card's own `keys.signing` set, compared as a set keyed by
   `keyId`, with byte-equal decoded public keys (§3.5) and equal `status` for
   every entry. A head set that omits a `keys.signing` entry, carries an entry
   absent from `keys.signing`, or disagrees on any entry's public key or `status`
   fails the chain. Because §3.3 requires `cardSignature.keyId` to be an `active`
   entry of `keys.signing`, exact correspondence also guarantees the signer is
   present in the head set;
4. verifies `cardSignature` (§3.4) against the key `keys.signing` binds to
   `cardSignature.keyId`.

If no chain is present, `cardSignature.keyId` MUST resolve to a key byte-equal to
the embedded genesis key (§3.5); for a legacy single-key card (§3.3) the resolved
key is the top-level `publicKeyMultibase`, which for a key-derived id MUST itself
be byte-equal to the embedded genesis key.

**Revoked genesis.** A revoked genesis key makes cold bootstrap impossible: a
first-time counterparty cannot root the identity, and the identity is compromised
for new counterparties. Warm counterparties that already hold a validated prior
card MAY continue under the continuity rule of §6. This is inherent to a
key-derived identity; the recoverable form is did:web (§4.2). The genesis key is
special only for BOOTSTRAP: it is the sole key a cold verifier can root against
with no chain. It is NOT uniquely sensitive to LEAKAGE. As §6 sets out, for a cold
verifier the leakage of any ever-active chain-era key, not only the genesis key,
permits full card fabrication, so historical-key hygiene matters as much as
genesis-key hygiene for cold counterparties.

**Chain cap.** A chain longer than 32 links is out of scope for v1. A signed
chain-rollup checkpoint that would compress a long history into one attested root
is explicitly DEFERRED to a future minor and MUST NOT be improvised. A verifier
MUST reject a `rotationChain` longer than 32 links.

### 4.2 did:web identities

Under the 1.0 profile a card whose `agentId` is a `did:web` identity MUST carry
`cardSignature` under the §3 construction. Before 1.0 an unsigned did:web card
still validates under Phase A (a first-contact unsigned card is accepted, §8),
so the MUST-carry is scoped to 1.0. The ANCHORING requirement is independent of
profile: WHENEVER a did:web card carries `cardSignature`, the verifying key MUST
be **anchored** in the DID document.

The DID document resolved at the standard did:web location MUST contain a
verification method whose public key, after multibase decode, is byte-equal
(§3.5) to the `cardSignature` signing key. The DID document is the root of trust;
the card signature extends that root over every non-key field of the card. A
did:web card whose signing key is absent from the resolved DID document is
REJECTED.

**Resolver-unavailable rule.** When the DID document is unreachable, the outcome
is profile-keyed. Pre-1.0 a verifier MAY fail open under
signature-plus-continuity (§6), emitting an audit mark that records the anchor
was not checked. At 1.0 a COLD verifier, one holding no cached authenticated card
for the principal, MUST FAIL CLOSED and reject the card. At 1.0 a WARM verifier,
one holding a cached authenticated card for the principal, MAY continue under
signature-plus-continuity from that cached card, MUST emit a
`card.anchor_unverified` audit mark and MUST re-check the anchor when the resolver
returns.

A did:web card MAY also carry a `rotationChain`, and a receiver MUST verify it
when present, but the DID document remains the root. The chain does not substitute
for the anchor. Because a did:web identity embeds no genesis key, the link-signer
rule's link-1 base case (§4.1) is re-rooted on the DID document: for a did:web card
carrying a `rotationChain`, link 1's signer, named by its `prevKeyId`, MUST be
byte-equal (§3.5) to a verification-method key in the resolved DID document. Every
later link is checked under the §4.1 link-signer rule unchanged, and the §4.1
head-binding check applies exactly as for a key-derived card: the head link's
`keySetVersion` MUST equal the card's top-level `keySetVersion`, and the head link's
committed `signing` set MUST correspond exactly to the card's `keys.signing` (§4.1
step 3). The DID document stays the trust root; the chain only corroborates
rotation history.

## 5. Verifier algorithm

A receiver enforcing this spec evaluates a fetched card in this normative order.
The first failing step rejects the card.

1. **Fetch contract.** Run the discovery-fetch steps 1 through 8 of
   [`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md)
   unchanged (status, declared length, content type, body size, JSON, schema,
   protocol, identity binding).
2. **Proof.** If `cardSignature` is present, strip it, canonicalize the remaining
   card (Protocol §3.2), prepend `ink/agent-card\n`, resolve `cardSignature.keyId`
   in the card's own `keys.signing` set (or, for a legacy single-key card, the
   literal `bootstrap` to the top-level `publicKeyMultibase`) and verify the
   Ed25519 signature under RFC 8032 strict. An invalid signature REJECTS the card
   outright; it is never demoted to unsigned (§3.4).
3. **Root.** Root the signing key per principal kind (§4). For a key-derived id,
   walk the rotation chain, apply the link-signer rule to every link, and BIND THE
   HEAD to the card: the head link's `keySetVersion` MUST equal the card's
   top-level `keySetVersion`, and the head link's committed `signing` set MUST
   correspond EXACTLY to the card's own `keys.signing` set, keyed by `keyId`, with
   byte-equal decoded public keys (§3.5) and equal `status` for every entry. For a
   did:web id, check the DID-document anchor (§4.2); and when the did:web card ALSO
   carries a `rotationChain`, walk it with link 1's `prevKeyId` rooted on a
   verification-method key of the resolved DID document (§4.2) rather than on an
   embedded genesis key, apply the link-signer rule to every later link, and BIND
   THE HEAD to the card by the same `keySetVersion` equality and exact
   `keys.signing` correspondence as for a key-derived id. A card that roots to no
   genuine head, or whose head set does not correspond exactly to `keys.signing`, or
   whose head `keySetVersion` disagrees with the card, is REJECTED.
4. **Continuity.** Apply the continuity and rollback rules of §6 against any
   cached prior card.
5. **Adopt.** Only after steps 1 through 4 pass does the card become the
   authoritative key set of the key-rotation rule. The rule's trust-on-first-use
   wording, "the first time a valid Agent Card is observed"
   (`docs/key-rotation-rule.md`), becomes "the first time a valid AUTHENTICATED
   Agent Card is observed" for a receiver enforcing this spec.

## 6. Continuity and rollback

When `cardSignature` is present, `keySetVersion` and `updatedAt` become MUST on
the card. Phase A adds `updatedAt` to [`ink-agent-card.md`](ink-agent-card.md) as
an OPTIONAL base member in the strict RFC 3339 profile (see
[`ink-timestamp-grammar`](ink-timestamp-grammar.md)), MUST-present when the card
is signed. `updatedAt` carries NO comparison rule by design: it is an
informational timestamp, and `keySetVersion` is the SOLE monotonic quantity the
continuity rules compare. A verifier MUST NOT reject a card on the basis of
`updatedAt` ordering; time-based rejection is not part of this spec.

A receiver that holds a cached prior authenticated card for the same principal:

- MUST reject a new card whose `keySetVersion` is lower than the cached one;
- MUST reject a new card whose signing key is not reachable from the cached
  card's non-revoked signing set, directly or through the rotation-chain links
  that connect the cached set to the new head;
- on either rejection MUST emit a `card.continuity_violation` audit event and
  MUST retain the cached card.

**Cold-receiver residual (chain-extension forgery).** Head-binding (§4.1)
forecloses fabrication WITHOUT valid links: a card whose head does not correspond
to a genuine chain the verifier can walk from the genesis key is rejected. It does
NOT foreclose fabrication VIA a forged chain-extension link signed by a leaked
historical key whose revocation the cold verifier cannot see. Concretely: suppose
a signing key was `active` in the committed set of some genuine link N, and its
revocation was announced in the genuine link N+1. An attacker who holds that
leaked key presents genuine links 1..N, OMITS the genuine revoking link N+1 and
appends a FORGED link N+1 whose `prevKeyId` is the leaked key. The leaked key is
`active` in link N's committed set, so the link-signer rule PASSES; the forged
link's `keySetVersion` N+1 is contiguous, so the contiguity check PASSES. The
forged link commits an arbitrary attacker-chosen `signing` set; the forged card
carries that set as its `keys.signing` at `keySetVersion` N+1, with `cardSignature`
made by an attacker key in it, so head-binding (§4.1 step 3a and 3b) PASSES because
the forged head link and the forged card agree. A COLD verifier therefore accepts a
fully fabricated key set at a fabricated version. Links carry no back-pointer, and
adding one would not help, because the attacker replays the genuine prefix
unchanged and forks only at the head. This is the inherent fork problem of an
unwitnessed hash chain.

The actual cold guarantee is therefore only this: the presented key set is
REACHABLE from the genesis key through keys that were `active` at some committed
point in a chain the verifier is shown. It is NOT a guarantee that the set or the
version is the agent's current genuine one. It follows that for a COLD verifier the
leakage of ANY ever-active chain-era key, not only the genesis key, permits full
card fabrication: the key set, the `keySetVersion` and every other field. The
severity distinction that treats genesis-key leakage as uniquely catastrophic does
NOT hold for a cold fetcher: genesis-key leakage and historical-key leakage are
equivalent in effect once a verifier has no cached state to constrain the chain.

A WARM verifier remains protected. The forged extension branches from a key that is
`revoked` in the cached authenticated card's set, so the continuity rule of this
section, that the new signing key MUST be reachable from the cached NON-revoked
set, rejects the forged card. The distinction above survives only for warm
verifiers.

External observation of card heads is the ONLY mechanism that closes the cold fork.
High-assurance deployments SHOULD submit card heads to the RFC 6962 witness log
(see [`ink-merkle-consistency.md`](ink-merkle-consistency.md)), which turns a fork
into detectable equivocation: two different signed heads at the same `keySetVersion`
cannot both sit in a consistent log. Prompt revocation hygiene only shrinks the
window in which a leaked historical key is still not-visibly-revoked; it does not
close the fork, because a cold verifier never sees the revoking link. This stays a
SHOULD, not a MUST, to keep the core minimal. Whether the 1.0 profile should
require witness submission for the key-derived COLD verification path, where it is
the only defense, is an OPEN QUESTION for the 1.0 profile and is not decided here.

## 7. Threats addressed

**Version-list stripping.** `supportedProtocolVersions` is inside the signed
bytes (§3.2), so removing or altering an entry invalidates the signature.
Combined with the already-signed envelope `protocol` field (Protocol §3.6), both
halves of version negotiation are integrity-protected.

**Signature stripping (transition-window attack).** An attacker who removes
`cardSignature` to present the card as unsigned is defeated by a monotonic
ratchet that mirrors trust-on-first-use. Once a receiver has observed one valid
authenticated card for a principal, it MUST reject any subsequent UNSIGNED card
for that principal, permanently. Additionally, a key-derived `agentId`
intrinsically possesses its signing authority in the identifier, so under the
Phase C 1.0 profile (§10) a verifier MUST reject an unsigned card for a `tulpa:` or
`ink:` principal even on first contact.

**Key-set substitution.** Covered by the proof (§3) plus rooting (§4). A
substituted key set either fails the signature or fails to root to the identity.
TLS and registry honesty drop from load-bearing to defense-in-depth.

## 8. Conformance vectors

A future `agent-card-signature` conformance category will pin the cases below.
The JSON vectors are a follow-up to this spec; the enumeration here fixes the
intent so the reference and the Go verifier reach the same accept-or-reject
decision on each. The enumeration fixes intent, not count: the list will exceed
its original 17 entries and MAY be renumbered as vectors are added.

**Vector-encoding convention.** Each vector stays a PURE FUNCTION of its input,
so any prior receiver state is encoded as INPUT rather than assumed. A vector
that exercises the ratchet or the continuity and rollback rules carries both the
cached state and the fetched card as `{"cachedCard": ..., "card": ...}`; a vector
with no prior state carries `{"card": ...}`. A vector whose outcome is
profile-keyed carries `"profile"` set to `"pre-1.0"` or `"1.0"` in the input and
a single `expect.result`, so the stateful and profile cases each split into one
vector per state rather than pinning two outcomes in one entry. The corpus
`schema.json` `expect` object gains one additive OPTIONAL field, `auditEvent`,
naming the audit mark a continuity or anchor case MUST emit (for example
`card.continuity_violation` or `card.anchor_unverified`); vectors that emit no
audit mark omit it.

1. **Signed key-derived, no chain, accept.** A `tulpa:zKEY` card with
   `cardSignature.keyId` naming an active key byte-equal to the embedded genesis
   key, no `rotationChain`. Accept.
2. **Rotated signer, valid chain, accept.** A key-derived card whose
   `cardSignature.keyId` is a rotated key, with a `rotationChain` from the genesis
   key to a head set whose entries correspond exactly to `keys.signing` and whose
   `keySetVersion` equals the card's. Every link verifies, versions strictly
   increasing and contiguous. Accept.
3. **Non-contiguous `keySetVersion`, reject.** A chain whose link versions have a
   gap or a repeat (for example 3 then 5). Reject.
4. **Head `keySetVersion` disagrees with card, reject.** A valid chain whose head
   link commits a `keySetVersion` different from the card's top-level
   `keySetVersion`. Reject (§4.1 step 3a).
5. **Head set not corresponding to `keys.signing`, reject.** A valid chain whose
   head `signing` set omits a `keys.signing` entry, carries an extra entry, or
   disagrees on a public key or a `status`, so it does not correspond exactly to
   the card's `keys.signing`. Reject (§4.1 step 3b).
6. **Head set missing `cardSignature.keyId`, reject.** A chain whose head
   `signing` set does not contain the key that signed `cardSignature`. Reject.
7. **`supportedProtocolVersions` mutated post-signing, reject.** A card whose
   version list was altered after signing so the signature no longer verifies.
   Reject.
8. **Active key substituted post-signing, reject.** A card whose `keys.signing`
   public key material was swapped after signing. Reject.
9. **Retired-key signer, reject.** `cardSignature.keyId` names an entry with
   status `retired`. Reject.
10. **Revoked-key signer, reject.** `cardSignature.keyId` names an entry with
    status `revoked`. Reject.
11. **`keyId` absent from `keys.signing`, reject.** `cardSignature.keyId` names no
    entry in the card's own signing set. Reject.
12. **`cardSignature.keyId` not equal to `currentSigningKeyId`, reject.** A signed
    key-set card whose `cardSignature.keyId` names an active entry that is not
    `currentSigningKeyId`, or a signed key-set card with no `currentSigningKeyId`.
    Reject (§3.3).
13. **Wrong-domain signature, reject.** A signature computed over `tulpa/sign\n`
    or `ink/sign\n` (or any domain other than `ink/agent-card\n`) instead of the
    card domain. Reject.
14. **Byte-exact fixed-vector pin.** A fixed card, key and signature triple that
    pins the exact signed bytes (`ink/agent-card\n` plus JCS of the card without
    `cardSignature`) and the exact 86-character signature, so two implementations
    agree byte for byte. Accept.
15. **Chain link signer not `active` in the prior set, reject.** A chain whose
    `prevKeyId` on link `i` names a key that is absent from link `i-1`'s committed
    `signing` set, or present but with status `retired` or `revoked`. Reject the
    whole chain (§4.1 link-signer rule).
16. **Legacy bootstrap-keyId card, accept.** A card with no `keys.signing`,
    `cardSignature.keyId` equal to the literal `bootstrap`, verifying against the
    top-level `publicKeyMultibase`, which for a key-derived id is byte-equal to
    the embedded genesis key. Accept.
17. **Unsigned after ratcheted observation, reject (stateful).** Input
    `{"cachedCard", "card"}` where the cached card is a valid authenticated card
    for a principal and the fetched card for the same principal is unsigned.
    Reject, retain the cached card.
18. **Unsigned first contact, pre-1.0 profile, accept.** Input with
    `"profile": "pre-1.0"` and an unsigned first-contact card from a
    non-key-derived principal, no cached card. Accept.
19. **Unsigned first contact, 1.0 profile, reject.** Input with
    `"profile": "1.0"` and the same unsigned first-contact card. Reject.
20. **`keySetVersion` regression versus cached, reject.** Input
    `{"cachedCard", "card"}` where the fetched card's `keySetVersion` is lower than
    the cached authenticated card's. Reject, `expect.auditEvent`
    `card.continuity_violation`, retain the cached card.
21. **did:web signer absent from DID document, reject / present, accept.** A
    did:web card whose `cardSignature` key is not a verification method in the
    resolved DID document (reject) versus one that is (accept).
22. **did:web resolver unavailable, cold verifier, 1.0, reject.** Input with
    `"profile": "1.0"`, no cached card, and an unreachable DID document. Reject
    (fail closed, §4.2).
23. **did:web resolver unavailable, warm verifier, continuity accept.** Input
    `{"cachedCard", "card", "profile": "1.0"}` where the DID document is
    unreachable and a cached authenticated card is held. Accept under
    signature-plus-continuity, `expect.auditEvent` `card.anchor_unverified`. This
    vector pins the MAY-accept branch of §4.2: warm continuation on an unreachable
    resolver is a MAY, not a MUST, so an implementation that instead fails closed is
    ALSO conformant. Conformance-category participants that fail closed skip or
    invert this vector rather than fail it.

## 9. Consistency with the stable-agentId model

The key-rotation spec treats `agentId` as a stable logical identifier that must
not encode the current signing key (see
[`ink-key-rotation-spec.md`](ink-key-rotation-spec.md) §4). This spec makes that
concrete for key-derived ids: the embedded key is demoted from "the identity's
current key" to "the identity's genesis root". The `agentId` stays stable across
arbitrarily many rotations, and trust in each new key flows through the signature
chain (§4.1) rather than through bare TLS.

Recovery, in the sense of preserving the `agentId` while rotating keys, is
expressed as an ordinary chain link. The recovery event publishes
`keySetVersion` N+1 signed by a key from version N or by a pre-declared offline
recovery key. A pre-declared recovery key is RECOMMENDED (SHOULD): a
`keys.signing` entry with a distinguished status, held offline, so a loss of the
online set is still recoverable. The exact status taxonomy for such an entry is
DEFERRED to the agentId-decoupling work. Any distinguished status is an ADDITION
to the card schema's status enum and MUST land through
[`ink-agent-card.md`](ink-agent-card.md) plus both validators plus conformance
vectors when it arrives. A recovery key attests chain links only, so it need not
be an eligible `cardSignature` signer, and §3.3's active-only signer rule is
unaffected.

Loss of all chain-capable keys for a key-derived id is identity loss. It is
inherent: nothing in the identifier can attest a new key without a prior key to
sign for it. The recoverable form is did:web, where the DID document is the root
and can name a fresh key out of band (§4.2).

This spec makes no change to the key-rotation rule's message-verification
semantics. Its only effect on that rule is to tighten the trust-on-first-use
boundary from "valid Agent Card" to "authenticated Agent Card" (§5).

## 10. Rollout and versioning

Card-signing capability is orthogonal to the wire version. It is a property of the
discovery surface, not of the message envelope, so this spec MUST NOT add a
`supportedProtocolVersions` entry for it and does not bump the message `protocol`
value.

The rollout is three phases.

**Phase A (shipped in 0.14, optional and backward-compatible).** The
schema lands `cardSignature` and `rotationChain` as OPTIONAL top-level members. A
conforming receiver verifies them if present, rejects a card whose present proof
is invalid and ratchets on a valid proof (§7). The `agent-card-signature`
conformance category ships in the SAME release, with lexicons, runtime, docs and
vectors moving together. There is zero breakage: unsigned cards from existing
deployments still validate, and a consumer unaware of the new members ignores
them.

**Phase B (producer MUST).** The reference and the Go implementation sign every
card. A key-derived producer MUST sign; a did:web producer MUST sign and SHOULD
anchor. `keySetVersion` and `updatedAt` become MUST-on-publish.

**Phase C (1.0 profile).** A receiver MUST verify a present proof, MUST enforce
the ratchet and continuity rules (§6, §7), MUST reject an unsigned card for a
key-derived principal and MUST require anchoring for a did:web card when the DID
document resolves. Under the 1.0 conformance profile an unsigned card is rejected
outright.

There MUST be a minimum of 90 days between Phase B and Phase C so counterparties
have a documented window to begin signing before unsigned cards are rejected.

## 11. Relationship to other specs

- [`ink-agent-card.md`](ink-agent-card.md) is the card schema this proof covers.
  The unknown-top-level-field rule there is what makes Phase A schema-safe.
- [`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md) is the
  8-step fetch contract that runs before §5 step 2.
- [`ink-key-rotation-spec.md`](ink-key-rotation-spec.md) and
  [`docs/key-rotation-rule.md`](../docs/key-rotation-rule.md) define the
  authoritative key set, the active/retired/revoked taxonomy, `keySetVersion`,
  and `currentSigningKeyId` that §3.3 and §6 build on. This spec tightens their
  trust-on-first-use boundary and does not otherwise amend them.
- [`ink-protocol.md`](ink-protocol.md) is the canonicalization, domain-separation,
  encoding and principal-grammar base every construction here relies on.
- [`ink-merkle-consistency.md`](ink-merkle-consistency.md) is the RFC 6962
  consistency proof a high-assurance deployment uses to convert cold-receiver
  rollback into detectable equivocation (§6).
