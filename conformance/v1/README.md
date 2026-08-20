# INK conformance vectors (ink.conformance.v1)

These vectors are the cross-implementation contract for INK's security
decisions. They pin the exact accept or reject outcome for a fixed set of
inputs, so that an independent implementation can prove it makes the same
decisions as the reference, rather than inferring behavior from the source.

A credible wire spec specifies its failures, not just its happy path, so the
corpus is mostly negative and adversarial cases.

## Layout

- `manifest.json` is the machine-readable index of the corpus: one entry per
  category with its vector file, spec, summary, case count, and the SHA-256 of
  the vector bytes. A second implementation reads it to enumerate the corpus and
  to detect drift. It is `{ "format": "ink.conformance.manifest.v1", "corpus":
  "ink.conformance.v1", "categories": [...] }`.
- `schema.json` is the JSON Schema for a vector file.
- `vectors/*.json` are the vector files, one per category. Each file is
  `{ "format": "ink.conformance.v1", "category": "...", "cases": [...] }`.
- `generate.mjs` regenerates the vectors and the manifest deterministically (a
  fixed test seed drives a single Ed25519 key), so re-running produces
  byte-identical output. Counts and hashes in the manifest are derived from the
  same bytes, never hand-maintained.

## A case

```json
{
  "caseId": "ink-alias-same-principal",
  "description": "The ink: alias of the same key normalizes to the same principal.",
  "input": { "agentId": "ink:z6Mk..." },
  "expect": { "result": "accept", "canonicalPrincipal": "key:z6Mk..." }
}
```

A case MAY also carry an `optionalBehavior` object next to `expect`, for a
decision the pinned spec leaves to the implementation:

```json
"optionalBehavior": {
  "id": "didweb-warm-resolver-unavailable",
  "alternative": "reject",
  "spec": "specs/ink-agent-card-signature.md §4.2",
  "rationale": "§4.2 says a warm verifier MAY continue when the resolver is unreachable."
}
```

`expect` still records the branch the reference takes; `alternative` is the other
conformant outcome. An implementation declares once, per behavior id, which branch
it takes, and its runner asserts exactly that: see
[`../../specs/ink-conformance-profile.md`](../../specs/ink-conformance-profile.md)
"Optional behaviors". Without the tag an implementation that fails closed where
the spec allows it would fail a base category for being conformant. An id with no
declaration is a failure, not a skip.

`expect.result` is `accept` or `reject`, and `expect.canonicalPrincipal`
(principal cases) carries the expected identity. Implementations assert the
result and, where present, the canonical principal. The `description` records why
a case rejects; a machine-readable error-code field is intentionally left out of
v1 until the implementation emits stable codes, and would be added as an
additive field then.

## Categories

- **`principal-normalization`**: `tulpa:` and `ink:` aliases of one key collapse
  to the same canonical principal; a literal `key:` agentId is escaped rather
  than confused with that principal; DIDs pass through; an empty id is rejected.
  Four cases pin that the mapping DECODES the multibase body and re-encodes it
  rather than replacing the prefix: a body that is not base58btc, a truncated
  body, a non-canonical spelling carrying an extra leading-zero byte, and an
  X25519 key where a signing key belongs are each escaped to `raw:`. A prefix
  string-replace passes every other case in the category and turns all four into
  `key:` principals, each with its own blocklist entry, rate-limit window and
  nonce scope.
- **`signature-base`**: a signature over the canonical signature base verifies;
  reordering JSON members of the signed body does not change the canonical bytes;
  altering a signed field or the key fails verification. Two cases pin the
  boundary between the two signature kinds on a body that carries a `signature`
  member, as every real intent envelope does: the transport base of §3.3 strips
  nothing, so the signature over the full body verifies and a base built over the
  stripped body does not. Stripping `signature` is the §3.6 body-signature rule
  and applying it here fails both cases. Three further cases pin the §3.3 CR/LF
  ban on the scalar fields: the base is newline-delimited, so a PATH of `/a\nb`
  with recipientDid `x` and a PATH of `/a` with recipientDid `b\nx` produce
  byte-identical bases, and one signature authenticates both. Both reject, as does
  a recipientDid carrying a CR, each against a signature that genuinely verifies
  over those bytes, so an implementation that omits the check accepts two
  different requests under one signature.
- **`authorization-header`**: the `INK-Ed25519 <base64url(sig)> [keyId=<keyId>]`
  transport Authorization header (§3.3). A well-formed header extracts the 86-char
  signature and the optional keyId; a wrong scheme, a wrong signature length or
  alphabet, stray or missing whitespace, an embedded CR/LF, an empty or over-long
  or ill-formed keyId, a second parameter, or trailing data are all rejected. An
  empty header is `missing_authorization`; every other malformed value is
  `invalid_auth_scheme`.
- **`jcs-number`**: a signed-body number must be a safe integer (`|v| <= 2^53-1`,
  not negative zero); an accepted body pins the exact canonical bytes. A safe
  integer, including one written with an exponent (`1e2` to `100`), is accepted;
  a fraction, an above-safe magnitude, a negative zero, and the integer just past
  `2^53` are rejected, so the signed bytes stay agnostic to which canonicalizer
  produced them. Three cases sit on the seam with the raw-text range rule: a
  literal outside the IEEE-754 double range rejects, and still rejects when a
  later duplicate member shadows it, while an in-range duplicate member
  canonicalizes last-wins and an underflowing exponent canonicalizes to `0`. The
  shadowed case is the one a value-level check cannot make, because the parser
  drops the literal before any value exists. See
  [`../../specs/ink-jcs-number-profile.md`](../../specs/ink-jcs-number-profile.md).
- **`key-rotation`**: a signature is verified against a key set under the
  authority rule: an active key verifies; a retired key verifies only while its
  validity window contains the message timestamp; a revoked key, an expired key,
  and a key set without the signing key all fail. Accept cases also pin the
  `keyStatus` that verified. Two layers share the category. A case without
  `liveAuth` is HISTORICAL verification, the bare multi-key primitive, where a
  retired key inside its window verifies. A case with `liveAuth: true` is LIVE
  TRANSPORT AUTHENTICATION, where the retired-key default of §3.3 then rejects
  a signature only a retired entry verified, with reason
  `retired_key_for_live_auth`, unless `liveAuthAllowRetired` opts into a bounded
  rotation grace window. An implementation that returns the primitive's answer
  to its transport-auth caller passes one layer and fails the other.
- **`replay-freshness`**: a message is accepted only inside the freshness window
  (5 minutes old to 30 seconds ahead of the receiver clock) and only if its
  nonce has not been seen; a stale or future timestamp, a duplicate nonce, and a
  malformed nonce all reject. Both edges are pinned to the millisecond and both
  are inclusive: exactly 300000 ms old and exactly 30000 ms ahead accept, one
  millisecond past either rejects, so a window of the wrong width or a comparison
  of the wrong strictness diverges instead of passing on a coarse case.
- **`timestamp-validity`**: INK timestamps use one strict RFC 3339 date-time
  grammar at millisecond precision; a full UTC or numeric-offset value is accepted
  and pins its epoch milliseconds, while a date-only, zoneless, space-separated,
  lowercase-`t`, comma-fraction, or out-of-range value rejects. See
  [`../../specs/ink-timestamp-grammar.md`](../../specs/ink-timestamp-grammar.md).
- **`jcs-string-safety`**: a signed body must not carry a `\uXXXX` escape for an
  unpaired UTF-16 surrogate in any member name or value; the scan runs on the raw
  JSON text before parsing, because a parser that rewrites a lone surrogate to
  U+FFFD would sign different bytes. See
  [`../../specs/ink-signed-string-safety.md`](../../specs/ink-signed-string-safety.md).
- **`signed-body-utf8`**: a signed body must be valid UTF-8 in its raw bytes,
  checked before parsing, because a lenient decode substitutes U+FFFD and would
  verify over bytes the signer never signed. The raw body rides in a hex-encoded
  `bodyHex` field a JSON string cannot express. Valid multibyte UTF-8 accepts,
  and the precomposed and decomposed forms of the same character both accept, so
  the rule is byte validity rather than Unicode normalization. A lone
  continuation byte, a truncated multibyte sequence, an overlong encoding, the
  bytes `0xFE` and `0xFF`, a raw surrogate encoding, an above-maximum code point,
  and UTF-16-encoded bytes all reject. A valid-UTF-8 body whose text carries a
  lone surrogate escape rejects because the surrogate scan still runs. A
  BOM-prefixed body rejects end to end: the BOM survives the fatal decode and
  fails at JSON parsing, which pins the fatal decoder against a lenient
  BOM-stripping decode that would diverge. The category also pins the numeric
  range rule the same gate enforces: a literal outside the IEEE-754 double range
  rejects as a bare body, as a member value, and when a later duplicate member
  shadows it, while the same characters inside a string, an underflowing
  exponent, and the largest finite double all accept. See
  [`../../specs/ink-signed-string-safety.md`](../../specs/ink-signed-string-safety.md).
- **`merkle-inclusion`**: an RFC 6962 inclusion-proof walk: a leaf hash and a
  top-down list of sibling hashes recompute the claimed Merkle root, with internal
  nodes hashed `SHA-256(0x01 || left || right)`. Every leaf position in a
  power-of-two and a non-power-of-two tree accepts; a tampered root, an
  out-of-range index, a proof that is too short, one padded with an unused entry,
  a treeSize past the JavaScript safe-integer range, and a malformed element all
  reject, so a mis-ordered or under-checked walker diverges. See
  [`../../specs/ink-merkle-inclusion.md`](../../specs/ink-merkle-inclusion.md).
- **`merkle-consistency`**: an RFC 6962 consistency proof: that the tree of
  `first` leaves is an append-only prefix of the tree of `second` leaves, the
  check that detects a forked (split-view) log rather than one that merely grew.
  A boundary matrix of prefixes accepts (power-of-two and non-power-of-two first
  sizes, the equal-size case, the empty prefix); a tampered first or second root,
  a wrong, short, or padded proof, `first > second`, an equal-size root mismatch,
  a non-empty root for `first = 0`, a malformed node, and a size past the
  safe-integer range all reject. See
  [`../../specs/ink-merkle-consistency.md`](../../specs/ink-merkle-consistency.md).
- **`merkle-checkpoint`**: the C2SP tlog-checkpoint body grammar a witness
  publishes its log head as: three lines (origin, decimal tree size, 64-hex root
  hash) plus a trailing newline. An accepted body pins its canonical
  re-serialization; a missing or extra newline, trailing junk, an empty origin, a
  non-decimal, signed, or out-of-range tree size, a mis-cased, short, long, or
  non-hex root hash, and an oversized body all reject, so a parser differential
  cannot let a malformed checkpoint through one implementation. See
  [`../../specs/ink-merkle-checkpoint.md`](../../specs/ink-merkle-checkpoint.md).
- **`merkle-leaf`**: the RFC 6962 leaf hash a witness commits for one audit
  event: `SHA-256(0x00 || JCS(event-without-agentSignature))`. An accepted event
  pins the exact digest; reordering members or attaching an `agentSignature`
  does not change it, while a non-object, a lone surrogate, and an
  unsafe-integer number reject, so the leaf path enforces the same signed-body
  profile as signing. See
  [`../../specs/ink-merkle-leaf.md`](../../specs/ink-merkle-leaf.md).
- **`inclusion-receipt`**: end-to-end verification of a witness inclusion receipt:
  structural validation, the witness Ed25519 service signature over
  `"ink/audit-inclusion/v1\n"` plus the JCS of the committed fields, an optional
  event-bound leaf-to-root proof walk, and an optional later-checkpoint
  anti-rollback and fork cross-check. A signature-only receipt accepts; the
  structural edges, a tamper of any signed field, a wrong key or malformed
  signature, an event-id mismatch or out-of-tree leaf, a tampered proof, and a
  rolled-back or forked checkpoint all reject, so a verifier that skips or
  mis-orders a step diverges. See
  [`../../specs/ink-inclusion-receipt.md`](../../specs/ink-inclusion-receipt.md).
- **`audit-query-response`**: end-to-end verification of a witness audit-query
  response: structure, the requester and messageId bindings, the witness envelope
  Ed25519 signature, the per-event scope rule, the events-to-proofs one-to-one
  mapping, every Merkle proof walk, the required per-event agent signature, and an
  optional later-checkpoint cross-check. A valid and empty-tree response accept;
  the structural edges, binding mismatches, a signature tamper or wrong key, scope
  violations, mapping violations, a tampered proof, a wrong-key or unresolvable
  agent signature, and a rolled-back or forked checkpoint all reject. See
  [`../../specs/ink-audit-query-response.md`](../../specs/ink-audit-query-response.md).
- **`handshake-message`**: schema validation for the three INK handshake messages
  (challenge, rejection, resolution): the protocol and type literals, the enum
  fields, the UTF-16 string and array caps, and the handshake timestamp grammar
  (a UTC date-time with a literal Z, no offset). A valid message of each type
  accepts; a wrong protocol or type, an unknown enum, a missing or non-string
  required field, an oversized string or array, an out-of-range or offset
  timestamp, and a malformed backoff hint all reject. See
  [`../../specs/ink-handshake-message.md`](../../specs/ink-handshake-message.md).
- **`connection-payload`**: schema validation for the connection_request and
  connection_response payloads, which are strict (an unknown key rejects) and
  embed a profile snapshot and availability config. A valid request and response
  accept; an unknown kind, an unknown key at any level, an unknown enum, a
  missing required field, an oversized string or array, and a type-confused field
  all reject. See
  [`../../specs/ink-connection-payload.md`](../../specs/ink-connection-payload.md).
- **`agent-card`**: schema validation for the Agent Card discovery document, including a pinned endpoint URL grammar (https, no
  userinfo, no fragment, no control/whitespace) used for all endpoint fields, the
  nested capabilities, key entries, and governance, and the invariant that
  inboxEndpoint equals endpoint when both are present. A minimal and a full card
  accept; a wrong protocol, a missing required field, a non-grammar endpoint
  (javascript:/mailto:/ftp:/http:/userinfo/fragment/no-host/bad-port), an
  inboxEndpoint mismatch, a bad publicKeyMultibase, an unknown or over-cap enum,
  and a malformed key entry all reject. The card top level and the nested
  `discovery` descriptor are separate TOLERANT surfaces, each with its own case:
  an unknown member on either is ignored rather than rejected, which is what makes
  a later minor additive (`ink-compatibility-policy.md` §3.1). See
  [`../../specs/ink-agent-card.md`](../../specs/ink-agent-card.md).
- **`agent-card-fetch`**: the discovery response-handling contract over synthetic
  response metadata (status, Content-Type, Content-Length, body, requested
  agentId, DID under resolution): status must be 200, Content-Type must be
  application/json with at most a utf-8 charset, the body is capped at 64 KiB by
  declared and actual size, and the parsed card must satisfy the schema, carry
  protocol ink/0.1, and bind to the requested agentId. A DID-mediated fetch
  additionally refuses a card whose `ownerDid` is not byte-equal to the DID under
  resolution; a card without an `ownerDid`, or a fetch that names no DID, passes
  that step unchanged. The request-side SSRF gate and card-content
  host checks are out of scope. See
  [`../../specs/ink-agent-card-discovery-fetch.md`](../../specs/ink-agent-card-discovery-fetch.md).
- **`agent-card-signature`**: the self-authenticating card verifier. The
  `cardSignature` proof binds the full card under `ink/agent-card`, resolved to
  the current active signing key or the legacy `bootstrap` key. Rooting is by
  principal kind: a key-derived id walks its rotation chain from the embedded
  genesis key and binds the head to `keys.signing`, and a did:web id anchors the
  signing key in the resolved DID document. An unsigned card ratchets once a
  signed one has been observed, and a cached card drives the continuity and
  rollback rules, including the cold chain-extension residual and its warm
  reject. Profile-keyed cases carry `pre-1.0` or `1.0` and a continuity or anchor
  case names the `auditEvent` it emits. See
  [`../../specs/ink-agent-card-signature.md`](../../specs/ink-agent-card-signature.md).
- **agent-card-signature-phase-c** (staged): the Phase C receiver rule of the
  card-signature spec, pinned before it is required. With the explicit
  `enforcePhaseC` flag on, an unsigned card is rejected outright for a
  key-derived and for a did:web principal, and a cold did:web verifier fails
  closed on an unreachable resolver; a signed card, a legacy `bootstrap` card and
  a warm resolver-unavailable continuation are unaffected, and the ratchet still
  takes precedence over the first-contact rule. With the flag off the
  pre-Phase-C decision stands, including over a `1.0` profile input, so the
  category tests the flag rather than the profile string. See
  [`../../specs/ink-agent-card-signature.md`](../../specs/ink-agent-card-signature.md) §10.1.
- **`private-hostname`**: the SSRF host-safety gate over a hostname string:
  accept means a public destination, reject means loopback, private, link-local,
  IANA special-use, or a malformed IP-shaped name (an over-range octet, a
  malformed IPv6 literal, or an IPv6 zone id all fail closed). Covers IPv4 and
  IPv6 special-use blocks, IPv4-mapped and 6to4 embedded addresses, bracketed
  and bare literals, and FQDN/case normalization. Hostname strings only; URL
  parsing is out of scope. See
  [`../../specs/ink-private-hostname.md`](../../specs/ink-private-hostname.md).
- **`payload-encryption`**: ECIES payload decryption (§3.4): X25519 key
  agreement, HKDF-SHA256, and AES-256-GCM with the outer envelope bound as AAD.
  A valid envelope decrypts to exact plaintext bytes when the mandatory
  recipient DID matches the inner `to`; the AAD binds a `recipientKey` (the
  recipient's static X25519 public key, recomputed locally) so a ciphertext for
  one recipient cannot be accepted by another. A missing recipient DID, a
  recipient-DID/inner-`to` mismatch, a tamper of any AAD-bound field
  (`protocol`, `type`, `from`, `ephemeralKey`, `nonce`, `timestamp`,
  `messageNonce`), a ciphertext-or-tag tamper, the wrong recipient key, a
  malformed or wrong-length ephemeral key or nonce, an all-zero (low-order)
  shared secret, and an inner/outer `from` mismatch all reject. See
  [`../../specs/ink-payload-encryption.md`](../../specs/ink-payload-encryption.md).
- **`first-contact-transcript`**: a complete stranger first-contact flow composed
  from the pinned primitives: discover the receiver's Agent Card, select a
  protocol version from `supportedProtocolVersions`, verify the signed
  `connection_request` under the freshness/replay rule, and verify the accepted
  `connection_response`. A valid exchange accepts and pins the selected version;
  a failed card fetch, no version overlap, a request emitted under an
  unadvertised version, a bad request or response signature, an invalid payload,
  an intent or transport-timestamp mismatch, a replayed nonce, a stale message,
  a non-accepted status, and a response under a different version all reject, so
  an implementation that skips or reorders a step diverges. The transcript also
  pins the endpoint binding: the signed request `path` must be the path component
  of the fetched card's `endpoint`. INK reserves no fixed inbound path, so a card
  advertising a different path accepts when the request is signed over it, and a
  request signed over any other path rejects even though that signature is itself
  valid. The two envelopes are COMPLETE §3.1 intent envelopes, carrying `id`,
  `correlationId`, `createdAt` and the §3.6 body `signature` alongside the
  transport signature, and the transcript validates the envelope structure before
  it verifies anything: an envelope missing a MUST member, an envelope carrying an
  unknown top-level member, and an envelope whose body signature was made with the
  wrong key all reject. A shortened envelope would fail a receiver that validates
  §3.1 before verifying, so the corpus must not contain one. See
  [`../../specs/ink-first-contact-transcript.md`](../../specs/ink-first-contact-transcript.md).
- **`discovery-query-envelope`**: schema validation, requester-key signature
  verification, audience binding, the freshness window and nonce replay for the
  authenticated discovery query envelope. Each case carries the directory's own
  verification context: its identity (`audience`, one spelling or the list of
  spellings it answers to), its clock (`now`) and the `(from, nonce)` pairs it has
  already burned. A requester-signed query with tags, scope and limit verifies
  against the requester's key, the vendor-neutral `network.ink.discovery_query`
  spelling verifies like the legacy spelling and an empty query object is a valid
  signed request. Changing the addressed directory, the wire type or a query tag
  after signing invalidates the signature because the spelling is signed rather
  than normalized; a wrong verifying key, a signature that is not valid base64url
  of the right length, an unknown top-level or in-query field under the strict
  schema, more than 32 tags, a limit above 100, a non-INK timestamp, a nonce
  shorter than 16 code units and a missing signature all reject. Verification is
  signature-before-context: with both the key and the audience wrong the verdict
  is the signature. A query addressed to another directory rejects as `audience`
  and a case-folded spelling of the same directory does not match, since the
  comparison is exact; a query matching any one of several supplied
  self-identifiers accepts; an empty audience set is a verifier input error and
  fails closed as `schema` rather than admitting every audience. A query older
  than five minutes rejects as `expired` and one more than thirty seconds ahead of
  the verifier clock as `not_yet_valid`, both bounds inclusive. A malformed
  verifier clock fails closed as `schema`. A burned `(from, nonce)` pair rejects as
  `replay`, the same nonce burned for a different requester does not and a stale
  replay reports the window because replay is checked last. An envelope is a
  signed body, so the raw-body gate applies to it: the cases that exercise a rule
  about bytes carry `envelopeRaw`, the exact wire text a sender put on the wire,
  in place of `envelope`, and a runner decodes it to bytes and verifies those. An
  out-of-range number literal rejects both in a live member and when a later
  duplicate member shadows it, which is the case that matters, because the
  shadowed literal never reaches the parsed envelope and the signature over the
  canonical form still verifies; a lone surrogate escape in the raw text rejects
  as `schema` before the signature; an underflowing exponent is in range and the
  envelope behind it accepts, so the gate is a range test rather than a ban on
  exponents; and the same envelope presented as whitespace-padded wire text
  verifies, because whitespace vanishes at canonicalization. See
  [`../../specs/ink-discovery-query.md`](../../specs/ink-discovery-query.md).
- **`agent-authorization`**: the sign-in challenge artifact: a bare-host `did:web`
  RP origin derivation, a registry-bounded `requestedScope`, a parser-independent
  literal redirectUri-prefix rule, an active-key-only RP signature checked at the
  verifier clock, the validity window and the challenge-derived `grantId`. A
  challenge signed by the RP's active key and verified inside its window accepts
  and derives its `grantId`, a non-default port in the `did:web` host carries into
  the derived origin, the active-key and window bounds are inclusive, a redirectUri
  that is the origin plus `/` plus a query accepts and the `grantId` is a
  deterministic base64url-nopad SHA-256 over exactly `rp`, `nonce`, `issuedAt` and
  `expiresAt`, so a challenge differing only in `requestedScope` or `redirectUri`
  derives the same id while one differing in `rp`, `nonce` or the window derives a
  distinct id. Verification is signature-before-window: a tampered body rejects on
  the signature, not on the clock. A retired or revoked RP key, an active key whose
  window does not contain the verifier clock, a non-signing or empty candidate key,
  a redirectUri or nonce changed after signing, an unknown field, the grant type or
  a `network.tulpa` spelling of the challenge type, a wrong protocol, a lone
  surrogate, a path-bearing `did:web`, an uppercase host, an all-numeric final
  label, a dotted-quad or bracketed IPv6 literal, an explicit port 443 or a
  lowercase `%3a` port marker, a port outside 1..65535, a percent-escaped host, a
  `requestedScope` lacking `identity.assert` or carrying an out-of-registry,
  duplicate, empty or non-string entry, a redirectUri that is not the origin plus
  `/` (a host suffix-extension, a missing trailing `/`, a fragment, a backslash, a
  control character, ASCII whitespace, an uppercase host or a trailing-dot host), a
  nonce shorter than 16 code units, an `expiresAt` not after `issuedAt`, a window
  past the ten-minute maximum, a mis-encoded or missing signature, a non-INK
  `issuedAt` or verifier clock and a challenge verified before `issuedAt` or after
  or exactly at `expiresAt` all reject. See
  [`../../specs/ink-agent-authorization.md`](../../specs/ink-agent-authorization.md).
- **`authorization-grant`**: the scoped signed authorization grant: schema bounds,
  the issuer-key signature, the audience binding, the presentation binding, the
  validity window, replay, revocation and the optional owner-verification hook. A
  grant verified against the issuer key for its named audience inside its window
  accepts, the vendor-neutral `network.ink.authorization_grant` spelling accepts
  like the legacy spelling, presentation at exactly `issuedAt` is inside the window
  (inclusive lower bound), an owner-requiring grant accepts only when the service
  supplies a verified owner while a grant that does not require one ignores owner
  status, a bearer grant with no presenter (absent or empty) skips the binding
  check and a `maxLifetimeMs` of 0 means unset. The checks are signature-first: a
  grant with a broadened scope rejects on the signature even when the audience,
  expiry, replay, revocation or owner check would also fail. A wrong key, a changed
  subject, a mismatched or relabeled audience, a presenter other than the signed
  subject, presentation after or exactly at `expiresAt` (exclusive upper bound) or
  before `issuedAt`, a seen `(issuer, grantId)` replay, a revoked grant, an
  unverified or absent required owner, an unknown field, a lone surrogate, an
  empty, duplicate, over-64, non-string or over-128-code-unit scope, an over-512
  issuer, subject or audience, an over-256 or under-16 grantId, a wrong protocol or
  type, an `expiresAt` not after `issuedAt`, a window past the ten-minute maximum, a
  grant longer than a caller-tightened `maxLifetimeMs`, a negative `maxLifetimeMs`,
  a non-INK `issuedAt` or verifier clock, a mis-encoded signature and a missing
  signature all reject. See
  [`../../specs/ink-authorization-grant.md`](../../specs/ink-authorization-grant.md).

## Conformance profiles

Each category carries a `profile` in `manifest.json` that pins which conformance
profile requires it. The `base` profile is the floor every conforming INK sender
and receiver MUST satisfy; `encryption`, `audit`, `witness`, `containment`,
`discovery` and `authorization` are capability-gated and required only when an
implementation advertises the matching capability. The base set is frozen by
drift tripwires in `test/conformance-profile.test.ts` and
`go/ink/conformance_manifest_test.go`. See
[`../../specs/ink-conformance-profile.md`](../../specs/ink-conformance-profile.md)
for the per-category sender and receiver obligations.

A `staged` category is not a conformance obligation. It pins a rule that both
implementations already satisfy behind an explicit default-off flag and that
becomes required on a scheduled date, so the rule enters `base` as an
already-agreed contract rather than a fresh negotiation. It is anchored in the
manifest now, with its case count and SHA-256, and the flip retags it from
`staged` to `base` without touching the vectors.

## String length and ordering

INK measures string lengths (the agentId and multibase caps) in UTF-16 code
units, matching JavaScript's `String.length`, and JCS sorts object members by
UTF-16 code unit per RFC 8785. An implementation in another language must measure
and sort the same way or it will disagree with these vectors.

The two rules are pinned separately, because they fail separately.

**Length.** `principal-normalization/non-ascii-under-utf16-cap-passes-through`
carries an identifier whose UTF-16 length is inside the 512 cap while its UTF-8
byte length is not, so an implementation that measures bytes rejects an id the
reference accepts.

**Ordering.** Member ORDER is decided by the comparator, not by the length rule,
and the two orders diverge only when a member NAME leaves the BMP: the astral key
U+1F511 is a surrogate pair whose leading code unit is D83D, so UTF-16 sorts it
BEFORE the BMP key U+FF21 while code-point and UTF-8 byte order sort it after.
Sorting by code point is the natural implementation in Go, Rust and Python, and it
agrees with UTF-16 on every all-ASCII object, so a wrong comparator is invisible
until it changes the signed bytes of every signature kind INK defines. Four
categories carry the discriminator, each at the point where canonicalization
decides the outcome: `jcs-number` pins the canonical string directly
(`member-order-astral-before-bmp-accepts`,
`member-order-mixed-scripts-nested-accepts`), `signature-base` pins a §3.3
transport signature over a body with such member names
(`non-ascii-member-order-accepts` and its reordered twin),
`agent-card-signature` pins the §3.4 card proof over a card carrying them
(`non-ascii-member-order-accept`), and `merkle-leaf` pins the committed leaf
digest (`non-ascii-member-order-accepts`).

Inputs are assumed to be well-formed Unicode; a lone surrogate is the one value
whose UTF-16 length does not round-trip through UTF-8, and is out of scope for v1.

## Running them

The reference implementation runs the corpus in `test/conformance.test.ts` as
part of `npm test`. Another implementation consumes the same files: load each
file, dispatch by `category`, run the input through its own pipeline, and assert
the outcome equals `expect`.

A `staged` category is skipped by a default run in both implementations and runs
only under `INK_STAGED_CONFORMANCE=1`, which is what the dedicated
`staged-conformance` CI job sets. Its manifest integrity, case count and SHA-256
are still checked on every run. An implementation that is not yet ready for a
staged rule can enumerate the manifest and skip the categories tagged `staged`.
