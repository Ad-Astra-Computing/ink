# INK Protocol Specification v1

**Status:** Draft, v1 stabilization. The elements marked **Frozen for 1.0** below are the base wire contract and MUST NOT change without a major version bump.
**Authors:** Ad Astra Computing
**Last updated:** 2026-07-20

## 1. Purpose

This is the in-repo normative source of truth for the INK core wire contract:
the message envelope, the signature base and its canonicalization, replay and
freshness, protocol versioning and negotiation, the message-type namespace, and
the principal grammar. An independent implementer MUST be able to build a
conformant sender or receiver from this document and the companion profiles it
references, without reading any product source.

Requirement keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** are used per RFC 2119.

This document is the master text the compliance checklist and other specs cite
as "Protocol §X". The cross-implementation conformance floor, which categories a
base sender and receiver MUST satisfy, is frozen in
[`ink-conformance-profile.md`](ink-conformance-profile.md) and pinned by the
`conformance/v1` corpus. Where the two overlap they agree.

### 1.1 What is Frozen for 1.0

The following are frozen for the 1.0 base profile. A change to any of them is a
breaking change (major version bump) under
[`ink-compatibility-policy.md`](ink-compatibility-policy.md) §2.1:

- the transport signature base string and its field order (§3.3);
- JCS (RFC 8785) canonicalization with the safe-integer number profile and the
  lone-surrogate rejection (§3.2);
- the `INK-Ed25519` authorization header grammar (§3.3);
- base64url (no padding), multibase, lowercase-hex and the strict RFC 3339
  timestamp grammar as the fixed encodings (§3.2, §3.3);
- the replay freshness window and the single-use nonce rule (§3.5);
- the version-keyed body-signature domain separators `tulpa/sign\n` and
  `ink/sign\n` and their selection from the signed `protocol` field (§3.6);
- Ed25519 verification under RFC 8032 strict rules (small-order and
  non-canonical public keys rejected) (§3.3).

What still legitimately varies by minor version: the message `protocol` value
(`ink/0.1` or `ink/0.2`, §8), which only selects the body-signature domain of
§3.6; and the set of allocated message-type suffixes in the §6 registry, which
grows under the minor-version rule without changing any of the above.

---

## 2. Discovery and the Agent Card

A receiver publishes an **Agent Card**, a signed-transport-independent JSON
document that a sender fetches before first contact. The discovery path and the
contract for evaluating the response are pinned by
[`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md), which
owns both; this specification does not restate the path.

A base Agent Card MUST include `protocol` (the literal `"ink/0.1"`), `agentId`,
`publicKeyMultibase` (a multibase base58btc Ed25519 key, §7) and `endpoint`
(the inbound message URL). It MUST declare `capabilities`, including the intent
types it accepts and sends. Consumers MUST ignore unknown top-level card fields
(forward compatibility).

The card MAY advertise `supportedProtocolVersions`, an array of the message
protocol versions this receiver can verify on the body signature (§3.6). When
the field is absent or empty a sender MUST assume `ink/0.1` only. Version
negotiation is specified in §8.

The full card schema, the endpoint URL grammar, key-set rotation fields and the
discovery path and response contract (status, content type, size cap, identity
binding, owner anti-substitution) are pinned by [`ink-agent-card.md`](ink-agent-card.md),
[`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md), and
[`ink-key-rotation-spec.md`](ink-key-rotation-spec.md). Every outbound discovery
or delivery URL MUST pass the SSRF host-safety check of
[`ink-private-hostname.md`](ink-private-hostname.md), failing closed on a
private, special-use or malformed host.

---

## 3. Core message contract

### 3.1 Message envelope

An INK **intent message** is a strict JSON object. The following fields are
defined; an implementation MUST reject an unknown top-level key on the intent
envelope.

| Field | Required | Type | Notes |
|---|---|---|---|
| `protocol` | MUST | string | `"ink/0.1"` or `"ink/0.2"` (§8). An unknown value is rejected, never inferred. |
| `id` | MUST | string (<= 256) | Message identifier. |
| `correlationId` | MUST | string (<= 256) | Conversation/thread identifier. |
| `createdAt` | MUST | string (<= 64) | Strict RFC 3339 timestamp (§3.2). |
| `from` | MUST | string (<= 512) | Sender principal (§7). |
| `to` | MUST | string (<= 512) | Recipient principal (§7). |
| `intent` | MUST | string | One of the allocated intent types. |
| `payload` | MUST | object | Intent-specific body. |
| `signature` | MUST | string (<= 256) | Body signature over the envelope (§3.6). |
| `expiresAt` | MAY | string (<= 64) | RFC 3339 timestamp. |
| `signingKeyId` | MAY | string (<= 128) | Key-rotation hint (§3.3, key-rotation spec). |
| `timestamp` | MAY | string (<= 64) | Transport freshness instant. Required at receipt for replay checks (§3.5). |
| `nonce` | MAY | string (<= 256) | Single-use replay nonce. Required at receipt when a nonce store is present (§3.5). |
| `provenance` | MAY | object | Optional origin metadata (`origin`, `extensionId`, `installationId`). |

String length bounds are measured in UTF-16 code units. Unknown fields on the
intent envelope are rejected by the strict schema; unknown fields on other
top-level INK objects (handshake, receipt, audit) are accepted, not rejected; the
reference validators strip unknown keys from the parsed object, per
[`ink-compatibility-policy.md`](ink-compatibility-policy.md) §3.1.

INK has two families of top-level object. **Intent messages** carry the action
in the `intent` field and have no `type` field. **Protocol messages** (the
encrypted envelope, handshake messages, receipts, audit and discovery messages)
carry a reverse-domain `type` field from the §6 registry. Both families sign
their bytes under §3.3 for transport and, where they carry an embedded
`signature`, under §3.6.

A receiver MUST check `protocol` on every inbound object and MUST reject any
value outside the closed set accepted for that surface (§8).

The envelope contract is pinned by the `first-contact-transcript` conformance
category, which validates the structure of both the request and the response
envelope before it verifies anything: a missing MUST member and an unknown
top-level member each reject a transcript whose signatures are otherwise valid.

### 3.2 Canonicalization

Every place INK signs, hashes or AEAD-binds a JSON value, it first serializes
that value to canonical bytes with **JCS (RFC 8785)**. The reference uses the
`canonicalize` library; a second implementation MUST produce byte-identical
output. JCS sorts object members by key and removes insignificant whitespace, so
member order on the wire is irrelevant to the signed bytes.

Three constraints narrow JSON to the portable subset every conforming
canonicalizer serializes identically:

- **Numbers.** A number in a signed body MUST be a safe integer:
  no fractional part, `-(2^53 - 1) <= v <= 2^53 - 1` and not negative zero.
  `NaN` and the infinities are forbidden. The profile is applied to the decoded
  double, not the source token, so `1e2` is accepted and canonicalizes to `100`.
  A signer MUST refuse and a receiver MUST reject a body carrying an out-of-profile
  number rather than canonicalize it. Full rule and vectors:
  [`ink-jcs-number-profile.md`](ink-jcs-number-profile.md). The profile is a check
  on decoded values, so it is paired with a raw-text rule that runs before
  parsing: a receiver MUST reject a body whose raw JSON text carries a number
  literal outside the IEEE-754 double range, because parsers disagree about
  whether such a document exists at all and a duplicate member can shadow the
  literal from every value-level check. See
  [`ink-signed-string-safety.md`](ink-signed-string-safety.md).
- **Lone surrogates.** A value carrying an unpaired UTF-16 surrogate MUST be
  rejected before signing or verifying, because a `\uXXXX` escape for a lone
  surrogate is not portable (a Go JSON parser rewrites it to U+FFFD, changing the
  canonical bytes). A receiver MUST additionally scan the raw request bytes for
  invalid UTF-8 before parsing. See
  [`ink-signed-string-safety.md`](ink-signed-string-safety.md).
- **Complexity bounds.** Before canonicalizing an attacker-supplied value an
  implementation MUST bound the walk. The reference caps at 10000 nodes, depth
  32, 1,200,000 aggregate string code units and a canonical output of
  1,048,576 bytes, and rejects a value that exceeds any of them. Both the
  UTF-16 code-unit length and the UTF-8 byte length of the canonical output are
  capped at 1,048,576 so a body that stays under the code-unit ceiling but
  exceeds it in bytes is still rejected.

**Timestamps.** Every parsed-and-compared instant (the message `timestamp`, a
key `validFrom`/`validUntil`, a `revokedAt`) MUST match INK's strict RFC 3339
profile: an uppercase `T` separator, a `Z` or numeric `±HH:MM` zone, no leap
second, no space separator, no lowercase `t`/`z`. The parsed instant is
whole-millisecond Unix time, floored, and all comparisons MUST be at
millisecond precision. An implementation MUST cap the accepted length (64
characters is sufficient) before parsing. A value that is not well-formed under
this grammar fails closed. Full grammar and vectors:
[`ink-timestamp-grammar.md`](ink-timestamp-grammar.md).

### 3.3 Transport signing

Every INK HTTP request authenticates with an Ed25519 signature over a
newline-delimited **signature base** carried in the `Authorization` header.

**Signature base (Frozen for 1.0).** The exact bytes signed are the UTF-8
encoding of:

```
ink/0.1\n<METHOD>\n<PATH>\n<recipientDid>\n<JCS(body)>\n<timestamp>
```

where the six fields are joined by single U+000A line feeds:

1. the literal domain-separation string `ink/0.1`. This first line is the fixed
   literal `ink/0.1` for **every** message, including `ink/0.2` traffic. The
   transport base does not track the message `protocol` value; only the
   body-signature domain of §3.6 does.
2. `<METHOD>`, the uppercase HTTP method.
3. `<PATH>`, the request path.
4. `<recipientDid>`, the receiving agent's principal.
5. `<JCS(body)>`, the RFC 8785 canonicalization of the request body object (§3.2).
   No field is stripped from the body before canonicalization; the base commits
   to the body exactly as delivered. This is the one place the two signature
   kinds differ in their treatment of the same object, and it is the difference
   an implementer is most likely to get wrong: the §3.6 body signature removes
   the `signature` member before canonicalizing, and the transport base of this
   section removes nothing. An intent envelope always carries a `signature`
   member (§3.1, a MUST), so on real traffic a transport base that strips it is
   computed over different bytes than the signer produced and every signature
   fails. The `signature-base` conformance category pins both directions on a
   body that carries the member.
6. `<timestamp>`, the request freshness instant, which MUST equal the body's
   `timestamp` field.

**What `PATH` is (Frozen for 1.0).** `PATH` is the path component of the
absolute URL the request is sent to, with no query string and no fragment. INK
does not reserve a fixed inbound path: the receiver chooses its own and
publishes it as the `endpoint` (and, when present, the identical
`inboxEndpoint`) of its Agent Card, so a sender MUST take `PATH` from the path
component of that URL and a receiver MUST reconstruct the base with the path
component of the endpoint it published. `/ink/v1/inbound`, `/ink/v1/intents`
and `/ink/v1/<recipientDid>/intent` are all conforming spellings, and none of
them is normative; the only normative requirement is that the two sides agree
because both read the same card. A document that names one spelling is
illustrating a deployment, not specifying the protocol.

The query string is deliberately outside the base, so a receiver MUST NOT place
authorization-relevant routing in the query: anything the signature must cover
belongs in the path or the body. The one path that IS pinned by a specification
is the card discovery path itself
([`ink-agent-card-discovery-fetch.md`](ink-agent-card-discovery-fetch.md)),
because a sender has to reach the card before it can learn anything else.

Because `PATH` is inside the frozen base, a mismatch is not a routing problem;
it fails every signature. A sender that signs a path other than the one it
posts to, or a receiver that reconstructs the base with a path other than the
one it advertised, produces `invalid_signature` on otherwise valid traffic. The
`first-contact-transcript` conformance category pins the binding by rejecting a
transcript whose signed request path is not the path component of the fetched
card's `endpoint`.

The four scalar fields (`METHOD`, `PATH`, `recipientDid`, `timestamp`) MUST NOT
contain a CR or LF. Because the base is newline-delimited, an embedded newline
could shift field boundaries and let two distinct inputs collide on one signed
string; an implementation MUST reject a scalar containing `\r` or `\n`. The
`signature-base` category pins the collision itself: a PATH of `/a\nb` with
recipientDid `x` and a PATH of `/a` with recipientDid `b\nx` build the same base,
so one signature authenticates both, and both MUST reject. The
reference caps the scalars, in UTF-16 code units, at method 16, path 2048,
recipientDid 256 and timestamp 64, and requires each to be non-empty. The
canonical body is capped at 1,048,576 bytes (§3.2).

**Signature.** The signer computes Ed25519 over the UTF-8 bytes of the base and
encodes the 64-byte signature as base64url with no padding (RFC 4648 §5), which
is exactly 86 characters `[A-Za-z0-9_-]`.

**Authorization header (Frozen for 1.0).**

```
INK-Ed25519 <base64url(signature)> [keyId=<keyId>]
```

The scheme token is the literal `INK-Ed25519`, followed by a single space and
the 86-character signature. A single optional ` keyId=<keyId>` parameter MAY
follow, where `<keyId>` matches `[A-Za-z0-9_:.-]{1,128}`. The reference parses
the header with `^INK-Ed25519 ([A-Za-z0-9_-]{86})(?: keyId=([A-Za-z0-9_:.-]{1,128}))?$`,
using literal single spaces (not `\s`) so CR/LF/TAB cannot enter a parsed value.
Future parameters would use the same space-separated `key=value` syntax after the
signature, but a deployed verifier rejects any unrecognized parameter (a second
unknown parameter is rejected, pinned by the `authorization-header` category), so
a new parameter is a reserved syntax slot rather than an additively deployable
change and ships only behind a negotiated capability or a version gate. When both
a header `keyId` and a body `signingKeyId` are present, the header `keyId` takes
precedence.

**Verification (Frozen for 1.0).** A verifier reconstructs the identical base
from the request and checks the Ed25519 signature under **RFC 8032 strict**
rules (the reference uses `@noble/ed25519` with `zip215:false`; the Go verifier
mirrors it): the public key MUST be canonically encoded and MUST NOT be a
small-order point, and the cofactorless verification equation MUST hold. A
malformed signature, an unresolvable or small-order key, an unbuildable base, or
any mismatch fails closed. Verification MUST fail on a wrong path, a tampered
body or a relabelled scalar, because each is bound into the base.

Key resolution order at a receiver: a hinted `keyId` first, then the agent's
published key set (honoring active/retired/revoked status), then a
single-key connection record, then a bootstrap key derived from the sender's
`agentId` when no key set exists. A published key set is authoritative: a
verifier MUST NOT fall back to the bootstrap key after a key set rejects the
signature. Live transport auth rejects a signature that only verifies against a
`retired` key (`retired_key_for_live_auth`) unless the deployment opts into a
rotation grace window. Full rules:
[`ink-key-rotation-spec.md`](ink-key-rotation-spec.md).

**Error codes.** A receiver returns `missing_authorization` (no header),
`invalid_auth_scheme` (wrong scheme or malformed header) and `invalid_signature`
(signature does not verify).

### 3.4 Payload encryption

Confidential intents are delivered inside an encrypted envelope. This is
capability-gated: it is required only when an implementation sends or accepts
encrypted payloads (see the `encryption` profile in
[`ink-conformance-profile.md`](ink-conformance-profile.md)). Intents the
protocol marks confidential (for example `schedule_meeting` and `context_share`)
MUST be sent encrypted, and a receiver MUST reject them in plaintext with
`encryption_required`.

**Scheme.** ECIES with:

1. an ephemeral X25519 keypair;
2. X25519 ECDH between the ephemeral private key and the recipient's static
   X25519 public key;
3. HKDF-SHA256 over the shared secret with `salt = "ink/0.1"` and
   `info = "ink/0.1/encrypt"`, deriving a 32-byte key;
4. AES-256-GCM over the JSON-serialized plaintext, with a 12-byte nonce.

An implementation MUST reject an all-zero ECDH shared secret (a low-order
recipient or ephemeral key), which would otherwise derive a publicly known key.

**AAD.** The GCM additional data is the UTF-8 bytes of:

```
ink/0.1:envelope\n<JCS(aadObject)>
```

where `aadObject` binds, in this member set, `protocol` (`"ink/0.1"`), `type`,
`from`, `recipientKey` (base64url of the recipient's static X25519 public key),
`ephemeralKey` (base64url), `nonce` (base64url of the AES nonce), `timestamp`,
and `messageNonce`. The `type` is bound **as received**, never normalized, so a
relabelled envelope reconstructs different AAD and fails the tag. The recipient
recomputes `recipientKey` from its own private key, so a ciphertext encrypted for
a different recipient fails the tag.

**Outer envelope.** `protocol` (`"ink/0.1"`), `type`
(`network.tulpa.encrypted` by default, or `network.ink.encrypted` when
negotiated, §6), `from`, `ephemeralKey`, `nonce`, `ciphertext`, `timestamp`,
`messageNonce`. On decryption an implementation MUST verify inner/outer
consistency: the inner `from` MUST equal the outer `from`, and the decrypter
MUST assert its own recipient identity so the inner `to` equals that DID.

Full profile and vectors:
[`ink-payload-encryption.md`](ink-payload-encryption.md).

### 3.5 Replay and freshness

A receiver MUST enforce timestamp freshness and single-use nonces so a captured
signed request cannot be replayed.

**Freshness window (Frozen for 1.0).** Let `drift = messageTimestamp - now`,
both parsed under §3.2 to millisecond Unix time. A receiver MUST reject when:

- `drift > 30_000` ms (more than 30 seconds in the future): `timestamp_too_far_future`;
- `-drift > 300_000` ms (older than 5 minutes): `timestamp_expired`.

A timestamp that does not parse under the strict grammar is not fresh (fail
closed).

**Nonce (Frozen for 1.0).** The replay nonce is a string of 16 to 256 code
units matching `[A-Za-z0-9_-]+`. A receiver MUST enforce single-use per message
within the freshness window: a nonce already recorded is a replay
(`nonce_replay`). The nonce MUST be recorded only **after** the signature
verifies, so a forged request never pollutes the store, but an authentic replay
is still rejected. A nonce store MUST retain a recorded nonce for at least the
5-minute freshness window. A distributed store SHOULD implement an atomic
check-and-record to close the check-then-act race between two concurrent
replays; the reference prefers `addIfAbsent` when available and falls back to a
non-atomic `has` + `add`.

**Nonce store scope.** A nonce store MAY be global to a receiver or scoped per
sender. Where it is scoped per sender, the scope key MUST be the canonical
principal of §7, never the raw `from` spelling: a store keyed on the raw value
splits on the two prefixes of one key, and a split replay set accepts the same
presentation twice. A global store needs no scope key and MUST still enforce
single use across senders, which is strictly stronger.

**Fail-closed nonce policy (Frozen for 1.0).** An INK auth verifier MUST NOT run
without nonce handling. If it is invoked with neither a nonce store nor an
explicit deferral, it MUST reject with `nonce_handling_required` so a
misconfigured deployment fails loudly rather than silently accepting replays.
When a nonce store is supplied, a body `nonce` that is missing or outside the
`[16,256]` charset bounds is rejected with `missing_nonce`, and a store backend
error (on `has`, `add` or `addIfAbsent`) fails closed with `nonce_store_error`.

Both bounds are INCLUSIVE, since the rule rejects only when the bound is
exceeded: a message exactly 300000 ms old, and one exactly 30000 ms ahead, are
fresh. The `replay-freshness` category pins each edge and the millisecond past it.

The standalone replay helper (`checkReplay`) applies the same window and returns
`duplicate_nonce` for a nonce already in the seen set and `expired_message` for a
stale, future or unparseable timestamp. Full vectors: the `replay-freshness`
category of `conformance/v1`.

### 3.6 Body signature and version-keyed domain separation

An INK object that carries an embedded `signature` field (a receipt, a handshake
message or a general signed object) is signed over its own canonical bytes,
under a version-keyed domain separator, distinct from the transport base of §3.3.

**Construction (Frozen for 1.0).** Remove the `signature` field, canonicalize
the remaining object (§3.2) and sign the UTF-8 bytes of:

```
<domain><JCS(object without signature)>
```

with Ed25519, base64url no-padding. The domain is selected from the signed
`protocol` field of the object:

| `protocol` value | Body-signature domain |
|---|---|
| exactly `"ink/0.2"` | `ink/sign\n` |
| anything else (including `"ink/0.1"` or an object with no `ink/0.2` protocol) | `tulpa/sign\n` |

Only the exact string `"ink/0.2"` switches domains, so no other value can smuggle
one in. Because `protocol` is inside the signed bytes, a relabelled object (an
`ink/0.2` body re-tagged `ink/0.1`) is verified under the wrong domain and fails.
The legacy `tulpa/sign\n` domain is retained permanently so every signature ever
produced still verifies. A verifier selects exactly one domain and MUST NOT try
an alternate prefix; unprefixed legacy signatures are not accepted.

Envelope-schema validation, which rejects an unknown `protocol`, runs before
this signer at the message layer. The raw signer itself stays permissive on
`protocol` because it is a general-purpose Ed25519 object signer.

**Other signing domains.** The audit and witness sub-protocols use their own
fixed domain prefixes over `JCS` of their payloads: `ink/audit-event\n` (audit
event, excluding `agentSignature`), `ink/audit-response\n` (bilateral audit
slice over `JCS(events)`) and `ink/audit-query-response/v1\n` (witness
query response, excluding `serviceSignature`). The RFC 6962 audit Merkle leaf is
`SHA-256(0x00 || JCS(event without agentSignature))`. These are capability-gated
and specified in [`ink-auditability.md`](ink-auditability.md),
[`ink-audit-query-response.md`](ink-audit-query-response.md), and
[`ink-merkle-leaf.md`](ink-merkle-leaf.md).

---

## 4. Rate limiting and abuse control

A receiver MAY rate-limit and MUST key every per-sender abuse control (block
lists, rate limits, duplicate-payload checks) on the canonical `principal` of
§7, never on the raw sender-chosen spelling, so a sender cannot switch the
`tulpa:`/`ink:` prefix to evade them. A rate-limited request returns
`rate_limited`. Containment-profile budgets (per-correlation handshake budget,
per-sender intent rate, counterparty cooldown) are specified in
[`ink-containment-phase1-implementation-spec.md`](ink-containment-phase1-implementation-spec.md).

---

## 5. Handshake messages

After discovery two agents MAY negotiate a connection through signed handshake
messages: a **challenge**, a **rejection** and a **resolution**. This is
capability-gated on the containment and governance extension (the
`containment`/`handshake-message` profile). Handshake messages travel over HTTP
and are therefore signed under the §3.3 transport rules, and their embedded
`signature`, when present, follows §3.6. A signature made for one handshake path
(`/challenge`) MUST fail at another (`/rejection`), because the path is bound
into the base.

- **challenge** (`network.tulpa.challenge`): `challengeType` is one of
  `mutual_connection_proof`, `identity_verification`, `availability_query`,
  `context_request`, `none`, with optional bounded `fields`, `availableWindows`,
  and `contextFields` arrays.
- **rejection** (`network.tulpa.rejection`): a `reason` from the policy, trust,
  capacity, intent, rate, expiry or containment set, with an optional `detail`,
  `retryAfter` and `backoffHint`.
- **resolution** (`network.tulpa.resolution`): an `outcome` of `accepted`,
  `declined`, `escalated_to_human` or `expired`, with optional `details` and
  `counterpartyDid`.

Both the vendor-neutral `network.ink.*` spellings and the legacy
`network.tulpa.*` spellings are accepted (§6). A receiver that encounters an
unknown `type` on a handshake or protocol message MUST respond with a rejection
whose reason is `unsupported_intent`. The full schema shape, enum sets, bounds,
and the handshake timestamp grammar are pinned by
[`ink-handshake-message.md`](ink-handshake-message.md); the connection payloads
exchanged inside a handshake are pinned by
[`ink-connection-payload.md`](ink-connection-payload.md).

---

## 6. Message-type namespace registry

Protocol messages carry a reverse-domain `type` string. Two prefixes are
equivalent on receipt: the legacy `network.tulpa.<suffix>` and the
vendor-neutral `network.ink.<suffix>`. The `network.tulpa.*` prefix is a
historical artifact of INK's origin and does not imply Tulpa ownership; Ad Astra
Computing stewards INK.

**Dual-accept rule (Frozen for 1.0).** A conforming receiver MUST accept both
spellings of every registered suffix; `network.ink.<suffix>` validates wherever
`network.tulpa.<suffix>` does. A sender MUST continue to EMIT `network.tulpa.*`
by default; emitting the vendor-neutral spelling is opt-in and reserved for a
negotiated capability, so a receiver that has not upgraded never sees the new
prefix. Dual-accept is a pure receiver-side leniency, independent of the signed
`protocol` field, and is not gated on `ink/0.2`. A validated message keeps its
actual `type` string; every signature, hash, receipt and AEAD binding is over
the spelling on the wire, never a normalized one, so relabelling a message fails
verification.

**Allocated suffixes.**

| Suffix | Purpose | Vendor-neutral spelling | Spec |
|---|---|---|---|
| `encrypted` | ECIES payload envelope | yes | ink-payload-encryption |
| `challenge` | Handshake challenge | yes | ink-handshake-message |
| `rejection` | Handshake rejection | yes | ink-handshake-message |
| `resolution` | Handshake resolution | yes | ink-handshake-message |
| `intent` | Intent transport wrapper (registry and lexicon name only; the intent envelope itself carries no `type` member, §3.1) | yes | this document §3.1 |
| `receipt` | Delivery/disposition receipt | yes | ink-auditability |
| `introduction_receipt` | Introduction receipt | yes | ink-introduction-receipts-extension |
| `audit_query` | Bilateral audit query | yes | ink-auditability |
| `audit_response` | Bilateral audit slice response | **no** (tulpa-only) | ink-auditability |
| `audit_query_response` | Witness audit-query response | yes | ink-audit-query-response |
| `audit_submit` | Witness submit | yes | ink-auditability |
| `audit_inclusion` | Witness inclusion receipt | **no** (tulpa-only) | ink-inclusion-receipt |
| `key_rotation` | Key-rotation audit bridge | yes | ink-key-rotation-spec |
| `agent_card_query` | Capability-gated card query | yes | ink-containment-phase1-implementation-spec |
| `agent_card_response` | Card query response | yes | ink-containment-phase1-implementation-spec |
| `agent_card_denied` | Card query denial | yes | ink-containment-phase1-implementation-spec |
| `discovery_query` | Directory discovery query | yes | ink-discovery-query |
| `authorization_challenge` | Sign in with INK challenge | yes | ink-agent-authorization |
| `authorization_grant` | Sign in with INK grant | yes | ink-authorization-grant |

**Excluded from dual-accept.** `audit_response` and `audit_inclusion` stay
`network.tulpa.*` only. Each carries a detached signature that authenticates a
payload subset and not the envelope `type`, so the relabel-rejection guarantee
cannot hold for them; the vendor-neutral spelling is withheld until a future wire
change brings `type` under their signature. Every other registered type either
signs its full body or binds `type` into its AEAD AAD, so its dual-accept is
relabel-safe.

**Allocation rule.** A new message type is a reverse-domain suffix added under
the minor-version rule of
[`ink-compatibility-policy.md`](ink-compatibility-policy.md) §2.2: it uses the
same envelope, signing and canonicalization rules, and a receiver that does not
recognize it responds with `unsupported_intent` rather than failing. Custom,
non-core intent types SHOULD use a vendor reverse-domain suffix (for example
`network.tulpa.custom_intent`) to avoid collisions with the registry above.

---

## 7. Principal grammar and normalization

An INK principal (the `agentId`, `from` and `to` values) is one of:

- `tulpa:<multibase>`, the canonical key-derived form emitted by senders;
- `ink:<multibase>`, an inbound alias introduced in ink/0.4 that carries the
  identical multibase key and therefore denotes the same actor;
- any other identifier, such as a `did:web:<host>` DID, carried through unchanged.

`<multibase>` is `z` followed by base58btc of the multicodec-prefixed public
key. The multicodec prefixes are `0xed 0x01` for Ed25519 (signing keys) and
`0xec 0x01` for X25519 (encryption keys). A signing principal decodes to a
32-byte Ed25519 public key that verifies the sender's transport and body
signatures. Both accepted prefixes decode their tail identically, so a malformed
tail is rejected the same way for each; the prefix is identity syntax, not
signing authority.

**Normalization (Frozen for 1.0).** Every per-sender security decision MUST key
on a single prefix-independent **principal**, derived once at the storage
boundary from the raw `agentId`:

- `tulpa:zKEY` and `ink:zKEY` for the same key, and any non-canonical multibase
  encoding of that key, map to `key:<canonical-multibase>`, so a sender cannot
  switch prefix or re-encode to dodge a block or split a rate-limit window;
- a raw `key:` input, which is never a legitimate agentId, is escaped to
  `raw:key:<value>` so it cannot forge a collision with a canonicalized key
  principal;
- a DID or any other identifier is returned unchanged;
- a malformed multibase body is escaped to `raw:<agentId>` (the function stays
  total; such an id cannot authenticate via the bootstrap path anyway).

Normalization is DECODE-then-re-encode, not a prefix rewrite: an implementation
that replaces `tulpa:`/`ink:` with `key:` textually maps a malformed, truncated,
non-canonically encoded or wrongly-typed body to a `key:` principal that no key
can authenticate, giving it a security scope of its own. Normalization is not
idempotent; an implementation MUST apply it exactly once, to the raw agentId. Full vectors: the `principal-normalization` category of
`conformance/v1`.

---

## 8. Protocol versioning and negotiation

INK carries a single version string in the `protocol` field of every top-level
object, formatted `ink/<major>.<minor>`. A **major** bump is an incompatible
wire change; a **minor** bump is a backward-compatible addition. An
implementation MUST reject any `protocol` value outside the closed set of wire
versions it implements; an unrecognized version is rejected outright, never
inferred from its major (this is the strict envelope enum of §3.1). A new minor
version deploys receiver-first through the negotiation below, not by receivers
accepting an unknown value.

Two wire versions are defined:

- **`ink/0.1`**, the original version and the default. A sender emits it unless
  it has positively negotiated otherwise.
- **`ink/0.2`**, a backward-compatible minor that changes **only** the
  body-signature domain separator of §3.6, from `tulpa/sign\n` to `ink/sign\n`.
  The transport signature base (§3.3), the envelope shape, encryption, audit,
  and every message type are identical to `ink/0.1`.

**Receiver-first negotiation (Frozen for 1.0).** A receiver advertises the
versions it verifies in its Agent Card `supportedProtocolVersions` array. When
that field is absent or empty a sender MUST assume `ink/0.1` only, and a sender
MUST NOT emit `ink/0.2` to a receiver that has not advertised it. Advertising a
version is necessary but not sufficient for a sender to use it; the sender
intersects the advertised list with the versions it can itself emit. This keeps
the change compatible: an `ink/0.1`-only receiver never receives `ink/0.2`
traffic, so it is never asked to verify a domain it does not implement. An
`ink/0.2` receiver selects the body-signature domain from the signed `protocol`
field and verifies both versions; because `protocol` is signed, a relabelled
message fails.

The `supportedProtocolVersions` entries are advisory hints and are parsed as
bounded strings, not the strict version enum, so a newer peer advertising a
version this build does not know does not make its whole card unparseable. The
strict enum lives on the message envelope (§3.1), where an unknown version is
rejected outright.

Full versioning policy, the breaking-versus-minor change tables and the fixed
encoding conventions are in
[`ink-compatibility-policy.md`](ink-compatibility-policy.md).

---

## Sources

This document is derived from the reference implementation and its conformance
corpus. Every rule above traces to:

- `src/crypto/ink.ts` (`buildSignatureBase`, `signInkMessage`,
  `verifyInkSignature`, `buildAuthHeader`, the ECIES encrypt/decrypt paths,
  `checkReplay`, the audit signing domains) and `go/ink/signature.go`,
  `go/ink/jcs.go` for the byte-exact signature base, canonicalization bounds, and
  strict verification;
- `src/crypto/sign.ts` (`signMessage`, `isJcsSafeNumber`, `bodySignatureDomain`)
  and `go/ink/signbody.go` (`SignInkBody`, `JCSCanonicalize`) for the
  version-keyed body-signature domain (§3.6);
- `src/ink/transport-auth.ts` and `src/middleware/ink-auth.ts` for the auth
  header grammar, key resolution order and the fail-closed nonce policy (§3.3,
  §3.5);
- `src/models/intent.ts` (`MessageEnvelopeSchema`, `INK_PROTOCOL_VERSIONS`),
  `src/models/agent-card.ts` (`supportedProtocolVersions`,
  `agentSupportedProtocolVersions`) and `src/models/wire-type.ts` /
  `go/ink/wire_type.go` for the envelope, version enum and dual-accept namespace;
- `src/crypto/keys.ts` (`AGENT_ID_KEY_PREFIXES`, `deriveAgentId`,
  `canonicalAgentPrincipal`) for the principal grammar (§7);
- the `conformance/v1` corpus categories `signature-base`, `jcs-number`,
  `timestamp-validity`, `replay-freshness`, `handshake-message`,
  `connection-payload` and `principal-normalization`.

**Note on timestamp grammars.** The signed-body timestamp grammar
([`ink-timestamp-grammar.md`](ink-timestamp-grammar.md), used by §3.2 and
§3.5) accepts a numeric `±HH:MM` offset, while the handshake-message grammar
([`ink-handshake-message.md`](ink-handshake-message.md), §5) accepts only a
literal `Z`. This is intentional today and both are pinned by vectors; a 1.0
decision to unify them would be a separate change pinned by new vectors. Noted
so an implementer does not assume one grammar covers both surfaces.
