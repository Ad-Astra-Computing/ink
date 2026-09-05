# Changelog

All notable changes to INK are recorded
here. Pre-1.0 releases follow `0.Y.Z` semantics, see
[`docs/maturity.md`](docs/maturity.md) for the versioning policy.

## Unreleased

### Changes

- The Go card verifier no longer demotes a card with a malformed key set to the
  legacy single-key path. `keys.signing` present but not an array failed a type
  assertion and was read as "no key set", so the card was verified against the
  top-level `publicKeyMultibase`: a card whose set retires or revokes that key
  stopped being consulted, and one signed with the `bootstrap` keyId was
  authenticated where the reference rejects it as an invalid card. A present
  but unusable key set is now `invalid_card`, which is the decision the
  reference reaches by entering the key-set branch and failing closed. Found by
  the new card-signature differential surface on its first run.
- The differential fuzzer covers its first composite verifier. The
  `agent-card-signature` surface generates cards from a key it holds, so a
  mutation can be re-signed and the checks past the signature are reachable;
  every other surface can only mutate bytes, which is why the composite
  verifiers were out of reach before.

- The signing and hashing entry points take `SignableBody` instead of
  `Record<string, unknown>`, so a value of a declared interface type, including
  the package's own message types, can be passed straight in. A declared
  interface has no index signature, so callers previously had to write
  `as unknown as Record<string, unknown>` at every call site, and a double cast
  is exactly the construct that hides a wrong argument. `isSignableBody` is
  exported alongside it and is enforced at each entry point: null, arrays and
  exotic objects such as `Date`, `Map` and class instances are refused. Those
  passed the old signature at runtime and canonicalize to `{}`, so a caller
  handing one to `signMessage` signed an empty body and got a valid signature
  back for it. The check reaches nested values too, so `{ when: new Date(0) }`
  is refused rather than signed as `{"when":{}}`, and it tests the prototype
  chain rather than one realm's `Object.prototype`, so an ordinary object that
  crossed a `vm`, worker or iframe boundary still signs. A boxed primitive is
  refused for the same reason: `new String("ink/0.2")` canonicalizes to the
  string it wraps, so the signed bytes named a protocol version that
  domain selection, which compares strictly, did not use.

- Governance: the soak exit criteria in
  [`governance/releases/1.0-readiness-evidence.md`](governance/releases/1.0-readiness-evidence.md)
  §2 gain a fourth criterion. The sixty-day window is now the container for
  adversarial evidence rather than the evidence itself: nightly differential
  fuzzing at a declared budget with every finding dispositioned, the interop
  lab green at the release commit and every ambiguity surfaced during the
  window resolved in spec text and both implementations. An implementation
  from outside the project passing the frozen base corpus, or a written
  waiver, completes it. The
  daily synthetic exchange gains a randomized arm with negative cases, where
  an invalid-accept or an unexplained valid-reject fails the day. Organic
  volume, third-party submissions and performance are recorded and do not
  gate.
- The attestation evidence surface of `specs/ink-attestation.md` activates:
  `buildAttestation` and `verifyAttestation` land in both implementations
  (`VerifyAttestation` in Go), the Agent Card gains the optional bounded
  `attestations` and `evidencePolicy` members, and the capability-gated
  `attestation` conformance category (34 vectors, new `evidence` profile) pins
  the accept and reject decisions across both, including the raw-body gate and
  the single vendor-neutral wire spelling.
- Agent Card validation now preserves unknown and unmodeled top-level members
  instead of stripping them. The card spec always said consumers ignore
  unknown members; the reference deleted them, which broke the card proof for
  any signed card carrying one, since the proof covers the fetched document
  with only `cardSignature` removed. Ignoring is not deleting, and the fix is
  what lets the evidence members ship receiver-first: a consumer on this
  release verifies a signed evidence-carrying card correctly before any
  producer emits one.
- The Go implementation validates the new card members too: `ValidateAgentCard`
  checks `attestations` and `evidencePolicy` exactly as the reference schema
  does, and the new capability-gated `agent-card-evidence` category (19
  vectors) pins the card-level decisions in both implementations, including
  card-proof coverage of carried evidence and the clockless acceptance of a
  stale but well-formed attestation.
- The `policy:evidence_required` structured refusal body the attestation spec
  promises is now a real surface: `parseEvidenceRefusal` in TypeScript,
  `ValidateEvidenceRefusal` in Go, and the `evidence-refusal` category (13
  vectors) pinning the code, the bounded distinct `requiredClaimTypes` set and
  forward-compatible tolerance of unknown members.
- Historical artifacts verify under the key rotation rules of
  `specs/ink-key-rotation-spec.md` §6.2 and §12, not only live transport
  auth. Every detached-signature verifier gains a `...WithKeys` sibling that
  takes the peer's candidate key set: audit events, audit responses,
  audit-query responses, inclusion receipts, checkpoints, message receipts
  and attestations in TypeScript, and the same surface minus message
  receipts in Go. A retired key inside its validity window verifies an
  artifact stamped in that window, a revoked key never verifies anything,
  including artifacts that predate `revokedAt`, and a missing or malformed
  artifact timestamp fails closed before any key is tried. The ordering and
  window policy now lives in one place, `verifyDetachedSignatureWithKeys`
  (`VerifyDetachedSignatureWithKeys` in Go), which the transport-auth
  verifier delegates to as well. The single-key verifiers are unchanged.
  Go also gains `ExtractCandidateKeys`, the card-to-key-set reader the
  reference already had; because it reads the raw decoded card, it applies
  the key-entry schema to each entry itself and skips any entry that fails
  it.
- Go gains the assembled transport-auth receiver, `VerifyInkAuth`, the
  counterpart of the reference `verifyInkAuth`. Go already had every
  primitive (header parse, strict timestamps, single-key and multi-key
  verification, the replay window) but not the order a receiver runs them
  in, so a Go receiver had to reassemble Protocol §3.3 and §3.5 by hand.
  `VerifyInkAuth` runs the stages in the reference order with the same error
  code at each: the fail-closed nonce policy (`nonce_handling_required`,
  `missing_nonce`), key resolution with a published key set authoritative
  and never falling back to a stored or bootstrap key, the
  `retired_key_for_live_auth` refusal, and nonce recording only after the
  signature verifies, through a pluggable `NonceStore` that prefers an atomic
  `AddIfAbsent`. `MemoryNonceStore` is the bounded in-process store for a
  single-process receiver.
- The Protocol §3.4 encryption requirement is now a gate both implementations
  ship rather than a sentence each receiver reimplements. `CONFIDENTIAL_INTENTS`
  names the set the protocol requires to be sent encrypted, `schedule_meeting`,
  `context_share` and `multi_party_sync`, and `checkEncryptionRequired`
  (`ConfidentialIntents` and `CheckEncryptionRequired` in Go) refuses a
  plaintext envelope carrying one with `encryption_required`. The spec text,
  which had listed two of the three as examples, now names all three and is
  machine-checked against the constant, and it pins the order: the plaintext
  refusal runs ahead of the intent allowlist, so a sender is told about the
  plaintext rather than about the receiver's intent support. The reference
  receiver example applies the gate. The compliance checklist rows for
  `unsupported_intent`, `encryption_required` and `rate_limited` now cite the
  tests that exercise them, and a new row records that transport auth returns
  the canonical principal every per-sender control keys on.
- The compliance checklist's Vectors column is gated. It had cited file names
  from a pre-corpus scheme (`signing.json`, `replay.json` and so on) that no
  longer exist, on most of its rows, so a reader could not tell which rows
  the corpus pins. The column now names `conformance/v1` categories by
  manifest id, `npm run check:facts` rejects an id the manifest does not
  have, and the coverage matrix in §16 is rendered from the rows and the
  manifest rather than transcribed. Rows whose old file name has no
  successor category are marked as pinned by tests only, which is what was
  true of them all along.
- The checklist's Tests column was read row by row against the test files it
  cited. Sixty-four rows cited a file that did not exercise them: most
  pointed at `test/security-fixes.test.ts`, which holds ECIES, SSRF and
  checkpoint tests and nothing about the signature base, the freshness
  window, the envelope or the audit chain those rows describe. Each row now
  cites the tests that assert it, a new `test/checklist-evidence.test.ts`
  covers the rows nothing had covered (the standalone replay helper's
  `duplicate_nonce`, unpadded base64url in the auth header, handshake path
  binding, envelope provenance and required members, canonicalization of
  unknown members, header `keyId` precedence over body `signingKeyId`, the
  rotation and containment audit event types, the receipt disposition set), and the rows that are receiver behaviour
  rather than library behaviour say "none in the library" instead of
  borrowing a file. A cited path inside the repository must now exist, which
  `npm run check:facts` enforces.

## 0.19.0, a key must fit its role

### Breaking

- Agent Card validation now enforces the identity model §4.1 key-role rule.
  A `keys.signing` entry must decode to the `0xed01` Ed25519 multicodec and a
  `keys.encryption` entry to `0xec01` X25519, each 32 bytes, with the
  algorithm label naming the role's algorithm. A card that previously
  validated with a role-mismatched, mislabeled or undecodable key now
  rejects. Such a key could never verify a signature or complete an ECDH, so
  no working deployment is affected; a card that trips this was already
  unusable in that role. Both implementations enforce it (`AgentCardSchema`,
  Go `ValidateAgentCard`) and the `agent-card` conformance category pins
  accept and reject sides. The corpus's own `full-card-accepts` vector
  previously carried the Ed25519 key in its encryption slot and has been
  corrected.

### Changes

- Protocol §5 no longer describes handshake messages as carrying an embedded
  signature. Handshake messages define no `signature` member in either
  implementation, in the shape profile or in the corpus; their authenticity
  mechanism is the §3.3 transport signature, which binds the request path. The
  §3.6 example list drops handshake messages, and §5 states that an
  unrecognized `signature` key is ignored like any other unknown top-level key
  and MUST NOT be treated as verified provenance. Three `handshake-message`
  vectors pin that acceptance so no implementation starts rejecting or
  verifying the key. An embedded signature may be specified post-1.0 as an
  additive optional member. No behavior changes.

## 0.18.0, the corpus checks itself

### Changes

- No runtime changes. `src/` and `bin/` are byte-for-byte the 0.17.0 code, so
  every signature, canonicalization and decrypt decision is unchanged. This
  release carries the conformance corpus, the specs and the governance record.

- The corpus is re-verified against constructions written from the spec text.
  [`conformance/v1/independent/`](conformance/v1/independent/) implements each
  signing construction, the RFC 6962 tree rules and the sealed-envelope receive
  side from their normative sections, importing nothing from the
  implementation, and the test suite checks every signature, hash and AEAD
  decision the corpus records against them. A mutation registry
  ([`conformance/v1/independent/mutants.json`](conformance/v1/independent/mutants.json))
  proves the check bites: disabling any registered rule turns the suite red,
  verified weekly and at every release cut.

- Corpus: one vector added, one corrected, 821 vectors total. New
  `agent-card-signature/card-field-rooted-chain-reject` distinguishes a
  rotation chain rooted in the agentId from one rooted in the mutable
  `card.publicKeyMultibase`; both implementations already rejected it, and the
  corpus can now tell. `payload-encryption/inner-from-mismatch` now supplies
  the recipient DID, so it exercises only the inner/outer `from` consistency
  rule its name states. Manifest anchor
  `375a65adf67bdbc3057a19a700dabcd3200831687936492fb3951c0ea5458fb3`.

- [`specs/ink-protocol.md`](specs/ink-protocol.md) §7 now states that only the
  `0xed 0x01` multicodec forms a key-derived principal. A well-formed X25519
  body escapes to `raw:` like a malformed one; both implementations already did
  this, and the spec no longer invites an implementer to canonicalize it.

- The differential fuzzer runs in CI: a fixed-seed budget on every pull
  request, 400,000 cases nightly, self-test first. See
  [`differential/README.md`](differential/README.md).

- Governance: the soak anchoring condition in
  [`governance/releases/1.0-readiness-evidence.md`](governance/releases/1.0-readiness-evidence.md)
  §1 was ruled on and re-drafted. The soak anchors on the first release cut
  after the condition holds, which is this release. The second-implementation
  residual is tracked in
  [#301](https://github.com/Ad-Astra-Computing/ink/issues/301).

## 0.17.0, identity model, resolver spec and two fail-closed guards

### Changes

- **Breaking:** a signed body may no longer contain an object member name
  written with an escape sequence, and a signer may no longer sign an object
  whose keys contain a quotation mark, a reverse solidus, or a character in
  `U+0000`-`U+001F`. Escapes in string values and array elements are unchanged.

  V8 returns the wrong property key from `JSON.parse` for a member name spelled
  with an escape, so `{"x":{"\\":1},"y":{"\n":2}}` parses to a `y` whose only
  member is named `\`. The wrong name survives serialization and reaches
  canonicalization, so a Go receiver and a receiver on Node 24 or newer, or on
  Cloudflare workerd, disagree about which bytes a signature covers, and one
  signature can validate against several different wire bodies. On workerd the
  defect is unconditional and persists across requests within an isolate.
  Upstream is unfixed ([chromium 521080746](https://issues.chromium.org/issues/521080746),
  [nodejs/node#63785](https://github.com/nodejs/node/issues/63785)) and
  reproduces on the newest V8 line. The rule and its rationale are in
  [`specs/ink-signed-string-safety.md`](specs/ink-signed-string-safety.md);
  the narrowing is recorded in
  [`specs/ink-compatibility-policy.md`](specs/ink-compatibility-policy.md) §2.1.

  Affected runtimes observed: Node 24.16.0, 25 and 26.5, and Cloudflare workerd.
  Unaffected: Node 22.23.2 and Go's `encoding/json`. Go enforces the rule
  regardless, so both implementations admit the same bodies.

  Migration: re-key any free-form map whose keys are Windows paths, regular
  expression source, or embedded JSON. `InkAuditEvent.data` and `Profile.custom`
  are where such a key could appear. Nothing in this repository needed changing.

- `hasEscapedMemberNameDefect()` probes the running runtime for the defect. A
  `true` result is proof the runtime is affected; a `false` result is not proof
  of the opposite, because the defect depends on isolate state. It is exported
  for applications whose own `JSON.parse` calls are outside INK's parse path.

- `evaluateAgentCardFetch` parses through the signed-body text gates rather than
  a bare `JSON.parse`. New `parseSignedBodyText` applies the three text-level
  rules for a caller holding a string; prefer `parseSignedBodyBytes` where the
  bytes survive, since a string has already crossed the UTF-8 boundary.

- Every signature-relevant parse in shipped code now runs the same text-level
  rules. New `ink.ParseSignedObject` in Go wraps `ParseSignedBody` for a caller
  that requires a JSON object at the root; `EvaluateAgentCardFetch`,
  `VerifyAuthorizationGrant`, `VerifyAuthorizationChallenge`,
  `VerifyAuthorizationChain` and `VerifyDiscoveryQueryEnvelope` go through it
  instead of gating a subset by hand. `ParseInclusionReceipt` keeps its own
  sequence, because it unmarshals into a typed struct, and now applies all four.
  Previously these admitted bodies the reference rejected.

- `ink verify-inclusion` reads the receipt as bytes and verifies it through the
  signed-body gate. It previously decoded with a non-fatal decoder and then
  parsed with a bare `JSON.parse`, so invalid UTF-8 reached the verifier as
  `U+FFFD` and no text-level rule ran at all. Its size cap now matches Go's
  `MaxInclusionReceiptBytes`; at the old value the CLI could refuse a receipt the
  library accepts.

- **Breaking:** `encryptInkPayload` and the Go `EncryptInkPayload` refuse to seal
  a plaintext whose inner binding disagrees with the outer envelope. The inner
  `from` MUST equal the outer `senderDid` and the inner `to` MUST be a non-empty
  string, and where the caller asserts which recipient the envelope is addressed
  to, the inner `to` MUST equal that value. Every conformant decrypter has
  required that binding since the recipient identity became a mandatory decrypt
  argument, so a seal that skipped it minted envelopes nothing would ever open.
  The failure now lands on the sender, where the mistake is. Go gains
  `InkEncryptOptions.RecipientDid` as a `*string`, because asserting a recipient
  and declining to assert one have to stay distinguishable: an asserted empty
  string is a reject rather than a silent skip, matching the reference.
  Migration: set the plaintext's `from` to the sending principal and its `to` to
  the recipient, and pass `recipientDid` (Go `RecipientDid`) whenever the caller
  knows the identity it is addressing. The producer obligation is stated in
  [`specs/ink-payload-encryption.md`](specs/ink-payload-encryption.md). The
  `encryption` vectors are byte-identical to 0.16.0: the generator now builds its
  one deliberately unbound envelope through a local sealer instead of through the
  library, so the corpus still carries the envelope a decrypter must reject.
- **Breaking:** `fetchAgentCard` fails closed by default. `requireSafeFetch`
  defaults to on, so a call that supplies no `options.fetch` returns null without
  touching the network. The literal-private-IP allowlist this module applies to
  `baseUrl` cannot stop a public hostname that resolves to a private address at
  connect time; only a connect-time-IP-pinning fetch can, so requiring one is the
  connect-time rule the function can actually enforce, and defaulting the
  requirement off made the unsafe path the quiet one. Migration: pass an
  `options.fetch` that pins connect targets (an undici dispatcher on Node,
  `cf.resolveOverride` on Cloudflare Workers, an egress proxy), or pass
  `requireSafeFetch: false` to opt out. The opt-out is legitimate when the
  `baseUrl` is operator-configured, a pinned partner or a fixture, and not when
  it is derived from a remote document or from user input.
- **Breaking, protocol implementers:** Protocol §3.5 is amended. Where a nonce
  store is scoped per sender, the scope key MUST be the canonical principal of §7
  and never the raw `from` spelling. A store keyed on the raw value splits across
  the two prefixes of one key, and a split replay set accepts the same
  presentation twice. A store that is global to a receiver has no scope key to
  get wrong and is unaffected. Nothing on the TypeScript or Go API moves, so an
  implementer whose store keyed on the raw spelling gets no compile error and
  has to re-key it.
- **Breaking:** the Go `EvaluateAgentCardFetch` takes a trailing
  `resolutionDID *string`, the DID a resolution was mediated by, for the owner
  anti-substitution step below. Every Go caller is a source break. Migration:
  pass `nil`, which is what a resolver beginning at the agent's own identifier
  means and which leaves the decision it reaches unchanged. The TypeScript input
  gains an optional `resolutionDid` member and existing callers are unaffected.
- **Breaking:** `verifyDiscoveryQueryEnvelope` takes the raw body bytes, a
  `Uint8Array`, where it took an already-parsed value. An envelope is a signed
  body, and every rule the raw-body gate enforces is a rule about bytes a parsed
  value has already lost, so an entry point that took a value could not run any
  of them. That was an accept-versus-reject split against the Go verifier, which
  has always taken bytes: an envelope carrying `"protocol":1e309` ahead of its
  real `protocol` member canonicalized cleanly, verified, and was accepted here,
  while Go refused the bytes. Member semantics are last-wins, so the literal
  never reached the parsed object and no value-layer check could see it; whoever
  could rewrite bytes in flight could choose which implementation accepted.
  The verifier now runs `parseSignedBodyBytes` itself and caps the body at
  `MAX_DISCOVERY_QUERY_BODY_BYTES`, 64 KiB, matching Go's
  `MaxDiscoveryQueryBodyBytes`; the cap is not redundant with the structural
  bounds, because JSON whitespace is unbounded and vanishes at canonicalization,
  so a schema-valid envelope padded to megabytes still carried a valid signature.
  No parsed-value form is kept: one that skipped the gate would be the same
  divergence under a second name. Migration: pass the bytes you received rather
  than the value you parsed from them, `new TextEncoder().encode(text)` if the
  body only ever existed as a string. A caller that still hands over a value gets
  a compile error, and a typed `schema` rejection at runtime rather than a
  coercion. The `discovery-query-envelope` category grows from 28 to 33 cases and
  gains an `envelopeRaw` input member, the exact wire text, on the five cases
  whose rule is about bytes; the other cases keep `envelope` unchanged.
- **Breaking:** `verifyAuthorizationGrant`, `verifyAuthorizationChain` and
  `verifyAuthorizationChallenge` take the raw body bytes, a `Uint8Array`, where
  they took an already-parsed value. These are the same divergence the discovery
  envelope carried, in the surfaces where it costs the most: a grant, a delegation
  chain and a sign-in challenge are all signed bodies, all three Go verifiers have
  always taken bytes and run the raw-body gate, and none of the rules that gate
  enforces could run on this side. A validly signed grant carrying
  `"protocol":1e309` ahead of its real `protocol` member was accepted here and
  refused by Go, so whoever could rewrite bytes in flight chose which
  implementation signed a user in. Each verifier now runs `parseSignedBodyBytes`
  itself and caps the body at `MAX_GRANT_BODY_BYTES`, `MAX_CHAIN_BODY_BYTES` and
  `MAX_CHALLENGE_BODY_BYTES`, 64 KiB each, matching `MaxGrantBodyBytes`,
  `MaxChainBodyBytes` and `MaxChallengeBodyBytes`. Those three constants were
  already exported and already carried the right values, but nothing enforced
  them: they documented an obligation for whatever layer held the bytes, and the
  whitespace-padding gap the discovery cap closes applied here unchanged. No
  parsed-value form is kept, for the reason the discovery fix gives. Migration:
  pass the bytes you received rather than the value you parsed from them,
  `new TextEncoder().encode(text)` if the body only ever existed as a string. A
  caller that still hands over a value gets a compile error, and a typed `schema`
  rejection at runtime rather than a coercion. The `authorization-grant`,
  `authorization-chain` and `agent-authorization` categories each grow by five
  raw-body cases and gain a `grantRaw`, `chainRaw` and `challengeRaw` input member
  respectively, the exact wire text; every other case keeps its parsed form
  unchanged. The owning specs gain a *Raw body* section citing the enforcement
  order of [`specs/ink-signed-string-safety.md`](specs/ink-signed-string-safety.md).
- **Breaking:** `ParseSignedBodyError.reason` gains `"number-range"` and
  `"member-name-escape"` alongside `"utf8"` and `"surrogate"`. Nothing about an
  existing rejection changes, but a consumer that discriminates on `reason` with
  an exhaustive `switch` and a `never`-typed default no longer type-checks.
  Migration: handle both as the byte-gate rejections they are, or widen the
  default arm. A consumer that reads `reason` without exhausting it, or that
  only catches `ParseSignedBodyError`, is unaffected.
- Two new normative specs.
  [`specs/ink-identity-model.md`](specs/ink-identity-model.md) is the single home
  for what an INK principal identifies, when two principals are the same, what a
  key means at each point in its life and what binds each of those things to the
  next. It adds no wire format, no field and no message type: where a rule was
  already normative elsewhere it states the edge and cites the owning spec, and
  where a behavior was implemented but unwritten it is now the normative home.
  [`specs/ink-resolver.md`](specs/ink-resolver.md) pins the walk from an
  identifier to verified key material, covering the base derivation, the request
  side of the fetch and the outcomes a resolver may reach.
- The discovery path is pinned in one place.
  `GET <base>/ink/v1/<agentId>/agent.json`, with the `agentId` percent-encoded as
  a single path segment, is the sole normative discovery surface of the base
  profile. It is stated once in
  [`specs/ink-agent-card-discovery-fetch.md`](specs/ink-agent-card-discovery-fetch.md)
  and cited rather than restated by every other document.
  `/.well-known/ink/agent.json` is demoted to an alias: an implementation MAY
  serve the same document there, and a resolver MUST NOT depend on it or fall
  back to it. One profile derives a different URL, and it now says so in its own
  text: a Sign in with INK relying party is named by a bare-host `did:web`
  identifier whose origin already determines exactly one card, so the URL is a
  function of the origin alone. That exception is confined to
  [`specs/ink-agent-authorization.md`](specs/ink-agent-authorization.md) and
  grants no license to prefer the alias anywhere else. This closes a real gap
  rather than tidying prose: the reference receiver served only the alias while
  the library fetched only the versioned path, so the reference library could not
  fetch the reference receiver's card at all. The serving examples now serve both
  paths from one build of the document.
- Owner anti-substitution is step 9 of the fetch contract. When a fetch was
  mediated by a DID document and the card carries an `ownerDid`, the card is
  rejected unless that `ownerDid` is byte-equal to the DID the resolution went
  through, so a host that legitimately publishes one owner's card cannot serve it
  in answer to resolution of another. The comparison is byte for byte with no
  canonicalization, and it is not owner authentication: `ownerDid` is
  self-asserted, and passing the step proves only that the card names the DID it
  was reached through, never that the owner consented to the agent. Both
  implementations carry it and the `agent-card-fetch` category grows from 29 to
  34 cases to pin it. The step is inert in this repository today. It fires only
  on an owner-mediated resolution, meaning one that begins at an owner's DID
  document and follows it to an agent's card, and no resolver here performs one;
  a resolver that begins at the agent's own identifier passes null and is
  unaffected.
- Go can now produce a body signature, not only verify one. `SignInkBody` builds
  the `signature` member an INK object carries in its own body (§3.6), and
  `JCSCanonicalize` is exported so a sender can construct the signed bytes. Both
  are pinned to the TypeScript signer by a golden vector file generated from it,
  so the two implementations agree on the signature bytes and on the
  version-keyed domain rather than only on accept-or-reject. A second
  implementation can therefore send, where before it could only verify. The
  generic body verifier stays unexported, and the condition for exporting it is
  recorded next to the producer.
- A `did:web` identifier's `%3A` port is carried into the URL that is fetched, or
  the identifier is rejected. Dropping it silently retargets the fetch at the
  default port, which is a different origin and so a different document. An
  explicit `%3A443` is method-legal, and it is accepted and carried;
  `did:web:host` and `did:web:host%3A443` stay distinct principals under the
  no-folding rule even though they resolve to one origin. The Sign in with INK
  profile keeps its stricter grammar refusing an explicit `443`, because it
  derives a single canonical origin string that two spellings would break. That
  refusal is profile-local and is not applied to general `did:web` resolution.
- A containerized cross-implementation interop lab. `./interop-lab/run.sh` builds
  both implementations, runs a live exchange between them over real HTTP in
  isolated containers and asserts the outcome of every step. Each side produces
  its own bytes at run time, which is the thing a fixed corpus cannot test: a
  disagreement about canonicalization, domain separation, header shape, replay
  state or AAD binding fails an assertion. It runs on every pull request in the
  [`interop-lab`](.github/workflows/interop-lab.yml) workflow. It needs a
  container engine, so it is not one of the checks a contributor runs by hand.
- Reference receiver. The served Agent Card is a pure function of configuration
  and key material, with `updatedAt` read from configuration rather than the
  clock, so any two processes serving one configuration serve identical bytes.
  The card is signed over itself, so a per-build timestamp makes two fetches of
  one document disagree and shows a polling consumer an update that never
  happened. Sender resolution failures now report a fixed reason and an
  operator-facing hint for the step that failed instead of a bare null, including
  the case an adopter is most likely to hit, a card published only at the
  well-known alias. The reasons are a closed enum and are never remote content,
  and nothing probes the alias to confirm a diagnosis.

### Documentation and governance

- The identity ruling is written down. `governance/decisions/` is a new
  numbered, append-only home for ratified project decisions, and its first entry
  records that key-derived principals are the identity root and that AT Protocol
  is one optional owner-linkage pipeline among several. The record states the
  rationale, the two costs it accepts (a key-derived identity is exactly as
  unrecoverable as its key material, and the identity layer answers nothing
  about which human is behind an agent) and the constraint it locks in (a
  key-derived `agentId` embeds a permanent Ed25519 genesis key and so cannot be
  re-rooted on a post-quantum scheme, where a `did:web` root can). It carries no
  normative text of its own; `specs/ink-identity-model.md` remains the model's
  home and now cites it.
- `README.md` no longer says INK assumes AT Protocol for identity by default. It
  did not, at any point in the project's history, and the sentence was the most
  widely read statement of a model nothing implemented.
- `docs/threat-model.md` is corrected in three places. The identity trust
  boundary is scoped to foreign principals, since a key-derived principal has no
  resolver between its identifier and its root key. The section asserting that
  the Agent Card is unsigned is replaced by one about the exposure that remains
  where the card proof is not enforced, without transcribing a phase state. The
  key-loss section names the offline recovery key and says plainly that a
  key-derived identity has nothing behind it, while a foreign principal may
  recover through its root document.

### Upgrading a conformance runner

One note for anyone running the corpus from outside this repository. Every
`agent-card-fetch` case input now carries a `resolutionDid` member. It is null on
the cases that were already there and on `resolution-did-absent-accepts`, and
non-null on the four DID-mediated owner cases. A runner that ignores it will
accept the two cases the corpus expects to reject, which is the intended signal:
the DID under resolution is now an input to the fetch decision.

The `base` profile gains exactly one category, `signed-body-member-name`. Sixteen
vector files changed in this release, so a runner should re-read the whole corpus
rather than diffing the categories it already knew about. The manifest pins a
SHA-256 per vector file; verify against those rather than against this list.

## 0.16.0, X25519 timing fix, staged Phase C and discovery query context

### Changes

- `@noble/curves` and `@noble/hashes` move from 2.2.0 to 2.3.0. curves 2.3.0
  hardens X25519 constant-time execution and closes a remote timing attack that,
  across many samples, leaked up to roughly 4 bits of a long-term private key.
  The upstream write-up is in the
  [noble-curves 2.3.0 release notes](https://github.com/paulmillr/noble-curves/releases/tag/2.3.0).
  INK uses curves for the X25519 key agreement on the encryption path, which is
  exactly where the fix lands. Ed25519 signing and verification are unaffected:
  they come from the separate `@noble/ed25519` package, which this release does
  not move. No wire, schema or conformance change; the full conformance corpus
  produces identical per-case results before and after the upgrade in both
  implementations.
- Agent Card signature Phase C is built and staged inert. Both implementations
  carry the Phase C receiver rule behind an explicit default-off switch,
  `enforcePhaseC` in the TypeScript reference and `EnforcePhaseC` in the Go
  verifier, specified in
  [`specs/ink-agent-card-signature.md`](specs/ink-agent-card-signature.md) §10.1.
  The switch is a boolean and is never inferred from a version string, so
  upgrading does not change what a receiver accepts. With the switch unset the
  verifiers make the same decisions, with the same reasons, that they made
  before it existed.
- A new `agent-card-signature-phase-c` conformance category pins the Phase C
  decisions: an unsigned card rejected for a key-derived and for a did:web
  principal, a cold did:web verifier failing closed on an unreachable resolver,
  the ratchet still taking precedence, and the flag-off path unchanged. It is
  tagged `profile: "staged"`, a new profile for a rule that is agreed and
  anchored now and becomes required on a scheduled date. A staged category is
  not a conformance obligation and is not part of the frozen base profile; both
  implementations run it in a dedicated flag-on CI job, and a default run skips
  it. The base profile and every frozen base vector file are unchanged.
- **Breaking:** `verifyDiscoveryQueryEnvelope` now enforces the signed context it
  already carried. The envelope signs `to`, `nonce` and `timestamp`, and the
  verifier ignored all three: it checked the schema and the signature and left
  audience binding, freshness and replay to whoever called it. A function named
  `verify` that ignores its own audience binding over-promises, so it now takes a
  third argument, the verification context, and returns a typed result instead of
  a boolean:

  ```ts
  verifyDiscoveryQueryEnvelope(raw, requesterPublicKey, {
    audience,        // this directory's identity, or the list of spellings it answers to
    now,             // verifier clock, a strict INK timestamp
    seenNonces,      // (from, nonce) pairs this directory has already burned
  }); // -> { ok: true, envelope } | { ok: false, reason }
  ```

  The Go verifier moves the same way:
  `VerifyDiscoveryQueryEnvelope(raw, requesterPublicKey, ink.DiscoveryQueryContext{...})`
  returns `(bool, DiscoveryQueryReason)`. Checks run signature first, then
  audience, then the freshness window, then replay, so a rejection never reveals
  whether the audience or the window would have passed. `reason` is one of
  `schema`, `signature`, `audience`, `expired`, `not_yet_valid` or `replay`. The
  freshness window is the INK message window: five minutes past, thirty seconds
  future, both bounds inclusive. Audience comparison is exact, and an empty
  audience set is a verifier input error rather than a wildcard. There is
  deliberately no signature-only escape hatch under the `verify` name; a caller
  that genuinely wants signature-only gets a differently named function, so the
  name never over-promises again.
- The discovery query `signature` field is now schema-bound to its exact shape,
  86 base64url characters, matching the authorization grant. A malformed
  signature rejects as `schema` before any signature work in both
  implementations. Nothing that previously verified stops verifying.
- The `discovery-query-envelope` conformance category grows from 15 to 28 cases:
  audience mismatch, exact (non-case-folded) comparison, a match against one of
  several self-identifiers, an empty audience set, signature-before-audience
  ordering, a stale timestamp, a timestamp past the skew allowance, both window
  bounds at their inclusive edge, a malformed verifier clock, a replayed nonce,
  the same nonce burned for a different requester and a stale replay reporting
  the window. Every reject case now pins its typed reason. The category is in the
  capability-gated `discovery` profile, so the frozen `base` profile and every
  frozen base vector file are untouched.

### Upgrading a conformance runner

Two notes for anyone running the corpus from outside this repository.

- A runner written against the 0.15 manifest that enumerates every category
  without filtering on `profile` will fail the new `agent-card-signature-phase-c`
  cases unless its verifier implements the Phase C flag. Staged categories are
  not a conformance obligation: skip any category whose manifest `profile` is
  `staged`, or run them with the flag on. This repository's own runners skip them
  unless `INK_STAGED_CONFORMANCE=1` is set. See
  [`conformance/v1/README.md`](conformance/v1/README.md).
- A runner that implements the `discovery` profile needs to read the new
  `audience`, `now` and optional `seenNonces` members of each
  `discovery-query-envelope` case input and feed them to its verifier. A runner
  that ignores them will fail the new context cases, which is the intended
  signal: the context is now part of the contract.

## 0.15.0, Agent Card producer signing (Phase B)

### Changes

- The Agent Card signature reaches Phase B: producer signing is now normative.
  The reference receiver signs every card it serves, and a deployed producer signs
  every card it can root under the trust rules of
  [`specs/ink-agent-card-signature.md`](specs/ink-agent-card-signature.md) §4. A
  key-derived producer signs against its genesis key (directly for a never-rotated
  identity, or through a `rotationChain` it can root back to the genesis key); a
  did:web producer signs and anchors the signing key in its DID document. A
  producer never emits a `cardSignature` it cannot root, so an unrootable identity
  stays unsigned rather than serving a proof a verifier would reject.
- `keySetVersion` and `updatedAt` are now emitted on every signed card, as §6
  requires on publish.
- No change to the 1.0 base profile. The `cardSignature` and `rotationChain`
  members and the `agent-card-signature` conformance category are unchanged from
  0.14.0; Phase B is a producer-side obligation, so a receiver validates a card
  exactly as before. Phase B starts the mandatory minimum 90-day window before
  Phase C (§10), under which the 1.0 profile rejects an unsigned key-derived card.
- The multi-hop authorization (delegation) chain ships as a named post-1.0
  extension: a normative spec at
  [`specs/ink-authorization-chain.md`](specs/ink-authorization-chain.md)
  (superseding the archived 2026-05 draft), a reference verifier, Go parity and a
  51-case `authorization-chain` conformance category under a new `delegation`
  capability. Chains are root-first arrays of delegation links built on the grant
  field model with strict attenuation and a hard depth cap of 4. The category is
  additive and optional; the 1.0 base profile and its frozen categories are
  untouched.
- The compatibility policy now states the strict frozen wire accurately: unknown
  fields are tolerated or rejected per surface, the `protocol` value is a closed
  per-surface enum, intent types and receipt dispositions are closed enums and a
  second cryptographic suite arrives through a reserved top-level card member
  with receiver-first negotiation. Adopter-facing examples and the wire-version
  notes were corrected to match, and the section 6 registry now notes that an
  intent envelope carries no `type` member.
- Dev dependency and example dependency updates clear all open npm advisories;
  the audit gate is clean across every project in the repo.

## 0.14.0, self-authenticating Agent Card trust root and Go sender parity

### Additions

- Self-authenticating Agent Card. A card MAY carry a `cardSignature` proof and a
  `rotationChain` so a consumer can establish key authority from the card itself
  rather than resting on TLS and registry honesty alone. A conforming receiver
  verifies the proof if present, rejects a card whose present proof is invalid,
  ratchets forward on a valid proof and roots the rotation chain by principal
  kind. The members are OPTIONAL and backward compatible: an unsigned card from
  an existing deployment still validates, and a consumer unaware of the new
  members ignores them. New `CardSignatureSchema` and a `verifyAgentCardSignature`
  verifier in the TypeScript reference, a matching Go verifier and a shared vector
  set. See
  [`specs/ink-agent-card-signature.md`](specs/ink-agent-card-signature.md).
- The rule is pinned by the new `agent-card-signature` conformance category, a
  `base`-profile category verified by both the TypeScript reference and the Go
  implementation over the same vectors. The corpus covers the `cardSignature`
  proof, the rotation-chain rooting by principal kind, head binding, the
  unsigned-card ratchet and the continuity and rollback rules, including
  head-mismatch and chain-link-signature vectors.
- Go sender parity for INK transport. The Go implementation gains an INK
  transport request signer and encryption sealing, so a Go agent can now emit
  signed requests and seal encrypted payloads, not only verify and open them.
  New interop tests exercise the Go sender against the reference receiver and the
  reference sender against the Go receiver, so the two implementations agree on
  the bytes in both directions of the path.
- An `authorization-header` conformance category that pins the
  `INK-Ed25519 <base64url(sig)> [keyId=<keyId>]` Authorization header grammar. A
  sender emits the header in the exact signature-base grammar and a receiver
  parses it under the same grammar, rejecting stray whitespace, an embedded CR or
  LF and a malformed keyId. It is a `base`-profile category verified by both
  implementations.
- This grows the mandatory base profile from thirteen to fifteen categories,
  adding `agent-card-signature` and `authorization-header`. The base set stays
  frozen by the drift tripwires in both implementations. See
  [`specs/ink-conformance-profile.md`](specs/ink-conformance-profile.md).

### Changes

- The key-rotation spec resolves the stable-agentId question: an agent keeps a
  stable `agentId` across a key rotation, and the rotation chain carries key
  authority forward rather than minting a new identity. See
  [`specs/ink-key-rotation-spec.md`](specs/ink-key-rotation-spec.md).

### Documentation and governance

- A canonical protocol specification,
  [`specs/ink-protocol.md`](specs/ink-protocol.md), that gathers the wire
  contract into one normative document, alongside a reworked self-describing
  conformance corpus and its generator.
- An expanded threat model in [`docs/threat-model.md`](docs/threat-model.md).
- Project governance and a contributor sign-off gate: a `GOVERNANCE.md` and a
  Developer Certificate of Origin requirement recorded in `CONTRIBUTING.md` and
  [`governance/DCO.txt`](governance/DCO.txt), with bot-opened pull requests
  exempt from the check.
- A relying-party reference example for Sign in with INK under
  `examples/reference-rp`.

## 0.13.0, authorization grant primitive and sign-in challenge conformance

### Additions

- Minimal authorization grant, the "Sign in with INK" primitive. An issuer signs
  a scoped grant bound to one subject, one audience and a fixed validity window,
  and a service verifies it against the issuer key and its own context. New
  `AuthorizationGrantSchema`, a `buildAuthorizationGrant` signer and a
  `verifyAuthorizationGrant` verifier that fails closed. The `type` accepts both
  the `network.tulpa.*` and `network.ink.*` spellings; the signature binds every
  field including the audience, so a grant minted for one service cannot be
  presented at another. This is a primitive, not a permissions framework: there
  is no delegation chain or policy language, and a scope entry is an opaque token
  the service interprets. See
  [`specs/ink-authorization-grant.md`](specs/ink-authorization-grant.md).
- The verifier returns a typed rejection reason (`schema`, `signature`,
  `audience`, `subject`, `expired`, `not_yet_valid`, `replay`, `revoked`,
  `owner_unverified`) so a service can map each failure to its own response
  without matching on prose, the same error-design pattern as
  `parseSignedBodyBytes`. The `AuthorizationGrantError` class and the
  `AuthorizationGrantReason` type are exported from the package root, alongside
  the `AuthorizationGrantVerifyContext`, `GrantKey` and `VerifiedOwnerStatus`
  types.
- The validity window is capped at a normative ten-minute maximum lifetime,
  exported as `MAX_GRANT_LIFETIME_MS`. A grant whose window is longer is out of
  profile and rejects as `schema` on the signed bytes alone, before the signature
  and independent of the verifier clock, so the short-window revocation control
  cannot be undercut by a long-lived grant. A verifier caller may tighten the
  ceiling per check through a `maxLifetimeMs` context value, which is clamped so
  it can only shorten and never raise the cap; the tightened check runs after the
  signature so the policy value is not observable on an unauthenticated grant.
- Replay and revocation key on the `(issuer, grantId)` pair, not `grantId` alone.
  Because `grantId` is issuer-chosen, two issuers can pick the same string, so
  keying on the pair keeps one issuer's seen or revoked ids from colliding with
  another's. The verify context takes `seenGrants` and an `isRevoked` predicate
  over the exported `GrantKey` shape.
- Revocation is a receiver-side denylist keyed by `(issuer, grantId)`, checked by
  a caller-supplied predicate at verify time, with short validity windows as the
  primary control. INK grants carry no protocol-level revocation list or
  endpoint, matching how the discovery query envelope leaves replay windows to
  receiver policy. The rationale is recorded in the spec.
- String safety is structural. A grant carrying a lone UTF-16 surrogate rejects
  as `schema` before the signature check, not as a signature failure. A malformed
  base64url signature rejects as `schema` in both implementations, and a verifier
  clock that is not a strict INK timestamp rejects as `schema` rather than
  reporting a window verdict the verifier never computed.
- A scope token's meaning is audience-local. A receiver interprets a token only
  under its own audience policy, and an unrecognized token implies no authority.
  The spec records the portability rule.
- Owner verification is a composition hook, not a computed signal. A grant may
  set `requireVerifiedOwner`, and the verifier then requires the service to pass
  in a verified owner status; the status itself comes from the service's own
  owner-verification pipeline.
- The rule is pinned by the new `authorization-grant` conformance category, a
  capability-gated `authorization` profile and is verified by both the
  TypeScript reference and the Go implementation over the same vectors. Each
  reject vector pins its typed reason so the two implementations agree on verify
  order. The corpus carries positive and negative cases: confused-deputy
  audience, replay and revocation keyed by `(issuer, grantId)`, a cross-issuer
  case where another issuer's entry for the same `grantId` does not interfere,
  expiry and clock-skew bounds, the maximum-lifetime and caller-tightened bounds,
  signature-first ordering under hostile context, a lone surrogate and scope and
  field-length fuzzing.
- Presentation is bound to the subject. The verify context takes an optional
  `presenter`, the authenticated identity of the principal presenting the grant as
  the transport establishes it; when it is supplied and does not equal the signed
  `subject` the grant rejects with the new `subject` reason, so a stolen grant is
  not presentable by another principal inside its window. When no presenter is
  supplied the grant is a bearer artifact the audience binds out of band. Over INK
  the audience verifies the authenticated envelope sender equals the subject, and
  grant bytes are confidential in transit. The check runs after the audience check
  and before the window checks in both implementations, and is pinned by
  presenter-matches, presenter-absent and presenter-mismatch conformance vectors.
- The caller-tightened `maxLifetimeMs` treats zero as unset and fails closed on a
  negative or non-finite value. A value of exactly zero uses the profile default,
  matching the Go context where a zero-value integer is indistinguishable from an
  unset one. A `NaN` would make the tightened-cap comparison silently false and
  disable the policy, so a negative or non-finite value rejects as `schema`, the
  same as a malformed clock. The Go context uses an integer type, so it cannot
  carry a non-finite value and enforces the rule by construction.
- The byte bound on a raw grant body is a shared byte-layer rule. A grant
  presented as raw bytes rejects as `schema` when longer than 65536 bytes, before
  it is decoded, since the largest well-formed grant is around 12 KiB and a body
  padded past the bound is not a legitimate presentation. The Go verifier receives
  bytes and enforces the bound itself through the exported `MaxGrantBodyBytes`; the
  reference verifier receives an already-decoded object and applies the structural
  bounds instead, so the exported `MAX_GRANT_BODY_BYTES` constant is the contract
  for whatever layer received its bytes. A post-parse node, depth and character
  walk mirrors the reference complexity bounds, so both implementations reject the
  same pathological structure.
- The spec pins that a service MUST record an accepted `(issuer, grantId)` pair
  atomically with acceptance, as a single check-and-insert, so two concurrent
  presentations of the same pair cannot both be accepted. Replay recording is
  receiver state the verifier reads but does not own; the `seenGrants` docs carry
  the same rule.
- The sign-in challenge, the one artifact the "Sign in with INK" flow profile
  adds on top of the grant. A relying party signs a challenge to request sign-in,
  the user's agent verifies it against an active RP signing key before minting the
  grant that answers it and the answering identity assertion adopts the `grantId`
  derived from the verified challenge. New `AuthorizationChallengeSchema`, a
  `buildAuthorizationChallenge` signer, a `verifyAuthorizationChallenge` verifier
  that fails closed and a `deriveChallengeGrantId` that binds the answering grant
  to the challenge. The `AuthorizationChallengeError` class and the
  `AuthorizationChallengeReason` type (`schema`, `signature`, `not_yet_valid`,
  `expired`) are exported from the package root alongside the challenge
  verify-context and result types. See
  [`specs/ink-agent-authorization.md`](specs/ink-agent-authorization.md).
- The `rp` is a bare-host `did:web`, and its origin is derived by explicit string
  rules rather than a URL parser so two implementations never disagree on the
  origin that gates redirect acceptance. The `redirectUri` MUST start with that
  derived origin followed by `/` under a literal prefix match and MUST contain no
  fragment, backslash, ASCII control character or ASCII whitespace. The
  `requestedScope` MUST draw from the closed registry (`identity.assert`,
  `profile.read`, `agent.message.send`) with `identity.assert` present. The validity window is capped at the same ten-minute
  ceiling as the grant and exported as `MAX_CHALLENGE_LIFETIME_MS`. A raw
  challenge body longer than `MAX_CHALLENGE_BODY_BYTES` rejects as `schema` before
  it is decoded.
- The rule is pinned by the new `agent-authorization` conformance category under
  the capability-gated `authorization` profile, verified by both the TypeScript
  reference and the Go implementation over the same vectors, with each reject
  vector pinning its typed reason so the two agree on verify order. The corpus
  covers an accepting case, an active-key-only RP signature evaluated at the
  verifier clock, non-bare-host `rp` and non-conforming `redirectUri` cases,
  scope and window bounds and derive-only vectors that pin the exact
  challenge-derived `grantId` for fixed inputs so both implementations compute
  the identical id.

- Optional durable storage for the Go `ink-witness-server`. Passing `-data-dir`
  keeps an append-only record file, one JSON line per accepted leaf holding the
  raw event bytes, and replays it on startup so the log survives a restart. An
  empty `-data-dir` keeps the log in memory, unchanged from before. The record
  for a leaf is fsynced to stable storage before its inclusion receipt is signed,
  so a receipt can never attest to a leaf a crash could lose; replay re-runs the
  submit-path validation and rebuilds the tree byte-identically, so the recovered
  checkpoint has the same root at the same size and prior receipts still verify.
  Recovery is fail-closed: a failed write or fsync is truncated away durably, so
  the only tail replay discards is an unterminated partial line a crash left mid
  write; a complete record with no receipt is a valid leaf replay keeps
  (at-least-once), and any newline-terminated record that fails to decode refuses
  start at any position. The record file's directory entry is fsynced on creation
  so a fresh log survives a crash, and a failed append that cannot roll back
  durably refuses further submissions. The `-max-leaves` bound applies to replay
  too. This is a Go-implementation server feature only, with no wire or protocol
  change.
- Extended the pre-parse byte caps and the post-parse structural walk to the
  remaining Go verifiers. The discovery query verifier now caps the raw envelope
  and runs the shared node, depth and character walk, matching the reference
  isWithinBounds call. The decrypted payload path adds no bound to the
  authenticated plaintext, matching the reference decrypt, which applies no
  structural walk; the plaintext size is already bounded by the step-9 ciphertext
  encoded-length cap and Go's encoding/json nesting limit is the stack backstop.
  The inclusion receipt, checkpoint reference and multi-key timestamp paths carry
  raw-bytes edge guards with headroom derived from the emitter ceiling and the
  wire escape-expansion worst case: a conforming witness signs a receipt core
  through canonicalization, which caps the signed portion at 1,048,576 UTF-16 code
  units of canonical output (mirroring the reference jcsCanonicalize string-length
  check), but that core can escape to about six mebibytes on the wire at six raw
  bytes per code unit, so the receipt cap is eight mebibytes; a well-formed
  checkpoint reference is under
  200 bytes but both parsers tolerate
  unknown members, so the cap is 64 kibibytes; the multi-key timestamp cap is 512
  bytes, above the worst-case fully escaped encoding of the longest well-formed
  RFC 3339 bound. These are Go-implementation changes only, with no wire or
  protocol change.
- Applied the canonical-output caps on the Go verify side, closing an
  accept-side parity gap where a Go verifier accepted signed input the reference
  verifier rejects. The inclusion-receipt signature verifier now caps the
  canonical signed core at 1,048,576 UTF-16 code units after canonicalization and
  before any signature work, mirroring the reference jcsCanonicalize string-length
  check the receipt verify path runs through, so a receipt whose canonical core
  exceeds one mebibyte of code units is rejected rather than verified. The INK
  signature base builder now runs the shared structural walk before
  canonicalizing and caps the canonical output at 1,048,576 both in UTF-16 code
  units and in UTF-8 bytes, mirroring the reference buildSignatureBase, so every
  caller of the signature-base builder, the single and multi-key request-signature
  verifiers, rejects an over-complex or over-cap body before spending signature
  work. Both are reject-only additions: input within bounds verifies unchanged.
  These are Go-implementation changes only, with no wire or protocol change.

## 0.12.0, raw-body UTF-8 conformance rule

### Additions

- Raw-UTF-8 validity of a signed body is now a normative rule pinned by the
  conformance corpus. A receiver MUST reject a signed body whose raw bytes are
  not valid UTF-8, before parsing, because a lenient decode substitutes U+FFFD
  and would verify a signature over bytes the signer never signed. The new
  `parseSignedBodyBytes` helper takes a `Uint8Array`, decodes it with a fatal
  UTF-8 decoder, runs the lone-surrogate scan, then parses, and is the entry
  point a receiver holding raw body bytes uses instead of a lenient string
  decode. The rule is pinned by the new `signed-body-utf8` conformance category
  and verified by both the TypeScript reference and the Go implementation. See
  [`specs/ink-signed-string-safety.md`](specs/ink-signed-string-safety.md).
- `parseSignedBodyBytes` throws `ParseSignedBodyError` with a `reason` of
  `"utf8"` or `"surrogate"` so a receiver can map each byte-gate rejection to
  its own response without matching on the error message. A malformed body
  still surfaces the native `SyntaxError` from `JSON.parse`. The error class and
  its `ParseSignedBodyReason` type are exported from the package root.

## 0.11.0, authenticated discovery query envelope

### Additions

- Authenticated discovery query envelope. A requester signs a bounded query
  (optional `tags`, `scope`, and `limit`) addressed to a directory, and the
  directory verifies it against the requester's key. New
  `DiscoveryQueryEnvelopeSchema` and `DiscoveryQuerySchema`, a
  `buildDiscoveryQueryEnvelope` signer, and a `verifyDiscoveryQueryEnvelope`
  verifier that fails closed. The `type` accepts both the `network.tulpa.*` and
  `network.ink.*` spellings; the signature binds every field. This is a protocol
  primitive only: the directory service, ranking, response, and consent
  semantics are out of scope. See
  [`specs/ink-discovery-query.md`](specs/ink-discovery-query.md). Pinned by the
  new `discovery-query-envelope` conformance category and verified by both the
  TypeScript reference and the Go implementation. The category is a new
  capability-gated `discovery` conformance profile, required only of an
  implementation that answers directory queries.

### Tooling

- The package builds cleanly against `@types/node` 26. Node 26 types `Uint8Array`
  as generic over `ArrayBufferLike`, which the WebCrypto `BufferSource` parameter
  no longer accepts; the AES-GCM envelope encrypt and decrypt paths now normalize
  their inputs to an `ArrayBuffer`-backed view at the WebCrypto boundary. The
  bytes are unchanged, so ciphertext, tags, and signatures are identical.

## 0.10.0, opt-in Agent Card discovery

### Additions

- Opt-in discovery descriptor on the Agent Card. A card MAY carry a `discovery`
  object (`enabled`, `scope`, optional `tags`, `queryable`, and `updatedAt`)
  that consents to being surfaced by a directory or index. It is additive and
  forward compatible: a card without it is not discoverable, and unknown
  descriptor keys are ignored. The descriptor can only narrow exposure, its
  `scope` reuses the card visibility enum and may not exceed the card's
  `visibility`. New `isDiscoverable` and `effectiveDiscoveryScope` helpers and
  the `DiscoveryDescriptorSchema` export. Covered by the `agent-card`
  conformance category in the TypeScript reference and the Go verifier. See
  [`specs/ink-discovery-descriptor.md`](specs/ink-discovery-descriptor.md). The
  authenticated query envelope and the directory service itself are out of
  scope and deferred.

### Tooling

- The static Go verifier now covers every wrappable conformance category on both
  the `ink` CLI and the `ink-verify-server` HTTP service: card, signature,
  receipt, audit-response, handshake, connection, checkpoint, inclusion, and
  consistency. Signed-artifact parsers reject raw invalid UTF-8 before decoding
  so a signature cannot verify over bytes that differ from the wire.

## 0.9.0, vendor-neutral message namespace

This release lets a receiver accept the vendor-neutral `network.ink.*` spelling
of the eligible message types alongside the legacy `network.tulpa.*` spelling.
The transition is receiver-first and backward compatible: senders keep emitting
`network.tulpa.*` by default, so a receiver that has not upgraded never sees the
new prefix. The two audit types whose detached signatures do not cover the
envelope type stay single-spelling, see the notes below. It is published on the
`next` dist-tag.

### Additions

- Receivers dual-accept both `network.tulpa.<suffix>` and `network.ink.<suffix>`
  for every message type they verify. The dual-accept is a pure receiver-side
  leniency and is independent of the signed `protocol` field, which continues to
  govern only the body-signature domain. Senders may opt in to emitting the
  neutral spelling per message (for example the `messageType` option on the
  payload encryption helper); the default emission is unchanged.
- New `network.ink.*` cases in the `handshake-message`, `payload-encryption`
  and `audit-query-response` conformance categories, including the
  relabel-rejection cases, so the TypeScript reference and the Go implementation
  make the same accept and reject decision on both spellings.

### Notes

- Every dual-accepted type binds its actual on-the-wire `type` into the material
  it authenticates, so changing `type` after a message is signed or encrypted
  fails verification. The `audit_response` and `audit_inclusion` types stay
  single-spelling because their detached signatures cover only a payload subset
  and not the envelope type. See the compatibility policy for the full
  transition rules.

## 0.8.0, first-contact transcript, the base conformance profile, and auth hardening

This release pins the end-to-end first-contact exchange as a single conformance
category, declares and freezes the mandatory base profile every conforming
sender and receiver must implement, and hardens the live-auth and payload
encryption paths following a focused review of the key, auth, and encryption
surface. It is published on the `next` dist-tag.

### Additions

- A `first-contact-transcript` conformance category that pins a full stranger
  first-contact flow: discover the Agent Card, select a protocol version, verify
  the signed connection request under the freshness and replay rule, and verify
  the accepted connection response. The TypeScript reference and the Go
  implementation make the same decision and select the same protocol version on
  every vector.
- A conformance profile for each category in `conformance/v1/manifest.json`. The
  `base` profile is the floor every conforming implementation must satisfy;
  `encryption`, `audit`, `witness`, and `containment` are capability gated. The
  per-category sender and receiver obligations are normative in
  [`specs/ink-conformance-profile.md`](specs/ink-conformance-profile.md), and the
  base set is frozen by drift tests in both implementations.
- An optional atomic `addIfAbsent` method on the `NonceStore` interface. When a
  store provides it, inbound verification uses it instead of the separate check
  and record calls, so two concurrent replays of one signed request cannot both
  pass on a distributed store.

### Changes

- Inbound transport verification rejects a retired key by default. A signature
  that only verifies against a retired key is refused for live auth unless the
  caller opts into a rotation grace window. Retired keys remain usable for
  historical-artifact verification through the key-set primitive.

### Breaking

- Encrypted payload envelopes bind the recipient's static encryption key into
  the additional authenticated data, and decryption requires the recipient
  identity. `decryptInkPayload` now takes a required recipient DID and rejects a
  missing or empty value, and a ciphertext is bound to one recipient identity so
  it cannot be accepted by another. Envelopes produced by an earlier release do
  not decrypt under this version. The `payload-encryption` conformance vectors
  are regenerated accordingly.

## 0.7.0, discovery conformance and a packaged vector corpus

This release extends the cross-implementation conformance contract to the
discovery and handshake surface and ships the corpus as a packaged, indexed
artifact. The Agent Card, connection request and response, handshake messages,
and the composite audit-query-response verifier are now pinned by shared vectors
that the TypeScript reference and the Go implementation both run. A
machine-readable manifest indexes every category so a second implementation can
enumerate the corpus and detect drift from a single file, and the corpus ships
in the npm tarball. Agent Card endpoint fields move to a pinned, parser-
independent URL grammar. It is published on the `next` dist-tag.

### Additions

- Conformance vector categories for the Agent Card, the connection request and
  response payloads, the challenge, rejection, and resolution handshake
  messages, and the composite audit-query-response verifier. Both
  implementations make the same accept or reject decision on every vector.
- `conformance/v1/manifest.json`, a machine-readable index of the corpus with
  each category's vector file, spec, summary, case count, and the SHA-256 of the
  vector bytes. The `conformance/` tree ships in the package and is resolvable as
  a subpath export.
- `isInkEndpointUrl(value)` exposes the Agent Card endpoint URL grammar so a
  caller can validate an endpoint with the same rule the schema applies.

### Potentially breaking validation tightenings

These reject inputs that `0.6.0` accepted. A well-formed Agent Card that already
advertised a plain `https` inbox endpoint is unaffected.

- Agent Card `endpoint`, `inboxEndpoint`, and `thirdPartyAudit` endpoint fields
  are validated against a narrow, deterministic URL grammar instead of a broad
  URL check. An endpoint must be an `https` URL with a host and no userinfo or
  fragment, at most 2048 bytes, free of control characters and whitespace, with
  well-formed percent escapes and a port in range when present. Endpoints using
  another scheme, a fragment, embedded credentials, or a malformed escape are
  now rejected. The grammar is validated by explicit string rules in both
  implementations rather than a runtime URL parser, so the decision is identical
  across them.

## 0.6.0, cross-implementation conformance contract

This release turns INK's wire behavior into a contract held by two independent
implementations rather than described by one. A new Go implementation runs a
shared conformance vector corpus alongside the TypeScript reference, so an
accept or reject decision is pinned by agreement between implementations reached
from different code. The release also tightens timestamp, key-window, string,
and number validation, and exports several verifier primitives. It is published
on the `next` dist-tag; the API is additive, with the validation tightenings
noted below.

### Additions

- A second, independent implementation in Go and a shared conformance vector
  corpus covering principal normalization, the signature base, JCS numbers and
  strings, key rotation, replay and freshness, the timestamp grammar, and the
  Merkle inclusion, consistency, checkpoint, and audit-leaf-hash rules. Both
  implementations make the same decision on every vector, so the spec is not
  accidentally shaped by one language.
- `parseInkTimestampMs`, `isInkTimestamp`, and `MAX_TIMESTAMP_LENGTH` for the
  strict RFC 3339 timestamp grammar.
- `containsLoneSurrogateEscape` and `hasUnpairedSurrogate` for detecting a lone
  UTF-16 surrogate in a signed string before it is parsed.
- `verifyInclusionProof(leafHash, proof, leafIndex, treeSize, rootHash)` as a
  low-level RFC 6962 inclusion-proof primitive. It attests only that a leaf
  walks to a root; use `verifyInclusionReceipt` for full receipt verification.
- Protocol specs for the timestamp grammar, key-rotation presence, signed-string
  safety, the JCS number profile, and the Merkle inclusion, consistency,
  checkpoint, and leaf-hash rules.

### Potentially breaking validation tightenings

These reject inputs that `0.5.0` accepted. Legitimate signer and receiver
traffic is unaffected; the rejected inputs are malformed or outside the
documented profile.

- A timestamp must be a strict RFC 3339 date-time at millisecond precision, with
  a `T` separator and a `Z` or numeric offset. Date-only, zoneless,
  space-separated, and other lenient forms are rejected.
- A present `validFrom`, `validUntil`, or `revokedAt` on a key now constrains
  that key even when empty, null, or non-string, rather than being ignored; a
  present but unparseable `revokedAt` fails closed and treats the key as revoked.
- A signed body that carries a `\uXXXX` escape for an unpaired UTF-16 surrogate
  is rejected at sign and verify, because a parser that rewrote it to U+FFFD
  would commit different bytes.
- A signed body number must be a safe integer (absolute value at most `2^53-1`,
  not negative zero); a fraction, an out-of-range magnitude, and a non-finite
  value are rejected so the canonical bytes are identical across implementations.

## 0.5.0, transparency-log consistency proofs

This release adds RFC 6962 consistency-proof verification, so a verifier can
confirm a transparency log only ever appended to its tree between two
checkpoints rather than forking its history. The size comparison alone cannot
detect a split view. It is published on the `next` dist-tag; this release is
additive, with no breaking changes.

### Additions

- `verifyConsistencyProof(first, firstRoot, second, secondRoot, proof)` verifies
  an RFC 6962 Section 2.1.2 consistency proof: that the tree of `first` leaves is
  an append-only prefix of the tree of `second` leaves. It returns false (never
  throws) for any malformed input or any proof that does not reconstruct both
  roots with every node consumed.
- The `verify-inclusion` CLI uses it: when `--origin` enables the checkpoint
  cross-check and the signature-verified checkpoint is newer than the receipt's
  tree, the CLI fetches a consistency proof and verifies the receipt's tree is an
  append-only prefix of the checkpoint. A witness that serves no proof has the
  step reported as skipped, not passed.

The reference witness serves these proofs at `GET /ink/v1/consistency?first=N&second=M`.

## 0.4.0, stricter verification, message-size bounds, checkpoint and receipt verification

This release tightens signature verification and input validation and adds
several verification helpers. It is published on the `next` dist-tag.

### Potentially breaking validation tightenings

These reject inputs that `0.3.0` accepted. Legitimate signer and receiver
traffic is unaffected; the rejected inputs are malformed, malicious, or outside
the documented profile.

- Ed25519 signatures are now verified in strict RFC 8032 mode at every
  verification site. Small-order public keys and non-canonical point encodings
  are rejected.
- Signed JSON numbers are constrained to the forms every canonicalizer
  serializes identically: non-finite values, negative zero, and values whose
  shortest form uses exponential notation are rejected at signing and
  verification.
- The agent card, audit, handshake, and discovery schemas now enforce maximum
  field lengths and array sizes.
- The `Authorization: INK-Ed25519` header is matched against single literal
  spaces; a tab, carriage return, or line feed in the separator is rejected.

### Additions

- `verifyCheckpoint(signed, witnessPublicKey, expectedOrigin)` verifies a signed
  C2SP checkpoint: the witness Ed25519 signature over the checkpoint body and the
  log origin. A checkpoint used for the inclusion-receipt cross-check must be
  verified this way first.
- `verifyReceipt({ receipt, senderPublicKey, expected })` binds a delivery
  receipt to the exact message it acknowledges: issuer key, `from`/`to`/
  `messageId`, the recomputed message hash, and an optional `disposition`.
- `verifyInclusionReceipt` accepts an `event` option that recomputes the leaf
  hash and binds it to `receipt.eventId`. The legacy `eventHash` is retained but
  does not provide that binding.
- `verifyInkAuth` returns a prefix-independent `principal` alongside the raw
  sender id; per-sender security state (blocks, rate limits) should key on
  `principal`. `canonicalAgentPrincipal(agentId)` is exported for the same use.

Per the pre-1.0 policy this release publishes under the `next` dist-tag; `latest`
is unchanged.

## 0.3.0, accept the ink: agentId alias for key extraction

`extractPublicKeyFromAgentId` now accepts either the canonical `tulpa:` prefix or the `ink:` alias introduced in ink/0.4. Both carry the identical multibase Ed25519 key, so the bootstrap verification key is byte-identical and a signature made with that key verifies regardless of which accepted prefix carried it. The prefix is identity syntax, not signing authority.

Emission is unchanged: `deriveAgentId` still returns `tulpa:` (accept both, emit one). The new `AGENT_ID_KEY_PREFIXES` export is frozen so a consumer cannot widen the accepted set at runtime. The change is additive and backward compatible. Existing `tulpa:` inputs behave exactly as before, and every previously rejected prefix other than `ink:` is still rejected. The wire protocol version is unchanged.

A receiver that keys per-sender security state (blocks, rate limits, duplicate-payload checks, cached verification keys, connection identity) MUST collapse the two spellings to one prefix-independent principal so a sender cannot switch prefix to dodge a block or split a rate-limit window. See [Identity](https://ink.tulpa.network/spec/identity/).

Per the pre-1.0 policy this release publishes under the `next` dist-tag.

## 0.2.0, version-keyed body-signature domain

Version-keyed body-signature domain. The body message signature is now domain-separated by protocol version. ink/0.1 messages, and any object with no explicit ink/0.2 protocol, keep the legacy `tulpa/sign` domain so every signature produced to date still verifies. ink/0.2 messages are signed and verified under the neutral `ink/sign` domain. The verifier selects exactly one domain from the signed `protocol` field and never tries an alternate, so a signature made under one version's domain cannot be replayed under another.

This change is receiver-first and backward compatible. Verifiers accept both versions and `MessageEnvelopeSchema` now accepts ink/0.1 and ink/0.2 as a strict enum, rejecting any unknown version. Senders still emit ink/0.1 by default. The HTTP transport-auth signature is unchanged.

New vectors in `test-vectors/body-signature.json` pin the version-keyed domain including the cross-version and tamper cases. The standalone Python interop client verifies them identically.

Per the pre-1.0 policy this release publishes under the `next` dist-tag.

## 0.1.7, expose per-intent payload schemas and getPayloadSchema from the package root

Pure additive release. Re-exports every per-intent Zod payload schema (`ScheduleMeetingPayloadSchema`, `IntroRequestPayloadSchema`, `OpportunityPayloadSchema`, `ConnectionRequestPayloadSchema`, `FollowUpPayloadSchema`, `AskPayloadSchema`, `PingPayloadSchema`, `RetractPayloadSchema`, `ContextSharePayloadSchema`, `MultiPartySyncPayloadSchema`, plus the matching `*ResponsePayloadSchema` variants) and the `getPayloadSchema(intent)` resolver from the package root. Adopters writing intent-aware receivers / handlers can now type their dispatch surface directly against the canonical payload shapes.

No wire-level changes. No behavior changes inside the existing functions. Receivers on 0.1.6 work unchanged on 0.1.7.

Per the pre-1.0 policy this release publishes under the `next` dist-tag.

## 0.1.6, expose intent + key-entry types and add optional inclusionProof to InkAuditInclusionSchema

Pure additive release. Two surface expansions and one backward-compatible schema addition:

- **Intent surface** — re-exports `IntentTypeSchema` constant and `IntentType` type from the package root. Adopters writing payload-aware receivers can now type their intent dispatch off the canonical Zod enum without reaching into a deep path.
- **Key-entry surface** — re-exports `KeyStatusSchema`, `KeyRoleSchema`, `KeyEntrySchema` constants and `KeyStatus`, `KeyRole`, `KeyEntry`, `StoredKey` types. Adopters wiring their own key-set storage and rotation can now type the persistence shapes without reaching into a deep path. `CandidateKey` was already root-exported.
- **InkAuditInclusionSchema** — adds an optional `inclusionProof: z.array(z.string()).optional()` field. Third-party auditor clients that verify Merkle inclusion proofs use this field; receivers that only check signatures can ignore it. Backward-compatible because the field is optional — receivers on 0.1.5 work unchanged on 0.1.6.

No wire-level changes. No behavior changes inside the existing functions.

Per the pre-1.0 policy this release publishes under the `next` dist-tag.

## 0.1.5, expose handshake type re-exports and InkTransportSchema from the package root

Pure additive release. Re-exports the `InkChallenge`, `InkRejection`, `InkResolution`, `InkTransport` types and the `InkTransportSchema` constant from the package root. Adopters writing handshake-aware receivers can now type their state-machine without reaching into a deep path. No wire-level changes. No behavior changes inside the existing functions. Receivers on 0.1.4 work unchanged on 0.1.5.

Per the pre-1.0 policy this release publishes under the `next` dist-tag.

## 0.1.4, expose receipts, transport-auth, discovery-gating, audit schemas and handshake schemas from the package root

Pure additive release. The implementation files have shipped in earlier releases under deep paths; this release brings them to the package root so adopters writing receivers, builders, or auditor clients can import everything they need from `@adastracomputing/ink` directly.

New root-level exports:

- **Receipts** (`./ink/receipts`): `buildReceipt`, `shouldSendReceipt`, `sendReceiptFireAndForget`. The canonical INK delivery-receipt builders, signing helpers and fire-and-forget transport. A receiver that wants to ack inbound envelopes per Auditability §6 can drop these in without rolling its own.
- **Transport-auth** (`./ink/transport-auth`): `resolveEffectiveTransports`, `checkTransportAllowed`. The token-level transport allowlist enforcement, including the "field absent vs empty array" semantics. Required for any extension token issuer.
- **Discovery-gating** (`./ink/discovery-gating`): `buildRedactedCard`, `shouldRedactOnGet`, `AgentCardQuerySchema`. Visibility-aware Agent Card responses (`public`, `network_only`, `capability_gated`, `private`).
- **Checkpoint parsing** (`./ink/checkpoint`): `parseCheckpoint`, `formatCheckpoint`, `CheckpointData`. For consumers of transparency-log signed checkpoints.
- **Audit event schemas + types** (`./models/ink-audit`): `InkAuditEventTypeSchema`, `InkAuditEventSchema`, `InkAuditInclusionSchema`, `InkReceiptSchema`, `InkAuditQuerySchema`, `InkIntroductionReceiptSchema`, plus matching types `InkAuditEventType`, `InkAuditEvent`, `InkAuditInclusion`, `InkReceipt`, `InkAuditQuery`, `InkAuditResponse`, `InkIntroductionReceiptStatus`.
- **Handshake message schemas** (`./models/ink-handshake`): `InkChallengeSchema`, `InkRejectionSchema`, `InkResolutionSchema`, type `AgentCardVisibility`.
- **Agent Card schema** (`./models/agent-card`): `AgentCardSchema` (the type was already exported).
- **Encryption key encoder** (`./crypto/keys`): `encodeEncryptionKeyMultibase` (the encoder companion to the already-exported `decodeEncryptionKeyMultibase` from 0.1.3).

No wire-level changes. No behavior changes inside the existing functions. Receivers on 0.1.3 work unchanged on 0.1.4.

Per the pre-1.0 policy this release publishes under the `next` dist-tag.

## 0.1.3, expose validateMessage and decodeEncryptionKeyMultibase from the package root

Pure additive release that re-exports two helpers from the package root so adopters no longer have to import them through a deep internal path:

- `validateMessage(raw)` runs the canonical `MessageEnvelopeSchema` parse plus the intent-specific payload schema. Receivers building from scratch were either re-implementing the schema check or pulling from `@adastracomputing/ink/dist/models/intent.js`, which is not a stable surface. The implementer-guide at https://ink.tulpa.network/guides/implementing-a-receiver/ documented this helper as if it were already exported; this release makes that documentation accurate.
- `decodeEncryptionKeyMultibase(multibase)` is the companion to the already-exported `decodePublicKeyMultibase`. The former handles X25519 keys (the Agent Card encryption-key prefix); the latter handles Ed25519. The encrypted-intents guide tells adopters to decode an Agent Card's `publicKeyMultibase` for use with `encryptInkPayload`, which expects hex; without the X25519 decoder exported, adopters had to inline the multicodec strip themselves.

Also re-exports the `MessageEnvelope` type and the `MessageEnvelopeSchema` constant so adopters can type their parser surface against the canonical schema. No wire-level changes. No behavior changes inside the existing functions. Receivers on 0.1.2 work unchanged on 0.1.3.

This release publishes under the npm `next` dist-tag per the pre-1.0 policy.

## 0.1.2, Python interop CLI emits canonical envelope

> **Maturity note.** v0.1.x is wire-compatible across patches (`ink/0.1` stays frozen) but the API surface and trust semantics remain alpha-quality. See [`docs/maturity.md`](docs/maturity.md). Starting with this release, pre-1.0 versions publish under npm's `next` dist-tag; `latest` only advances when a release is explicitly promoted. Adopters who want the current pre-1.0 line install with `npm install @adastracomputing/ink@next`; the bare `npm install @adastracomputing/ink` will resolve to the most recent release a maintainer has stamped adopter-grade.

Fixes the v0.1.1 erratum: the Python `examples/interop-cli/` shipped in v0.1.1 emitted a phantom envelope shape (`type`, `intentType`, `purpose`, `urgency` at top level, no `id`, no `correlationId`, no `createdAt`, no body-level `signature`) that no conforming receiver could accept. v0.1.2 rewrites the CLI's envelope builder to emit the canonical `MessageEnvelopeSchema` shape:

- `id` and `correlationId` are now generated as 26-char Crockford-base32 ULIDs.
- `createdAt` is the canonical envelope creation timestamp (ISO-8601 UTC); the body also carries a separate `timestamp` field that `verifyInkAuth()` uses for HTTP §3.3 freshness, distinct from `createdAt`.
- `intent` is the canonical enum value (`intro_request` for introductions); the legacy `intentType`/`purpose` flatten into `payload: { target, reason, urgency }` per `IntroRequestPayloadSchema`.
- Body-level `signature` is now produced by the canonical domain-separated signer (`Ed25519("tulpa/sign\n" + JCS(envelope-without-signature))`, base64url, no padding) — matches `src/crypto/sign.ts` byte-for-byte.
- `provenance` is omitted when absent (the field is `.optional()`; an explicit `null` would be rejected by Zod).
- HTTP §3.3 fields (`timestamp`, `nonce`) ride alongside the canonical fields so `verifyInkAuth()` still reads them.

**CLI now builds `connection_request` envelopes.** `ink-interop send/build --intent-type connection_request` (or the alias `connection`) constructs a `ConnectionRequestPayloadSchema`-conformant payload (`method`, `context`, `profileSnapshot`). This is the bootstrap intent for first contact between strangers: receivers that opt in to foreign senders verify the body signature against the inline key extracted from the sender's `did:key` (trust-on-first-use). Other intent types (`intro_request`, `ask`, `follow_up`) presume the sender is already a known contact and remain reserved for established relationships.

Verified end-to-end against `https://api.tulpa.network/ink/v1/<agentId>/intent`: a `did:key:` `connection_request` from `ink-interop send` lands as a pending action in the recipient's inbox (`status: 200`, `accepted: true`, `pendingActionId: 01KT…`). Coverage spans schema validation, body + transport signature verification, replay/freshness, identity resolution, routing, and the foreign-DID policy gate. Tests pinned to the canonical shape (`tests/test_envelope.py`) prevent regression. The npm library itself is unchanged from v0.1.1.

**Example-helper API break.** `examples/interop-cli/`'s Python helper `build_intent_envelope()` now requires `keypair`, replaces `intent_type`/`purpose`/`timestamp` with canonical args (`target`, `reason`, `created_at`, etc.), and removes the `extra=` kwarg. Adopters who imported the old helper directly will need to update their calls — the previous signature emitted invalid wire data so no callable interop existed there to preserve. This is an example-only change; the npm library (`@adastracomputing/ink`) exports are unchanged.

## 0.1.1, discovery rename and normative SSRF floor

> **Erratum, 2026-06-01:** the bundled Python interop CLI at
> `examples/interop-cli/` shipped with this tag emits an envelope
> shape that does not match the canonical `MessageEnvelopeSchema`
> (`id`, `correlationId`, `createdAt`, `intent` enum, payload,
> body-level `signature`). The npm library is unaffected. End-to-end
> sends from the Python CLI to a conforming receiver fail with
> `invalid_envelope`. Fixed in v0.1.2.

This release is **wire-compatible with v0.1.0**; the wire version stays `ink/0.1`. Every change below is additive and accepts the prior shape for the duration of the v0.1.x line — implementations that emit and consume v0.1.0 cards / service entries continue to interoperate. One observable library behavior changes: the runtime emit value of the redacted Agent Card `type` field flips from `"tulpa.agent.card"` to `"ink.agent.card"` (see below). Consumers that pinned to the literal must accept either string; the TypeScript union has been widened accordingly.

**Service entry rename.** The DID Document service entry for INK endpoints is now `type: "INKAgentEndpoint"`. The legacy `"TulpaAgentEndpoint"` is still accepted by consumers during v0.1.x; new publishers SHOULD emit `INKAgentEndpoint`. When both are present, `INKAgentEndpoint` takes precedence. Removed at the next wire-version bump.

**Service entry now points at the Agent Card URL.** `serviceEndpoint` is the URL of the Agent Card, not the inbound message endpoint. Inbound URL stays on the Card itself in the `endpoint` field. Per the spec update, `inboxEndpoint` is also accepted as a synonym for `endpoint`.

**Normative SSRF floor for discovery fetches.** The Discovery spec now mandates HTTPS-only, refusal of private/link-local/loopback/cloud-metadata hosts, bounded redirects with host re-checking on each hop, response size and time caps, and honoring `Cache-Control`. Detailed hardening stays implementer responsibility but the normative floor lives in the spec.

**Normative DID-binding of fetched cards.** Consumers MUST bind the card's `ownerDid` (when present) to the DID under resolution, and bind the card's `agentId` to the agent identifier being sent to. A mismatch on either field is a hard reject. This closes the substitution attack where a host that legitimately publishes one DID claims to publish another.

**Cache and refresh rules lifted into normative Discovery.** Refresh on signature/keyId miss, on observed `keySetVersion` increase, never fall back to bootstrap keys after a valid card has been observed.

**Redacted Agent Card type renamed.** The `type` field on a redacted Agent Card is now `"ink.agent.card"`. Consumers MUST also accept the legacy `"tulpa.agent.card"` during v0.1.x. The `network.tulpa.*` wire-message types are explicitly **frozen** for v0.x per the compatibility policy; rewriting them would break every deployed router.

**Wire version is `ink/0.1`.** All v0.1.x package releases emit `protocol: "ink/0.1"` on the wire. The next wire-version bump is `ink/0.2`.

## 0.1.0-alpha.5, ship compiled JS

Fixes a publish-time regression in `0.1.0-alpha.3` (and the unreleased
`alpha.4`) where the package shipped raw TypeScript under `main` and
`exports`. Node 24 refuses to strip types from anything under
`node_modules`, so any consumer following the quickstart hit
`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING` on the first `import`
and could not use the library at all.

### Changed

- `npm run build` compiles `src/` to `dist/` via `tsconfig.build.json`;
  `prepublishOnly` runs it automatically so the npm tarball always
  contains compiled JS plus declaration maps.
- `main`, `types` and `exports."."` now point at `./dist/index.js` and
  `./dist/index.d.ts`. The `files` array ships `dist/` instead of
  `src/`, so consumers no longer see raw TS in `node_modules`.
- Dev shell and `engines.node` move from Node 22 to Node 24 (the
  current Active LTS) to match CI.

End-to-end verified against `witness-demo.tulpa.network`: the
quickstart `submit.mjs` now returns a signed inclusion receipt on
Node 24 without modification.

## 0.1.0-alpha.3, signed audit-query response

Closes the last HIGH conformance-audit finding (witness audit-query
response missing signature, proofs and protocol envelope).

### Added

- `signAuditQueryResponse(payload, privateKey)` and `verifyAuditQueryResponseSignature(payload, signature, publicKey)` primitives. Canonical signed bytes are `ink/audit-query-response/v1\n` + JCS(payload without serviceSignature). The payload binds `serviceDid`, `messageId`, `requester`, `events`, `proofs`, `treeSize`, `rootHash`, `timestamp`, so a valid signature cannot be rebound to a different witness, message, requester, or root.
- `verifyAuditQueryResponse({response, witnessPublicKey, expectedRequester, expectedMessageId, verifyEventSignature, expectedServiceDid?, laterCheckpoint?})` is the recommended high-level verifier. `verifyEventSignature` is a REQUIRED callback that resolves the submitting agent's keys and validates each event's `agentSignature`. Without it, the verifier refuses to return valid, because Merkle inclusion alone does not prove agent provenance (§7.5). The function enforces envelope shape, requester binding, events/proofs strict one-to-one alignment, the §7.4 per-event scope rule, walks every Merkle proof via `computeAuditMerkleLeafHash` up to the response's `rootHash`, runs `verifyEventSignature` on every event and supports optional later-checkpoint cross-check. `verifyAuditQueryResponseSignature` alone is signature-only and is documented as a low-level primitive.
- `computeAuditMerkleLeafHash(event)` primitive: the RFC 6962 leaf-hash rule for inclusion proofs, `SHA-256(0x00 || JCS(event-without-agentSignature))`. Distinct from `computeEventHash` (unprefixed, used only for `previousEventHash` chain linkage). Verifiers walking an inclusion proof MUST use this function, not `computeEventHash`.
- Nix flake now exposes `apps.default`, so `nix run github:Ad-Astra-Computing/ink -- verify-inclusion --file r.json --witness URL` works without `npm install`.

### Security

- The §7.3 envelope now binds `requester`. Without this binding, a signed witness response generated for Alice could be replayed to Bob as Bob's authoritative view of the same `messageId`. Verifiers MUST check the response's `requester` equals their locally authenticated requester before accepting events as a complete view.
- Witnesses MUST fail closed when the requester's visible event set for a `messageId` exceeds the response cap, returning an unsigned HTTP 413 rather than silently signing a partial response. The reference and OSS witnesses query `LIMIT MAX_QUERY_EVENTS + 1`, detect overflow and refuse to sign.
- Witnesses MUST emit a deterministic, stable result-set order so signed bytes are reproducible. The reference and OSS witnesses use `ORDER BY event_id ASC`.
- Storage-integrity failures during proof construction (missing event_hash, hash mismatch, missing Merkle node, unprovable leaf, malformed event_json) now return HTTP 500 instead of silently omitting events from a signed response.
- All canonicalize-and-sign / canonicalize-and-verify paths now cap by UTF-8 byte length, not JS string length. With non-ASCII event data the prior cap could be undercounted and let oversized payloads through. Affects `buildSignatureBase`, `computeMessageHash`, `signAuditEvent` / `verifyAuditEventSignature`, `computeEventHash`, `signAuditResponse` / `verifyAuditResponseSignature`, `signAuditQueryResponse` / `verifyAuditQueryResponseSignature` and the witness `handleQuery` response-size guard.
- `verifyAuditEventSignature`, `verifyAuditResponseSignature`, `verifyAuditQueryResponseSignature` now wrap canonicalization inside the try/catch, so payloads that pass the complexity precheck but throw inside `jcsCanonicalize` (e.g. objects with `undefined` values) return `false` instead of propagating.

### Spec

- `specs/ink-auditability.md` §7.3 (audit-query response) now defines the full signed-envelope shape: `{protocol, type: "network.tulpa.audit_query_response", serviceDid, messageId, requester, events, proofs[{eventId, leafIndex, inclusionProof}], treeSize, rootHash, timestamp, serviceSignature}`. Previous text described a bare `{events}` shape with no signature, no protocol envelope and no per-event proofs.
- §7.3 leaf-hash text now references `computeAuditMerkleLeafHash` directly and warns implementers that `computeEventHash` (chain linkage) is NOT the leaf input.
- §7.3 now explicitly forbids witnesses from signing partial results: truncation MUST be an unsigned error. A signed response is a complete enumeration of the requester's visible events at `(treeSize, rootHash)`.
- §7.3 requires witnesses to emit `events` and `proofs` in a stable, deterministic order.

## 0.1.0-alpha.2, inclusion-receipt verifier

Adds a public verification path for INK Auditability Section 7
inclusion receipts, plus a CLI any third party can run without
trusting any specific operator's UI.

### Added

- `verifyInclusionReceipt({receipt, witnessPublicKey, eventHash?, laterCheckpoint?})` exported from the package root. Pure function. Returns `{valid, steps[]}` where each step explains pass/fail with detail. Always verifies structure + Ed25519 service signature against the canonical `ink/audit-inclusion/v1\n` + JCS format. Optionally walks the Merkle proof when `eventHash` is provided, and cross-checks against a `laterCheckpoint` for tree-grew-not-rewound + no-fork-at-same-treeSize.
- `ink` CLI dispatcher with a `verify-inclusion` subcommand. `npx @adastracomputing/ink verify-inclusion --file receipt.json --witness https://witness.example.com` fetches the witness DID document + current checkpoint and runs the full verification. Witness URL is validated (https-only by default, `--allow-http` opt-in, no credentials). Exit code 0 = valid, 1 = invalid, 2 = usage / network / validation error. Self-contained ESM JavaScript so it works on any Node 22+ install with no TypeScript toolchain.

## 0.1.0-alpha.1, spec clarification

Spec-only release. Library code in `src/` is
unchanged from `0.1.0-alpha.0`; the bundled spec text is updated.

### Spec changes

- `specs/ink-auditability.md` now pins the canonical
  inclusion-receipt signature format: `ink/audit-inclusion/v1\n` +
  JCS(`{eventId, leafIndex, treeSize, rootHash, timestamp}`).
  Previously the spec described the signature as "over (eventId +
  treeSize + rootHash + timestamp)" without specifying a separator
  or encoding, which caused interop drift between implementations.
  No code change in this package; downstream witness and verifier
  implementations should align with the canonical format.

## 0.1.0-alpha.0, first public alpha

Initial open-source release of the INK protocol library and specification.

### Protocol surface

- Ed25519-signed envelopes with JCS (RFC 8785) canonicalization.
- Domain-separated signing base: `ink/0.1\nMETHOD\nPATH\nrecipientDid\nJCS(body)\ntimestamp`.
- Agent Card schema with `keys.signing` and `keys.encryption`.
- Key rotation authority rule (see `docs/key-rotation-rule.md`).
- Timestamp freshness window: 5 minutes past, 30 seconds future.
- ECIES encryption envelopes with AAD bound to all security-relevant
  outer fields.
- Receipt and audit envelope structures.
- Optional containment extension: capability-gated visibility, handshake
  budgets, sender silent-drop after first rate-limit violation.

### Library

- Public API exported from the package root, see README for the export
  surface.
- Defense-in-depth SSRF protections in `fetchAgentCard`: https-only
  baseUrl, no userinfo, IANA special-use IPv4 and IPv6 blocklists,
  6to4-embedded-v4 extraction, manual redirect, body-size stream cap,
  Zod runtime card validation, recursive endpoint validation,
  integrator-supplied fetch hook for connect-time defenses.
- Length and format caps on every base64url/hex decode call site.
- Strict signature length and charset validation before any
  cryptographic operation.
- Authoritative empty-key-set semantics, once an Agent Card publishes
  a signing key set, callers must not fall back to bootstrap keys.
- `verifyInkAuth` requires an explicit `nonceStore: NonceStore | "deferred"`
  option: pass a `NonceStore` to have the middleware enforce single-use
  semantics on `body.nonce` within the freshness window, or `"deferred"`
  to acknowledge that `checkReplay` (or equivalent) will run elsewhere
  in the request pipeline. Omitting the option returns
  `nonce_handling_required`, so a misconfigured deployment fails
  loudly rather than silently accepting replays.
- `verifyAuditEventChain(events)` validates internal continuity of an
  audit response slice: strictly +1 sequence, `previousEventHash`
  linkage, duplicate-sequence fork detection. Consumers of
  audit-exchange responses MUST run this alongside
  `verifyAuditResponseSignature`.
- `checkReplay` standalone helper with explicit nonce + timestamp
  freshness; nonce backing storage is the integrator's choice.

### Test surface

- 430 unit and integration tests across crypto, middleware, discovery,
  containment, and security-regression suites.
- Interop test vectors in `test-vectors/` covering signing base, key
  rotation, replay, and Agent Card shapes.
