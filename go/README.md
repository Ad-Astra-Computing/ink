# INK Go implementation

An independent Go implementation of INK's security-relevant decisions, built to
run the shared conformance vectors in [`../conformance/v1`](../conformance/v1).
It is deliberately not a port of the TypeScript reference: agreement on the same
vectors, reached from different code, is what proves the wire spec is not
accidentally TypeScript-shaped.

## What it covers

The `ink` package implements, and the conformance runner verifies against the
shared vectors:

- **Principal normalization** (`principal.go`, `multibase.go`) — base58btc
  multibase encode/decode and the canonical agent-principal rules, with string
  lengths measured in UTF-16 code units to match the reference contract.
- **Signature base** (`jcs.go`, `signature.go`) — RFC 8785 JCS canonicalization
  (object members sorted by UTF-16 code unit, minimal string escaping), the INK
  signature-base construction, and RFC 8032 strict Ed25519 verification.
- **Replay and freshness** (`replay.go`) — the timestamp freshness window and
  nonce de-duplication.
- **Key rotation** (`multikey.go`) — the multi-key authority rule (hint, then
  active, then retired; revoked and out-of-window keys skipped).
- **Merkle inclusion** (`merkle.go`) — the RFC 6962 inclusion-proof walk that a
  witness receipt's `(leafIndex, treeSize, rootHash)` is checked against.
- **Merkle consistency** (`consistency.go`) — the RFC 6962 consistency-proof walk
  that confirms a later checkpoint is an append-only extension of an earlier one.
- **Checkpoint grammar** (`checkpoint.go`) — the C2SP tlog-checkpoint body parser
  that turns a witness checkpoint into `(origin, treeSize, rootHash)`.
- **Audit leaf hash** (`auditleaf.go`) — the RFC 6962 leaf hash a witness commits
  for one audit event, `SHA-256(0x00 || JCS(event-without-agentSignature))`.
- **Inclusion receipt** (`receipt.go`) — end-to-end verification of a witness
  inclusion receipt: structure, the witness Ed25519 service signature, an
  optional event-bound proof walk, and an optional later-checkpoint cross-check.
- **Audit-query response** (`auditquery.go`, `auditevent.go`) — end-to-end
  verification of a witness audit-query response: structure, bindings, the
  witness envelope signature, per-event scope, events-to-proofs mapping, the
  Merkle proof walks, and the required per-event agent signature.
- **Handshake messages** (`handshake.go`) — schema validation for the challenge,
  rejection, and resolution handshake messages: literals, enums, UTF-16 caps,
  array bounds, and the handshake timestamp grammar.
- **Connection payloads** (`connection.go`) — strict schema validation for the
  connection_request and connection_response payloads and their embedded profile
  snapshot and availability config, rejecting unknown keys at every level.
- **Agent Card** (`agentcard.go`) — schema validation for the
  `.well-known/ink/agent.json` discovery document: the pinned endpoint URL
  grammar, nested capabilities/keys/governance, enums, and the
  inboxEndpoint-equals-endpoint invariant.

Signed-body numbers follow INK's safe-integer profile in both implementations: a
number must be an integer in `|v| <= 2^53-1` and not negative zero, and is
canonicalized as a plain base-10 integer that equals ECMAScript `String(v)`
byte-for-byte. A fraction, an out-of-range magnitude, a negative zero, or a
non-finite value fails closed rather than producing a possibly divergent
exponential serialization. The `jcs-number` vectors pin the accept set and the
exact canonical bytes. See
[`../specs/ink-jcs-number-profile.md`](../specs/ink-jcs-number-profile.md).

Ed25519 verification matches the reference's strict mode (`@noble/ed25519` with
`zip215:false`): the public key must be canonically encoded (`y < p`) and must
not be a small-order point, both enforced before the cofactorless equation. Go's
bare `crypto/ed25519.Verify` accepts both, so the verifier adds an explicit
public-key check.

Timestamps follow INK's strict RFC 3339 profile in both implementations: a full
date-time with a `T` and a `Z` or numeric offset, calendar-range validated, with
the instant floored to whole milliseconds. The shared `timestamp-validity`
vectors pin the grammar and precision. See
[`../specs/ink-timestamp-grammar.md`](../specs/ink-timestamp-grammar.md).

Key-window presence is semantic in both implementations: a present `validFrom`,
`validUntil`, or `revokedAt` constrains the key even when empty, `null`, or
non-string, via the `OptionalTimestamp` type that distinguishes absent from
present. The `key-rotation` vectors pin the present-empty, present-null, and
non-string cases. See
[`../specs/ink-key-rotation-spec.md`](../specs/ink-key-rotation-spec.md) §6.5.

Lone UTF-16 surrogates in signed strings are banned in both implementations,
because `encoding/json` would rewrite a lone surrogate to U+FFFD and canonicalize
different bytes. A receiver MUST parse a signed body through `ParseSignedBody`,
which scans the raw JSON for an unpaired surrogate escape before unmarshaling;
`VerifyInkSignature` takes an already-parsed body and cannot recover a dropped
surrogate on its own. The `jcs-string-safety` vectors pin the scanner. See
[`../specs/ink-signed-string-safety.md`](../specs/ink-signed-string-safety.md).

Merkle inclusion proofs walk identically in both implementations:
`VerifyInclusionProof`'s sibling order is top-down, internal nodes are hashed
`SHA-256(0x01 || left || right)`, and a proof that is too short or padded with an
unused entry is rejected rather than silently matched. A `treeSize` past the JS
safe-integer range (`2^53 - 1`) is rejected before the walk, matching the
reference, so neither side splits on a value the other cannot represent exactly.
The `merkle-inclusion` vectors pin every leaf position plus the rejection edges.
See [`../specs/ink-merkle-inclusion.md`](../specs/ink-merkle-inclusion.md).

Merkle consistency proofs walk identically in both implementations:
`VerifyConsistencyProof` confirms the tree of `first` leaves is an append-only
prefix of the tree of `second` leaves, the check that detects a forked log a size
comparison cannot. The shift logic, `0x01` node prefix, and short/extra-node
rejection match the reference, and a size past the safe-integer range rejects
before the walk. The `merkle-consistency` vectors pin the prefix matrix plus the
rejection edges. See
[`../specs/ink-merkle-consistency.md`](../specs/ink-merkle-consistency.md).

Checkpoint bodies parse identically in both implementations: `ParseCheckpoint`
accepts the three-line C2SP grammar (origin, decimal tree size, 64-hex root hash,
trailing newline), measures its line and body caps in UTF-16 code units to match
the reference on a non-ASCII origin, rejects a tree size past the safe-integer
range, and `FormatCheckpoint` reproduces the canonical bytes. The
`merkle-checkpoint` vectors pin the accept set, the canonical form, and the
rejection edges. See
[`../specs/ink-merkle-checkpoint.md`](../specs/ink-merkle-checkpoint.md).

Audit events hash to a leaf identically in both implementations:
`ComputeAuditMerkleLeafHash` strips `agentSignature`, canonicalizes the rest
with the same JCS profile, and returns `SHA-256(0x00 || canonical)`, so the leaf
a witness logs is independent of the agent signature and carries the `0x00`
leaf-domain prefix that an inclusion proof walks up from. It takes the value
parsed by `ParseSignedBody`, so a lone surrogate is already rejected, and an
unsafe-integer number fails closed. The `merkle-leaf` vectors pin the digest,
the agentSignature stripping, and the rejection edges. See
[`../specs/ink-merkle-leaf.md`](../specs/ink-merkle-leaf.md).

Inclusion receipts verify identically in both implementations:
`VerifyInclusionReceipt` validates the receipt shape, the witness Ed25519 service
signature over `"ink/audit-inclusion/v1\n"` plus the JCS of the committed fields,
and, when supplied, the event-bound proof walk and the later-checkpoint
anti-rollback and fork cross-check, in that order. The `inclusionProof` is not
signed, so a tampered proof is caught by the walk rather than by the signature.
The `inclusion-receipt` vectors pin the accept set and every rejection edge
across the four steps. See
[`../specs/ink-inclusion-receipt.md`](../specs/ink-inclusion-receipt.md).

Audit-query responses verify identically in both implementations:
`VerifyInkAuditQueryResponse` checks structure, the requester and messageId
bindings, the witness envelope Ed25519 signature over
`"ink/audit-query-response/v1\n"` plus the JCS of the response without its
signature, the per-event scope rule, the events-to-proofs one-to-one mapping,
every Merkle proof walk, and a required per-event agent signature
(`VerifyAuditEventSignature` over `"ink/audit-event\n"` plus the JCS of the event
without its agentSignature), then an optional later-checkpoint cross-check. The
`audit-query-response` vectors pin the accept set and every rejection edge. See
[`../specs/ink-audit-query-response.md`](../specs/ink-audit-query-response.md).

This package targets 64-bit platforms: it uses native `int` for `treeSize`,
`leafIndex`, and the consistency `first`/`second` sizes, and a `2^53 - 1` integer
bound that does not fit a 32-bit `int`, so the safe-integer edge is deterministic
only where `int` is 64 bits wide.

## Known divergences pending a spec decision

These are edges the shared conformance vectors do not yet cover. They are
recorded so the 1.0 spec can mandate one behavior and both implementations
converge by specification:

- **Raw UTF-8 validity.** `encoding/json` replaces invalid UTF-8 with U+FFFD,
  the same parser-loss class as lone surrogates; a receiver should require valid
  UTF-8 before parsing. Tracked at the same boundary as the surrogate check.

## Running the conformance suite

```sh
cd ink
go test ./...
```

Each `Test*` loads its category from `../../conformance/v1/vectors` and asserts
this implementation makes the expected accept or reject decision on every
vector, plus the canonical principal or verifying key where the vector pins it.

## The `ink` verifier binary

`cmd/ink` builds a single static binary that verifies INK protocol artifacts
using this library, with no Node or npm runtime. The command layer
(`internal/cli`) only parses arguments, reads the artifact JSON, and maps the
result to an exit code; the verification itself lives in `internal/verify` so a
later witness or inbound-verifier server can reuse it.

```sh
cd go
CGO_ENABLED=0 go build -o ink ./cmd/ink
```

Commands read the artifact JSON from `--file PATH`, or from stdin when `--file`
is omitted, and print a JSON result object (`--pretty` for indented output):

- `verify-card` validates an Agent Card document.
- `verify-signature` verifies a detached Ed25519 signature over a signed
  request (input fields `signInput` with `method`, `path`, `recipientDid`,
  `body`, `timestamp`, plus `signature` and one of `publicKeyHex` or
  `publicKeyMultibase`, matching the `signature-base` vectors). The signed body
  is parsed through the surrogate-safe path before verification.
- `verify-receipt` verifies a witness inclusion receipt: its structure, the
  witness Ed25519 service signature, and, when supplied, the event-bound proof
  walk and a later-checkpoint cross-check (input fields `receipt`, one of
  `witnessPublicKeyHex` or `witnessPublicKeyMultibase`, and optional `event`,
  `eventHash`, `laterCheckpoint`, matching the `inclusion-receipt` vectors).
- `verify-audit-response` verifies a witness audit-query response: the requester
  and messageId bindings, the witness envelope signature, the per-event scope and
  proof walks, and the required per-event agent signature, then an optional
  later-checkpoint cross-check (input fields `response`, one of
  `witnessPublicKeyHex` or `witnessPublicKeyMultibase`, `expectedRequester`,
  `expectedMessageId`, a per-agent `agentKeysHex` map, and optional
  `expectedServiceDid` and `laterCheckpoint`, matching the `audit-query-response`
  vectors).
- `verify-handshake` validates a handshake message (challenge, rejection, or
  resolution) against the reference schema; the message object is the whole
  input, matching the `handshake-message` vectors.
- `verify-connection` validates a connection_request or connection_response
  payload against the schema for the named kind (input fields `kind` and
  `payload`, matching the `connection-payload` vectors).
- `verify-checkpoint` validates a signed-tree-head checkpoint body: its line
  structure, integer tree size, hex root, and single trailing newline (input
  field `body`, matching the `merkle-checkpoint` vectors). On acceptance the
  result carries the `canonical` re-serialization so a caller can confirm the
  body is in canonical form.
- `verify-inclusion` verifies a Merkle inclusion proof (input fields
  `leafHash`, `inclusionProof`, `leafIndex`, `treeSize`, `rootHash`, matching the
  `merkle-inclusion` vectors).
- `verify-consistency` verifies a Merkle consistency proof (input fields `first`,
  `firstRoot`, `second`, `secondRoot`, `proof`, matching the `merkle-consistency`
  vectors).
- `version` prints the verifier version.

The exit code is the machine contract: `0` verified, `1` well-formed but
rejected, `2` bad input or usage (malformed JSON, a missing file, an unknown
command).

```sh
echo '{"leafHash":"…","inclusionProof":[],"leafIndex":0,"treeSize":1,"rootHash":"…"}' \
  | ink verify-inclusion
# {"ok":true,"kind":"merkle-inclusion"}
```

## The `ink-verify-server` HTTP service

`ink-verify-server` exposes the same verifiers over HTTP, so another
implementation or a test harness can reach them without the CLI. It is
verify-only and stateless: it holds no keys and issues nothing.

```sh
ink-verify-server --addr :8080
```

Each verifier is a `POST /verify/<name>` endpoint whose body is the artifact
JSON the matching subcommand would read: `card`, `signature`, `receipt`,
`audit-response`, `handshake`, `connection`, `checkpoint`, `inclusion`,
`consistency`. `GET /healthz` reports liveness.

```sh
curl -s localhost:8080/verify/card --data @card.json
# {"ok":true,"kind":"agent-card"}
```

The HTTP status mirrors the CLI exit-code contract: `200` carries a verdict
(`{"ok":true|false,"kind":…}`) for a well-formed artifact, `400` is bad input
(malformed JSON, a missing or unknown field), `404` is an unknown route, `405`
is a known route with the wrong method, and `413` is a body over the size cap.

## The `ink-witness-server` issuing service

`ink-witness-server` runs a single in-memory witness log over HTTP. Unlike the
verify server it is stateful and holds an Ed25519 witness key: it stamps a
server-side timestamp, appends each submitted audit event as a new leaf, and
returns a signed inclusion receipt. It also serves the current signed checkpoint
and the inclusion and consistency proofs of its tree. It is in-memory and
non-durable, so a restart starts an empty log; it is a development and interop
witness, not a durable production log.

The witness key is a hex-encoded 32-byte Ed25519 seed in `INK_WITNESS_SEED_HEX`.
Submit is authenticated by default: set the bearer token in
`INK_WITNESS_SUBMIT_TOKEN`, or pass `-allow-unauthenticated` for local testing.

```sh
INK_WITNESS_SEED_HEX=$SEED INK_WITNESS_SUBMIT_TOKEN=$TOK \
  ink-witness-server --addr :8081 --origin example.com/ink-witness
```

- `POST /submit` appends the audit event in the body and returns the signed
  inclusion receipt. It requires `Authorization: Bearer <token>` unless the
  server was started with `-allow-unauthenticated`.
- `GET /checkpoint` returns the current signed checkpoint note.
- `GET /inclusion?index=N` returns `{index, size, proof}` for leaf `N`.
- `GET /consistency?first=A&second=B` returns the consistency proof between the
  trees of size `A` and `B`.
- `GET /healthz` reports liveness.

The status map adds `401` for a submit without a valid bearer token and `507`
when the log has reached its configured capacity (`-max-leaves`), on top of the
`200/400/404/405/413` the verify server uses.
