# Changelog

All notable changes to INK are recorded
here. Pre-1.0 releases follow `0.Y.Z` semantics, see
[`docs/maturity.md`](docs/maturity.md) for the versioning policy.

## Unreleased

No unreleased changes.

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
