# Changelog

All notable changes to INK and the reference implementation are recorded
here. Pre-1.0 releases follow `0.Y.Z` semantics, see
[`docs/maturity.md`](docs/maturity.md) for the versioning policy.

## Unreleased

No unreleased changes.

## 0.1.0-alpha.2, inclusion-receipt verifier

Adds a public verification path for INK Auditability Section 7
inclusion receipts, plus a CLI any third party can run without
trusting any specific operator's UI.

### Added

- `verifyInclusionReceipt({receipt, witnessPublicKey, eventHash?, laterCheckpoint?})` exported from the package root. Pure function. Returns `{valid, steps[]}` where each step explains pass/fail with detail. Always verifies structure + Ed25519 service signature against the canonical `ink/audit-inclusion/v1\n` + JCS format. Optionally walks the Merkle proof when `eventHash` is provided, and cross-checks against a `laterCheckpoint` for tree-grew-not-rewound + no-fork-at-same-treeSize.
- `ink` CLI dispatcher with a `verify-inclusion` subcommand. `npx @adastracomputing/ink verify-inclusion --file receipt.json --witness https://witness.example.com` fetches the witness DID document + current checkpoint and runs the full verification. Witness URL is validated (https-only by default, `--allow-http` opt-in, no credentials). Exit code 0 = valid, 1 = invalid, 2 = usage / network / validation error. Self-contained ESM JavaScript so it works on any Node 22+ install with no TypeScript toolchain.

## 0.1.0-alpha.1, spec clarification

Spec-only release. Reference-implementation code in `src/` is
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

Initial open-source release of the INK protocol reference implementation
and accompanying specification.

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

### Reference implementation

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
