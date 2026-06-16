# Maturity Notice

> INK is **experimental**. The current defined wire version is `ink/0.2`, a
> backward-compatible minor over `ink/0.1` (both major version 0). Wire formats,
> trust semantics and APIs may change without backward-compatible migration
> before v1.0. Do not use for load-bearing production traffic without your own
> review.

## What "experimental" means here

- The repository has **not** undergone an independent security audit.
  It has been through structured internal review covering signature
  handling, key rotation, replay protection, SSRF defenses on
  agent-card fetch, and DoS-amplification surfaces. Internal review is
  not a substitute for a third-party audit, treat the security
  posture accordingly.
- The cross-implementation conformance corpus (`../conformance/v1/`, indexed by
  `../conformance/v1/manifest.json`) is the authoritative contract for the
  current wire version: the TypeScript reference and the independent Go
  implementation make the same accept or reject decision on every vector. The
  corpus may be added to or revised between patch releases. Mismatched
  implementations should report discrepancies as issues.
- The protocol is in use by one production integrator (Tulpa). That is
  one data point, not a guarantee of robustness at scale.
- The library in `src/` runs on any runtime providing
  standard Web Crypto (`crypto.subtle`) and `fetch`, modern Node, Deno,
  Bun, and edge runtimes. Browser use is feasible but not exercised by
  the maintainers.

## What is stable

These hold across major version 0 (`ink/0.1` and `ink/0.2`):

- Envelope structure (fields, canonicalization with JCS / RFC 8785).
  Signed bodies are restricted to JSON numbers that every conforming
  canonicalizer serializes identically: non-finite values, negative zero,
  and values whose shortest form uses exponential notation (for example
  `1e21` or `1e-7`) are rejected at sign and verify time. INK payloads
  carry only small integers and plain decimals, so this keeps the signed
  bytes unambiguous across implementations.
- Ed25519 signing base: `ink/0.1\nMETHOD\nPATH\nrecipientDid\nJCS(body)\ntimestamp`
- Agent Card schema for `keys.signing` and `keys.encryption`
- Key rotation authority rule (see `key-rotation-rule.md`)
- Timestamp freshness semantics: 5 min past tolerance, 30 s future
  tolerance. Nonce cache TTL is integrator-defined (the witness
  reference uses 10 min); INK does not mandate it.
- Receipt envelope structure

## What may still change

- Authorization chain attenuation semantics, currently spec'd as
  scope-subset-only delegation; may gain time-bounded or usage-bounded
  variants.
- Containment vocabulary (capability-gated visibility, sender budgets,
  backoff hints), the current shape is deliberately minimal; a v0.2
  may formalize policy expression.
- Third-party witness submission API, currently a reference client
  only. The submission envelope may move to a signed-bundle format in
  the future.
- Encryption envelope AAD composition, the current AAD is
  `ink/0.1:envelope\n` followed by the JCS canonicalization of
  `{protocol, type, from, ephemeralKey, nonce, timestamp, messageNonce}`.
  Future versions may include the recipient DID or evolve the field set.

## Versioning

Pre-1.0 releases follow `0.Y.Z` semantics:

- `0.Y.0`, Minor version bump indicates a wire-format change. Receivers
  must support at least one prior minor during a transition window.
- `0.Y.Z` (Z > 0), Patch bumps fix bugs in the library
  and update test vectors where needed. They do not change wire format.

Breaking changes before v1.0 will be announced in the repository
changelog with at least 30 days of overlap support in the reference
implementation.

## How to evaluate for your use

Before adopting INK for any use where signature forgery or replay would
be a real incident:

1. Read [`threat-model.md`](./threat-model.md). Make sure your use case
   falls inside the in-scope protections and you accept the out-of-scope
   limits.
2. Run the `../conformance/v1/` manifest categories against your implementation.
3. Fuzz your envelope parser. The library's tests are
   not a substitute.
4. Pen-test the rotation and revocation flows specifically. The
   authority rule is the single most security-sensitive piece and the
   most common place to introduce a shadowing bug.
5. If your integration accepts delegation tokens or other capability
   handoffs, design their trust model explicitly, INK v0.1 does not
   specify one.
