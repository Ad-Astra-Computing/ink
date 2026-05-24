# Security Policy

INK is an experimental pre-1.0 protocol. We treat security reports
seriously and will work with reporters in good faith.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report privately to: **security@adastracomputing.com**

Include:

- A description of the issue and why it's a security problem
- Reproduction steps, or a proof-of-concept if you have one
- The affected commit SHA or release tag
- Whether you'd like to be credited publicly in the fix notes

We'll acknowledge receipt within 3 business days and aim to respond with a
triage decision within 7 days. Coordinated disclosure preferred — we'll
agree on a public-disclosure date with the reporter, typically after a fix
has shipped and been adopted by known integrators.

## Supported versions

INK is pre-1.0. Only the `main` branch receives security fixes. Pinned
releases before a hypothetical v1.0 are not separately maintained — if
you're integrating from a pin, expect to rebase forward for security
updates.

| Version | Supported |
|---------|-----------|
| `main`  | Yes |
| v0.x tags | On best-effort basis only |

## Scope

In scope:

- Signature forgery, replay attacks, nonce collisions
- Bypass of the key-rotation authority rule (see
  `docs/key-rotation-rule.md`)
- Authorization-chain attenuation bypass
- Receipt / audit envelope tampering
- Agent Card discovery gating bypass that exposes non-public fields
- Cryptographic misuse (wrong signing base, non-canonical JSON, etc.)

Out of scope (at least until a future hardening pass):

- DoS via high-entropy inputs against the reference implementation
- Attacks that rely on a compromised identity-system (e.g., a malicious PDS
  returning a fabricated DID document)
- Timing side-channels in the reference `@noble/ed25519` verification
- Attacks on Tulpa's product infrastructure (that's a separate codebase
  and a separate disclosure process)

## Threat model

See [`docs/threat-model.md`](docs/threat-model.md) for what INK aims to
protect against and what it does not.

## Audit status

INK has **not** undergone an independent security audit. Do not describe
or adopt INK as "audited" or "hardened" on that basis.

## Credits

Security researchers who help us will be credited in release notes unless
they prefer to remain anonymous.
