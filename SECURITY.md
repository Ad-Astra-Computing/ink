# Security Policy

INK is an experimental pre-1.0 protocol. Security reports are taken seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Report privately to: **security@adastracomputing.com**

Include:

- A description of the issue and why it is a security problem
- Reproduction steps or a proof-of-concept
- The affected commit SHA or release tag
- Whether you want public credit in the fix notes

Acknowledgement within 3 business days; triage decision within 7. We coordinate disclosure with the reporter, public disclosure after a fix ships and known integrators have had time to update.

## Supported versions

INK is pre-1.0. Only the `main` branch receives security fixes. Pinned pre-1.0 releases are not separately maintained.

| Version | Supported |
|---------|-----------|
| `main`  | Yes |
| v0.x tags | Best-effort only |

## Scope

In scope:

- Signature forgery, replay attacks, nonce collisions
- Bypass of the key-rotation authority rule (see `docs/key-rotation-rule.md`)
- Authorization-chain attenuation bypass
- Receipt/audit envelope tampering
- Agent Card discovery gating bypass that exposes non-public fields
- Cryptographic misuse (wrong signing base, non-canonical JSON, etc.)

Out of scope:

- DoS via high-entropy inputs against the reference implementation
- Attacks that require a compromised identity system (e.g., a malicious PDS returning a fabricated DID document)
- Timing side-channels in the reference `@noble/ed25519` verification
- Attacks on Tulpa's product infrastructure (separate codebase, separate disclosure process)

## Threat model

See [`docs/threat-model.md`](docs/threat-model.md).

## Audit status

INK has not undergone an independent security audit. Do not describe or adopt INK as "audited" or "hardened" on that basis.

## Credits

Reporters who help us will be credited in release notes unless they prefer to remain anonymous.
