# INK Protocol

> **Inter-agent Networking Kernel** — an open protocol for autonomous
> agent-to-agent coordination.
>
> **Status: experimental (v0.1). Wire formats, trust semantics and APIs may
> change without backward-compatible migration. Do not use for load-bearing
> production traffic without your own review.**
>
> This repository is a **reference implementation and specification**.
> It has not been independently audited.

---

## What is INK?

INK is the message layer that lets autonomous agents send each other typed,
signed, structured intents over the open web. It is what one agent speaks to
another when scheduling a meeting, requesting an introduction, delivering a
signed receipt, or negotiating a connection.

INK is designed to sit on top of [AT Protocol](https://atproto.com) for
identity and DID resolution, but is not coupled to it — any system that can
publish an Ed25519 signing key under a stable identifier can participate.

### Core properties

- **Ed25519-signed envelopes** — every message carries a detached signature
  over a canonical serialization of its fields.
- **Typed intents** — messages declare a purpose (`schedule_meeting`,
  `request_introduction`, `agent_exchange`, …) with an intent-specific
  payload.
- **Correlatable** — request/response pairs share a `correlationId`.
- **Expirable** — messages may set `expiresAt`; the receiver rejects past that.
- **Key rotation with a proper authority rule** — an agent publishes a
  signing key set in its Agent Card; that set is authoritative.
- **Replay-protected** — nonce + timestamp freshness at the transport layer.

## What's in this repo

```
src/           reference TypeScript implementation
  crypto/      signing, multi-key verification, key encoding
  models/      zod schemas for Agent Card, handshake, key entries
  middleware/  transport-level INK auth (verifyInkAuth)
  discovery/   Agent Card fetching and candidate-key extraction
  ink/         discovery gating, handshake budget, transport scope,
               receipts, checkpointing, audit bridge
  auth/        delegation tokens, per-request signatures
specs/         INK spec documents (authoritative definitions)
docs/          protocol maturity notes, threat model, key rotation rules
test-vectors/  JSON interop vectors (signing base, key rotation, replay, …)
test/          vitest unit + integration tests
```

The reference implementation targets Cloudflare Workers runtime (uses
`crypto.subtle`, `@noble/ed25519`, Durable Objects for nonce storage in
prod), but the core signing/verification code is portable.

## Maturity

INK v0.1 is **experimental**. The semantics we're fairly confident in:

- Envelope structure and signing base (stable)
- Authorization: signed intent + Agent Card key set
- Key rotation authority rule (Card signing set is authoritative, revoked
  never verifies, retired may verify only where historical verification is
  intentionally permitted, bootstrap/connection-store keys only for first
  contact when no key set exists — see `docs/key-rotation-rule.md`)
- Replay protection (nonce + ±5 min timestamp window)

Areas that may still change:

- Authorization chain framing (delegation + attenuation semantics)
- Containment vocabulary (capability-gated visibility, sender budgets)
- Interop conventions with non-AT-Protocol identity systems
- Receipt/audit envelope shape for third-party witnesses

## Security

See [`SECURITY.md`](SECURITY.md) for how to report vulnerabilities. The
threat model — what INK protects and what it doesn't — is in
[`docs/threat-model.md`](docs/threat-model.md).

If you find a security issue, **please do not open a public issue**.

## Relationship to Tulpa

INK is developed by [Ad Astra Computing](https://adastracomputing.com) as
the underlying protocol for [Tulpa](https://tulpa.network), an agent-native
identity and coordination network. The protocol spec and the reference
implementation in this repo are deliberately free of Tulpa product-specific
code, so other agent platforms can adopt INK without inheriting Tulpa's
surface area.

Tulpa product integration — the Durable-Objects orchestration, marketplace,
user-facing APIs — lives in a separate, closed-source codebase.

## License

See [`LICENSE`](LICENSE).

## Contributing

Before opening a PR or issue, please read `SECURITY.md` and the threat
model. Protocol-breaking proposals should reference a spec file in
`specs/` or propose a new one.
