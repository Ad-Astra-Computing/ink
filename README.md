<img src="docs/logo.svg" alt="INK" width="200">

# INK: Inter-agent Networking Kernel

An open protocol for AI agents that need to send each other typed, signed messages on the public web. Built for scheduling, introductions, receipts, and other coordination flows where a user delegates an agent to act on their behalf.

**Status: experimental; current defined wire version `ink/0.2`.** Wire formats, trust semantics, and APIs may change without backward-compatible migration before v1.0. On npm, `latest` is `0.1.2` and `0.2.0` is published on the `next` tag; senders still emit `ink/0.1` by default unless explicitly configured.

`ink/0.2` is the recommended target for new receiver implementations. It is a backward-compatible minor over `ink/0.1`, changing only the body-signature domain: the neutral `ink/sign` in place of the legacy `tulpa/sign`, selected from the signed `protocol` field. `ink/0.1` remains fully supported: both are major version 0, and conformant major-0 receivers accept either. There is no plan to drop `ink/0.1` within major 0; any future version sunset follows the [compatibility policy](specs/ink-compatibility-policy.md).

| | |
|---|---|
| Spec | [`specs/`](specs/) |
| Docs | [ink.tulpa.network](https://ink.tulpa.network) |
| npm | [`@adastracomputing/ink`](https://www.npmjs.com/package/@adastracomputing/ink) |
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Security | [`SECURITY.md`](SECURITY.md) |
| Code of Conduct | [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |

## Contents

- [What's in the envelope](#whats-in-the-envelope)
- [Install](#install)
- [Agent-assisted implementation](#agent-assisted-implementation)
- [Tests](#tests)
- [Layout](#layout)
- [What's stable](#whats-stable)
- [Naming](#naming)
- [Relationship to Tulpa](#relationship-to-tulpa)
- [Interoperability](#interoperability)
- [Security](#security)
- [License](#license)

## What's in the envelope

Every INK message is an Ed25519-signed envelope over a [JCS](https://datatracker.ietf.org/doc/html/rfc8785) (RFC 8785) canonical serialization. The signature base binds the protocol version, HTTP method, request path, recipient DID, body, and timestamp. Replay protection uses a per-sender nonce plus a timestamp freshness window of 5 minutes past and 30 seconds future.

Message types cover intents, challenges, resolutions, receipts, audit events, encrypted payloads, and authenticated agent-card queries. Handshake messages carry a correlation ID; audit and receipt messages do not. Key rotation is governed by an authority rule documented in [`docs/key-rotation-rule.md`](docs/key-rotation-rule.md): the Agent Card's published key set is canonical, revoked keys never verify, and a stale bootstrap key cannot bypass rotation.

A foreign sender's first envelope to an unestablished recipient is a `connection_request` — the bootstrap intent for first contact. Receivers that opt in to foreign senders verify the body signature against the inline key extracted from the sender's DID (trust-on-first-use) and SHOULD reject any other intent type from a sender they have no prior relationship with; richer intent types (`intro_request`, `ask`, `follow_up`, `schedule_meeting`) presume the sender is already a known contact. See the [Accepting Foreign Senders guide](https://ink.tulpa.network/guides/accepting-foreign-senders/) for the receive-side rules and [`examples/foreign-sender-receiver/`](examples/foreign-sender-receiver/) for a reference implementation.

INK assumes [AT Protocol](https://atproto.com) for identity by default but isn't coupled to it. Any system that can publish an Ed25519 signing key under a stable identifier can participate.

## Install

```bash
npm install @adastracomputing/ink
```

The package ships compiled ESM with bundled type definitions (`dist/index.js` + `dist/index.d.ts`). Any project with a standard JS toolchain can import it directly — no TypeScript build step on the consumer side. The build runs automatically via `prepack` before publish.

From 0.1.3 onward, receivers can also import `validateMessage` (canonical envelope + payload-schema parse, throws on drift) and `decodeEncryptionKeyMultibase` (X25519 multibase → 32 bytes, the companion to `decodePublicKeyMultibase` for Ed25519). These let an implementer drop the inline schema guard and key-decode helpers the previous guides asked them to write. `MessageEnvelope` (type) and `MessageEnvelopeSchema` (Zod constant) are also re-exported for adopters who want to type their parser surface against the canonical schema.

```ts
import {
  generateKeypair,
  deriveAgentId,
  signInkMessage,
  verifyInkSignature,
  verifyInkAuth,
} from "@adastracomputing/ink";

const keypair = await generateKeypair();
const agentId = deriveAgentId(keypair.publicKey);

const input = {
  method: "POST",
  path: "/ink/v1/tulpa:zRecipient/intent",
  recipientDid: "tulpa:zRecipient",
  body: {
    protocol: "ink/0.1",
    id: crypto.randomUUID(),
    correlationId: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    from: agentId,
    to: "tulpa:zRecipient",
    intent: "schedule_meeting",
    payload: {
      proposedTimes: ["2026-06-15T14:00:00Z"],
      topic: "Quick sync",
      format: "video",
      urgency: "normal",
    },
    timestamp: new Date().toISOString(),
    nonce: crypto.randomUUID(),
  },
  timestamp: new Date().toISOString(),
};

const signature = await signInkMessage(input, keypair.privateKey);
const ok = await verifyInkSignature(input, signature, keypair.publicKey);
```

For inbound request verification, `verifyInkAuth` parses the `Authorization: INK-Ed25519 <sig>` header, checks freshness, and applies the key-rotation authority rule. It requires a `nonceStore` option so the 5-minute freshness window does not silently accept replays; pass a `NonceStore` to have the middleware enforce single-use, or `"deferred"` to acknowledge that the caller will run `checkReplay` (or equivalent) elsewhere in the request pipeline.

For consumers of bilateral audit-exchange responses (`network.tulpa.audit_response`), call both `verifyAuditResponseSignature` (signed response wrapper) and `verifyAuditEventChain` (sequence-by-one and `previousEventHash` continuity, fork detection). The signature gate alone does not prevent a peer from returning a gapped or forked slice.

For consumers of witness audit-query responses (`network.tulpa.audit_query_response`, Auditability §7.3, added in `0.1.0-alpha.3`), call `verifyAuditQueryResponse({response, witnessPublicKey, expectedRequester, expectedMessageId, verifyEventSignature, expectedServiceDid?, laterCheckpoint?})`. The `verifyEventSignature` callback is REQUIRED: it resolves the submitting agent's Ed25519 keys (typically via Agent Card §2) and validates each event's `agentSignature`. Without it, the verifier refuses to return valid, because Merkle inclusion alone does not prove a real agent produced the event (§7.5). The verifier enforces envelope shape, the `requester` binding (prevents cross-requester replay), events/proofs strict one-to-one alignment, the §7.4 per-event scope rule, walks every Merkle proof via `computeAuditMerkleLeafHash` up to the response's `rootHash`, runs `verifyEventSignature` on every event and supports an optional later-checkpoint cross-check. The lower-level `verifyAuditQueryResponseSignature` is signature-only and is not sufficient to accept a witness response on its own.

Verification helpers added in `0.4.0`:

- `verifyCheckpoint(signed, witnessPublicKey, expectedOrigin)` verifies a signed C2SP checkpoint's witness Ed25519 signature and binds its log origin, returning the parsed `{origin, treeSize, rootHash}` or `null`. Any checkpoint passed to `verifyInclusionReceipt`'s `laterCheckpoint` cross-check must be verified this way first; an unverified checkpoint body is attacker-controllable and provides no anti-rollback value.
- `verifyReceipt({receipt, senderPublicKey, expected})` verifies a delivery receipt against the message it acknowledges: the issuer's signature plus `from`/`to`/`messageId`, the recomputed message hash, and an optional `disposition`. It returns `{valid, reason?}`.
- `verifyInclusionReceipt` accepts an `event` option that recomputes the leaf hash and binds `event.id` to `receipt.eventId`, so the proof attests the named event's inclusion. Prefer it over the legacy unbound `eventHash`.
- `verifyInkAuth` returns a prefix-independent `principal` alongside the raw `senderAgentId`. Per-sender security state (block lists, rate limits) MUST key on `principal`, because the `tulpa:` and `ink:` spellings of one key are the same actor; `canonicalAgentPrincipal(agentId)` exposes the same mapping.

Added in `0.5.0`:

- `verifyConsistencyProof(first, firstRoot, second, secondRoot, proof)` verifies an RFC 6962 consistency proof that the tree of `first` leaves is an append-only prefix of the tree of `second` leaves, so a witness that forks its history rather than only appending is detected. The witness serves these proofs at `GET /ink/v1/consistency?first=N&second=M`, and the `verify-inclusion` CLI checks one against the current checkpoint when `--origin` is passed.

## Agent-assisted implementation

If you are asking an AI coding agent to add INK support to an existing service, the canonical packet for that workflow is the [Agent-assisted implementation](https://ink.tulpa.network/guides/agent-assisted-implementation/) guide. It contains the curated implementer prompt, a mandatory traceability matrix, the conformance checklist, and a human-review checklist. The guide is updated as the protocol evolves; treat it as the live source rather than copying its contents into your repo.

Adopters who want the second open implementation to cross-check against can use the [`examples/foreign-sender-receiver/`](examples/foreign-sender-receiver/) TypeScript reference and the [`examples/interop-cli/`](examples/interop-cli/) Python from-scratch sender.

## Tests

```bash
npm test            # vitest
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm run check:surface   # public-surface drift check
```

For Nix users: `nix develop` gives a pinned Node 24 + git + gitleaks shell. `nix build` produces the publishable npm tarball under `result/`. `nix run github:Ad-Astra-Computing/ink -- verify-inclusion --file receipt.json --witness https://witness.example.com` runs the CLI without installing anything globally.

## Layout

```
src/           library implementation
  crypto/      signing, multi-key verification, key encoding
  models/      Zod schemas for Agent Card, handshake, key entries
  middleware/  transport-level INK auth (verifyInkAuth)
  discovery/   Agent Card fetching and candidate-key extraction
  ink/         discovery gating, handshake budget, receipts, checkpointing
specs/         protocol spec documents
docs/          maturity notes, threat model, key rotation rules
test-vectors/  JSON interop vectors
test/          vitest unit + integration tests
```

The library runs on any runtime providing standard Web Crypto and `fetch`: Node 24+, Deno, Bun, Cloudflare Workers, browsers. The timestamp freshness window is enforced inside `verifyInkAuth`; nonce single-use is enforced when a `NonceStore` is passed (otherwise `checkReplay` must be called separately). Nonce backing storage and its TTL policy are the integrator's choice.

## What's stable

These hold across major version 0 (both `ink/0.1` and `ink/0.2`). Reliable to depend on:

- Envelope structure and signing base
- Authorization: signed intent plus Agent Card key set
- Key rotation authority rule (see [`docs/key-rotation-rule.md`](docs/key-rotation-rule.md))
- Replay protection (nonce plus timestamp window)

Subject to change before v1.0:

- Authorization chain framing (delegation and attenuation semantics)
- Containment vocabulary (capability-gated visibility, sender budgets)
- Interop conventions with non-AT-Protocol identity systems
- Receipt and audit envelope shape for third-party witnesses

## Naming

You will see `network.tulpa.*` on the wire (e.g. `network.tulpa.intent`) and `ink.tulpa.network` for the docs site. Both are historical artifacts of the protocol's origin and do not imply a runtime dependency on Tulpa. A vendor-neutral namespace may be introduced in a future revision.

As a first, non-breaking step in that direction, agentIds may use either the canonical `tulpa:` method prefix or the `ink:` alias; both encode the same Ed25519 key and denote the same actor. `deriveAgentId` still emits `tulpa:`, and `extractPublicKeyFromAgentId` accepts both (accept-both, emit-one). A receiver MUST collapse the two spellings to one prefix-independent principal for all per-sender security state (blocks, rate limits, duplicate-payload checks, cached keys, connection identity).

## Relationship to Tulpa

INK is developed by [Ad Astra Computing](https://adastracomputing.com) as the underlying protocol for [Tulpa](https://tulpa.network). The spec and the library in this repo are deliberately free of Tulpa product code so other agent platforms can adopt INK without inheriting Tulpa's surface area. Tulpa's product integration (message orchestration, marketplace, user-facing APIs) lives in a separate codebase.

## Interoperability

INK is a wire protocol. Any compatible service that publishes a DID and exposes an `/ink/v1/...` endpoint can accept signed envelopes from agents that live on other platforms — cross-platform interop is a primary design goal.

[`tulpa.network`](https://tulpa.network) is one current example of an accepting endpoint. Its receive side resolves inbound senders against published Agent Cards and applies operator-level and per-user acceptance policies; see [docs.tulpa.network/guide/foreign-agents](https://docs.tulpa.network/guide/foreign-agents/) for how a Tulpa user opts in. The protocol is intended to support other accepting endpoints.

## Security

See [`SECURITY.md`](SECURITY.md) for the disclosure path. The threat model is in [`docs/threat-model.md`](docs/threat-model.md). **Do not open a public issue for security problems.**

## License

Dual-licensed under either of:

- MIT ([`LICENSE-MIT`](LICENSE-MIT))
- Apache 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))

at your option. The Apache 2.0 license includes an explicit patent grant; MIT is the simpler text. Pick whichever fits your downstream policy. This covers the code, specs, docs, and test vectors. Contributions are accepted under both licenses.
