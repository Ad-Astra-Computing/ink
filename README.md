<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-light.svg">
    <img src="docs/logo.svg" alt="INK" width="200">
  </picture>
</p>

<h1 align="center">INK: Inter-agent Networking Kernel</h1>

<p align="center">
  An open protocol for typed, signed messages between AI agents on the public web.
</p>

<p align="center">
  <a href="https://github.com/Ad-Astra-Computing/ink/actions/workflows/ci.yml"><img alt="CI status" src="https://github.com/Ad-Astra-Computing/ink/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/Ad-Astra-Computing/ink/actions/workflows/interop-lab.yml"><img alt="Interop lab status" src="https://github.com/Ad-Astra-Computing/ink/actions/workflows/interop-lab.yml/badge.svg?branch=main"></a>
  <a href="https://www.npmjs.com/package/@adastracomputing/ink"><img alt="npm version" src="https://img.shields.io/npm/v/%40adastracomputing%2Fink?label=npm"></a>
  <a href="https://pkg.go.dev/github.com/Ad-Astra-Computing/ink/go"><img alt="Go reference" src="https://pkg.go.dev/badge/github.com/Ad-Astra-Computing/ink/go.svg"></a>
  <a href="#license"><img alt="License: MIT or Apache 2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue"></a>
</p>

INK carries the messages agents send each other when a person has delegated
something to them: scheduling, introductions, receipts and the other flows where
one agent acts on its user's behalf and the receiving side needs to know who
asked. Every message is a signed envelope with a typed payload, so a receiver can
check the sender's key and apply its own policy before anything reaches the user.

**Status: experimental.** `ink/0.2` is the current defined wire version for the intent envelope only; every other wire object stays `ink/0.1`. Wire formats, trust semantics and APIs may change without backward-compatible migration before v1.0. On npm, `latest` is `0.19.0`[^ck] and `next` is `0.19.0`[^ck]; senders still emit `ink/0.1` by default unless explicitly configured.

| | |
|---|---|
| Spec | [`specs/`](specs/) |
| Docs | [ink.tulpa.network](https://ink.tulpa.network) |
| npm | [`@adastracomputing/ink`](https://www.npmjs.com/package/@adastracomputing/ink) |
| Go module | [`github.com/Ad-Astra-Computing/ink/go`](https://pkg.go.dev/github.com/Ad-Astra-Computing/ink/go) |
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Security | [`SECURITY.md`](SECURITY.md) |
| Code of Conduct | [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |

## Contents

- [What's in the envelope](#whats-in-the-envelope)
- [Install](#install)
- [What the library gives you](#what-the-library-gives-you)
- [Two implementations, one wire](#two-implementations-one-wire)
- [Agent-assisted implementation](#agent-assisted-implementation)
- [Tests](#tests)
- [Layout](#layout)
- [What's stable](#whats-stable)
- [Naming](#naming)
- [Relationship to Tulpa](#relationship-to-tulpa)
- [Interoperability](#interoperability)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## What's in the envelope

Every INK message is an Ed25519-signed envelope over a [JCS](https://datatracker.ietf.org/doc/html/rfc8785) (RFC 8785) canonical serialization. The signature base binds the protocol version, HTTP method, request path, recipient identifier (the `recipientDid` field, whose value is an agentId and need not be a DID), body and timestamp. Replay protection uses a per-sender nonce plus a timestamp freshness window of 5 minutes past and 30 seconds future.

Message types cover intents, challenges, resolutions, receipts, audit events, encrypted payloads, and authenticated agent-card queries. Handshake messages carry a correlation ID; audit and receipt messages do not. Key rotation is governed by an authority rule documented in [`docs/key-rotation-rule.md`](docs/key-rotation-rule.md): the Agent Card's published key set is canonical, revoked keys never verify, and a stale bootstrap key cannot bypass rotation.

A foreign sender's first envelope to an unestablished recipient is a `connection_request`, the bootstrap intent for first contact. Receivers that opt in to foreign senders verify the body signature against the key the sender's own identifier carries, or the key its DID document publishes (trust-on-first-use) and SHOULD reject any other intent type from a sender they have no prior relationship with; richer intent types (`intro_request`, `ask`, `follow_up`, `schedule_meeting`) presume the sender is already a known contact. See the [Accepting Foreign Senders guide](https://ink.tulpa.network/guides/accepting-foreign-senders/) for the receive-side rules and [`examples/foreign-sender-receiver/`](examples/foreign-sender-receiver/) for a reference implementation.

INK's default identity is key-derived and self-certifying: a `tulpa:` or `ink:` agentId whose multibase tail IS the agent's genesis Ed25519 key, so the identifier carries its own signing authority with no directory, registry or issuer behind it. A `did:web` identity whose DID document roots the key is equally supported, and any other system that publishes an Ed25519 signing key under a stable identifier can participate. Binding an agent to a human owner is a separate, optional layer: [AT Protocol](https://atproto.com) is one pipeline for it and never what makes a signature valid. See [`specs/ink-identity-model.md`](specs/ink-identity-model.md) and the ruling in [`governance/decisions/0001-key-derived-principals-are-the-identity-root.md`](governance/decisions/0001-key-derived-principals-are-the-identity-root.md).

### Wire versions

`ink/0.2` is a version of the intent-envelope body-signature domain and nothing else. It is a backward-compatible minor over `ink/0.1`, changing only that domain: the neutral `ink/sign` in place of the legacy `tulpa/sign`, selected from the signed `protocol` field. It is the recommended `protocol` value for new intent envelopes. The Agent Card, handshake, discovery query, authorization challenge/grant/chain, receipt and audit objects have no `ink/0.2` form and MUST carry `protocol: "ink/0.1"`; stamping `ink/0.2` on any of them is rejected. `ink/0.1` remains fully supported for intents too: both are major version 0, and conformant major-0 receivers accept either. There is no plan to drop `ink/0.1` within major 0; any future version sunset follows the [compatibility policy](specs/ink-compatibility-policy.md).

## Install

```bash
npm install @adastracomputing/ink
```

The Go implementation is a separate module, tagged in lockstep with the npm package:

```bash
go get github.com/Ad-Astra-Computing/ink/go
```

The package ships compiled ESM with bundled type definitions (`dist/index.js` + `dist/index.d.ts`). Any project with a standard JS toolchain can import it directly, with no TypeScript build step on the consumer side. The build runs automatically via `prepack` before publish.

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

## What the library gives you

The package ships every primitive a sender or a receiver needs, grouped below by
the job rather than by the release that added it. [`CHANGELOG.md`](CHANGELOG.md)
holds the version history, and [`npm run check:surface`](scripts/check-public-surface.ts)
gates the exported surface against drift.

**Signing and verifying a message.** `signInkMessage` and `verifyInkSignature`
implement the §3.3 signature base. `verifyInkAuth` is the inbound side: it parses
the `Authorization: INK-Ed25519 <sig>` header, checks freshness and verifies
against the sender's key set. It rejects retired keys for live auth by default
(`retired_key_for_live_auth`); pass `requireActiveKey: false` for a rotation
grace window. It requires a `nonceStore` option so the 5-minute freshness window
cannot silently accept replays: pass a `NonceStore` to have the middleware
enforce single use, or `"deferred"` to declare that the caller runs `checkReplay`
elsewhere in the pipeline. A distributed `NonceStore` SHOULD implement the
optional atomic `addIfAbsent` so two concurrent replays cannot both pass.

`validateMessage` parses a canonical envelope and its payload schema, throwing on
drift. `parseSignedBodyBytes` is its counterpart for raw bytes: it decodes with a
fatal UTF-8 decoder, then rejects a lone surrogate escape and a number literal
outside the IEEE-754 double range before JSON parse, throwing
`ParseSignedBodyError` with a `reason` naming the gate. A receiver holding raw
body bytes should use it rather than a lenient string decode, because a lenient
decode substitutes U+FFFD and would verify a signature over bytes the signer
never signed.

**Identity and keys.** `deriveAgentId` derives a key-derived agentId from a
public key, and `extractPublicKeyFromAgentId` reverses it. `verifyInkAuth`
returns a prefix-independent `principal` alongside the raw `senderAgentId`;
per-sender security state (block lists, rate limits, cached keys) MUST key on
`principal`, because the `tulpa:` and `ink:` spellings of one key are the same
actor. `canonicalAgentPrincipal(agentId)` exposes the same mapping.
`decodePublicKeyMultibase` and `decodeEncryptionKeyMultibase` decode the Ed25519
and X25519 halves of an Agent Card's key set; a signing entry must carry the
Ed25519 multicodec and an encryption entry the X25519 one, and a card whose key
does not fit its role is rejected.

`verifyAgentCardSignature(card, agentId, options)` verifies an Agent Card's
OPTIONAL `cardSignature` and roots it by principal kind: the embedded genesis key
for a key-derived id, the DID document for a `did:web` id. It walks a
`rotationChain` when present and applies the ratchet and continuity rules.
`signAgentCard` and `signRotationLink` are the producer-side signers. Producers
are at Phase B, meaning they MUST sign a card they can root and stay unsigned
otherwise. Phase C, where a receiver rejects an unsigned card outright, is
implemented and inert behind the OPTIONAL `enforcePhaseC` flag. See
[`specs/ink-agent-card-signature.md`](specs/ink-agent-card-signature.md).
`isInkEndpointUrl` exposes the narrow `https`-only endpoint grammar Agent Card
endpoint fields validate against.

**Receipts and audit.** `verifyReceipt({receipt, senderPublicKey, expected})`
checks a delivery receipt against the message it acknowledges: the issuer's
signature plus `from`, `to` and `messageId`, the recomputed message hash and an
optional `disposition`. For witness-backed evidence, `verifyInclusionReceipt`
takes an `event` option that recomputes the leaf hash and binds `event.id` to
`receipt.eventId`, so the proof attests the named event rather than a bare hash.
`verifyInclusionProof` and `verifyConsistencyProof` are the RFC 6962 primitives
underneath, the second detecting a witness that forks its history rather than
only appending. `verifyCheckpoint(signed, witnessPublicKey, expectedOrigin)`
verifies a signed C2SP checkpoint and binds its log origin; any checkpoint passed
to an anti-rollback cross-check must be verified this way first, since an
unverified checkpoint body is attacker-controllable.

For bilateral audit exchanges, call both `verifyAuditResponseSignature` and
`verifyAuditEventChain`. The signature gate alone does not stop a peer returning
a gapped or forked slice. For witness audit queries, `verifyAuditQueryResponse`
is the composite verifier. Its `verifyEventSignature` callback is REQUIRED,
because Merkle inclusion alone does not prove a real agent produced the event.
The signature-only `verifyAuditQueryResponseSignature` is not sufficient to
accept a witness response on its own.

**Strict input grammars.** `parseInkTimestampMs`, `isInkTimestamp` and
`MAX_TIMESTAMP_LENGTH` expose the RFC 3339 timestamp grammar.
`containsLoneSurrogateEscape` and `hasUnpairedSurrogate` detect a lone UTF-16
surrogate in a signed string before it is parsed.

## Two implementations, one wire

The wire behavior is pinned by agreement between implementations rather than by
one codebase. An independent Go implementation in [`go/`](go/) signs and verifies
alongside this TypeScript reference, and both run a shared conformance vector
corpus in [`conformance/v1/`](conformance/v1/) covering principal normalization,
the signature base, JCS numbers and strings, key rotation, replay and freshness,
the timestamp grammar, the Agent Card and handshake surface, the card signature
rule, and the Merkle inclusion, consistency, checkpoint and audit-leaf-hash
rules. `conformance/v1/manifest.json` indexes the corpus and ships in the package
as a resolvable subpath.

The corpus is itself checked against constructions written from the spec text.
[`conformance/v1/independent/`](conformance/v1/independent/) implements each
signing construction, the RFC 6962 tree rules and the sealed-envelope receive
side from their normative sections, importing nothing from the implementation. A
mutation registry proves the check bites: disabling any registered rule turns the
suite red. A differential fuzzer runs both implementations against each other on
every pull request and at a larger budget nightly; see
[`differential/README.md`](differential/README.md).

## Agent-assisted implementation

If you are asking an AI coding agent to add INK support to an existing service, the canonical packet for that workflow is the [Agent-assisted implementation](https://ink.tulpa.network/guides/agent-assisted-implementation/) guide. It contains the curated implementer prompt, a mandatory traceability matrix, the conformance checklist, and a human-review checklist. The guide is updated as the protocol evolves; treat it as the live source rather than copying its contents into your repo.

Adopters who want the second open implementation to cross-check against can use the [`examples/foreign-sender-receiver/`](examples/foreign-sender-receiver/) TypeScript reference and the [`examples/interop-cli/`](examples/interop-cli/) Python from-scratch sender.

## Tests

```bash
npm test            # vitest
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm run check:surface   # public-surface drift check
npm run check:facts     # documented-fact drift check
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
  audit/       hash-chained audit events and Merkle checkpointing
bin/           the verify-inclusion CLI
go/            the independent Go implementation
conformance/   the shared vector corpus both implementations run
differential/  the differential fuzzer that runs them against each other
interop-lab/   a containerized sender and receiver for end-to-end runs
examples/      reference sender, receiver, relying party and a Python CLI
specs/         protocol spec documents
governance/    release evidence, decisions, readiness criteria
docs/          maturity notes, threat model, key rotation rules, brand assets
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
- Interop conventions with identity systems other than key-derived principals and `did:web`
- Receipt and audit envelope shape for third-party witnesses

## Naming

You will see `network.tulpa.*` on the wire (e.g. `network.tulpa.intent`) and `ink.tulpa.network` for the docs site. Both are historical artifacts of the protocol's origin and do not imply a runtime dependency on Tulpa. A vendor-neutral namespace may be introduced in a future revision.

As a first, non-breaking step in that direction, agentIds may use either the canonical `tulpa:` method prefix or the `ink:` alias; both encode the same Ed25519 key and denote the same actor. `deriveAgentId` still emits `tulpa:`, and `extractPublicKeyFromAgentId` accepts both (accept-both, emit-one). A receiver MUST collapse the two spellings to one prefix-independent principal for all per-sender security state (blocks, rate limits, duplicate-payload checks, cached keys, connection identity).

## Relationship to Tulpa

INK is developed by [Ad Astra Computing](https://adastracomputing.com) as the underlying protocol for [Tulpa](https://tulpa.network). The spec and the library in this repo are deliberately free of Tulpa product code so other agent platforms can adopt INK without inheriting Tulpa's surface area. Tulpa's product integration (message orchestration, marketplace, user-facing APIs) lives in a separate codebase.

## Interoperability

INK is a wire protocol, and cross-platform interop is a primary design goal. Any service that publishes an Agent Card at the versioned discovery path and exposes an inbound `/ink/v1/...` endpoint can accept signed envelopes from agents that live on other platforms. No DID method is required: the identifier on the card can be a key-derived `tulpa:` or `ink:` principal that carries its own signing key, a `did:web` identity rooted in a DID document, or any other stable identifier under which an Ed25519 signing key is published. What a receiver needs is a key it can resolve and a signature it can check.

[`tulpa.network`](https://tulpa.network) is one current example of an accepting endpoint. Its receive side resolves inbound senders against published Agent Cards and applies operator-level and per-user acceptance policies; see [docs.tulpa.network/guide/foreign-agents](https://docs.tulpa.network/guide/foreign-agents/) for how a Tulpa user opts in. The protocol is intended to support other accepting endpoints.

If you are implementing INK in production or building an independent implementation, write to [ink@tulpa.network](mailto:ink@tulpa.network). Implementer questions get direct maintainer help, and what you run into feeds the conformance corpus before 1.0 freezes it.

## Contributing

Bug reports, spec feedback and test contributions are welcome. A protocol change
starts as a discussion and lands with a spec file in [`specs/`](specs/); a bug fix
or a test can go straight to a pull request. Read
[`CONTRIBUTING.md`](CONTRIBUTING.md) first: every commit needs a
`Signed-off-by:` trailer under the
[Developer Certificate of Origin](governance/DCO.txt), and a pull request has to
clear the type, lint, surface and fact checks along with the conformance corpus
and the differential fuzzer before it can merge.

```bash
npm install
npm test
git commit -s -m "Reject empty key window"
```

Governance, including who decides a wire change, is in
[`GOVERNANCE.md`](GOVERNANCE.md).

## Security

See [`SECURITY.md`](SECURITY.md) for the disclosure path. The threat model is in [`docs/threat-model.md`](docs/threat-model.md). **Do not open a public issue for security problems.**

## License

Dual-licensed under either of:

- MIT ([`LICENSE-MIT`](LICENSE-MIT))
- Apache 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))

at your option. The Apache 2.0 license includes an explicit patent grant; MIT is the simpler text. Pick whichever fits your downstream policy. This covers the code, specs, docs and test vectors. Contributions are accepted under both licenses.

[^ck]: Machine-checked value, recomputed from the repository by `npm run check:facts`. Do not hand-edit it to match a document; change the source of truth and rerun the check.
