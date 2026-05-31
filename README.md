<img src="docs/logo.svg" alt="INK" width="200">

# INK: Inter-agent Networking Kernel

An open protocol for AI agents that need to send each other typed, signed messages on the public web. Built for scheduling, introductions, receipts, and other coordination flows where a user delegates an agent to act on their behalf.

**Status: v0.1, experimental.** Wire formats, trust semantics, and APIs may change without backward-compatible migration before v1.0.

| | |
|---|---|
| Spec | [`specs/`](specs/) |
| Docs | [ink.tulpa.network](https://ink.tulpa.network) |
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Security | [`SECURITY.md`](SECURITY.md) |
| Code of Conduct | [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |

## What's in the envelope

Every INK message is an Ed25519-signed envelope over a [JCS](https://datatracker.ietf.org/doc/html/rfc8785) (RFC 8785) canonical serialization. The signature base binds the protocol version, HTTP method, request path, recipient DID, body, and timestamp. Replay protection uses a per-sender nonce plus a timestamp freshness window of 5 minutes past and 30 seconds future.

Message types cover intents, challenges, resolutions, receipts, audit events, encrypted payloads, and authenticated agent-card queries. Handshake messages carry a correlation ID; audit and receipt messages do not. Key rotation is governed by an authority rule documented in [`docs/key-rotation-rule.md`](docs/key-rotation-rule.md): the Agent Card's published key set is canonical, revoked keys never verify, and a stale bootstrap key cannot bypass rotation.

INK assumes [AT Protocol](https://atproto.com) for identity by default but isn't coupled to it. Any system that can publish an Ed25519 signing key under a stable identifier can participate.

## Install

```bash
npm install @adastracomputing/ink
```

The package ships compiled ESM with bundled type definitions (`dist/index.js` + `dist/index.d.ts`). Any project with a standard JS toolchain can import it directly — no TypeScript build step on the consumer side. The build runs automatically via `prepack` before publish.

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
    type: "network.tulpa.intent",
    from: agentId,
    to: "tulpa:zRecipient",
    intent: "meeting_request",
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

## What's stable in v0.1

Reliable to depend on:

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

## Relationship to Tulpa

INK is developed by [Ad Astra Computing](https://adastracomputing.com) as the underlying protocol for [Tulpa](https://tulpa.network). The spec and the library in this repo are deliberately free of Tulpa product code so other agent platforms can adopt INK without inheriting Tulpa's surface area. Tulpa's product integration (message orchestration, marketplace, user-facing APIs) lives in a separate, closed-source codebase.

## Security

See [`SECURITY.md`](SECURITY.md) for the disclosure path. The threat model is in [`docs/threat-model.md`](docs/threat-model.md). **Do not open a public issue for security problems.**

## License

Dual-licensed under either of:

- MIT ([`LICENSE-MIT`](LICENSE-MIT))
- Apache 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))

at your option. The Apache 2.0 license includes an explicit patent grant; MIT is the simpler text. Pick whichever fits your downstream policy. This covers the code, specs, docs, and test vectors. Contributions are accepted under both licenses.
