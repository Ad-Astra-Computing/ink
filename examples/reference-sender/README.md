# INK Reference Sender

A runnable INK sender built solely on the public surface of
`@adastracomputing/ink`. It mints an identity, signs an envelope, discovers
the recipient's inbox, and POSTs the envelope with an INK Authorization
header. It is the send-side companion to the
[reference receiver](../reference-receiver/): point it at that worker (or at
`did:web:ink-echo.tulpa.network`) and watch a full request go through.

The goal is the same as the receiver's: prove the OSS package, by itself, is
enough to build a working sender. No internal Tulpa modules, no private fork
of the schema. Every module is code an adopter can lift directly.

## Quick start

No build step. The CLI runs the TypeScript source directly under Node's
native type stripping. `@adastracomputing/ink` requires Node 24+.

```sh
cd examples/reference-sender
npm install

# Send a ping to the public reference receiver, discovering its inbox
# from its did:web Agent Card.
node bin/ink-send.mjs --to did:web:ink-echo.tulpa.network --intent ping --note "hello"
```

A successful run prints the receiver's JSON acknowledgement:

```
minted ephemeral sender did: did:key:z6Mk...
delivered: status 200
{"ok":true,"receiverDid":"did:web:ink-echo.tulpa.network","receivedIntent":"ping",...}
```

## What it does

| Step | Module | What happens |
|------|--------|--------------|
| Identity | `src/identity.ts` | Mint an ephemeral `did:key`, or load a stable one from a seed. The multibase public key IS the DID, so a receiver decodes the verification key inline with no fetch. |
| Envelope | `src/envelope.ts` | Assemble the canonical fields, attach the domain-separated body signature (`signMessage`), then re-validate with `validateMessage` so a malformed envelope never leaves the process. |
| Discovery | `src/discovery.ts` | `did:web` → resolve the DID document, honour an `InkAgentCard` service entry on the same authority when one is declared, otherwise fetch the versioned card path `/ink/v1/<agentId>/agent.json`, all behind an SSRF gate. Apply the discovery response contract (status 200, JSON, size cap, `AgentCardSchema`, protocol, agentId binding), then read the inbox with `resolveAgentInbox`. `did:key` → the endpoint must be supplied with `--endpoint`. |
| Transport | `src/transport.ts` | SSRF-validate the target URL (host check in `src/host-safety.ts`), sign the INK §3.3 Authorization over `{method, path, recipientDid, body, timestamp}`, POST with a bounded timeout, `redirect: "manual"`, and a capped response read. |

`src/index.ts` ties them together as `sendIntent`. `src/cli.ts` is the thin
argument-parsing and orchestration layer behind `bin/ink-send.mjs`.

## The two signatures

An INK request carries two distinct signatures, and the example keeps them
separate on purpose:

1. **Body signature** (`envelope.signature`) commits to the canonical
   envelope fields and travels inside the JSON. It proves authorship
   independent of transport.
2. **Transport signature** (the `Authorization: INK-Ed25519 ...` header) binds
   the request to one endpoint path, freshness window, and replay nonce per
   INK §3.3. It is signed over the full envelope, so the body signature is
   attached first, and over the envelope's own `timestamp` field, so the
   receiver's `verifyInkAuth` reconstructs the identical signature base.

## Recipients

- **`did:key:`** — self-certifying, no SSRF surface, the quickest target.
  There is no service endpoint to look up, so pass `--endpoint`.
- **`did:web:`** — the inbox is discovered from the Agent Card at the versioned
  discovery path, `https://<host>/ink/v1/<agentId>/agent.json`, or at the
  `InkAgentCard` service endpoint the DID document names when it names one on
  the same authority. The `/.well-known/ink/agent.json` alias is never fetched:
  a resolver must not depend on it, so a peer that publishes only the alias is
  not discoverable. A `%3A`-encoded port is carried into both discovery and
  delivery. Pass `--endpoint` to override.

## Identity

Without an identity in the environment, a fresh ephemeral `did:key` is minted
each run and its DID is printed. For a stable DID a receiver can allow-list,
mint one once and export both halves:

```sh
node bin/ink-send.mjs --keygen
# did: did:key:z6Mk...
# INK_SENDER_SIGNING_SEED=...
# INK_SENDER_PUBLIC_KEY_MULTIBASE=z6Mk...
export INK_SENDER_SIGNING_SEED=... INK_SENDER_PUBLIC_KEY_MULTIBASE=z6Mk...
```

The seed is the secret; treat it like a private key.

## Security posture

The SSRF gate (https only, no userinfo, no fragment, no IP-literal or
private/loopback/cloud-metadata host) is a compact static-literal classifier
in `src/host-safety.ts`, the same shape the `foreign-sender-receiver` example
carries. It does **not** defend against DNS rebinding: a public hostname
that resolves to a private IP at connect time still needs connect-time IP
pinning at the platform layer. Pass a custom `fetchImpl` (an undici dispatcher
on Node, `cf.resolveOverride` on Workers) when the destination is untrusted.

For `did:web` recipients the delivery URL host must equal the DID host, so a
signed envelope for one identity cannot be redirected to an unrelated endpoint.

## How it relates to the other examples

- **[`reference-receiver`](../reference-receiver/)** — the runnable receiver
  this sender targets. Together they are a full INK round trip on the OSS
  package alone.
- **[`foreign-sender-receiver`](../foreign-sender-receiver/)** — lift-able
  policy and transport modules (not a runnable service).
- **[`interop-cli`](../interop-cli/)** — a from-scratch Python sender that
  reimplements the wire format without the package, for cross-checking.

## Build and test

```sh
npm install
npm test         # vitest: envelope, transport, discovery, CLI, and a full
                 # round trip through the package's own verification path
npm run typecheck
```

The round-trip test is the proof of interop: it runs each envelope this
sender produces through `validateMessage`, the body-signature check, and
`verifyInkAuth` — the exact path a package-based receiver runs — and asserts
acceptance, plus a replayed-nonce rejection.
