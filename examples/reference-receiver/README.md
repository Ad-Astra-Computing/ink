# INK Reference Receiver

A publicly addressable INK receiver, built solely on the public surface of
`@adastracomputing/ink`. Anyone with a `did:web:`-resolvable agent can sign an
envelope, POST it with an INK Authorization header, and the worker verifies the
header against the sender's published card and replies with a plain JSON
acknowledgement.

The goal: prove the OSS INK package, by itself, is enough to build a working
receiver. No internal Tulpa modules. No private fork of the schema. Code
adopters can lift directly.

## What it accepts

| Intent | What the receiver does |
|--------|-----------------------|
| `connection_request` | The foreign-first-contact bootstrap intent. Returns `{ ok: true, inReplyTo, receiverDid, receivedIntent, correlationId }`. |
| `intro_request` | Same plain ack. |
| `ping` | Same plain ack — minimal liveness check. |
| `ask` | Same plain ack; payload is logged in the audit ring. |

Everything else is rejected with `400 unsupported_intent`.

## Sender DID methods

- **`did:key:`** — the public key is decoded inline from the identifier. No
  fetch, no SSRF surface. This is what the [`interop-cli`](../interop-cli/)
  reference sender uses, so it is the quickest way to exercise the receiver.
- **`did:web:`** — the sender's agent card is resolved over HTTPS behind the
  SSRF guards in `did-web-resolver.ts`, and the card's `agentId` must match the
  DID (identity binding).
- Any other method is rejected as an unresolvable sender.

## Authentication model

The receiver implements INK transport-layer authentication: the sender computes
`signInkMessage` over `{ method, path, recipientDid, body, timestamp }`, wraps
the signature in `Authorization: INK-Ed25519 <sig>`, and POSTs the envelope as
the request body. The worker calls `verifyInkAuth` from the package; the call
enforces the spec's signature, timestamp freshness, and replay-nonce checks in
one place. The receiver does NOT reimplement those checks.

The receiver does NOT sign its response in Phase A. The body is a plain JSON
ack with `inReplyTo` so the caller can correlate. Phase B should either wrap
the ack in a signed INK envelope or push a separate signed response back to
the sender's published inbox.

## What it does NOT do (intentional Phase A cuts)

- Envelope-level signed responses (see Phase B note above).
- End-to-end encryption (cleartext payloads only).
- Receipt persistence beyond a 7-day rolling KV audit log.
- Anything resembling a policy / abuse / spam layer.

For receive-side patterns that include those, see
[`examples/foreign-sender-receiver`](../foreign-sender-receiver/) which is the
policy + SSRF-defense reference, and the production receiver operated by Ad
Astra Computing at `api.tulpa.network`.

## Layout

| File | Purpose |
|------|---------|
| `src/index.ts` | Cloudflare Worker entry. Routes, rate limit, audit hand-off. |
| `src/keys.ts` | Load Ed25519 identity from secrets; self-check at boot. |
| `src/agent-card.ts` | Build the AgentCard document served at `/ink/v1/<agentId>/agent.json`. |
| `src/did-web.ts` | Build the DID document for `/.well-known/did.json`. |
| `src/did-web-resolver.ts` | Resolve a sender's `did:web` to their agent card (SSRF-guarded). |
| `src/inbound.ts` | Envelope validation + `verifyInkAuth` + plain JSON ack. |
| `src/rate-limit.ts` | Per-IP and per-sender KV-backed sliding window. |
| `src/audit-log.ts` | 7-day KV audit ring of accepted / rejected envelopes. |
| `src/nonce-store.ts` | In-memory ring buffer used by `verifyInkAuth` for replay defense. |
| `test/*.test.ts` | Vitest tests for the pure helpers. |

## Deploy

This example requires `@adastracomputing/ink` 0.12.0 or newer, for
`parseSignedBodyBytes`. Running `npm install` here resolves the pin in
`package.json` directly. If you lift this code into your own project, decide
which dist-tag you want: `npm install @adastracomputing/ink@next` tracks the
current pre-1.0 line, while the default `latest` resolves to the most recent
release a maintainer has stamped adopter-grade, which may lag `next`. Both
currently satisfy this example's floor.

```sh
cd examples/reference-receiver
npm install
npm run typecheck
npm test

# Mint a signing keypair offline (any libsodium-compatible tool works):
#   node -e "import('@adastracomputing/ink').then(async m => {
#     const kp = await m.generateKeypair();
#     console.log('seed_base64url:', m.base64urlEncode(kp.privateKey));
#     console.log('public_multibase:', m.encodePublicKeyMultibase(kp.publicKey));
#   })"

# Push the secret + public-key vars:
wrangler secret put INK_RECEIVER_SIGNING_SEED
wrangler kv namespace create INK_RECEIVER   # paste id into wrangler.toml
# Add INK_RECEIVER_PUBLIC_KEY_MULTIBASE and INK_RECEIVER_HOST under [vars].

# Deploy:
wrangler deploy
```

After deploy, the receiver answers on the host you configured. Confirm with:

```sh
# The discovery path, the one the reference library's fetchAgentCard builds:
curl "https://<your-host>/ink/v1/did%3Aweb%3A<your-host>/agent.json"
# Byte-identical alias, for consumers that resolve by the well-known convention:
curl https://<your-host>/.well-known/ink/agent.json
curl https://<your-host>/.well-known/did.json
```

## Send a test envelope

Use the [`examples/interop-cli`](../interop-cli/) Python sender to exercise the
wire format end-to-end. It signs from a `did:key:`, which this receiver decodes
inline:

```sh
cd ../interop-cli && pip install -e .
ink-interop keygen --out-seed /tmp/sender.seed   # prints the did:key

ink-interop send \
  --seed /tmp/sender.seed \
  --from-did did:key:<printed-multibase> \
  --to-did did:web:ink-echo.tulpa.network \
  --target-url https://ink-echo.tulpa.network/ink/v1/inbound \
  --path /ink/v1/inbound \
  --intent-type connection_request \
  --purpose "interop smoke"
```

A `200` with `{ "ok": true, ... }` means your envelope is on the canonical wire.
Point `--to-did` / `--target-url` at your own deployment to test it instead.

## Live reference deployment

Ad Astra Computing runs this example at **ink-echo.tulpa.network**:

- DID: `did:web:ink-echo.tulpa.network`
- Landing page: <https://ink-echo.tulpa.network/>
- Agent card: <https://ink-echo.tulpa.network/ink/v1/did%3Aweb%3Aink-echo.tulpa.network/agent.json>
  (byte-identical alias: <https://ink-echo.tulpa.network/.well-known/ink/agent.json>)
- DID document: <https://ink-echo.tulpa.network/.well-known/did.json>
- Inbound endpoint: `https://ink-echo.tulpa.network/ink/v1/inbound`

Treat the live deploy as a moving target. Keys rotate, rate limits drop
unauthenticated callers, and the deploy may go offline without notice. The
canonical artifact is the source in this directory, not the live URL.

## Replay defense in multi-isolate deployments

`nonce-store.ts` is an in-memory ring buffer scoped to a single Cloudflare
Worker isolate. Cloudflare may run the same worker in many isolates across
regions, so a determined replay attacker can land their second request on a
different isolate and slip past the local ring. The OSS `verifyInkAuth`
fails closed when no nonce store is provided, so it WILL refuse the request,
but the per-isolate ring is not a substitute for a KV-backed nonce store for a
production receiver. Adopters with non-test traffic should swap in a KV (or
Durable Object) implementation.

## Production status

This receiver is the publicly-routable test target Ad Astra Computing operates
against the OSS INK package. It is intentionally minimal so a single page of
code review covers the whole worker. Treat it as a starting point, not a
template for a hardened production receiver.

If you spot a security gap, please open an issue in the
[ink repo](https://github.com/Ad-Astra-Computing/ink/issues).
