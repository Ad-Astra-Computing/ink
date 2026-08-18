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
| `src/agent-card.ts` | Build the AgentCard document served at `/ink/v1/<agentId>/agent.json`. Deterministic: no clock, no randomness. |
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

Node 24 is the only prerequisite. With nix,
`nix develop ..#reference-receiver` from this directory supplies one without
installing anything globally. Wrangler comes from this example's own
`package.json`, so `npm install` is what puts it on your path.

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
# Add INK_RECEIVER_PUBLIC_KEY_MULTIBASE, INK_RECEIVER_HOST and (optionally)
# INK_RECEIVER_CARD_UPDATED_AT under [vars]. See "A deterministic card" below.

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

## A deterministic card

The card body is a pure function of configuration and key material. The same
`INK_RECEIVER_HOST`, the same `INK_RECEIVER_CARD_UPDATED_AT` and the same
signing seed produce the same bytes in every isolate, in every process and at
every moment, `cardSignature` included. That is what lets the versioned
discovery path and the `/.well-known/ink/agent.json` alias be byte-identical,
and it is what keeps a consumer polling the card from seeing an update that
never happened.

Determinism is a property of the card, not of any cache. Cloudflare gives a
low-traffic worker a cold isolate for nearly every request, so a per-isolate
cache is missed most of the time and could never have carried this guarantee;
the one in `src/index.ts` exists only to keep the Ed25519 signature off the hot
path. If you fork this receiver, do not put a clock read, a random value or a
counter into the card. Nothing else in the document varies, so `updatedAt` is
the one field that had to be pinned:

| Var | Meaning |
|-----|---------|
| `INK_RECEIVER_CARD_UPDATED_AT` | The card's `updatedAt`, a strict RFC 3339 timestamp. Optional; unset takes `DEFAULT_CARD_UPDATED_AT` from `src/agent-card.ts`. A value that is not strict RFC 3339 fails the request with `receiver_misconfigured` naming this var. |

Bump it by hand when you actually change what the card says. The spec supports
this reading directly: `updatedAt` is informational and "carries no comparison
rule" (`specs/ink-agent-card.md`), `keySetVersion` is the sole monotonic
quantity and a verifier MUST NOT reject on `updatedAt` ordering
(`specs/ink-agent-card-signature.md` §6), and a resolver MUST NOT derive a
cache lifetime from it (`specs/ink-resolver.md`). It must be present on a signed
card and it must parse; nothing reads more into it than that.

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

### When your sender cannot be resolved

A `did:web:` sender is verified against the signing keys on its published agent
card, so the receiver has to resolve that card first. When it cannot, the `400`
carries `"code": "sender_key_unresolved"` plus a `reason` naming the step that
failed and a `hint` describing the fix:

| `reason` | What to fix |
| --- | --- |
| `did_unresolvable` | The identifier is malformed or names a host the receiver will not fetch. Public https names only, no IP literals or private addresses. |
| `did_document_unreachable` | Publish a DID document at the did:web document URL. |
| `card_absent_from_discovery_path` | Serve the card at `/ink/v1/<agentId>/agent.json`, or declare an `InkAgentCard` service endpoint in the DID document. |
| `card_absent_from_service_endpoint` | The DID document names an `InkAgentCard` endpoint that serves nothing. It must be https and on the DID's own authority. |
| `card_schema_invalid` | The served card does not validate against the agent card schema. |
| `card_agent_id_mismatch` | The card announces a different `agentId` than the DID being resolved. |
| `unsupported_did_method` | This receiver resolves `did:key` and `did:web` senders only. |
| `did_key_undecodable` | The `did:key` does not decode to an Ed25519 public key. |

`card_absent_from_discovery_path` is the common one for a peer built against an
older draft. `/.well-known/ink/agent.json` is an alias a publisher may serve,
but it is not a resolution surface: `specs/ink-resolver.md` §3.2 forbids a
resolver from depending on it or falling back to it, so a card published only
there is not discoverable. Serve the versioned discovery path as well.

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
