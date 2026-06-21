# Dockerized INK reference receiver

The [reference receiver](../reference-receiver/) is a Cloudflare Worker. This
example runs that **same handler, unchanged**, inside a container — so you can
stand up a working INK endpoint anywhere Docker runs, with no Cloudflare
account. It is the receiver bundled with esbuild and served by a tiny
`node:http` adapter.

The point: INK is a wire protocol, not a platform. The same `@adastracomputing/ink`
code that runs on Workers runs on plain Node, and the bundle proves it.

## Run it with Docker

```sh
npm install
npm run keygen > .env        # mint a receiver identity
docker compose up --build
```

`docker compose up` starts two services and you watch one INK agent talk to
another:

- **receiver** — the bundled reference receiver on port 8787.
- **sender** — a one-shot agent that fetches the receiver's agent card, signs a
  `ping`, POSTs it, prints the acknowledgement, and exits.

Expected sender output:

```
sender:   did:key:z6Mk...
receiver: did:web:ink-receiver.example
status:   200
ack:      {"ok":true,"receivedIntent":"ping",...}
```

## Run it without Docker

Everything works under plain Node 24 (native fetch, Web Crypto, type stripping),
which is also how the container runs it:

```sh
npm install
npm run build                # esbuild-bundle the receiver -> dist/
eval "$(npm run --silent keygen)"   # export the three identity vars
npm start                    # receiver on http://localhost:8787

# in another shell:
RECEIVER_URL=http://localhost:8787 npm run demo "hello"
```

## How it fits together

| File | Role |
|------|------|
| `build.mjs` | esbuild bundles `../reference-receiver` (and the agent demo) into self-contained ESM under `dist/`. The bundle inlines `@adastracomputing/ink`, so the runtime image carries no `node_modules`. |
| `server.mjs` | `node:http` adapter: converts each Node request to a Web `Request`, calls the Worker's `fetch(request, env, ctx)`, writes the `Response` back. Supplies `env` (config from the environment plus an in-memory `INK_RECEIVER` KV shim) and a `ctx.waitUntil` for the receiver's audit writes. |
| `agent-demo.mjs` | The integration example: a sender agent that discovers the receiver and sends a signed `ping` using only the package surface. |
| `keygen.mjs` | Mints the receiver identity and prints the three env vars. |
| `Dockerfile` | Multi-stage: bundle in a build stage, then a runtime stage that is just Node plus `dist/` and `server.mjs`. |
| `compose.yaml` | The receiver plus the one-shot sender agent. |

## Configuration

The server reads the same variables as the Worker:

| Variable | Meaning |
|----------|---------|
| `INK_RECEIVER_SIGNING_SEED` | base64url 32-byte Ed25519 seed (secret). |
| `INK_RECEIVER_PUBLIC_KEY_MULTIBASE` | `z6Mk...` multibase public key, published in the agent card. |
| `INK_RECEIVER_HOST` | bare host used to derive the `did:web` id and the card URLs. |
| `PORT` | listen port (default 8787). |
| `TRUST_PROXY_HEADER` | optional. The receiver rate-limits per client IP via `cf-connecting-ip`. The adapter ignores the client's copy of that header and sets it from the real TCP peer. If you run behind a proxy you control that overwrites a forwarding header, set this to that header name (e.g. `x-forwarded-for`) so the limit keys on the true client. |

## Production notes

This carries the same intentional cuts as the reference receiver: no user auth,
no policy layer, no signed responses. Two container-specific ones to close
before real use:

- **Shared state.** The `INK_RECEIVER` KV shim and the nonce store are
  in-memory, so rate-limit counters and replay-nonce tracking are per-process.
  Run one replica, or swap in a shared store (Redis, a KV service, Postgres) so
  limits and replay protection hold across restarts and replicas.
- **TLS and host.** INK endpoints are `https`. Terminate TLS at a proxy in front
  of this container and set `INK_RECEIVER_HOST` to the public host that serves
  the `did:web` document at `/.well-known/did.json`.

DNS-rebinding and connect-time SSRF defenses for outbound card fetches are the
platform's responsibility, as in the reference receiver.
