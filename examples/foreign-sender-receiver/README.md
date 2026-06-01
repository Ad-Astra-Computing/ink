# Foreign-Sender Receiver Example

A self-contained TypeScript implementation of the receive-side patterns documented in the [Accepting Foreign Senders implementer guide](https://ink.tulpa.network/guides/accepting-foreign-senders/). It is not a runnable service on its own — the code is structured as small, focused modules so an integrator can lift any one of them into their own receiver.

## What's here

| File | What it shows |
|------|---------------|
| `src/inbound-policy.ts` | The per-user acceptance policy shape, decision precedence (block list → native → opt-in → allow-lists), and canonicalization rules. Decision function is pure and tested. |
| `src/did-web-resolver.ts` | `did:web:` DID-document URL derivation, host validation, private-IP rejection, and DNS-rebinding defenses. |
| `src/outbound-delivery.ts` | The companion sender-side primitive: SSRF-safe HTTPS POST with INK §3.3 Authorization signing, IPv6-literal rejection, and identity binding for `did:web` recipients. |
| `src/index.ts` | Re-exports the public surface so a consumer can `import { evaluateInboundForeign, didWebToDocUrl } from "../examples/foreign-sender-receiver"`. |

There is no Durable Object, no SQLite, no Cloudflare Worker glue. Plug the modules into whatever runtime you use.

## How it relates to other reference material

- **`@adastracomputing/ink`** — the canonical signing/verification library. This example uses the library's primitives where appropriate; the example's code is the *policy + transport* layer that sits on top of those primitives.
- **`examples/interop-cli/`** — Python sender that exercises the wire format end-to-end. Run it against any receiver you build with this example to confirm interop.
- **The implementer guide** at [ink.tulpa.network/guides/accepting-foreign-senders/](https://ink.tulpa.network/guides/accepting-foreign-senders/) — describes the *why* behind every guard in this code. Read it first.

## Production status

The patterns shown here are derived from a production INK receiver (operated by Ad Astra Computing) and several rounds of external security review. They are not a complete service implementation; they are the load-bearing decision and SSRF-defense surfaces that have caught real bugs.

If you find a gap or a bypass, please open an issue in this repo.

## Build

```sh
cd examples/foreign-sender-receiver
npm install
npm run typecheck
```

The example has zero runtime dependencies. `npm install` is only used to fetch types.
