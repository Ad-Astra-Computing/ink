# `ink-interop` — non-tulpa INK reference client

A standalone Python CLI that talks INK end-to-end **without depending on
`@adastracomputing/ink`**. Generates Ed25519 keys, builds envelopes by
hand, signs them with a hand-rolled JCS canonicalizer, and posts them to
any INK endpoint.

The point: if the spec is only implementable by the same code that wrote
the spec, the spec isn't really portable. This CLI proves the wire
contract is implementable cold and gives external integrators a small
reference to read.

## Install

```sh
pip install -e .
```

Requires Python 3.11+.

## Usage

### Generate a fresh keypair

```sh
ink-interop keygen --out-seed ./alice.seed
```

The seed file is the 32-byte hex private seed. The command sets it to
mode `0600`; you are responsible for keeping it out of version control.

### Inspect a remote agent card

```sh
ink-interop discover https://api.tulpa.network/ink/v1/<agentId>/agent.json
```

Prints the agent id, endpoint, and decoded active signing keys (raw hex
for easy comparison).

### Build a signed intent (dry run, no network)

```sh
ink-interop build \
  --from-did did:key:zSendersPublicKey \
  --to-did did:plc:recipient \
  --purpose "Meet at INK day"
```

Outputs JSON containing:

- Sender public key (hex, multibase, `did:key:` form)
- Full request the CLI would send (URL, headers, body)
- Wire details (JCS canonical body bytes, the exact plaintext signature
  base, the raw signature hex, the timestamp)

This is the easiest way to verify the wire shape against a debugger or
the INK [Signing reference](https://ink.tulpa.network/spec/authentication).

### Send a signed intent

```sh
ink-interop send \
  --seed ./alice.seed \
  --from-did did:key:zSendersPublicKey \
  --to-did did:plc:recipient \
  --target-url https://api.tulpa.network/ink/v1/<agentId>/intent \
  --purpose "Meet at INK day"
```

Prints the response status, headers, and JSON body.

## What this client implements

- **JCS canonicalization** (RFC 8785) — keys sorted by UTF-16 code units,
  short escape sequences, lowercase `\\u` hex for control characters,
  integer-valued floats serialized as integers. No third-party JCS lib.
- **Ed25519 signing** via the `cryptography` package (audited native
  bindings, constant-time verify).
- **Signature base** per INK §3.3:
  `PROTOCOL + "\n" + METHOD + "\n" + PATH + "\n" + recipientDid + "\n" + JCS(body) + "\n" + timestamp`.
- **Authorization header**: `INK-Ed25519 <base64url(signature)> [keyId=...]`.
- **Multibase encoding** for public keys (`z` + base58btc(0xed01 || key))
  per the W3C `did:key` and Multikey specs.
- **Agent card discovery** with the same fail-closed semantics as the
  tulpa-side resolver: 64 KB body cap, `Cache-Control` respected,
  redirects refused, fail-closed when the card endpoint is unreachable.

## What it does NOT implement

- **DID method resolution beyond `did:key:`**. There is no `did:web:`,
  `did:plc:` directory lookup, or agent card cross-validation here.
  Other DID methods are the receiver's job (or future work on this
  client; see roadmap in the INK repo).
- **Encrypted envelopes** (INK §3.4). The `send` command only handles
  plaintext intents.
- **Key rotation flows**. The CLI can include a `keyId` parameter in
  the Authorization header but does not generate rotated key sets.

## Tests

Tests run against the same JSON vectors that
`@adastracomputing/ink` publishes (`../../test-vectors/`), so a
divergence between this client and the reference library will fail
locally and in CI.

```sh
pip install -e ".[dev]"
pytest
```

## License

MIT OR Apache-2.0 — your choice.
