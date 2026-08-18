# INK interop lab

One command runs a full INK exchange between the TypeScript reference
implementation and the Go implementation, over real HTTP, in isolated
containers, and asserts the outcome of every step.

```sh
./interop-lab/run.sh
```

It builds two images, starts four services on a container network with no route
off it, runs two drivers, prints their assertions and tears everything down.
Exit code 0 means every assertion passed; 1 means at least one failed.

## Why it exists

The conformance corpus proves both implementations agree on a fixed set of
bytes. It cannot prove they agree on a live exchange, because both sides read
the same fixture file. Here each side produces its own bytes at run time, hands
them to the other side over a socket, and the decision is read back as an HTTP
status or a typed verdict. If the two implementations disagree about
canonicalization, domain separation, header shape, replay state or AAD binding,
an assertion fails.

## What runs

| Container | Image | What it is |
|---|---|---|
| `ts-receiver` | ts | The reference receiver from `examples/reference-receiver`, unmodified, behind the `node:http` adapter from `examples/docker-receiver`. Serves its DID document, its signed Agent Card and its inbox. |
| `ts-peer` | ts | Lab fixture. Opens encrypted envelopes and verifies envelope body signatures, the two consuming operations the reference receiver does not offer. |
| `go-verifier` | go | The verification service from `go/cmd/ink-verify-server`, unmodified. |
| `go-peer` | go | Lab fixture. Opens encrypted envelopes and runs the Agent Card signature verifier, which the verification service does not expose. |
| `go-driver` | go | One-shot. Produces Go artifacts, asserts against the TypeScript side, exits 0 or 1. |
| `ts-driver` | ts | One-shot. Produces TypeScript artifacts, asserts against the Go side, exits 0 or 1. |

Both peers are lab fixtures and neither is a product surface: every
cryptographic decision inside them is made by the reference library for that
language, and the handler only decodes a request, calls the library and encodes
the typed result.

## What each assertion proves

`go-driver`, Go produces and TypeScript verifies:

| Assertion | What it proves |
|---|---|
| card fetch returns 200, carries an agentId | The receiver publishes a discoverable card over HTTP. |
| Go schema accepts the TypeScript card | The two schema validators agree on a live card, not a fixture. |
| verify service accepts the card | The same verdict is reachable over the Go service's HTTP surface. |
| did document returns 200 and publishes a verification key | The did:web anchor a card signature roots under is reachable. |
| Go authenticates the TypeScript card signature | Cross-implementation Agent Card proof: JCS canonicalization, the `ink/agent-card` domain, the legacy `bootstrap` key resolution and did:web rooting all agree. This is the Phase B posture, where the producer signs its card. |
| Go rejects a tampered card signature | The proof is checked, not assumed. |
| schema check alone does not catch the tamper | Documents that the verification service's `/verify/card` is a schema check; a consumer that stops there has not authenticated the key set. |
| receiver accepts the Go-signed intent | The core wire exchange: a Go sender's envelope and its §3.3 Authorization header are accepted by the TypeScript receiver. |
| acknowledgement correlates to the sent envelope | The ack carries `inReplyTo` for the envelope actually sent. |
| TypeScript verifies the Go envelope body signature | The Go-built canonical body bytes match what the TypeScript body-signature verifier reconstructs, under the legacy signing domain that `ink/0.1` selects. |
| receiver rejects the replayed nonce | Replay state is enforced across a second identical request. |
| receiver rejects a tampered transport signature | The Authorization signature is verified, and the rejection reason is the signature verdict rather than a parse error. |
| receiver rejects a body altered after signing | The signature binds the body bytes, not just the headers. |
| TypeScript opens the Go-sealed payload | Cross-implementation ECIES: X25519, HKDF, AES-GCM and the canonical AAD all agree, and the recipient binding in the opened plaintext holds. |
| TypeScript refuses a corrupted ciphertext | The GCM tag is checked. |

`ts-driver`, TypeScript produces and Go verifies:

| Assertion | What it proves |
|---|---|
| Go verifies the TypeScript transport signature | The §3.3 signature base is byte-identical across implementations for a live request. |
| Go rejects a tampered transport signature | The verdict is a real verification, not a parse. |
| Go rejects a signature over a body that changed | The signature base commits to the body. |
| Go authenticates the TypeScript card signature | The card proof verifies in the key-derived direction too, where the signer must equal the key inside the `did:key` identity. |
| Go rejects a tampered card signature | The proof is checked. |
| Go rejects a card served under another identity | The identity binding between the card and the requested agent holds. |
| Go peer publishes an encryption key | The seal target is discovered at run time, never configured. |
| Go opens the TypeScript-sealed payload | ECIES agreement in the other direction. |
| Go refuses a corrupted ciphertext | The GCM tag is checked. |
| Go refuses a relabelled wire type | The wire type is bound into the AAD, so a dual-accepted spelling cannot be swapped after sealing. |
| Go refuses an envelope sealed to another key | The recipient key is bound into the AAD. |

## What it deliberately does not prove

- **Not a conformance run.** It exercises a live path, not the vector corpus.
  A green lab and a red conformance run are both possible; they answer
  different questions.
- **Not the transparency log.** Witness submission, inclusion receipts,
  checkpoints and consistency proofs are covered by the verifiers and the
  corpus, and are out of scope here.
- **Not delegation.** Authorization grants, chains and challenges are not
  exercised.
- **Not discovery over the public internet.** The network has no route off
  itself, so did:web resolution against a real host, TLS, redirects and the SSRF
  guards around them are not exercised.
- **Not durability or scale.** The receiver's nonce and rate-limit state is
  in-memory, so the replay assertion proves the check runs, not that it survives
  a restart or holds across replicas.
- **Not performance.** No timing or load claims.
- **Not the published packages.** Both sides are built from the sources in this
  repository, on purpose: the lab tests the tree, not a release artifact.

## What this lab found

Building the first version surfaced two wire-contract gaps, both fixed in the
same change that added the lab:

- The Go implementation had no exported producer for the envelope's own
  `signature` member and its JCS canonicalizer was unexported, so a Go sender
  could not assemble a schema-valid envelope without reimplementing
  canonicalization. The first version of `interop-lab/go/cmd/lab-driver` had to
  do exactly that. Go now exports `SignInkBody` and `JCSCanonicalize`, with
  golden vectors generated from the TypeScript signer pinning byte parity, and
  the driver uses them.
- Both decrypt paths require the sealed plaintext to carry `from` equal to the
  outer envelope sender and `to` equal to the recipient identity the decrypter
  asserts, and neither seal path checked that before encrypting, so a producer
  could mint an envelope no conformant decrypter would open. That is the
  failure the first run of this lab hit. Both `encryptInkPayload` and
  `EncryptInkPayload` now reject the mismatch at seal time.

One note from building it stands as designed and is pinned by lab assertions so
it cannot drift silently:

- The card-signature spec roots exactly two principal kinds, key-derived and
  did:web. A card whose `agentId` is a `did:key` is rejected as an unrooted
  principal, even though `did:key` is a perfectly good transport identity and
  the reference receiver resolves sender keys from it. The lab's TypeScript
  driver therefore signs its card under a key-derived principal while its
  transport identity stays a `did:key`. That split is easy to trip over. In the
  same family: the Go verification service's `/verify/card` endpoint is
  schema-only and never checks `cardSignature`, which the lab asserts
  explicitly so the limitation stays visible.

## Offline and key material

- The container network is created with `--internal`, so no service can reach
  anything outside the lab while the exchange runs.
- Base images are pinned by digest. The image build itself fetches base images,
  npm packages and Go modules; nothing is fetched after that.
- Every identity is minted at container start: the receiver mints its keypair in
  its entrypoint, each peer mints its signing and encryption keys in `main`, and
  each driver mints its sender identity per run. No key material is committed,
  baked into an image layer or shared between runs, and nothing here resembles a
  production credential.

## Layout

```
interop-lab/
  run.sh                       build, run, assert, tear down
  ts/
    Dockerfile                 reference receiver + peer + driver, digest-pinned
    build.mjs                  bundles all four entry points against ./src
    keygen.mjs                 mints the receiver identity at container start
    receiver-entrypoint.sh     mints, exports, execs the receiver
    peer.mjs                   lab peer service
    driver.mjs                 TypeScript-produces assertions
  go/
    Dockerfile                 verification service + CLI + peer + driver
    go.mod                     module with a local replace onto ../../go
    cmd/lab-peer/main.go       lab peer service
    cmd/lab-driver/main.go     Go-produces assertions
```

## Requirements and notes

- The lab runs in CI on every push to `main` and every pull request, as the
  [`interop-lab`](../.github/workflows/interop-lab.yml) workflow. It calls
  `run.sh` unmodified under the runner's Docker, with no caches, so what CI
  proves is that the sources in the tree build and interoperate from scratch.
- Docker or Podman. The script picks whichever is on `PATH`; override with
  `INTEROP_LAB_ENGINE`, which may carry flags.
- The build context is the repository root. Each Dockerfile ships a matching
  `Dockerfile.dockerignore`, which BuildKit reads; an engine that does not read
  per-Dockerfile ignore files will send a larger context but build the same
  image.
- Rootless Podman needs a working user namespace and a container store on a
  filesystem that supports layer extraction. If a pull fails while unpacking,
  point the store somewhere else, for example
  `INTEROP_LAB_ENGINE="podman --root /var/tmp/ink-lab/root --runroot /var/tmp/ink-lab/runroot --storage-driver vfs"`.
