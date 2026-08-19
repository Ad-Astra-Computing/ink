# Independent constructions

`generate.mjs` imports the signing and encoding primitives from `../../dist/index.js`,
so every signature byte in the corpus is produced by the implementation the
corpus exists to validate. Accept and reject expectations are hand-written; the
bytes are not. A systematic divergence between the reference and the spec is
therefore invisible to the corpus, and it propagated to the Go verifier, which
was written to match the reference rather than the spec.

This directory is the second opinion. Each module implements one construction
from its normative text, citing the section it came from, and imports nothing
from `src/`, `dist/` or the Go tree:

| module | construction | source |
|---|---|---|
| `jcs.mjs` | RFC 8785 canonicalization | RFC 8785 §3.2 |
| `multibase.mjs` | base58btc and the ed25519-pub multicodec | multibase and multicodec tables |
| `signature-base.mjs` | transport signature base | `specs/ink-protocol.md` §3.3 |
| `body-signature.mjs` | body signature base and its version-keyed domain | `specs/ink-protocol.md` §3.6 |
| `card-signature.mjs` | Agent Card and rotation-link bases | `specs/ink-agent-card-signature.md` §3.2, §5 |
| `principal.mjs` | principal normalization | `specs/ink-protocol.md` §7 |
| `audit-and-chain.mjs` | audit domains, RFC 6962 leaf, delegation parent hash | `specs/ink-protocol.md` §3.6, `specs/ink-merkle-leaf.md`, `specs/ink-authorization-chain.md` |

`../../../test/conformance-independent.test.ts` re-verifies every signature the corpus records against bases
built here. An accept case whose signature does not verify means the corpus and
the spec disagree, which is the failure the corpus could not previously report.

## Coverage

The base profile's crypto-bearing vectors are covered, plus the signed bytes of
the authorization, discovery and audit profiles. Grants and authorization
challenges need no construction of their own: they sign under the §3.6 body
base, so the same module covers them.

Not yet covered, and honest about it: `payload-encryption` (an AEAD binding
rather than a signature, so it needs X25519 and HKDF rather than a preimage),
the witness `merkle-checkpoint`, `merkle-consistency` and `merkle-inclusion`
proof recomputation, and the `authorization-chain` parent-hash linkage, whose
construction is written here but not yet asserted against vectors.

## What independence does and does not mean

Independent of INK's code, not of the JavaScript runtime. RFC 8785 §3.2.2
defines number and string serialization by reference to ECMAScript, so
`JSON.stringify` on a scalar is the normative algorithm rather than a shortcut
past it. Ed25519 itself stays on `@noble/ed25519`: the signature primitive is
not what these vectors are testing, the bytes fed to it are.

## Adding a construction

Write it from the spec section, cite the section in the module, and add a case to
`test/conformance-independent.test.ts`. Do not consult `src/` while writing it. Reading the
implementation first is how the corpus became circular, and it is the one thing
this directory exists to avoid.
