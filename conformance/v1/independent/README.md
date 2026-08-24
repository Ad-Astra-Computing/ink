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
| `audit-and-chain.mjs` | audit domains, inclusion-receipt base, RFC 6962 leaf and proof walk, delegation parent hash | `specs/ink-protocol.md` §3.6, `specs/ink-merkle-leaf.md`, `specs/ink-merkle-inclusion.md`, `specs/ink-inclusion-receipt.md`, `specs/ink-authorization-chain.md` |

`../../../test/conformance-independent.test.ts` re-verifies every signature the corpus records against bases
built here. An accept case whose signature does not verify means the corpus and
the spec disagree, which is the failure the corpus could not previously report.

## Coverage

The base profile's crypto-bearing vectors are covered, plus the signed bytes of
the authorization, discovery and audit profiles. Grants and authorization
challenges need no construction of their own: they sign under the §3.6 body
base, so the same module covers them.

Not yet covered, and honest about it:

- `payload-encryption`, an AEAD binding rather than a signature, so it needs
  X25519 and HKDF rather than a preimage.
- The witness `merkle-checkpoint` and `merkle-consistency` proofs. Neither
  category carries a crypto artifact in the corpus today, so there is nothing
  here for this to check.
- `handshake-message`, same reason.

Everything else that carries a signature or a hash is covered: the base profile,
grants, authorization challenges, discovery envelopes, audit query responses and
their per-event `agentSignature`, inclusion receipts, the RFC 6962 leaf hash and
inclusion-proof walk, and delegation link signatures.

## The mutation registry

`mutants.json` in this directory names one mutant per rule these modules
enforce. `npm run check:mutants` applies each one, runs the oracle suite, and
requires a red run; a mutant the suite survives means the rule it disables is
constrained by nothing. The weekly conformance workflow runs it, so the claim
that this oracle is not vacuous re-earns itself on cadence instead of resting on
a demonstration performed once.

A find string that stops matching fails the harness rather than skipping, so a
refactor that would silently retire a mutant has to update the registry in the
same change.

## What independence does and does not mean

Independent of INK's code, not of the JavaScript runtime. RFC 8785 §3.2.2
defines number and string serialization by reference to ECMAScript, so
`JSON.stringify` on a scalar is the normative algorithm rather than a shortcut
past it. Ed25519 itself stays on `@noble/ed25519`: the signature primitive is
not what these vectors are testing, the bytes fed to it are.

## Read the profile, not the RFC you remember

`recomputeMerkleRoot` was written twice. The first version used RFC 6962's
`PATH` ordering from memory, where the leaf-adjacent sibling comes first.
`ink-merkle-inclusion.md` orders proof elements **top-down**, the reverse, and
says so plainly. The corpus rejected every multi-leaf proof until it was read.

The second version consumed the proof top-down but still combined hashes in the
same pass, which mispairs any leaf that is not at index 0. The split is decided
from the root down and the hashing runs from the leaf up; those are two
directions and they need two passes.

Both were caught by the corpus, which is the arrangement working. Neither would
have been caught by reading `src/`.

## Adding a construction

Write it from the spec section, cite the section in the module, and add a case to
`test/conformance-independent.test.ts`. Do not consult `src/` while writing it. Reading the
implementation first is how the corpus became circular, and it is the one thing
this directory exists to avoid.
