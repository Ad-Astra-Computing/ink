# INK conformance vectors (ink.conformance.v1)

These vectors are the cross-implementation contract for INK's security
decisions. They pin the exact accept or reject outcome for a fixed set of
inputs, so that an independent implementation can prove it makes the same
decisions as the reference, rather than inferring behavior from the source.

A credible wire spec specifies its failures, not just its happy path, so the
corpus is mostly negative and adversarial cases.

## Layout

- `schema.json` is the JSON Schema for a vector file.
- `vectors/*.json` are the vector files, one per category. Each file is
  `{ "format": "ink.conformance.v1", "category": "...", "cases": [...] }`.
- `generate.mjs` regenerates the vectors deterministically (a fixed test seed
  drives a single Ed25519 key), so re-running produces byte-identical output.

## A case

```json
{
  "caseId": "ink-alias-same-principal",
  "description": "The ink: alias of the same key normalizes to the same principal.",
  "input": { "agentId": "ink:z6Mk..." },
  "expect": { "result": "accept", "canonicalPrincipal": "key:z6Mk..." }
}
```

`expect.result` is `accept` or `reject`, and `expect.canonicalPrincipal`
(principal cases) carries the expected identity. Implementations assert the
result and, where present, the canonical principal. The `description` records why
a case rejects; a machine-readable error-code field is intentionally left out of
v1 until the implementation emits stable codes, and would be added as an
additive field then.

## Categories

- **principal-normalization** — `tulpa:` and `ink:` aliases of one key collapse
  to the same canonical principal; a literal `key:` agentId is escaped rather
  than confused with that principal; DIDs pass through; an empty id is rejected.
- **signature-base** — a signature over the canonical signature base verifies;
  reordering JSON members of the signed body does not change the canonical bytes;
  altering a signed field or the key fails verification.
- **jcs-number** — numbers whose shortest form is exponential are rejected even
  when they are otherwise valid, so the signed bytes stay agnostic to which
  canonicalizer produced them.

## Running them

The reference implementation runs the corpus in `test/conformance.test.ts` as
part of `npm test`. Another implementation consumes the same files: load each
file, dispatch by `category`, run the input through its own pipeline, and assert
the outcome equals `expect`.
