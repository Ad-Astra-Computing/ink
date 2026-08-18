# INK differential fuzzing

Two implementations of INK exist: the TypeScript reference and the Go
implementation. This harness generates inputs, feeds each one to both, and
asserts that they reach the same decision.

```sh
node differential/run.mjs --cases 20000
```

Exit 0 means every case agreed. Exit 1 means at least one did not, and the
minimized case is written to `differential/findings/`.

## Why it exists

The conformance corpus proves both implementations agree on a fixed set of
inputs that a human wrote down. The interop lab proves they agree on a live
exchange over a socket. Neither can find a disagreement nobody thought of, and
a single implementation cannot detect one at all: on its own, an implementation
is definitionally correct, because there is nothing to be wrong against.

A second implementation is what makes wrongness observable. Any input where the
two reach different decisions is either a bug in one of them or a place where
the spec does not actually decide, and both of those are things a 1.0 needs to
have found on purpose rather than in production.

## What it proves, and what it does not

It proves: across the surfaces listed below, for the cases actually run, the two
implementations make the same accept-or-reject decision, and where the decision
carries a value (a canonical principal, an epoch, canonical bytes, a parsed
signature) they produce the same value.

It does not prove: that either implementation is correct. Two implementations
can agree and both be wrong against the spec; that is what the conformance
corpus and the specs are for. It does not prove absence of divergence outside
the case budget, and it does not cover the surfaces named under "not covered"
below. It says nothing about performance, memory or timing.

A count of agreeing cases is only evidence if the harness can detect a
disagreement at all, so that is a first-class check:

```sh
node differential/run.mjs --self-test private-hostname --cases 100
```

This tells the TypeScript decider to invert its answer on one surface and passes
only if the comparison catches it. Run it in the same job that runs the fuzzer.

## Surfaces

Ranked by how much damage a disagreement does. Each surface id is also the
conformance category id, and each input shape is the category's input shape, so
a finding promotes into the corpus with no translation step.

| Tier | Surface | The decision |
|---|---|---|
| 1 | `signed-body-canonical` | raw JSON text to canonical bytes: the signed-body gate plus RFC 8785 canonicalization |
| 1 | `signed-body-utf8` | raw bytes to a parsed signed body: fatal UTF-8, the lone-surrogate escape scan, JSON parsing |
| 1 | `signature-base` | §3.3 envelope verification end to end |
| 2 | `principal-normalization` | agentId to canonical principal |
| 2 | `timestamp-validity` | INK timestamp to epoch milliseconds |
| 2 | `authorization-header` | `INK-Ed25519` header to signature and keyId |
| 3 | `agent-card` | Agent Card schema validation |
| 3 | `agent-card-fetch` | discovery response contract: status, content type, caps, identity binding |
| 3 | `private-hostname` | the SSRF host gate |
| 3 | `merkle-checkpoint` | the checkpoint body grammar and its canonical re-serialization |
| 3 | `merkle-inclusion` | RFC 6962 inclusion walk |
| 3 | `merkle-consistency` | RFC 6962 consistency walk |
| 3 | `discovery-query-envelope` | schema, signature, audience, freshness, replay, in that order |

Tier 1 is the signature path. A disagreement there means a body one side refuses
is accepted by the other, or that a message signed by one is unverifiable by the
other: the only class where a divergence is a security bug outright. Tier 2 is
identity and freshness, where a divergence is attribution confusion or a widened
replay window. Tier 3 is admission, where a divergence is an interop break and
sometimes an SSRF or a forged-inclusion gap.

The Merkle surfaces earn tier 3 rather than lower because they are the sharpest
JavaScript-versus-Go numeric boundary in the protocol: a tree size past the
safe-integer range is an exact int64 in Go and a lossy double in JavaScript.

### Not covered, and why

- **Payload encryption (ECIES decrypt).** A mutated or random envelope fails the
  AEAD tag on both sides after one check, so it produces reject/reject with no
  signal. Getting signal means starting from a valid sealed envelope, which
  means the harness has to hold a private key and drive each implementation's
  sealer as the generator. That is the right next surface to add, and it is the
  first thing on the list, but it is a second key-holding component and it did
  not belong in the first pass. Today the AAD binding is pinned case by case in
  the `payload-encryption` conformance category and exercised live, with real
  keys on both sides, in `interop-lab/`.
- **The composite verifiers**: agent-card signature, authorization grant,
  authorization chain, inclusion receipt, audit-query response, first-contact
  transcript. Same reason: their inputs are multi-key signed contexts, so a
  generator that reaches past the first signature check has to become a signer.
  Every primitive they are built from (canonicalization, the signature base,
  timestamps, principals, the Merkle walks) is covered here, which is where a
  divergence in them would originate.
- **`replay-freshness` and `key-rotation`** are compositions of timestamp
  parsing and set membership over the covered primitives.
- **The request-side SSRF gate and card-content host checks** are out of scope
  in the conformance category itself, not just here.

Nothing is skipped to make comparison easier. No check is disabled, no
security-relevant branch is bypassed, and neither decider reaches into a module
its package does not export. A divergence found through a private path is a
divergence no adopter can hit.

## How the two sides are compared

Both deciders are batch NDJSON filters: `{caseId, surface, input}` in,
`{caseId, result, ...}` out. This is the shape the conformance runners already
use, extracted from `test/conformance.test.ts` and `go/ink/conformance_test.go`,
rather than a new bridge.

- `deciders/ts-decide.mts` imports `src/index.ts`, the package's public entry
  point.
- `deciders/go/main.go` imports `github.com/Ad-Astra-Computing/ink/go/ink`, the
  package an adopter imports. It is a nested Go module with a `replace` back to
  `go/`, so it builds without touching the released module.

Batching rather than a subprocess per case is what makes a large budget
tractable: process startup dominates the cost of every decision on this list. A
400,000-case run is two subprocess launches per batch, not 800,000.

The runner compares, in order: an unhandled crash on either side; the
accept-or-reject result; then every value field either side emitted
(`canonicalPrincipal`, `canonicalString`, `epochMs`, `signature`, `keyId`); then
the typed reason code, but only when both sides emitted one.

### Two things the bridge deliberately does

**The payload is ASCII.** Case lines escape every character above U+007F.
Node's readline splits lines on U+2028 and U+2029, which `JSON.stringify` emits
literally, so an unescaped payload would fail on one side for a reason that has
nothing to do with the library.

**Hex decoding is the platform's, not the library's.** The bridge carries raw
bytes as hex. Decoding them with the library's own `hexToBytes` imported a
4096-character input cap that Go's `encoding/hex` does not have, which showed up
as a disagreement about a payload neither library ever saw. Bridge decoding uses
the platform decoder on both sides, under one mirrored rule: even length, hex
alphabet, or the input fails closed to reject.

### The one input class that cannot cross

An unpaired UTF-16 surrogate as a live string value is filtered out of every
generated case. A Go string is UTF-8 bytes and cannot hold one, so the input is
not expressible on the Go side of any API and there is nothing to compare; the
conformance corpus puts it out of scope for v1 for the same reason. The rule the
protocol actually pins is about a `\uXXXX` escape for an unpaired surrogate
inside raw JSON text. That is ASCII, it crosses intact, and it is generated
heavily on both signed-body surfaces.

### The asymmetric surface, and what it cost

`discovery-query-envelope` used to be the one surface where the two public entry
points took different things: Go took raw bytes, TypeScript took an
already-parsed value. The harness gave Go the exact bytes and TypeScript
`JSON.parse` of the same bytes, which was what a TypeScript caller would have,
and a body that was not JSON at all carried a `__harness_unparsed` marker
because the TypeScript verifier was unreachable.

That asymmetry was not a harness inconvenience, it was a divergence. Every rule
the raw-body gate enforces (UTF-8 validity, the lone-surrogate escape scan, the
out-of-range number literal) is a rule about bytes that a parsed value has
already lost, so an entry point taking a parsed value cannot run any of them.
The surrogate rule survived only because TypeScript re-checks it at the value
layer; that mitigation is impossible for a literal a duplicate member shadows,
because the value never reaches the parsed object. A signed envelope carrying
`"protocol":1e309` ahead of the real `protocol` member canonicalized cleanly,
verified, and was accepted, while Go refused the bytes: an accept-versus-reject
split in a signed path, choosable by anyone who could rewrite bytes in flight.

`verifyDiscoveryQueryEnvelope` now takes `Uint8Array` and runs
`parseSignedBodyBytes` itself, so both entry points take the same thing, the
reason code is comparable on every case and `__harness_unparsed` is no longer
emitted.

## Generation

Three arms, round-robin across every surface so a truncated budget still covers
all of them.

- **corpus**: the conformance vector inputs, unmutated. They are already the
  interesting shapes, so they are the starting population rather than a
  hand-written one. This arm is small and finite by construction.
- **mutate**: a corpus input with one to four structure-aware mutations. Field
  drop, type flip, unknown key, a near-duplicate member differing by an
  invisible character, deep nesting, array growth past the caps, Unicode
  insertion. On the text surfaces the mutations run on the raw JSON text so they
  can express what a parsed value cannot: duplicate members, escape spellings,
  number literals. On the byte surface they run on the bytes, splicing the
  sequences that separate a fatal UTF-8 decoder from a lenient one.
- **random**: constructed from the edge banks without a corpus seed, so the
  corpus's imagination is not the only source. Half of the random Agent Card arm
  starts from the required shape so it reaches past the first required-field
  check often enough to be worth running.

The banks in `lib/mutators.mjs` are the edges that historically separate two
implementations of one grammar: Unicode that survives one language's string
model and not the other's, numbers at the safe-integer and exponent and
double-range boundaries including negative zero, base64url at the wrong length
or alphabet, RFC 3339 spellings a lenient parser accepts, every spelling of a
principal, and the IPv4/IPv6/FQDN special-use blocks.

### Member names are their own bank

Object member names decide exactly one thing, the sort order, and that is the
one decision an all-ASCII body cannot exercise. RFC 8785 orders members by
UTF-16 code unit. The natural implementation in Go, Rust or Python orders by
code point or by UTF-8 bytes, and those two orders agree on every all-ASCII
input. They part company at one place: a BMP name above the surrogate range
(U+E000 to U+FFFF) compared against an astral name (U+10000 and above). UTF-16
puts the astral name first, because its high surrogate is D800 to DBFF and so
below any such BMP unit; code-point and UTF-8 order put it last.

One name out of such a pair proves nothing, because a canonicalizer emits a
single member in the only position there is. So `ORDERING_PAIRS` is a bank of
name *pairs*, and `orderingMemberNames` returns both or neither. The first group
of pairs is the UTF-16 versus code-point split, with variants that share a
prefix so the deciding comparison lands off the first code unit;
`UTF16_SPLIT_PAIRS` recomputes which entries actually split the two orders and
the module refuses to load if none do, so a wrong code point cannot quietly turn
a case into a no-op. The remaining groups are the other near-ties a sort can get
wrong: names differing only by case, names differing only in normalization form,
one name a prefix of another, the empty name and names whose canonical
serialization is an escape sequence, which sorts against a leading U+005C rather
than against the raw character.

Thirty percent of the `signed-body-canonical` random arm is spent on bodies
built to force an ordering decision, and the text mutator can splice a pair into
any corpus body that already canonicalizes cleanly. The leaf values in a
generated ordering case are deliberately dull: a divergence in sort order is
only observable when both sides accept the body and emit canonical bytes, so a
leaf either side refuses turns the case into reject/reject and the ordering is
never reached.

## Determinism

Every case is a pure function of three numbers: the run seed, the surface and
arm, and the round index. The run seed is printed on every run and can be given
back with `--seed`. Nothing in the generator reads the clock, the filesystem or
the environment.

The corpus and mutate arms draw from `conformance/v1/vectors/`, so a case from
those arms is a function of the seed *and* the corpus at that commit. A seed
replays exactly on the same checkout; adding a conformance case reshuffles those
two arms. The random arm depends on nothing but the seed.

A finding file is a pure function of its content too: no timestamps, and the
filename is a hash of the surface and the minimized input, so the same
divergence found by two different runs lands in one file.

## Minimization

A raw divergence is usually a multi-kilobyte blob with forty mutations on it.
The shrinker replays the same comparison on progressively simpler inputs and
keeps the smallest one that still diverges the same way. Candidates are batched,
so a shrink pass is two subprocess launches regardless of how many candidates it
tries.

Three shrinkers: a generic one over JSON values (drop a member, empty a string,
zero a number, halve an array), a byte-level one for the raw-bytes surface, and
a text-level one that offers every balanced bracket group and every scalar token
in a JSON body on its own. The text one matters: an out-of-range exponent, a
duplicate member or an escape spelling does not survive a parse-and-stringify
round trip, so a shrinker that works on parsed values destroys the very thing it
is minimizing.

In practice this takes a 2 KB generated body down to `1e309`.

## Budget

| Flag | Default | What it does |
|---|---|---|
| `--cases N` | 2000 | case budget for the run |
| `--seconds S` | none | wall-clock budget; the run stops at whichever budget runs out first |
| `--seed N` | random | run seed, printed either way |
| `--surfaces a,b` | all | restrict to some surfaces |
| `--arms a,b` | all three | `corpus`, `mutate`, `random` |
| `--batch N` | 2000 | cases per decider invocation |
| `--shrink-passes N` | 8 | minimization passes per finding |
| `--shrink-candidates N` | 400 | candidates per pass |
| `--minimize-per-shape N` | 25 | stop minimizing a `(surface, kind)` shape after N witnesses |
| `--self-test SURFACE` | off | negative control: inject a fault and require it to be caught |

Minimization, not comparison, is the expensive step, so a systematic divergence
would otherwise dominate a large run while teaching nothing after the first few
witnesses. Past the cap the case is still counted and reported, just not
shrunk.

Throughput is roughly 1,200 cases per second across all thirteen surfaces on one
core, so a per-PR budget of a few thousand costs seconds and a scheduled budget
of a few hundred thousand costs minutes. `ci-snippet.yml` is the workflow, ready
to copy to `.github/workflows/differential.yml`: the self-test plus 5,000 cases
on every pull request, 400,000 on a nightly schedule, findings uploaded as an
artifact on failure. It is kept here rather than in `.github/workflows` so that
turning the harness into a gate is a deliberate move.

## When it finds something

A finding is written to `differential/findings/<surface>/<kind>-<hash>.json` as
`ink.differential.finding.v1`: the original case, the minimized case, both
decisions for both, the run seed and the origin case id.

The finding is not the deliverable. The corpus entry is. A divergence that is
fixed but not pinned will come back, and the corpus should grow from real
findings rather than from imagination:

```sh
node differential/promote.mjs differential/findings/<surface>/<file>.json --expect reject
```

That prints the conformance case block for the matching category and the exact
steps to land it. It does not edit `conformance/v1/generate.mjs` itself: the
vector files and their SHA-256s are pinned in `manifest.json` and referenced by
release evidence, so adding a case is a reviewed change rather than a side
effect of a fuzz run.

The judgement the harness cannot make for you is which side is right. It proves
they disagree. If the spec does not decide, the spec is the thing to change
first: write the rule down, then make both implementations follow it, then pin
it.

## Open findings

None. The reference run is `--seed 20260818 --cases 400000`: 400,000 cases in
roughly two minutes, about 30,000 per surface, 521 from the corpus arm and the
rest split evenly between mutate and random. Every case agreed, on all thirteen
surfaces, on the decision and on every value and reason code either side emitted.

The run that found something is worth keeping, because it is what the harness is
for. It reported 389 divergences in three shapes with one root cause: **a JSON
number literal whose magnitude is outside the IEEE-754 double range**.
`JSON.parse` turns `1e309` into `Infinity` and hands it back; Go's
`encoding/json` refuses the document with a range error. So:

| Input | TypeScript | Go |
|---|---|---|
| `1e309` (`parseSignedBodyBytes` vs `ParseSignedBody`) | accept | reject |
| `{"a":1e309}` through canonicalization | reject | reject |
| `{"a":1e309,"a":1}` through canonicalization | accept, canonical `{"a":1}` | reject |
| `{"a":2,"a":1}` through canonicalization | accept, canonical `{"a":1}` | accept, canonical `{"a":1}` |
| `1e-400` through canonicalization | accept, canonical `0` | accept, canonical `0` |

The middle row was the one that mattered. The INK number profile is a check on
parsed *values*, so an out-of-range literal that reaches canonicalization is
rejected by both. But JSON member semantics are last-wins, so a duplicate member
shadows the literal: the value never reaches the number check, the TypeScript
reference emitted canonical bytes and would verify a signature over them, and Go
refused the body outright. That was an interop break in the signature path,
reachable by anyone who could choose the bytes of a signed body.

It read as a spec gap rather than a plain implementation bug. The profile decided
which values could appear in a signed body and said nothing about which literals
could appear in its text, even though INK already ran two other checks (the fatal
UTF-8 decode and the lone-surrogate escape scan) on the raw bytes *before*
parsing, precisely so that a parser difference could not pick the outcome. An
out-of-range exponent is the same hazard in the same place, and the consistent
resolution was to reject it at the raw-body gate, which is what Go already did.
`ink-signed-string-safety.md` now states the rule and its position in the
enforcement order, `parseSignedBodyBytes` runs it, and `signed-body-utf8` and
`jcs-number` pin it.

The third shape was the same cause one layer up, and it was an API shape rather
than a scanner: `discovery-query-envelope` took bytes on one side and a parsed
value on the other, so the raw gate could not run on the TypeScript path at all.
See "the asymmetric surface" above. Both entry points now take bytes, and the
`discovery-query-envelope` category pins the shadowed literal on that surface too.

### A runtime bug, not a library bug: JSON.parse on Node 24

The member-name bank found one open divergence that neither implementation
causes. On Node 24, `JSON.parse` can return the wrong object key. Parse a
document whose second member is named `\\`, then parse another of the same shape
whose second member is named `\"`, and the second parse hands back the first
document's key:

```js
// JSON text {"A":1,"\\":2} - keys A and one backslash, correct
Object.keys(JSON.parse('{"A":1,"\\\\":2}'));

// JSON text {"A":1,"\"":2} - keys A and one double quote
// Node 22 returns [ 'A', '"' ]. Node 24 returns [ 'A', '\\' ].
Object.keys(JSON.parse('{"A":1,"\\"":2}'));
```

Both names are two characters of escaped source that decode to one character, so
whatever the parser is reusing between the two documents is matching on the
source length and not on what the escape decodes to.

The consequence for INK is a tier-1 divergence with no INK bug behind it: on Node
24 the TypeScript reference canonicalizes such a body to bytes Go does not
produce, so a signature made over one is not verifiable against the other. It
reproduces from `src/index.ts` alone, through `parseSignedBodyBytes`, with no
harness code involved.

Node 22 is correct on the same inputs, and so is Go. The reference run at
`--seed 20260818 --cases 400000` is clean on Node 22 and reports about twenty
cases on Node 24, all of this one shape. `findings/signed-body-canonical/
value-90cbc5057745a4ad.json` is kept as the witness; the rest were the same bug
under a larger body and were not worth keeping.

There is nothing to fix in either implementation, so this is recorded here rather
than promoted into the corpus. A conformance case pinned against a broken runtime
would fail for the wrong reason and start passing again when the runtime is
fixed, which is the opposite of what a vector is for.

## Layout

```
differential/
  run.mjs              the runner: generate, compare, minimize, report
  promote.mjs          turn a finding into a conformance case block
  lib/rng.mjs          seeded PRNG and seed derivation
  lib/mutators.mjs     edge-value banks and structure-aware mutators
  lib/shrink.mjs       the three shrinkers
  lib/surfaces.mjs     the surfaces, their generators and their tiers
  deciders/ts-decide.mts   TypeScript decider, over src/index.ts
  deciders/go/main.go      Go decider, over go/ink
  findings/            minimized divergences, one file each
```

Requirements: Node with the repo's dev dependencies installed (for `tsx`) and a
Go toolchain on `PATH`. The runner builds the Go decider itself on first use and
whenever `main.go` is newer than the binary.
