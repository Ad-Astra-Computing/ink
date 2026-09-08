# Releasing INK

INK ships two verifiers of one wire format. `@adastracomputing/ink` on npm is
the TypeScript reference, and `github.com/Ad-Astra-Computing/ink/go` on the Go
module proxy is the second implementation. The 1.0 claim rests on those two
agreeing over the same conformance corpus, which is only a meaningful claim
while an adopter can install both at the same version.

That is the rule this document exists to hold. Everything else here follows
from it.

## The parity rule

A release publishes both artifacts at the same version, from the same commit,
or it publishes neither.

The npm side has a gate for this and the Go side does not, which is worth
understanding before reading the sequence below. Pre-1.0 npm releases go to the
`next` dist-tag, and `latest` only moves when the lead maintainer promotes a
version by hand. The Go module proxy has no equivalent of a dist-tag. The
moment `go/v<version>` is pushed, that version is what `go get` resolves for
everyone, with nothing standing in front of it.

So the discipline that npm gets from `next` has to come from the version string
on the Go side. Pre-stable Go releases are tagged `go/v<version>-next.<n>`.
[Go's `latest` query](https://go.dev/ref/mod#version-queries) resolves to the
highest version with no prerelease suffix, and only falls back to a prerelease
when the module has published no unsuffixed version at all. So once a single
bare tag exists, a suffixed tag reaches only the people who ask for it by name.
Promotion is the act of pushing the bare `go/v<version>` tag, and it happens in
the same sitting as the npm dist-tag move.

There is one asymmetry with npm that cannot be designed away. A Go tag is
permanent: the proxy caches it on first request and there is no unpublish. What
a later release can do is
[retract](https://go.dev/ref/mod#go-mod-file-retract) it, which leaves the
version fetchable by name but takes it out of `@latest` and out of upgrade
selection. That redirects rather than withdraws, and it only helps
where there is another published version to fall back to. Get the Go tag right the
first time. This is why the gauntlet runs before either artifact is published
rather than between them.

## Before a cut

Everything below is green at the release commit, in both languages, before any
tag is pushed.

- `npm test`, `npm run typecheck`, `npm run lint`
- `npm run check:surface`, `npm run check:facts`, `npm run check:pack`
- `npm run check:mutants` at the release commit, not at the last weekly run
- `go test ./...` in `go/`, which runs the Go side of the conformance corpus
- The `go-ts-interop`, `go-conformance`, `staged-conformance` and `interop-lab`
  jobs on the release commit
- The differential fuzzer at its declared budget

The corpus checks are the ones that carry the parity rule. `check:facts` and
`check:release-parity` fail if the tree's two version strings disagree with
each other or with what is recorded in `governance/releases/`. Both read the
committed pins rather than the registries, so they catch a release commit that
updates one artifact and forgets the other. Only `check:facts` reaches the
network, and only for the npm dist-tags; nothing in CI asks the Go proxy what
it serves. Keeping the Go pin true is a step in the sequence below.

For a release that changes runtime code during a soak window, read
[§2.2 of the readiness record](governance/releases/1.0-readiness-evidence.md)
first. Adoption restarts the window, so the question of whether to cut at all
is a governance question and not a mechanical one.

## Cutting a release

1. Open a release pull request that bumps `version` in `package.json`, the
   `Version` constant in `go/internal/cli/cli.go`, the dist-tag pin in
   `governance/releases/npm-dist-tags.json`, the Go pin in
   `governance/releases/go-module.json` and the changelog section.
   `check:release-parity` reads the two version strings, the Go pin and the
   `latest` entry of the dist-tag pin, and enforces the parity rules over them
   with no exceptions. It does not read the `next` entry, which moves ahead of
   `latest` by design.
2. Merge it once CI is green and the review is signed off.
3. Push the npm tag at the merge commit, and wait for it:

   ```sh
   git tag -s "v${VERSION}" -m "v${VERSION}"
   git push origin "v${VERSION}"
   ```

   It triggers the [`publish`](.github/workflows/publish.yml) workflow, which
   builds under the pinned Nix toolchain and publishes to the `next` dist-tag
   with sigstore provenance. Watch it finish before going on.
4. Push the Go tag at the same commit:

   ```sh
   git tag -s "go/v${VERSION}-next.1" -m "go/v${VERSION}-next.1"
   git push origin "go/v${VERSION}-next.1"
   ```

   It publishes nothing on its own; the proxy serves it the first time somebody
   fetches it.
5. Confirm both landed at the version the release commit pinned:

   ```sh
   npm view @adastracomputing/ink dist-tags
   go list -m -versions github.com/Ad-Astra-Computing/ink/go
   go list -m github.com/Ad-Astra-Computing/ink/go@latest
   ```

   The last one is the check that matters on the Go side. Listing the versions
   says what exists; only the `@latest` query says what an adopter who asks for
   nothing in particular will get, and after a prerelease cut that should still
   be the previous promoted version.

The two pushes are separate steps in that order because they fail differently.
An npm publish that goes wrong can be republished or unpublished within the
window; a Go tag cannot be taken back. Publishing npm first means a failure
there stops the release before anything irreversible happens. The residual risk
runs the other way: if step 4 cannot run after step 3 succeeded, npm is a
release ahead of Go until the tag is pushed, which is the recoverable direction.

Pushing the Go tag without a prerelease suffix promotes it, whether or not that
was the intent.

## Promoting to adopter-grade

Promotion is a separate act with its own authority. It says the version has
soaked and an adopter should install it without re-testing. The lead maintainer
runs it, and it moves both artifacts in one sitting.

### Which gate applies

The bar depends on the version being promoted, and the two bars are not
interchangeable.

A `0.x` version passes the pre-1.0 default-channel gate. Every line is about the
commit being promoted, not about the state of `main` on the day:

- The version is published on `next` already, with the provenance the publish
  workflow was supposed to attach.
- The npm release tag and the Go tag resolve to the same commit.
- The release gauntlet was green on that commit.
- Conformance, the Go and TypeScript interop suites and the security tests were
  green on that same commit.
- No release-attributable correctness or security finding is open.
- The published limitations and the release notes describe the version as
  pre-1.0.
- The soak evidence has been read, and whatever is missing from it is recorded
  as accepted pre-1.0 risk. Evidence nobody gathered is not evidence of safety.
- The lead maintainer records the decision in the pull request that carries the
  pin change.

A `1.0` or later version passes
[§2](governance/releases/1.0-readiness-evidence.md#2-soak-exit-criteria) and the
checklist in
[§4](governance/releases/1.0-readiness-evidence.md#4-promote-recommendation-checklist)
of the readiness record. The pre-1.0 gate applies only while the major version
is `0`. Nothing here authorizes a `1.x` move on the shorter bar.

Passing the pre-1.0 gate is not a waiver of §2, a partial completion of it or
any kind of credit against it. A promotion that took the shorter path is not
citable later as evidence that a soak criterion was met.

### The sequence

1. Have the pin change ready. If `main` already names the destination, verify
   it: `npm run check:release-pin -- --tag latest --version "${VERSION}"`. If it
   does not, open the pull request that flips it and get it reviewed before
   step 4. The pin is the record of an act that has no undo, so it is written
   and reviewed in advance and merged straight after, never reconstructed from
   memory afterwards.
2. Confirm the gate above is satisfied for this version, and say which of the
   two it was.
3. Resolve the commit the prerelease tag names, before touching npm:

   ```sh
   COMMIT=$(git rev-parse --verify "go/v${VERSION}-next.1^{commit}")
   git verify-tag "go/v${VERSION}-next.1"
   ```

   `git tag` places a tag at `HEAD` unless it is given a commit, and a bare Go
   tag at the wrong commit is not something that can be undone. Resolving it
   here also fails early if the prerelease was never pushed.
4. Move the npm dist-tag:
   `npm dist-tag add @adastracomputing/ink@${VERSION} latest --otp=<code>`.
   Trusted publishing cannot authenticate a dist-tag move
   ([npm/cli#8547](https://github.com/npm/cli/issues/8547)), so this is
   attended and uses a second factor rather than a stored credential.
5. Push the bare Go tag at that commit:

   ```sh
   git tag -s "go/v${VERSION}" -m "go/v${VERSION}" "${COMMIT}"
   git push origin "go/v${VERSION}"
   go list -m github.com/Ad-Astra-Computing/ink/go@latest
   ```

6. Update both pins in `governance/releases/` on `main`, then rerun
   `npm run check:facts` for the npm pin and every document that quotes a
   version, and `npm run check:release-parity` for the Go pin. The two pins have
   different checks because only the npm one can be verified against a registry
   from CI.

A promotion that moves one artifact and not the other is the failure this
document is written to prevent. If step 4 succeeds and step 5 cannot run,
`latest` is ahead of Go and the gap is visible to adopters until it is closed.
Finish both or roll the dist-tag back to its previous version.

### Reconciling npm to an existing Go stable tag

Sometimes the Go tag is out and npm is behind. That is not the sequence above
running late. The irreversible half has already happened, and what is left is
the reversible half catching up to it, so the steps are different.

1. Confirm what the proxy actually serves:
   `go list -m github.com/Ad-Astra-Computing/ink/go@latest`. It has to name
   `${VERSION}` exactly.
2. Resolve the commit the Go tag names and check its signature:

   ```sh
   COMMIT=$(git rev-parse --verify "go/v${VERSION}^{commit}")
   git verify-tag "go/v${VERSION}"
   ```

3. Confirm the npm release tag names that same commit:
   `git rev-parse --verify "v${VERSION}^{commit}"` and compare it with
   `${COMMIT}`. If they differ, stop. The two implementations were cut from
   different trees and no dist-tag move fixes that.
4. Confirm `next` names `${VERSION}`, and that the published artifact carries
   the provenance the publish workflow attaches:

   ```sh
   npm view @adastracomputing/ink dist-tags --json
   npm view @adastracomputing/ink@${VERSION} dist.attestations
   ```

   `dist-tags` says which version is on the channel and nothing about how it got
   there, so the attestation needs its own command.
5. Apply the gate above for this version.
6. Open the pull request that flips the npm pin to `${VERSION}` and records the
   decision. Get it reviewed. Do not merge it yet: until step 7 lands, the pin
   would claim something the registry does not say.
7. Move the dist-tag, then read the registry back:

   ```sh
   npm dist-tag add @adastracomputing/ink@${VERSION} latest --otp=<code>
   npm view @adastracomputing/ink dist-tags --json
   ```

8. Set `verifiedAt` in the pin to the day of that reading, rerun
   `npm run check:facts` and `npm run check:release-parity`, and merge the
   prepared pull request.

This path never creates, moves, replaces or force-pushes a Go tag. If Go is
ahead and npm cannot catch up, the way out is the next release publishing both
together under the sequence above.

## Security posture

The [`publish`](.github/workflows/publish.yml) workflow splits the build from
the publish so that no third-party code ever executes in a job holding a
credential. The gauntlet job builds and tests with no permissions beyond
reading the repository, and hands the publish job a tarball pinned by SHA-256.
The publish job holds `id-token: write` for provenance and runs nothing but a
download, a checksum and `npm publish`. Installs pass `--ignore-scripts`.
Keep that split intact. It is the reason a compromised dependency cannot reach
the trusted-publisher identity.

The Go side has no equivalent exposure, because there is no publish step to
compromise. What it has instead is permanence. Treat a Go tag as an
irreversible act, and do not push one from a tree that has not passed the
gauntlet above.

A release also does not ship while an unlanded finding in
`governance/releases/1.0-readiness-evidence.md` changes an accept or reject
decision in either implementation. Review the whole release diff, not only the
individual pull requests that make it up. Cross-change interactions are the
class of defect that per-change review does not catch, and a large release is
where they live.
