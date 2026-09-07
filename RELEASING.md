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
on the Go side. Pre-stable Go releases are tagged `go/v<version>-next.<n>`. The
`go` command skips prerelease versions when it resolves `@latest`, as long as at
least one stable version exists, so a prerelease Go tag reaches only the people
who ask for it by name. Promotion is the act of pushing the bare `go/v<version>`
tag, and it happens in the same sitting as the npm dist-tag move.

There is one asymmetry with npm that cannot be designed away. A Go tag is
permanent. The proxy caches it on first request and there is no unpublish. The
only correction is a `retract` directive in a later version's `go.mod`, which
takes effect only once that later version is itself published and resolved. Get
the Go tag right the first time. This is why the gauntlet runs before either
artifact is published rather than between them.

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
each other or with what is recorded in `governance/releases/`.

For a release that changes runtime code during a soak window, read
[§2.2 of the readiness record](governance/releases/1.0-readiness-evidence.md)
first. Adoption restarts the window, so the question of whether to cut at all
is a governance question and not a mechanical one.

## Cutting a release

1. Open a release pull request that bumps `version` in `package.json`, the
   `Version` constant in `go/internal/cli/cli.go`, the dist-tag pin in
   `governance/releases/npm-dist-tags.json`, the Go pin in
   `governance/releases/go-module.json` and the changelog section. These move
   together or `check:release-parity` fails.
2. Merge it once CI is green and the review is signed off.
3. Push both signed tags at the merge commit, npm first:

   ```sh
   git tag -s "v${VERSION}" -m "v${VERSION}"
   git tag -s "go/v${VERSION}-next.1" -m "go/v${VERSION}-next.1"
   git push origin "v${VERSION}" "go/v${VERSION}-next.1"
   ```

   The npm tag triggers the [`publish`](.github/workflows/publish.yml)
   workflow, which builds under the pinned Nix toolchain and publishes to the
   `next` dist-tag with sigstore provenance. The Go tag publishes nothing on
   its own. The proxy serves it the first time somebody fetches it.
4. Confirm both. `npm view @adastracomputing/ink dist-tags` and
   `go list -m -versions github.com/Ad-Astra-Computing/ink/go` should agree
   with the pins in the release commit.

Pushing the npm tag without the Go tag leaves the second implementation behind
a release the corpus claims it verifies. Pushing the Go tag without a
prerelease suffix promotes it, whether or not that was the intent.

## Promoting to adopter-grade

Promotion is a separate act with its own authority. It says the version has
soaked and an adopter should install it without re-testing. The lead maintainer
runs it, and it moves both artifacts in one sitting.

1. Verify the pin on `main` names the destination:
   `npm run check:release-pin -- --tag latest --version "${VERSION}"`.
2. Confirm the release gate is green under
   [§2 of the readiness record](governance/releases/1.0-readiness-evidence.md).
3. Move the npm dist-tag:
   `npm dist-tag add @adastracomputing/ink@${VERSION} latest --otp=<code>`.
   Trusted publishing cannot authenticate a dist-tag move
   ([npm/cli#8547](https://github.com/npm/cli/issues/8547)), so this is
   attended and uses a second factor rather than a stored credential.
4. Push the bare Go tag at the same commit the prerelease named:

   ```sh
   git tag -s "go/v${VERSION}" -m "go/v${VERSION}"
   git push origin "go/v${VERSION}"
   ```

5. Update both pins in `governance/releases/` on `main` and rerun
   `npm run check:facts`, which reads them and every document that quotes a
   version.

A promotion that moves one artifact and not the other is the failure this
document is written to prevent. If step 3 succeeds and step 4 cannot run,
`latest` is ahead of Go and the gap is visible to adopters until it is closed.
Finish both or roll the dist-tag back to its previous version.

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

## Current state

`go/v0.19.0` was pushed as a bare tag on 2026-09-02, before this document
existed, and it is the only Go version the proxy has. Because it is stable and
alone, it is what `go get ...@latest` resolves, while npm `latest` is still
0.18.0. The two verifiers an adopter installs today are one release apart.

The Go tag cannot be withdrawn. The gap closes when 0.19.0 is promoted on npm
or when the next release publishes both under the rules above, whichever comes
first.
