# Contributing to INK

INK is an experimental pre-1.0 protocol. Bug reports, spec feedback and test contributions are welcome. Code contributions for protocol changes require a discussion first.

## License of contributions

Contributions are accepted under the project's dual license: MIT OR Apache-2.0 (see [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE)). By submitting a pull request you agree that your contribution may be distributed under either license.

## Sign your commits (DCO)

Every commit must carry a `Signed-off-by:` line. This is a Developer Certificate of Origin: by signing off you certify that you wrote the change or otherwise have the right to submit it under the project's license. The full text you are certifying is in [`governance/DCO.txt`](governance/DCO.txt).

Add the trailer with the `-s` flag:

```bash
git commit -s -m "Reject empty key window"
```

That appends a line matching your commit author identity:

```
Signed-off-by: Jane Doe <jane@example.com>
```

Use a real name and a reachable email. The email in the sign-off must match the commit author email. The [`dco`](.github/workflows/dco.yml) workflow checks every non-merge commit in your PR and fails if one is missing a matching sign-off. If you forgot on an earlier commit, sign off the whole range in place:

```bash
git rebase --exec 'git commit --amend --no-edit -s' <base>
```

## Before you open an issue or PR

- **Security issues**: do not open a public issue. Report privately per [`SECURITY.md`](SECURITY.md).
- **Protocol changes**: open a discussion first. Breaking protocol changes must reference or propose a spec file in `specs/`.
- **Bug fixes and test improvements**: open a PR directly.

## Development setup

```bash
npm install
npm test          # vitest run
npm run typecheck # tsc --noEmit
```

Requires Node 24+ and npm 10+.

## Test policy

All changes must include tests. For bug fixes, add a regression test that fails before the fix and passes after. For new protocol features, add unit tests and update or add test vectors in `test-vectors/`.

## Code style

- TypeScript strict mode
- No external runtime dependencies beyond those in `package.json`
- Prefer explicit error returns over thrown exceptions in public API functions

## Submitting a PR

1. Fork and branch from `main`.
2. Run all six CI checks, every one must pass before requesting review:
   - `npm test`
   - `npm run typecheck`
   - `npm run lint`
   - `npm run check:surface` (asserts public schema fields match the documented snapshot in `scripts/check-public-surface.ts`)
   - `npm run check:facts` (recomputes every derivable number quoted in `governance/`, `specs/`, `README.md` and `CHANGELOG.md` and fails on a stale one)
   - `npm run check:release-pin -- --tag any` (asserts the version in the tree is recorded on a dist-tag in `governance/releases/npm-dist-tags.json`)

   Only a release pull request can fail the last one, since only a release pull request bumps the version. When it does, update `governance/releases/npm-dist-tags.json` in the same commit and rerun `npm run check:facts` to pick up the documents that quote a dist-tag. The publish workflow runs a stricter form of the same check and refuses to publish without it.
3. Keep commits small and focused. Commit messages: imperative mood, under 72 characters.
4. Reference any related issue or spec section in the PR description.

The [`interop-lab`](.github/workflows/interop-lab.yml) workflow runs on every pull request as well. It builds both implementations from your branch and runs a live exchange between them in containers, which is the check that catches a wire-contract change the fixed conformance vectors cannot see. It needs Docker or Podman, so it is not in the list above; run `./interop-lab/run.sh` locally if you have an engine, and otherwise read the job output.

## Checks that run without a push

Some checks run on a schedule as well as on pull requests, so a quiet week still produces a result. The [`weekly-conformance`](.github/workflows/weekly-conformance.yml) workflow re-verifies the conformance corpus in both implementations once a week. A scheduled run covers two commits, the head of `main` and the highest released `v*` tag, so the corpus is re-checked against the newest release without anyone starting a run by hand; when the two are the same commit it is verified once. It can also be dispatched against a specific ref, which verifies that ref alone. Nothing about it is a contributor step, but a red run on `main` is a real failure and is treated like one. The [`audit`](.github/workflows/audit.yml) and [`zizmor`](.github/workflows/zizmor.yml) workflows run daily on the same principle.

## Spec and protocol work

The authoritative spec lives in `specs/`. If your change would alter the on-wire format, signing base, trust model or key-rotation rules, update the relevant spec file first and link to it in your PR. Spec and implementation are treated as a single artifact, they must stay in sync.
