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
2. Run all five CI checks, every one must pass before requesting review:
   - `npm test`
   - `npm run typecheck`
   - `npm run lint`
   - `npm run check:surface` (asserts public schema fields match the documented snapshot in `scripts/check-public-surface.ts`)
   - `npm run check:facts` (recomputes every derivable number quoted in `governance/`, `specs/`, `README.md` and `CHANGELOG.md` and fails on a stale one)
3. Keep commits small and focused. Commit messages: imperative mood, under 72 characters.
4. Reference any related issue or spec section in the PR description.

## Spec and protocol work

The authoritative spec lives in `specs/`. If your change would alter the on-wire format, signing base, trust model or key-rotation rules, update the relevant spec file first and link to it in your PR. Spec and implementation are treated as a single artifact, they must stay in sync.
