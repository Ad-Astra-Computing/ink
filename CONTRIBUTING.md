# Contributing to INK

INK is an experimental pre-1.0 protocol. Bug reports, spec feedback and test contributions are welcome. Code contributions for protocol changes require a discussion first.

## License of contributions

Contributions are accepted under the project's dual license: MIT OR Apache-2.0 (see [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE)). By submitting a pull request you agree that your contribution may be distributed under either license.

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

Requires Node 22+ and npm 10+.

## Test policy

All changes must include tests. For bug fixes, add a regression test that fails before the fix and passes after. For new protocol features, add unit tests and update or add test vectors in `test-vectors/`.

## Code style

- TypeScript strict mode
- No external runtime dependencies beyond those in `package.json`
- Prefer explicit error returns over thrown exceptions in public API functions

## Submitting a PR

1. Fork and branch from `main`.
2. Run all four CI checks, every one must pass before requesting review:
   - `npm test`
   - `npm run typecheck`
   - `npm run lint`
   - `npm run check:surface` (asserts public schema fields match the documented snapshot in `scripts/check-public-surface.ts`)
3. Keep commits small and focused. Commit messages: imperative mood, under 72 characters.
4. Reference any related issue or spec section in the PR description.

## Spec and protocol work

The authoritative spec lives in `specs/`. If your change would alter the on-wire format, signing base, trust model or key-rotation rules, update the relevant spec file first and link to it in your PR. Spec and implementation are treated as a single artifact, they must stay in sync.
