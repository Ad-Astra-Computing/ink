#!/usr/bin/env bash
#
# Dependency vulnerability gate. Runs `npm audit` across every npm project in
# the repo (the library and the example apps) and fails on a high or critical
# advisory, including dev dependencies. Each project must carry a lockfile so
# the audit runs against the exact dependency graph contributors install, and
# so a missing lockfile cannot silently skip a project (the gap that let a
# vulnerable example dependency reach Dependabot before it reached CI).
#
# Run locally with `npm run audit:all`.
set -euo pipefail

# Every directory that holds its own package.json. Keep in sync when adding an
# example or sub-package.
projects=(
  "."
  "examples/foreign-sender-receiver"
  "examples/reference-receiver"
)

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0

for project in "${projects[@]}"; do
  dir="${repo_root}/${project}"
  if [[ ! -f "${dir}/package.json" ]]; then
    echo "audit: ${project} has no package.json" >&2
    fail=1
    continue
  fi
  if [[ ! -f "${dir}/package-lock.json" ]]; then
    echo "audit: ${project} has no package-lock.json — cannot audit a reproducible graph" >&2
    fail=1
    continue
  fi
  echo "audit: ${project}"
  if ! ( cd "${dir}" && npm audit --audit-level=high ); then
    fail=1
  fi
done

if [[ "${fail}" -ne 0 ]]; then
  echo "audit: failed — resolve the advisories above (or update the lockfile)" >&2
  exit 1
fi
echo "audit: all projects clean at the high/critical threshold"
