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
  "examples/reference-sender"
  "examples/reference-rp"
  "examples/docker-receiver"
)

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0

# Run one project's audit with a bounded retry on registry outages. npm exits
# nonzero both for real advisories and for a 5xx from the advisory endpoint;
# only the latter is retried, and only twice, so a registry blip does not
# redden the gate while a real advisory still fails on the first attempt and
# an extended outage still fails closed.
audit_project() {
  local dir="$1" attempt out
  for attempt in 1 2 3; do
    if out="$( cd "${dir}" && npm audit --audit-level=high 2>&1 )"; then
      printf '%s\n' "${out}"
      return 0
    fi
    printf '%s\n' "${out}"
    if grep -q "audit endpoint returned an error" <<<"${out}"; then
      if [[ "${attempt}" -lt 3 ]]; then
        echo "audit: registry advisory endpoint unavailable, retrying in $((attempt * 30))s (${attempt} of 2)" >&2
        sleep $((attempt * 30))
        continue
      fi
      echo "audit: registry advisory endpoint still unavailable after 3 attempts — failing closed" >&2
    fi
    return 1
  done
}

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
  if ! audit_project "${dir}"; then
    fail=1
  fi
done

if [[ "${fail}" -ne 0 ]]; then
  echo "audit: failed — resolve the advisories above (or update the lockfile)" >&2
  exit 1
fi
echo "audit: all projects clean at the high/critical threshold"
