#!/usr/bin/env bash
# Print the CHANGELOG section for one version, without its heading line.
# Usage: scripts/changelog-section.sh <version>
#
# Used by both publish paths in .github/workflows/publish.yml to build the
# GitHub Release body, so the two paths cannot drift apart. If no section
# matches, prints a pointer to the changelog instead of failing, so a release
# never blocks on a missing entry.

set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "usage: $0 <version>" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Match `## <version>` where the version is followed by a comma or end of
# line, then print until the next `## ` heading. Dots are escaped so a version
# cannot match a neighbouring heading through the regex wildcard.
# Passed through the environment rather than -v, which would strip one level
# of escaping before awk sees the pattern.
export VERSION_RE="^## ${VERSION//./\\.}(,|$)"
section="$(awk '
  $0 ~ ENVIRON["VERSION_RE"] { in_block=1; next }
  in_block && /^## / { in_block=0 }
  in_block { print }
' "${REPO_ROOT}/CHANGELOG.md")"

if [ -z "$(printf '%s' "$section" | tr -d '[:space:]')" ]; then
  echo "No CHANGELOG section found for ${VERSION}; using a pointer body." >&2
  echo "Refer to CHANGELOG.md for changes."
  exit 0
fi

printf '%s\n' "$section"
