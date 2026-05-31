#!/usr/bin/env bash
# Pack-and-import smoke test. Runs `npm pack`, installs the resulting
# tarball into a throwaway directory, and imports the public entry
# point. Catches any release that would ship a broken package — e.g.
# missing `dist/`, wrong `main`, or unresolvable re-exports.
#
# Triggered by `npm run check:pack` and by CI on every publish job.
# An exit code other than 0 here MUST block release.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$REPO_ROOT"
echo "==> Packing tarball"
TARBALL_NAME="$(npm pack --silent --pack-destination "$WORK_DIR")"
TARBALL="$WORK_DIR/$TARBALL_NAME"
echo "    -> $TARBALL"

echo "==> Inspecting tarball contents"
TARBALL_ENTRIES="$(tar -tzf "$TARBALL")"
if ! grep -q '^package/dist/index\.js$' <<<"$TARBALL_ENTRIES"; then
  echo "FAIL: dist/index.js missing from tarball" >&2
  echo "$TARBALL_ENTRIES" | head -20 >&2
  exit 1
fi
if tar -tzf "$TARBALL" | grep -qE '^package/src/.+\.ts$'; then
  echo "FAIL: tarball still ships raw TS source under src/ — would re-trigger ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING on Node 24" >&2
  exit 1
fi

echo "==> Installing tarball into clean project"
INSTALL_DIR="$WORK_DIR/consumer"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
cat > package.json <<EOF
{"name":"ink-pack-smoke","version":"0.0.0","type":"module","private":true}
EOF
npm install --silent "$TARBALL" >/dev/null

echo "==> Importing package entry"
cat > smoke.mjs <<'EOF'
import {
  generateKeypair,
  deriveAgentId,
  signAuditEvent,
  signInkMessage,
  buildAuthHeader,
  jcsCanonicalize,
} from "@adastracomputing/ink";

const me = await generateKeypair();
const id = deriveAgentId(me.publicKey);
if (!id || typeof id !== "string") {
  console.error("FAIL: deriveAgentId did not return a string");
  process.exit(1);
}
const canonical = jcsCanonicalize({ b: 2, a: 1 });
if (canonical !== '{"a":1,"b":2}') {
  console.error("FAIL: jcsCanonicalize produced unexpected output:", canonical);
  process.exit(1);
}
if (typeof signAuditEvent !== "function" || typeof signInkMessage !== "function" || typeof buildAuthHeader !== "function") {
  console.error("FAIL: expected functions are not exported");
  process.exit(1);
}
console.log("ok");
EOF
node smoke.mjs

echo "==> Pack-and-import smoke OK"
