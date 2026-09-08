/**
 * The two implementations must publish at the same version.
 *
 * The rules live in `release-parity.ts`. This reads the four places a version
 * is written down and reports what they say about each other. It is offline: it
 * trusts the committed pins in `governance/releases/` rather than asking npm or
 * the Go proxy, so it catches a release commit that forgets one of them, not a
 * pin that was never true. `check:facts` is what verifies the npm pin against
 * the registry.
 *
 * Usage:
 *   tsx scripts/check-release-parity.ts
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parityFailures, type GoPin } from "./release-parity.js";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function read(relativePath: string): string {
  return readFileSync(join(repoRoot, relativePath), "utf8");
}

function readJson<T>(relativePath: string): T {
  return JSON.parse(read(relativePath)) as T;
}

const packageVersion = readJson<{ version: string }>("package.json").version;
const cliMatch = /^const Version = "([^"]+)"$/m.exec(read("go/internal/cli/cli.go"));
const goPin = readJson<GoPin>("governance/releases/go-module.json");
const npmPin = readJson<{ distTags: Record<string, string> }>(
  "governance/releases/npm-dist-tags.json",
);
const npmLatest = npmPin.distTags.latest;

const failures = parityFailures({
  packageVersion,
  cliVersion: cliMatch?.[1] ?? null,
  goPin,
  npmLatest,
});

if (failures.length > 0) {
  console.error("release parity check failed:\n");
  for (const failure of failures) console.error(`  - ${failure}\n`);
  process.exit(1);
}

console.log(
  `release parity ok: ${packageVersion} in the tree, npm latest ${npmLatest}, ` +
    `Go stable ${goPin.published.stable ?? "none"}`,
);
