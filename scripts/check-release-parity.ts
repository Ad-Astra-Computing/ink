/**
 * The two implementations must publish at the same version.
 *
 * INK ships a TypeScript verifier on npm and a Go verifier on the Go module
 * proxy, and the 1.0 wire claim rests on the two agreeing over one conformance
 * corpus. That claim only means something while an adopter can install both at
 * the same version, so a published version gap is a conformance hole rather
 * than a bookkeeping slip.
 *
 * Nothing else in the tree checks it. The npm side has `next` to hold a release
 * back from adopters and a pin that gates every dist-tag move, but the Go proxy
 * has no dist-tags: pushing `go/v<version>` publishes it as Go's `@latest`
 * immediately, and a Go tag cannot be unpublished. So the discipline npm gets
 * from its pin has to come from this check plus the version suffix rules in
 * RELEASING.md.
 *
 * Three things are asserted:
 *
 *   1. The version in `package.json` and the `Version` constant in
 *      `go/internal/cli/cli.go` are the same string. A release that bumps one
 *      and not the other ships two verifiers that disagree about their own
 *      identity, which is what makes a version skew hard to see from a bug
 *      report.
 *   2. `governance/releases/go-module.json` records that version on one of its
 *      two channels, so a release commit that forgets the Go pin fails review
 *      rather than the tag push.
 *   3. The Go stable version is not ahead of the npm `latest` dist-tag.
 *      `go get ...@latest` and `npm install` are the two commands an adopter
 *      runs without asking for anything in particular, and they have to land on
 *      the same release.
 *
 * The third assertion is the one with real teeth and it is failing today for a
 * documented reason. `go/v0.19.0` was pushed bare before this check existed and
 * the proxy will serve it forever. `--allow-known-gap` acknowledges exactly
 * that recorded state and nothing else: it passes only while the gap is the one
 * named in the go pin's `knownGap` field, so a NEW skew still fails. Remove the
 * field and the flag once the gap closes.
 *
 * Usage:
 *   tsx scripts/check-release-parity.ts [--allow-known-gap]
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function read(relativePath: string): string {
  return readFileSync(join(repoRoot, relativePath), "utf8");
}

function readJson<T>(relativePath: string): T {
  return JSON.parse(read(relativePath)) as T;
}

interface GoPin {
  module: string;
  published: { stable: string | null; prerelease: string | null };
  knownGap?: { npmLatest: string; goStable: string; reason: string };
}

interface NpmPin {
  package: string;
  distTags: Record<string, string>;
}

/** Compare two `x.y.z` strings numerically, ignoring any prerelease suffix. */
function compareVersions(a: string, b: string): number {
  const parse = (v: string): [number, number, number] => {
    const [major = 0, minor = 0, patch = 0] = (v.split("-")[0] ?? "").split(".").map(Number);
    return [major, minor, patch];
  };
  const [aMajor, aMinor, aPatch] = parse(a);
  const [bMajor, bMinor, bPatch] = parse(b);
  if (aMajor !== bMajor) return aMajor - bMajor;
  if (aMinor !== bMinor) return aMinor - bMinor;
  return aPatch - bPatch;
}

const failures: string[] = [];

const packageVersion = readJson<{ version: string }>("package.json").version;

// The constant is the version the `ink` binary reports, so it is what an
// adopter quotes in a bug report and the only version string the Go module
// carries in its own source.
const cliSource = read("go/internal/cli/cli.go");
const cliMatch = /^const Version = "([^"]+)"$/m.exec(cliSource);
if (!cliMatch) {
  failures.push("go/internal/cli/cli.go has no `const Version = \"...\"` line to read");
} else if (cliMatch[1] !== packageVersion) {
  failures.push(
    `version skew in the tree: package.json is ${packageVersion}, ` +
      `go/internal/cli/cli.go is ${cliMatch[1]}`,
  );
}

const goPin = readJson<GoPin>("governance/releases/go-module.json");
const npmPin = readJson<NpmPin>("governance/releases/npm-dist-tags.json");

const goChannels = [goPin.published.stable, goPin.published.prerelease].filter(
  (v): v is string => v !== null,
);
if (!goChannels.some((v) => compareVersions(v, packageVersion) === 0)) {
  failures.push(
    `governance/releases/go-module.json records ${goChannels.join(" and ") || "nothing"}, ` +
      `which does not include the tree's version ${packageVersion}. ` +
      "A release commit bumps the Go pin with package.json (see RELEASING.md).",
  );
}

const npmLatest = npmPin.distTags.latest;
const goStable = goPin.published.stable;
if (goStable && npmLatest && compareVersions(goStable, npmLatest) > 0) {
  const gap = goPin.knownGap;
  const acknowledged =
    process.argv.includes("--allow-known-gap") &&
    gap !== undefined &&
    gap.npmLatest === npmLatest &&
    gap.goStable === goStable;
  if (!acknowledged) {
    failures.push(
      `the Go module serves ${goStable} as its @latest while npm latest is ${npmLatest}. ` +
        "An adopter running `go get` and an adopter running `npm install` get " +
        "different builds of the same protocol. Promote npm or record the gap " +
        "in the go pin's `knownGap` field with a reason.",
    );
  }
}

if (failures.length > 0) {
  console.error("release parity check failed:\n");
  for (const failure of failures) console.error(`  - ${failure}\n`);
  process.exit(1);
}

console.log(`release parity ok: ${packageVersion} in the tree, npm latest ${npmLatest}, Go stable ${goStable ?? "none"}`);
