/**
 * Pre-release gate on the offline dist-tag pin.
 *
 * `governance/releases/npm-dist-tags.json` is the offline source of truth for
 * every dist-tag quoted in prose. `npm run check:facts` compares it against the
 * registry, so once the registry moves past the pin, `main` goes red and stays
 * red until someone edits the file by hand. That is the wrong end of the
 * process to discover a missing pin bump: the release has already shipped and
 * every document quoting a dist-tag is already stale.
 *
 * This check moves the failure to release time. It runs on the publish path,
 * before anything is published, and refuses to proceed while the pin disagrees
 * with the version and dist-tag the release is about to move. The pin is
 * therefore part of the release commit, as GOVERNANCE.md already requires, and
 * the registry can never move past it.
 *
 * This does NOT relax `check:facts`, and it must not: the pin stays committed
 * and offline so a gate running without network access cannot silently pass,
 * and `check:facts` still fails loudly whenever the pin and the registry
 * genuinely disagree. This check is a second, earlier gate on the same fact.
 *
 * Usage:
 *   tsx scripts/check-release-pin.ts --tag <latest|next|any> [--version <x.y.z>]
 *
 * With no `--version`, the version is read from package.json. `--tag` is
 * required, because which dist-tag a release moves is a property of the
 * publish path (a `v*` tag moves `next`, a `latest-v*` tag moves `latest`)
 * and guessing it would defeat the check.
 *
 * `--tag any` is the weaker form CI runs on every push: it asks only that the
 * version in the tree is recorded on some dist-tag in the pin, without caring
 * which. That is true of every commit under this discipline, because a version
 * bump only ever happens in a release commit and a release commit bumps the
 * pin with it. It holds for a normal release, whose version lands on `next`,
 * and for a promotion re-cut, whose version lands on `latest`. So a release
 * pull request that forgets the pin fails review rather than the tag push,
 * and the tag push stays the backstop.
 *
 * `--match-package-version` additionally requires the version to be the one in
 * the tree. The publish paths pass it, because they ship what the tree builds.
 * The fallback promotion path does not, because moving a dist-tag onto an
 * already-published version, including rolling one back, is legitimately about
 * a version other than the one on `main`.
 *
 * Written in erasable TypeScript so bare `node scripts/check-release-pin.ts`
 * runs it. The credentialed promotion job needs no dependency install to
 * check the pin before it moves a tag.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../", import.meta.url).href);
const PIN_FILE = "governance/releases/npm-dist-tags.json";
const SEMVER = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const TAGS = ["latest", "next"] as const;
type DistTag = (typeof TAGS)[number];

function readJson<T>(file: string): T {
  return JSON.parse(readFileSync(repoRoot + file, "utf8")) as T;
}

function die(lines: string[]): never {
  console.error("");
  console.error("Release blocked: the release commit does not describe this release correctly.");
  console.error("");
  for (const line of lines) console.error(line === "" ? "" : `  ${line}`);
  console.error("");
  console.error("Fix the release commit and re-cut the tag. Nothing has been published.");
  process.exit(1);
  // `process.exit` is typed as returning `void` under this project's ambient
  // globals, so the compiler cannot see that control stops here.
  throw new Error("unreachable");
}

function arg(name: string): string | undefined {
  const flag = `--${name}`;
  const i = process.argv.indexOf(flag);
  if (i !== -1) {
    const value = process.argv[i + 1];
    // An empty or missing value means the caller meant to pass something and
    // did not. Falling back to a default here would check a fact nobody asked
    // about, so it is a usage error.
    if (value === undefined || value === "" || value.startsWith("--")) {
      console.error(`${flag} requires a value`);
      process.exit(2);
    }
    return value;
  }
  const inline = (process.argv as string[]).find((a) => a.startsWith(`${flag}=`));
  return inline?.slice(flag.length + 1);
}

const pkg = readJson<{ name: string; version: string }>("package.json");
const pin = readJson<{
  package: string;
  distTags: Record<string, string>;
  verifiedAt?: string;
}>(PIN_FILE);

const ANY = "any";
const rawTag = arg("tag");
if (!rawTag || !([...TAGS, ANY] as readonly string[]).includes(rawTag)) {
  console.error(`usage: check-release-pin --tag <${TAGS.join("|")}|${ANY}> [--version <x.y.z>]`);
  console.error(`  (got --tag ${rawTag === undefined ? "<missing>" : `\`${rawTag}\``})`);
  process.exit(2);
}
const tag = rawTag as DistTag | typeof ANY;

const version = arg("version") ?? pkg.version;
if (!SEMVER.test(version)) {
  die([
    `\`${version}\` is not a bare semver version.`,
    "A release names a bare `<major>.<minor>.<patch>`; a prerelease or build-metadata",
    "version is not something a dist-tag pin can describe.",
  ]);
}

// The version being published must be the version in the tree, or the gauntlet
// that ran before this point tested something other than what ships. The
// publish workflow checks this against the git tag too; checking it here as
// well keeps the script honest when it is run by hand. Off by default so the
// fallback promotion path can move a tag onto an older published version.
if (process.argv.includes("--match-package-version") && version !== pkg.version) {
  die([
    `publishing \`${version}\`, but package.json says \`${pkg.version}\`.`,
    "Bump package.json in the release commit so the tree matches the release.",
  ]);
}

if (pin.package !== pkg.name) {
  die([
    `${PIN_FILE} pins dist-tags for \`${pin.package}\`, but this package is \`${pkg.name}\`.`,
  ]);
}

if (tag === ANY) {
  const recorded = TAGS.filter((t) => pin.distTags[t] === version);
  if (recorded.length === 0) {
    die([
      `the tree is at \`${version}\`, but ${PIN_FILE} records no dist-tag at that version`,
      `(${TAGS.map((t) => `${t} = \`${pin.distTags[t] ?? "absent"}\``).join(", ")}).`,
      "",
      "A version bump only ever happens in a release commit, and a release commit updates",
      `${PIN_FILE} with it, so the two cannot legitimately disagree. If this is a`,
      "release commit, add the pin bump to it and rerun `npm run check:facts` to pick up",
      "every document that quotes a dist-tag. The pin is the offline source of truth for",
      "those documents, and leaving it behind is what puts them a release out of date.",
    ]);
  }
  console.log(
    `Release pin OK: ${pkg.name}@${version} is recorded on \`${recorded.join("`, `")}\` in ${PIN_FILE}.`,
  );
  process.exit(0);
}

const pinned = pin.distTags[tag];
if (pinned === undefined) {
  die([`${PIN_FILE} has no \`${tag}\` entry, so the release has nothing to be checked against.`]);
}

if (pinned !== version) {
  die([
    `this release moves the \`${tag}\` dist-tag to \`${version}\`,`,
    `but ${PIN_FILE} still pins \`${tag}\` = \`${pinned}\`.`,
    "",
    "The pin is the offline source of truth for every dist-tag quoted in the README, the",
    "1.0 readiness record and the specs. Publishing now would move the registry past the",
    "pin and leave those documents describing the previous release, which is exactly the",
    "drift `npm run check:facts` exists to catch. It is a release-commit edit, not a",
    "post-release cleanup.",
    "",
    `Set \`${tag}\` to \`${version}\` in ${PIN_FILE}, refresh \`verifiedAt\`, then rerun`,
    "`npm run check:facts` to pick up every document that quotes a dist-tag.",
  ]);
}

// A release only ever moves the tag it is publishing. If the other tag also
// names this version, that is either a promotion recorded on the wrong path or
// a copy-paste, and it would make the readiness record claim an adopter-grade
// stamp that no maintainer gave.
const other: DistTag = tag === "next" ? "latest" : "next";
if (tag === "next" && pin.distTags[other] === version) {
  die([
    `${PIN_FILE} pins \`${other}\` = \`${version}\` as well, but this release only moves \`${tag}\`.`,
    `A version reaches \`latest\` through a \`latest-v*\` re-cut, never as a side effect of a \`${tag}\` release.`,
    `Leave \`${other}\` at the version a maintainer actually stamped.`,
  ]);
}

console.log(
  `Release pin OK: ${pkg.name}@${version} moves \`${tag}\`, and ${PIN_FILE} already records it` +
    (pin.verifiedAt ? ` (pin verifiedAt ${pin.verifiedAt}).` : "."),
);
