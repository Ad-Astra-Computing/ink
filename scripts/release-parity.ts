/**
 * The rules behind `check-release-parity.ts`, kept apart from the file reading
 * so they can be tested against states the repository is not in.
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
 * from its pin has to come from these rules plus the version suffix convention
 * in RELEASING.md.
 */

export interface GoPin {
  module: string;
  published: { stable: string | null; prerelease: string | null };
}

export interface ParityInput {
  packageVersion: string;
  /** The `Version` constant in `go/internal/cli/cli.go`, or null if unreadable. */
  cliVersion: string | null;
  goPin: GoPin;
  npmLatest: string | undefined;
}

interface Parsed {
  release: [string, string, string];
  prerelease: string[];
}

/**
 * The whole grammar, so a string this check cannot order is rejected outright
 * rather than read as something near it. Leading zeros, an empty or malformed
 * build suffix and a character outside the alphabet all fail here: a pin the
 * check cannot order is a pin it cannot vouch for.
 */
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$/;

/**
 * The version, or null when the string is not one. Build metadata is parsed and
 * discarded, because SemVer gives it no precedence. Release components stay as
 * digit strings: a counter wide enough to overflow a double still has to order.
 */
function parse(version: string): Parsed | null {
  const match = SEMVER.exec(version);
  if (match === null) return null;
  const [, major = "0", minor = "0", patch = "0", suffix] = match;
  return {
    release: [major, minor, patch],
    prerelease: suffix === undefined ? [] : suffix.split("."),
  };
}

function require_(version: string): Parsed {
  const parsed = parse(version);
  if (parsed === null) throw new RangeError(`${version} is not a semantic version`);
  return parsed;
}

/** True when the string is a semantic version, and so one this check can order. */
export function isVersion(version: string): boolean {
  return parse(version) !== null;
}

export function isPrerelease(version: string): boolean {
  return require_(version).prerelease.length > 0;
}

/** True when two versions name the same release, prerelease suffix aside. */
export function sameRelease(a: string, b: string): boolean {
  const [x, y] = [require_(a).release, require_(b).release];
  return x.every((part, i) => part === y[i]);
}

/**
 * Numeric identifiers compared without turning them into doubles, so two
 * counters that differ past the point a double can represent still order, and
 * two wide enough to round to infinity do not come back equal. Longer is larger
 * once the leading zeros are gone.
 */
function compareNumeric(a: string, b: string): number {
  const [l, r] = [a.replace(/^0+(?=\d)/, ""), b.replace(/^0+(?=\d)/, "")];
  if (l.length !== r.length) return l.length - r.length;
  return l === r ? 0 : l < r ? -1 : 1;
}

/**
 * Semantic version ordering, including the prerelease rules: a suffixed version
 * sorts below the release it precedes, and numeric identifiers compare as
 * numbers so `next.10` is after `next.2`.
 */
export function compareVersions(a: string, b: string): number {
  const left = require_(a);
  const right = require_(b);
  for (let i = 0; i < 3; i++) {
    const diff = compareNumeric(left.release[i] ?? "0", right.release[i] ?? "0");
    if (diff !== 0) return diff;
  }
  if (left.prerelease.length === 0 || right.prerelease.length === 0) {
    return right.prerelease.length - left.prerelease.length;
  }
  for (let i = 0; i < Math.max(left.prerelease.length, right.prerelease.length); i++) {
    const l = left.prerelease[i];
    const r = right.prerelease[i];
    if (l === undefined || r === undefined) return (l === undefined ? 0 : 1) - (r === undefined ? 0 : 1);
    if (l === r) continue;
    const digits = /^\d+$/;
    const [ln, rn] = [digits.test(l), digits.test(r)];
    if (ln && rn) return compareNumeric(l, r);
    // A numeric identifier ranks below an alphanumeric one.
    if (ln !== rn) return ln ? -1 : 1;
    return l < r ? -1 : 1;
  }
  return 0;
}

/** Every parity rule the release commit has to satisfy, worst first. */
export function parityFailures(input: ParityInput): string[] {
  const failures: string[] = [];
  const { packageVersion, cliVersion, goPin, npmLatest } = input;

  // Nothing below can order a string it cannot read, and reading an unreadable
  // one as 0.0.0 would let it pass every comparison. Stop here instead.
  const unreadable = [
    ["package.json", packageVersion],
    ["go/internal/cli/cli.go", cliVersion],
    ["the Go pin's stable channel", goPin.published.stable],
    ["the Go pin's prerelease channel", goPin.published.prerelease],
    ["the npm `latest` pin", npmLatest],
  ].filter(([, v]) => typeof v === "string" && !isVersion(v));
  if (unreadable.length > 0) {
    return unreadable.map(
      ([where, v]) => `${where} records ${v}, which is not a version this check can order`,
    );
  }

  // The constant is the version the `ink` binary reports, so it is what an
  // adopter quotes in a bug report and the only version string the Go module
  // carries in its own source.
  if (cliVersion === null) {
    failures.push('go/internal/cli/cli.go has no `const Version = "..."` line to read');
  } else if (cliVersion !== packageVersion) {
    failures.push(
      `version skew in the tree: package.json is ${packageVersion}, ` +
        `go/internal/cli/cli.go is ${cliVersion}`,
    );
  }

  const stable = goPin.published.stable;
  if (stable !== null && isPrerelease(stable)) {
    failures.push(
      `the Go pin records ${stable} on its stable channel. A suffixed version is a ` +
        "prerelease and belongs on `prerelease`; recording it as stable would hide a skew.",
    );
  }
  if (npmLatest !== undefined && isPrerelease(npmLatest)) {
    failures.push(
      `the npm pin records ${npmLatest} on \`latest\`. Pre-1.0 releases sit on ` +
        "`next` until they are promoted, and `latest` never holds a prerelease.",
    );
  }

  const channels = [stable, goPin.published.prerelease].filter((v): v is string => v !== null);
  if (!channels.some((v) => sameRelease(v, packageVersion))) {
    failures.push(
      `governance/releases/go-module.json records ${channels.join(" and ") || "nothing"}, ` +
        `which does not include the tree's version ${packageVersion}. ` +
        "A release commit bumps the Go pin with package.json (see RELEASING.md).",
    );
  }

  if (stable !== null && npmLatest !== undefined && compareVersions(stable, npmLatest) !== 0) {
    const goAhead = compareVersions(stable, npmLatest) > 0;
    const shared =
      "An adopter running `go get` and an adopter running `npm install` get " +
      "different builds of the same protocol.";
    failures.push(
      goAhead
        ? `the Go module serves ${stable} as its @latest while npm latest is ${npmLatest}. ` +
            `${shared} Promote npm to close the gap; the Go tag cannot be withdrawn to open it.`
        : `npm serves ${npmLatest} on \`latest\` while the Go module's stable channel is ` +
            `${stable}. ${shared} Tag the Go module to close the gap.`,
    );
  }

  return failures;
}
