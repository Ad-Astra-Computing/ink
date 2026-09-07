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
  knownGap?: { npmLatest: string; goStable: string; reason: string };
}

export interface ParityInput {
  packageVersion: string;
  /** The `Version` constant in `go/internal/cli/cli.go`, or null if unreadable. */
  cliVersion: string | null;
  goPin: GoPin;
  npmLatest: string | undefined;
  allowKnownGap: boolean;
}

/**
 * The one published skew this check accepts, held here rather than read from
 * the pin file. `go/v0.19.0` was pushed bare on 2026-09-02, before RELEASING.md
 * set the prerelease rule, and a Go tag cannot be withdrawn. Reading the
 * allowance out of the same file a release commit edits would let any later
 * skew be waved through by editing two lines, which is the opposite of what the
 * check is for. Delete this and the `--allow-known-gap` flag once npm catches
 * up.
 */
export const ACKNOWLEDGED_GAP = { npmLatest: "0.18.0", goStable: "0.19.0" } as const;

interface Parsed {
  release: [number, number, number];
  prerelease: string[];
}

function parse(version: string): Parsed {
  const [base = "", ...rest] = version.split("-");
  const [major = 0, minor = 0, patch = 0] = base.split(".").map(Number);
  const suffix = rest.join("-");
  return { release: [major, minor, patch], prerelease: suffix === "" ? [] : suffix.split(".") };
}

export function isPrerelease(version: string): boolean {
  return parse(version).prerelease.length > 0;
}

/** True when two versions name the same release, prerelease suffix aside. */
export function sameRelease(a: string, b: string): boolean {
  const [x, y] = [parse(a).release, parse(b).release];
  return x[0] === y[0] && x[1] === y[1] && x[2] === y[2];
}

/**
 * Semantic version ordering, including the prerelease rules: a suffixed version
 * sorts below the release it precedes, and numeric identifiers compare as
 * numbers so `next.10` is after `next.2`.
 */
export function compareVersions(a: string, b: string): number {
  const left = parse(a);
  const right = parse(b);
  for (let i = 0; i < 3; i++) {
    const diff = (left.release[i] ?? 0) - (right.release[i] ?? 0);
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
    const [ln, rn] = [Number(l), Number(r)];
    const numeric = !Number.isNaN(ln) && !Number.isNaN(rn);
    if (numeric) return ln - rn;
    return l < r ? -1 : 1;
  }
  return 0;
}

/** Every parity rule the release commit has to satisfy, worst first. */
export function parityFailures(input: ParityInput): string[] {
  const failures: string[] = [];
  const { packageVersion, cliVersion, goPin, npmLatest } = input;

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

  if (stable !== null && npmLatest !== undefined && compareVersions(stable, npmLatest) > 0) {
    const acknowledged =
      input.allowKnownGap &&
      npmLatest === ACKNOWLEDGED_GAP.npmLatest &&
      stable === ACKNOWLEDGED_GAP.goStable;
    if (!acknowledged) {
      failures.push(
        `the Go module serves ${stable} as its @latest while npm latest is ${npmLatest}. ` +
          "An adopter running `go get` and an adopter running `npm install` get " +
          "different builds of the same protocol. Promote npm to close the gap; " +
          "the Go tag cannot be withdrawn to open it.",
      );
    }
  }

  return failures;
}
