import { describe, expect, it } from "vitest";
import {
  ACKNOWLEDGED_GAP,
  compareVersions,
  parityFailures,
  type ParityInput,
} from "../scripts/release-parity.js";

const basePin: ParityInput["goPin"] = {
  module: "github.com/Ad-Astra-Computing/ink/go",
  published: { stable: "0.19.0", prerelease: null },
};

function input(overrides: Partial<ParityInput> = {}): ParityInput {
  return {
    packageVersion: "0.19.0",
    cliVersion: "0.19.0",
    goPin: basePin,
    npmLatest: "0.18.0",
    allowKnownGap: true,
    ...overrides,
  };
}

describe("compareVersions", () => {
  it("orders by major, minor and patch", () => {
    expect(compareVersions("0.19.0", "0.18.0")).toBeGreaterThan(0);
    expect(compareVersions("0.9.0", "0.10.0")).toBeLessThan(0);
    expect(compareVersions("1.0.0", "0.99.99")).toBeGreaterThan(0);
    expect(compareVersions("0.19.0", "0.19.0")).toBe(0);
  });

  it("sorts a prerelease below the release it precedes", () => {
    expect(compareVersions("0.20.0-next.1", "0.20.0")).toBeLessThan(0);
    expect(compareVersions("0.20.0", "0.20.0-next.1")).toBeGreaterThan(0);
  });

  it("orders prerelease counters numerically rather than as text", () => {
    expect(compareVersions("0.20.0-next.2", "0.20.0-next.10")).toBeLessThan(0);
    expect(compareVersions("0.20.0-next.1", "0.20.0-next.1")).toBe(0);
  });
});

describe("parityFailures", () => {
  it("passes the state recorded in the tree today", () => {
    expect(parityFailures(input())).toEqual([]);
  });

  it("catches the two version strings drifting apart", () => {
    const [failure] = parityFailures(input({ cliVersion: "0.18.9" }));
    expect(failure).toMatch(/version skew in the tree/);
  });

  it("catches a release commit that forgets the Go pin", () => {
    const [failure] = parityFailures(input({ packageVersion: "0.20.0", cliVersion: "0.20.0" }));
    expect(failure).toMatch(/does not include the tree's version 0\.20\.0/);
  });

  it("accepts a prerelease channel that names the tree's version", () => {
    expect(
      parityFailures(
        input({
          packageVersion: "0.20.0",
          cliVersion: "0.20.0",
          goPin: { ...basePin, published: { stable: "0.19.0", prerelease: "0.20.0-next.1" } },
          npmLatest: "0.19.0",
          allowKnownGap: false,
        }),
      ),
    ).toEqual([]);
  });

  it("does not let a prerelease channel stand in for the release itself", () => {
    const [failure] = parityFailures(
      input({
        packageVersion: "0.20.0",
        cliVersion: "0.20.0",
        goPin: { ...basePin, published: { stable: "0.19.0", prerelease: "0.21.0-next.1" } },
      }),
    );
    expect(failure).toMatch(/does not include the tree's version/);
  });

  it("fails when Go is ahead of npm and nothing acknowledges it", () => {
    const [failure] = parityFailures(input({ allowKnownGap: false }));
    expect(failure).toMatch(/serves 0\.19\.0 as its @latest while npm latest is 0\.18\.0/);
  });

  it("accepts only the recorded gap, not a wider one the pin was edited to claim", () => {
    const widened = parityFailures(
      input({
        packageVersion: "0.20.0",
        cliVersion: "0.20.0",
        goPin: {
          ...basePin,
          published: { stable: "0.20.0", prerelease: null },
          knownGap: { npmLatest: "0.18.0", goStable: "0.20.0", reason: "widened by hand" },
        },
      }),
    );
    expect(widened.join("\n")).toMatch(/serves 0\.20\.0 as its @latest/);
  });

  it("holds the acknowledged gap as a literal the pin file cannot move", () => {
    expect(ACKNOWLEDGED_GAP).toEqual({ npmLatest: "0.18.0", goStable: "0.19.0" });
  });

  it("rejects a pin that records a prerelease on the stable channel", () => {
    const [failure] = parityFailures(
      input({
        packageVersion: "0.20.0",
        cliVersion: "0.20.0",
        goPin: { ...basePin, published: { stable: "0.20.0-next.1", prerelease: null } },
        npmLatest: "0.20.0",
      }),
    );
    expect(failure).toMatch(/stable channel/);
  });

  it("rejects an npm pin whose latest is a prerelease", () => {
    const failures = parityFailures(input({ npmLatest: "0.19.0-next.1" }));
    expect(failures.join("\n")).toMatch(/npm pin records 0\.19\.0-next\.1 on `latest`/);
  });
});
