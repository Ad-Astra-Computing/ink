/**
 * Build info: what library this deployment is actually running.
 *
 * The receiver is built only from the published `@adastracomputing/ink`
 * package, and it is deployed by hand. Nothing else in the repository can tell
 * a current deployment from one running a release or two behind, so an
 * interop check against it can report a pass for a build that was never the
 * one under test. These tests pin the surface that makes staleness visible.
 *
 * The version is read from the installed package rather than written down,
 * because a transcribed version is a claim and an imported one is a fact.
 */
import { describe, it, expect } from "vitest";
import inkPkg from "@adastracomputing/ink/package.json" with { type: "json" };
import { buildInfo, buildInfoHeader, BUILD_INFO_HEADER } from "../src/build-info.js";

describe("build info", () => {
  it("reads the ink version from the installed package, not a transcript", () => {
    // Comparing the module's import to the test's import of the same file
    // only proves the wiring holds, so the shape assertion carries the rest:
    // an undefined or empty version would otherwise sail through as a value
    // and reach a freshness check as a blank answer.
    expect(buildInfo({}).ink).toBe(inkPkg.version);
    expect(buildInfo({}).ink).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("names the deployed worker version when Cloudflare provides one", () => {
    const info = buildInfo({ CF_VERSION_METADATA: { id: "abc-123", tag: "v7" } });
    expect(info.deployment).toBe("abc-123");
  });

  it("says unknown rather than inventing a deployment id", () => {
    // Local `wrangler dev` and the test runner have no version metadata. An
    // empty string here would read as a real answer in a freshness check.
    expect(buildInfo({}).deployment).toBe("unknown");
  });

  it("formats a header a human can read off curl -i", () => {
    const value = buildInfoHeader({ CF_VERSION_METADATA: { id: "abc-123", tag: "" } });
    expect(value).toBe(`ink=${inkPkg.version}; deployment=abc-123`);
    expect(BUILD_INFO_HEADER).toBe("Ink-Receiver-Build");
  });

  it("keeps the header value free of characters that cannot go in one", () => {
    // A header value carrying a newline is a response-splitting primitive.
    // The inputs are ours today, so this pins the property rather than
    // trusting that they stay that way.
    const value = buildInfoHeader({ CF_VERSION_METADATA: { id: "a\r\nX-Evil: 1", tag: "" } });
    expect(value).not.toMatch(/[\r\n]/);
  });
});
