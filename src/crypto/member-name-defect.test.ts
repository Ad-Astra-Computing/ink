import { describe, it, expect } from "vitest";
import { hasEscapedMemberNameDefect } from "./member-name-defect.js";

describe("hasEscapedMemberNameDefect", () => {
  it("returns a boolean without throwing on any runtime", () => {
    expect(typeof hasEscapedMemberNameDefect()).toBe("boolean");
  });

  it("is stable across repeated calls in one process", () => {
    // The defect is state-dependent, but the probe plants its own transition on
    // the first call, so from then on the answer must not oscillate. A flapping
    // probe would be worse than no probe: an adopter gating on it would get a
    // different answer depending on when they asked.
    const first = hasEscapedMemberNameDefect();
    for (let i = 0; i < 20; i++) {
      expect(hasEscapedMemberNameDefect()).toBe(first);
    }
  });

  it("agrees with a direct observation of the defect", () => {
    const direct = JSON.parse(String.raw`{"x":{"\\":1},"y":{"\n":2}}`) as {
      y: Record<string, unknown>;
    };
    const observed = !Object.prototype.hasOwnProperty.call(direct.y, "\n");
    expect(hasEscapedMemberNameDefect()).toBe(observed);
  });
});
