import { describe, it, expect } from "vitest";
import {
  containsLoneSurrogateEscape,
  containsOutOfRangeNumberLiteral,
  containsEscapedMemberName,
  parseSignedBodyBytes,
  ParseSignedBodyError,
} from "../src/index.js";
import * as binGate from "../bin/signed-body-gate.mjs";

/**
 * `bin/signed-body-gate.mjs` is a second copy of the signed-body text rules.
 * It exists because the CLI must run from a git checkout with no `dist/`, so it
 * cannot import the library's copy. A second copy of a security rule is exactly
 * the drift this release fixed elsewhere, so it is held in step here rather
 * than by care: the two are run against one table and must agree on every case.
 *
 * If this fails, one side was changed and the other was not. Fix the copy, do
 * not relax the test.
 */

const enc = new TextEncoder();

// Cases chosen to exercise each rule and each other rule's non-interference.
const CASES: string[] = [
  // ordinary
  `{"a":1}`,
  `{"a":1,"b":{"c":[1,2,3]}}`,
  `{"é":1,"𝄞":2}`,
  `{"":1}`,
  `[]`,
  `123`,
  `null`,
  `"plain"`,
  // escapes in values and elements, which no rule touches
  String.raw`{"a":"line\nbreak"}`,
  String.raw`{"a":"back\\slash"}`,
  String.raw`{"a":"\u0041"}`,
  String.raw`{"a":["\n","\\","\u0041"]}`,
  String.raw`{"a":"b:c","d":"\n:e"}`,
  String.raw`{"a":"ends with \"","b":1}`,
  // surrogates
  String.raw`{"note":"\uD83D\uDE00"}`,
  String.raw`{"note":"\\uD800"}`,
  String.raw`{"note":"\uD800"}`,
  String.raw`{"note":"\uDC00"}`,
  String.raw`{"note":"\ud800"}`,
  String.raw`{"a":["x","\uDC00"]}`,
  // A high surrogate followed by some other \u escape, which catches a copy that
  // treats "followed by any \u" as a valid pair.
  String.raw`{"note":"\uD800\u0041"}`,
  // number literals
  `{"n":1}`,
  `{"n":1e2}`,
  `{"n":1e309}`,
  // Just past the double maximum, which catches a copy keying on exponent text
  // rather than on the decoded value.
  `{"n":2e308}`,
  `{"n":1.7976931348623157e308}`,
  `{"n":-1e309}`,
  `{"n":1e-400}`,
  `{"n":1e309,"n":1}`,
  `{"note":"1e309"}`,
  `1e309`,
  // escaped member names
  String.raw`{"\n":1}`,
  String.raw`{"\t":1}`,
  String.raw`{"\\":1}`,
  String.raw`{"\"":1}`,
  String.raw`{"\/":1}`,
  String.raw`{"\u0041":1}`,
  String.raw`{"a\nb":1}`,
  String.raw`{"a":{"\n":1}}`,
  String.raw`{"a":[{"b":{"\\":1}}]}`,
  String.raw`{"\n"  :  1}`,
  String.raw`{"x":{"\\":1},"y":{"\n":2}}`,
  String.raw`{"a":"ends with \"","\n":1}`,
  // truncated and malformed, where both must at least agree and not throw
  `{"a":"\\`,
  `{"\\`,
  `{"a"`,
  `{`,
  ``,
];

describe("bin/signed-body-gate.mjs agrees with the library", () => {
  for (const text of CASES) {
    it(`decides ${JSON.stringify(text)} the same way`, () => {
      expect(binGate.containsLoneSurrogateEscape(text)).toBe(containsLoneSurrogateEscape(text));
      expect(binGate.containsOutOfRangeNumberLiteral(text)).toBe(containsOutOfRangeNumberLiteral(text));
      expect(binGate.containsEscapedMemberName(text)).toBe(containsEscapedMemberName(text));
    });
  }

  for (const text of CASES) {
    it(`parses or rejects ${JSON.stringify(text)} identically`, () => {
      let libReason: string | null = null;
      let libValue: unknown;
      let libThrew = false;
      try {
        libValue = parseSignedBodyBytes(enc.encode(text));
      } catch (e) {
        libThrew = true;
        libReason = e instanceof ParseSignedBodyError ? e.reason : null;
      }

      let binReason: string | null = null;
      let binValue: unknown;
      let binThrew = false;
      try {
        binValue = binGate.parseSignedBodyBytes(enc.encode(text));
      } catch (e) {
        binThrew = true;
        binReason = e instanceof binGate.SignedBodyGateError ? e.reason : null;
      }

      expect(binThrew).toBe(libThrew);
      expect(binReason).toBe(libReason);
      if (!libThrew) expect(binValue).toEqual(libValue);
    });
  }

  it("rejects invalid UTF-8 bytes the same way", () => {
    const bytes = new Uint8Array([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]);
    const lib = (() => {
      try {
        parseSignedBodyBytes(bytes);
        return null;
      } catch (e) {
        return e instanceof ParseSignedBodyError ? e.reason : "other";
      }
    })();
    const bin = (() => {
      try {
        binGate.parseSignedBodyBytes(bytes);
        return null;
      } catch (e) {
        return e instanceof binGate.SignedBodyGateError ? e.reason : "other";
      }
    })();
    expect(bin).toBe(lib);
    expect(lib).toBe("utf8");
  });
});
