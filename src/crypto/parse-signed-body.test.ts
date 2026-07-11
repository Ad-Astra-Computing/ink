import { describe, it, expect } from "vitest";
import { parseSignedBodyBytes, ParseSignedBodyError } from "./parse-signed-body.js";

// A single backslash. Escape sequences are built by concatenation so the test
// source never carries a literal escape a tool might fold into a code point.
const bs = "\\";

function bytes(...values: number[]): Uint8Array {
  return Uint8Array.from(values);
}

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

describe("parseSignedBodyBytes", () => {
  it("parses a valid ASCII body", () => {
    expect(parseSignedBodyBytes(utf8(`{"note":"hello"}`))).toEqual({ note: "hello" });
  });

  it("parses a valid multibyte UTF-8 body", () => {
    // €, an emoji surrogate pair, and a CJK character are all valid UTF-8.
    const body = `{"note":"€ 😀 你"}`;
    expect(parseSignedBodyBytes(utf8(body))).toEqual({ note: "€ 😀 你" });
  });

  it("rejects a lone continuation byte", () => {
    expect(() => parseSignedBodyBytes(bytes(0x7b, 0x80, 0x7d))).toThrow(/utf-8/i);
  });

  it("rejects a truncated multibyte sequence", () => {
    // 0xE2 0x82 begins a three-byte sequence with the third byte missing.
    expect(() => parseSignedBodyBytes(bytes(0x7b, 0xe2, 0x82, 0x7d))).toThrow(/utf-8/i);
  });

  it("rejects an overlong encoding of the solidus", () => {
    // 0xC0 0xAF is an overlong two-byte encoding of "/".
    expect(() => parseSignedBodyBytes(bytes(0x7b, 0xc0, 0xaf, 0x7d))).toThrow(/utf-8/i);
  });

  it("rejects the byte 0xFF, which never appears in UTF-8", () => {
    expect(() => parseSignedBodyBytes(bytes(0x7b, 0xff, 0x7d))).toThrow(/utf-8/i);
  });

  it("rejects UTF-16 bytes of a non-ASCII body", () => {
    // The UTF-16BE code unit for the euro sign, 0x20AC, puts 0xAC where UTF-8
    // wants a lead byte, so the body is not valid UTF-8.
    expect(() => parseSignedBodyBytes(bytes(0x7b, 0x20, 0xac, 0x7d))).toThrow(/utf-8/i);
  });

  it("runs the lone-surrogate scan after a successful UTF-8 decode", () => {
    // The bytes are valid UTF-8, but the decoded JSON text carries a lone
    // high-surrogate escape, so the surrogate scan must still reject it.
    const body = `{"note":"${bs}uD800"}`;
    expect(() => parseSignedBodyBytes(utf8(body))).toThrow(/surrogate/i);
  });

  it("rejects a body that is valid UTF-8 but not JSON", () => {
    expect(() => parseSignedBodyBytes(utf8("{not json"))).toThrow();
  });

  it("throws ParseSignedBodyError with reason utf8 for invalid UTF-8", () => {
    try {
      parseSignedBodyBytes(bytes(0x7b, 0xff, 0x7d));
      expect.unreachable("expected a throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ParseSignedBodyError);
      expect((err as ParseSignedBodyError).reason).toBe("utf8");
    }
  });

  it("throws ParseSignedBodyError with reason surrogate for a lone surrogate escape", () => {
    const body = `{"note":"${bs}uD800"}`;
    try {
      parseSignedBodyBytes(utf8(body));
      expect.unreachable("expected a throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ParseSignedBodyError);
      expect((err as ParseSignedBodyError).reason).toBe("surrogate");
    }
  });

  it("throws a native SyntaxError, not ParseSignedBodyError, for invalid JSON", () => {
    try {
      parseSignedBodyBytes(utf8("{not json"));
      expect.unreachable("expected a throw");
    } catch (err) {
      expect(err).toBeInstanceOf(SyntaxError);
      expect(err).not.toBeInstanceOf(ParseSignedBodyError);
    }
  });
});
