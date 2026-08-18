import { describe, it, expect } from "vitest";
import { containsEscapedMemberName, hasUnsafeObjectKey } from "./member-name.js";
import { parseSignedBodyText, ParseSignedBodyError } from "./parse-signed-body.js";
import { signMessage, verifyMessage } from "./sign.js";

describe("the V8 defect this rule exists for", () => {
  // Not a test of our code: a characterisation of the runtime, so that if a
  // future V8 fixes the bug the test tells us rather than the rule quietly
  // becoming unnecessary. Whether it fires depends on the isolate's transition
  // tables, so this asserts only that our gate rejects the input either way.
  it("rejects the poisoning-and-victim document before it can be parsed", () => {
    const raw = String.raw`{"x":{"\\":1},"y":{"\n":2}}`;
    expect(() => parseSignedBodyText(raw)).toThrow(ParseSignedBodyError);
    try {
      parseSignedBodyText(raw);
    } catch (e) {
      expect((e as ParseSignedBodyError).reason).toBe("member-name-escape");
    }
  });

  it("still admits the same document once its member names carry no escape", () => {
    // The rule bans a spelling, not a structure: the same shape with plainly
    // spelled names is unaffected, which is what keeps the narrowing narrow.
    const parsed = parseSignedBodyText(`{"x":{"backslash":1},"y":{"newline":2}}`);
    expect(parsed).toEqual({ x: { backslash: 1 }, y: { newline: 2 } });
  });

  it("leaves escapes in values and array elements alone after a poisoning name would have been rejected", () => {
    expect(parseSignedBodyText(`{"a":"line\\nbreak","b":["\\\\","\\t"]}`)).toEqual({
      a: "line\nbreak",
      b: ["\\", "\t"],
    });
  });
});

describe("containsEscapedMemberName", () => {
  it("accepts member names with no escape", () => {
    expect(containsEscapedMemberName(`{"a":1}`)).toBe(false);
    expect(containsEscapedMemberName(`{"a":1,"b":{"c":[1,2,3]}}`)).toBe(false);
    expect(containsEscapedMemberName(`{"é":1,"𝄞":2}`)).toBe(false);
    expect(containsEscapedMemberName(`{"a.b-c_d":1,"":2}`)).toBe(false);
  });

  it("accepts escapes in string values", () => {
    expect(containsEscapedMemberName(`{"a":"line\\nbreak"}`)).toBe(false);
    expect(containsEscapedMemberName(`{"a":"back\\\\slash"}`)).toBe(false);
    expect(containsEscapedMemberName(`{"a":"\\u0041"}`)).toBe(false);
    expect(containsEscapedMemberName(`{"a":"quote\\"inside"}`)).toBe(false);
  });

  it("accepts escapes in array elements", () => {
    expect(containsEscapedMemberName(`{"a":["\\n","\\\\","\\u0041"]}`)).toBe(false);
    expect(containsEscapedMemberName(`["\\n","\\\\"]`)).toBe(false);
  });

  it("rejects every two-character escape in a member name", () => {
    for (const esc of ["\\n", "\\t", "\\r", "\\b", "\\f", "\\/", '\\"', "\\\\"]) {
      expect(containsEscapedMemberName(`{"${esc}":1}`)).toBe(true);
    }
  });

  it("rejects a \\uXXXX escape in a member name even when it decodes to an ordinary character", () => {
    expect(containsEscapedMemberName(`{"\\u0041":1}`)).toBe(true);
    expect(containsEscapedMemberName(`{"\\u00e9":1}`)).toBe(true);
  });

  it("rejects an escape anywhere inside a member name, not only at the start", () => {
    expect(containsEscapedMemberName(`{"a\\nb":1}`)).toBe(true);
    expect(containsEscapedMemberName(`{"ab\\\\":1}`)).toBe(true);
  });

  it("rejects an escaped member name nested at any depth", () => {
    expect(containsEscapedMemberName(`{"a":{"\\n":1}}`)).toBe(true);
    expect(containsEscapedMemberName(`{"a":[{"b":{"\\\\":1}}]}`)).toBe(true);
    expect(containsEscapedMemberName(`[[{"\\t":1}]]`)).toBe(true);
  });

  it("rejects the measured V8 corruption vectors", () => {
    // The poisoning key and the victim key from the characterisation.
    expect(containsEscapedMemberName(String.raw`{"x":{"\\":1},"y":{"\n":2}}`)).toBe(true);
    expect(containsEscapedMemberName(String.raw`{"A":1,"\"":2}`)).toBe(true);
  });

  it("tolerates whitespace between a member name and its colon", () => {
    expect(containsEscapedMemberName(`{"\\n"  :  1}`)).toBe(true);
    expect(containsEscapedMemberName(`{"\\n"\n\t: 1}`)).toBe(true);
    expect(containsEscapedMemberName(`{"a"  :  "\\n"}`)).toBe(false);
  });

  it("does not treat a colon inside a string value as a key separator", () => {
    expect(containsEscapedMemberName(`{"a":"b:c","d":"\\n:e"}`)).toBe(false);
  });

  it("handles a string value that ends in an escaped quote", () => {
    // The escaped quote must not be read as the closing quote, which would
    // desynchronise the scan and misclassify the following text.
    expect(containsEscapedMemberName(`{"a":"ends with \\"","b":1}`)).toBe(false);
    expect(containsEscapedMemberName(`{"a":"ends with \\"","\\n":1}`)).toBe(true);
  });

  it("handles a trailing backslash without reading past the end", () => {
    expect(() => containsEscapedMemberName(`{"a":"\\`)).not.toThrow();
    expect(() => containsEscapedMemberName(`{"\\`)).not.toThrow();
  });

  it("accepts a bare top-level scalar", () => {
    expect(containsEscapedMemberName(`"\\n"`)).toBe(false);
    expect(containsEscapedMemberName(`123`)).toBe(false);
    expect(containsEscapedMemberName(`null`)).toBe(false);
  });
});

describe("hasUnsafeObjectKey", () => {
  it("accepts ordinary keys", () => {
    expect(hasUnsafeObjectKey({ a: 1, b: { c: [1, 2] } })).toBe(false);
    expect(hasUnsafeObjectKey({ "é": 1, "𝄞": 2, "": 3 })).toBe(false);
    expect(hasUnsafeObjectKey({ "a.b-c_d/e": 1 })).toBe(false);
  });

  it("accepts values containing characters that are unsafe in a key", () => {
    expect(hasUnsafeObjectKey({ a: 'quote " backslash \\ newline \n' })).toBe(false);
    expect(hasUnsafeObjectKey({ a: ['\\', '"', "\u0000"] })).toBe(false);
  });

  it("rejects a key containing a quote, a backslash or a control character", () => {
    expect(hasUnsafeObjectKey({ 'a"b': 1 })).toBe(true);
    expect(hasUnsafeObjectKey({ "a\\b": 1 })).toBe(true);
    expect(hasUnsafeObjectKey({ "a\nb": 1 })).toBe(true);
    expect(hasUnsafeObjectKey({ "\u0000": 1 })).toBe(true);
    expect(hasUnsafeObjectKey({ "\u001f": 1 })).toBe(true);
  });

  it("accepts U+007F, which JCS does not escape", () => {
    expect(hasUnsafeObjectKey({ "\u007f": 1 })).toBe(false);
  });

  it("rejects an unsafe key nested at any depth", () => {
    expect(hasUnsafeObjectKey({ a: { b: { "c\\d": 1 } } })).toBe(true);
    expect(hasUnsafeObjectKey({ a: [{ "b\nc": 1 }] })).toBe(true);
    expect(hasUnsafeObjectKey([[{ '"': 1 }]])).toBe(true);
  });

  it("round-trips: a key it accepts never serializes to an escaped member name", () => {
    const safe = { "é": 1, "𝄞": 2, "a.b-c_d/e": 3, "": 4, "\u007f": 5 };
    expect(hasUnsafeObjectKey(safe)).toBe(false);
    expect(containsEscapedMemberName(JSON.stringify(safe))).toBe(false);
  });

  it("round-trips: every key it rejects does serialize to an escaped member name", () => {
    for (const key of ['a"b', "a\\b", "a\nb", "\u0000", "\u001f"]) {
      expect(hasUnsafeObjectKey({ [key]: 1 })).toBe(true);
      expect(containsEscapedMemberName(JSON.stringify({ [key]: 1 }))).toBe(true);
    }
  });
});

describe("the body-signature path refuses an unsafe key", () => {
  // §3.6 canonicalizes in sign.ts, not through jcsCanonicalize, so it needed
  // the check separately. Go's JCSCanonicalize already refused these, so
  // without this the two implementations disagreed about what can be signed,
  // which is the divergence this whole rule exists to remove.
  const KEY = 'a"b';
  const priv = new Uint8Array(32).fill(7);

  it("refuses to sign an object whose key would need escaping", async () => {
    await expect(
      signMessage({ protocol: "ink/0.1", [KEY]: 1 } as Record<string, unknown>, priv),
    ).rejects.toThrow(/object key/);
  });

  it("refuses to sign a nested unsafe key", async () => {
    await expect(
      signMessage({ protocol: "ink/0.1", a: { "b\\c": 1 } } as Record<string, unknown>, priv),
    ).rejects.toThrow(/object key/);
  });

  it("still signs an object whose keys are all safe", async () => {
    await expect(
      signMessage({ protocol: "ink/0.1", note: "line\nbreak" } as Record<string, unknown>, priv),
    ).resolves.toBeTypeOf("string");
  });

  it("fails closed rather than throwing when verifying an unsafe key", async () => {
    // The verify half of the guard. It cannot be isolated by comparing against
    // a passing verification, because the key is part of the signed content, so
    // any body carrying it fails on the signature too. What IS specific to the
    // guard is the manner of failure: it sits before canonicalize, so an unsafe
    // key returns false instead of escaping as an exception from the
    // canonicalizer. A caller that hands a parsed object straight to
    // verifyMessage has no raw text to gate, and a throw there would surface as
    // a server fault rather than a rejected message.
    const pub = new Uint8Array(32).fill(3);
    const body = { protocol: "ink/0.1", note: "ok", signature: "x".repeat(86), [KEY]: 1 };
    await expect(verifyMessage(body as Record<string, unknown>, pub)).resolves.toBe(false);
  });
});
