import { describe, it, expect } from "vitest";
import { containsLoneSurrogateEscape, hasUnpairedSurrogate } from "./surrogate.js";
import { signMessage } from "./sign.js";
import { signInkMessage, verifyInkSignature } from "./ink.js";

// A single backslash. Escape sequences are built by concatenation (bs + "uD800")
// so the test source never contains a literal escape a tool might fold into a
// real code point.
const bs = "\\";
const hi = bs + "uD83D";
const lo = bs + "uDE00";
const loneHi = bs + "uD800";
const loneLo = bs + "uDC00";

describe("containsLoneSurrogateEscape (raw JSON text)", () => {
  const accepts: Array<[string, string]> = [
    ["plain", `{"note":"hello"}`],
    ["empty string", `{"note":""}`],
    ["no strings", `{"n":1,"b":true,"x":null}`],
    ["valid pair", `{"note":"${hi}${lo}"}`],
    ["lowercase valid pair", `{"note":"${bs}ud83d${bs}ude00"}`],
    ["literal escaped backslash u", `{"note":"${bs}${bs}uD800"}`],
    ["bmp escape", `{"note":"${bs}u0041"}`],
    ["surrogate-shaped hex outside string", loneHi],
  ];
  for (const [name, raw] of accepts) {
    it(`accepts ${name}`, () => expect(containsLoneSurrogateEscape(raw)).toBe(false));
  }

  const rejects: Array<[string, string]> = [
    ["lone high", `{"note":"${loneHi}"}`],
    ["lone low", `{"note":"${loneLo}"}`],
    ["lowercase lone high", `{"note":"${bs}ud800"}`],
    ["high then bmp", `{"note":"${loneHi}${bs}u0041"}`],
    ["high split by char", `{"note":"${loneHi}x${loneLo}"}`],
    ["high then literal backslash u", `{"note":"${loneHi}${bs}${bs}uDC00"}`],
    ["lone high in key", `{"${loneHi}":"v"}`],
    ["lone low in array", `{"a":["x","${loneLo}"]}`],
    ["truncated lone high", `{"note":"${loneHi}`],
  ];
  for (const [name, raw] of rejects) {
    it(`rejects ${name}`, () => expect(containsLoneSurrogateEscape(raw)).toBe(true));
  }
});

describe("hasUnpairedSurrogate (parsed value)", () => {
  const H = String.fromCharCode(0xd800); // lone high
  const L = String.fromCharCode(0xdc00); // lone low
  const pair = String.fromCharCode(0xd83d, 0xde00); // valid astral pair

  it("accepts plain values", () => {
    expect(hasUnpairedSurrogate({ note: "hello", n: 1, ok: true })).toBe(false);
  });
  it("accepts a valid surrogate pair", () => {
    expect(hasUnpairedSurrogate({ note: pair })).toBe(false);
  });
  it("rejects a lone high in a value", () => {
    expect(hasUnpairedSurrogate({ note: H })).toBe(true);
  });
  it("rejects a lone low in a value", () => {
    expect(hasUnpairedSurrogate({ note: L })).toBe(true);
  });
  it("rejects a lone surrogate in a key", () => {
    expect(hasUnpairedSurrogate({ [H]: "v" })).toBe(true);
  });
  it("rejects a lone surrogate nested in an array", () => {
    expect(hasUnpairedSurrogate({ a: ["x", { b: L }] })).toBe(true);
  });
});

// The raw-text scanner (receiver boundary) and the parsed-object walk (signer
// boundary) must flag the same set: a lone surrogate detected on either side is
// detected on the other after JSON.parse / serialization.
describe("raw scan and object walk agree", () => {
  const bodies = [
    `{"note":"hello"}`,
    `{"note":"${hi}${lo}"}`,
    `{"note":"${loneHi}"}`,
    `{"note":"${loneLo}"}`,
    `{"a":["x","${loneLo}"]}`,
    `{"deep":{"k":"${loneHi}"}}`,
  ];
  for (const body of bodies) {
    it(`agree on ${body.slice(0, 24)}`, () => {
      const rawResult = containsLoneSurrogateEscape(body);
      const objResult = hasUnpairedSurrogate(JSON.parse(body));
      expect(objResult).toBe(rawResult);
    });
  }
});

describe("signMessage integration", () => {
  it("refuses to sign a body containing a lone surrogate", async () => {
    const key = new Uint8Array(32).fill(7);
    await expect(
      signMessage({ note: String.fromCharCode(0xd800) }, key),
    ).rejects.toThrow(/surrogate/);
  });
  it("signs an ordinary body", async () => {
    const key = new Uint8Array(32).fill(7);
    await expect(signMessage({ note: "hello" }, key)).resolves.toMatch(/^[A-Za-z0-9_-]{86}$/);
  });
});

describe("signInkMessage / verifyInkSignature integration", () => {
  const base = {
    method: "POST",
    path: "/ink/v1/x/intent",
    recipientDid: "tulpa:z",
    timestamp: "2026-06-11T00:00:00.000Z",
  };
  it("signInkMessage refuses a body with a lone surrogate", async () => {
    const key = new Uint8Array(32).fill(7);
    await expect(
      signInkMessage({ ...base, body: { note: String.fromCharCode(0xd800) } }, key),
    ).rejects.toThrow(/surrogate/);
  });
  it("verifyInkSignature rejects a body with a lone surrogate", async () => {
    const ok = await verifyInkSignature(
      { ...base, body: { note: String.fromCharCode(0xd800) } },
      "A".repeat(86),
      new Uint8Array(32),
    );
    expect(ok).toBe(false);
  });
});
