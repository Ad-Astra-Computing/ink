import { describe, it, expect } from "vitest";
import { containsOutOfRangeNumberLiteral } from "./number-literal.js";

describe("containsOutOfRangeNumberLiteral", () => {
  it("accepts a body with no numbers", () => {
    expect(containsOutOfRangeNumberLiteral(`{"note":"hello"}`)).toBe(false);
  });

  it("accepts in-range numbers of every shape", () => {
    expect(containsOutOfRangeNumberLiteral(`{"a":0,"b":-7,"c":1e2,"d":3.14,"e":1E+21}`)).toBe(false);
  });

  it("accepts the largest finite double", () => {
    expect(containsOutOfRangeNumberLiteral(`{"n":1.7976931348623157e308}`)).toBe(false);
  });

  it("accepts an exponent that underflows to zero", () => {
    // 1e-400 is below the smallest subnormal, so every IEEE-754 parser decodes
    // it to 0. Both implementations accept it, so the gate must not reject it.
    expect(containsOutOfRangeNumberLiteral(`{"n":1e-400}`)).toBe(false);
  });

  it("rejects an exponent above the double range", () => {
    expect(containsOutOfRangeNumberLiteral(`{"n":1e309}`)).toBe(true);
  });

  it("rejects a mantissa that rounds above the largest double", () => {
    expect(containsOutOfRangeNumberLiteral(`{"n":1.7976931348623159e308}`)).toBe(true);
  });

  it("rejects a negative literal below the double range", () => {
    expect(containsOutOfRangeNumberLiteral(`{"n":-1e1000}`)).toBe(true);
  });

  it("rejects a bare out-of-range literal as the whole document", () => {
    expect(containsOutOfRangeNumberLiteral("1e309")).toBe(true);
  });

  it("rejects an out-of-range literal shadowed by a later duplicate member", () => {
    // The whole point of the raw scan: last-wins member semantics hide the
    // literal from any check that runs on the parsed value.
    expect(containsOutOfRangeNumberLiteral(`{"a":1e309,"a":1}`)).toBe(true);
  });

  it("rejects an out-of-range literal nested in an array", () => {
    expect(containsOutOfRangeNumberLiteral(`{"a":[1,{"b":9e999}]}`)).toBe(true);
  });

  it("ignores number-like text inside a string", () => {
    expect(containsOutOfRangeNumberLiteral(`{"note":"1e309"}`)).toBe(false);
    expect(containsOutOfRangeNumberLiteral(`{"1e309":"v"}`)).toBe(false);
  });

  it("ignores number-like text inside a string that ends in an escaped quote", () => {
    const bs = "\\";
    expect(containsOutOfRangeNumberLiteral(`{"note":"a${bs}"1e309"}`)).toBe(false);
  });

  it("does not read the literals true, false and null as numbers", () => {
    expect(containsOutOfRangeNumberLiteral(`{"a":true,"b":false,"c":null}`)).toBe(false);
  });

  it("ignores a malformed numeric run, which the JSON parser rejects on its own", () => {
    expect(containsOutOfRangeNumberLiteral(`{"a":1e}`)).toBe(false);
  });
});
