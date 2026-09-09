import { describe, expect, it } from "vitest";
import { REFERENCE, compareAll, compareOne, comparePair } from "./compare.mjs";

const accept = { result: "accept" };
const reject = { result: "reject" };

/** A decisions map in the shape decideAll produces. */
function decisions(byDecider) {
  return new Map(
    Object.entries(byDecider).map(([id, decision]) => [id, new Map([["c1", decision]])]),
  );
}

const ALL = [
  { id: REFERENCE, surfaces: null },
  { id: "go", surfaces: null },
  { id: "witness", surfaces: new Set(["merkle-checkpoint"]) },
];

describe("comparePair", () => {
  it("agrees when both sides reach the same decision", () => {
    expect(comparePair(accept, accept, "go")).toBeNull();
  });

  it("reports a decision divergence", () => {
    expect(comparePair(accept, reject, "go")).toMatchObject({ kind: "decision" });
  });

  it("reports a value divergence", () => {
    expect(comparePair({ ...accept, keyId: "a" }, { ...accept, keyId: "b" }, "go")).toMatchObject({
      kind: "value",
    });
  });

  it("reports a missing side", () => {
    expect(comparePair(accept, undefined, "go")).toMatchObject({ kind: "missing" });
  });
});

describe("compareAll", () => {
  it("returns every diverging pair, not just the first", () => {
    const out = compareAll(ALL, decisions({ typescript: accept, go: reject, witness: reject }), "c1", "merkle-checkpoint");
    expect(out.map((d) => d.against).sort()).toEqual(["go", "witness"]);
  });

  it("leaves out a decider that does not answer the surface", () => {
    const out = compareAll(ALL, decisions({ typescript: accept, go: accept }), "c1", "timestamp-validity");
    expect(out).toEqual([]);
  });
});

describe("compareOne", () => {
  it("agrees when the named decider agrees", () => {
    expect(compareOne(decisions({ typescript: accept, go: accept }), "c1", "go", "timestamp-validity")).toBeNull();
  });

  it("reports a decision divergence for the named decider", () => {
    expect(compareOne(decisions({ typescript: accept, go: reject }), "c1", "go", "timestamp-validity")).toMatchObject({
      kind: "decision",
      against: "go",
    });
  });

  // The bug this locks: a decider that was asked and said nothing once read as
  // agreement here, so a genuine missing-response finding was dropped during the
  // recheck and the run could exit clean with a real divergence unrecorded.
  it("reports a decider that was asked and answered nothing", () => {
    expect(compareOne(decisions({ typescript: accept }), "c1", "go", "timestamp-validity")).toMatchObject({
      kind: "missing",
      against: "go",
    });
  });

  it("reports a missing reference the same way", () => {
    expect(compareOne(decisions({ go: accept }), "c1", "go", "timestamp-validity")).toMatchObject({ kind: "missing" });
  });
});
