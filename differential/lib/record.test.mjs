import { describe, expect, it } from "vitest";
import { REFERENCE } from "./compare.mjs";
import { reproduce } from "./record.mjs";

const accept = { result: "accept" };
const reject = { result: "reject" };

const SURFACE = { id: "signature-base" };
const ORIGINAL = { size: 9 };
const SMALLER = { size: 1 };

/** A decisions map in the shape decideAll produces, for one case. */
function answers(caseId, byDecider) {
  return new Map(
    Object.entries(byDecider).map(([id, decision]) => [
      id,
      decision === undefined ? new Map() : new Map([[caseId, decision]]),
    ]),
  );
}

/** A stand-in for decideAll that answers from a script keyed on case id, and
 *  records what it was asked so a test can say what was NOT re-decided. */
function decider(script) {
  const asked = [];
  const decide = async (cases) => {
    const [c] = cases;
    asked.push(c.caseId);
    const byDecider = script[c.caseId];
    if (byDecider === undefined) throw new Error(`nothing scripted for ${c.caseId}`);
    return answers(c.caseId, byDecider);
  };
  decide.asked = asked;
  return decide;
}

const DIFF = { against: "go", kind: "decision", detail: "accept vs reject" };

describe("reproduce", () => {
  it("keeps the minimized case when it diverges the same way", async () => {
    const decide = decider({ min: { [REFERENCE]: accept, go: reject } });
    const out = await reproduce(SURFACE, ORIGINAL, SMALLER, DIFF, decide);
    expect(out).toMatchObject({ caseId: "min", input: SMALLER });
    expect(out.diff).toMatchObject({ kind: "decision", against: "go" });
  });

  it("does not re-decide the original when the minimized case holds", async () => {
    const decide = decider({ min: { [REFERENCE]: accept, go: reject } });
    await reproduce(SURFACE, ORIGINAL, SMALLER, DIFF, decide);
    expect(decide.asked).toEqual(["min"]);
  });

  it("falls back to the original when the minimized case goes silent", async () => {
    const decide = decider({
      min: { [REFERENCE]: accept, go: undefined },
      orig: { [REFERENCE]: accept, go: reject },
    });
    const out = await reproduce(SURFACE, ORIGINAL, SMALLER, DIFF, decide);
    expect(decide.asked).toEqual(["min", "orig"]);
    expect(out).toMatchObject({ caseId: "orig", input: ORIGINAL });
    expect(out.diff).toMatchObject({ kind: "decision" });
  });

  it("falls back to the original when the minimized case agrees", async () => {
    const decide = decider({
      min: { [REFERENCE]: accept, go: accept },
      orig: { [REFERENCE]: accept, go: reject },
    });
    const out = await reproduce(SURFACE, ORIGINAL, SMALLER, DIFF, decide);
    expect(out).toMatchObject({ caseId: "orig", input: ORIGINAL });
  });

  // A shrink that lands on a different kind is a different finding, so the
  // artifact must not claim it is a smaller version of this one.
  it("falls back to the original when the minimized case diverges differently", async () => {
    const decide = decider({
      min: { [REFERENCE]: { ...accept, keyId: "a" }, go: { ...accept, keyId: "b" } },
      orig: { [REFERENCE]: accept, go: reject },
    });
    const out = await reproduce(SURFACE, ORIGINAL, SMALLER, DIFF, decide);
    expect(out).toMatchObject({ caseId: "orig", input: ORIGINAL });
    expect(out.diff).toMatchObject({ kind: "decision" });
  });

  it("records nothing when neither case reproduces", async () => {
    const decide = decider({
      min: { [REFERENCE]: accept, go: accept },
      orig: { [REFERENCE]: accept, go: accept },
    });
    expect(await reproduce(SURFACE, ORIGINAL, SMALLER, DIFF, decide)).toBeNull();
    expect(decide.asked).toEqual(["min", "orig"]);
  });

  // The pair is fixed. Another decider disagreeing on the re-decision is not
  // this finding reproducing.
  it("ignores a divergence against a different decider on the recheck", async () => {
    const decide = decider({
      min: { [REFERENCE]: accept, go: accept, witness: reject },
      orig: { [REFERENCE]: accept, go: accept, witness: reject },
    });
    expect(await reproduce(SURFACE, ORIGINAL, SMALLER, DIFF, decide)).toBeNull();
  });

  it("carries the decisions the artifact reports, from the case that landed", async () => {
    const decide = decider({
      min: { [REFERENCE]: accept, go: accept },
      orig: { [REFERENCE]: accept, go: reject },
    });
    const out = await reproduce(SURFACE, ORIGINAL, SMALLER, DIFF, decide);
    expect(out.decisions.get("go").get("orig")).toEqual(reject);
  });
});
