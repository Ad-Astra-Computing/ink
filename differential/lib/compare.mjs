/** The comparison rules the differential harness judges by. Kept apart from
 * the runner so the decision of what counts as a divergence can be tested on
 * its own, without spawning a decider.
 */

/** The implementation every other decider is measured against. */
export const REFERENCE = "typescript";

const VALUE_FIELDS = ["canonicalPrincipal", "canonicalString", "epochMs", "signature", "keyId"];
const isHarness = (r) => typeof r === "string" && r.startsWith("__harness");

/** Compare one decider against the reference. Returns null when they agree. */
export function comparePair(ts, other, id) {
  if (!ts || !other) {
    return { kind: "missing", detail: `ts=${ts ? "present" : "missing"} ${id}=${other ? "present" : "missing"}` };
  }
  if (isHarness(ts.reason) && ts.reason.startsWith("__harness_error")) {
    return { kind: "crash", detail: `typescript: ${ts.reason}` };
  }
  if (isHarness(other.reason) && other.reason.startsWith("__harness_error")) {
    return { kind: "crash", detail: `${id}: ${other.reason}` };
  }
  if (ts.result !== other.result) {
    return { kind: "decision", detail: `ts=${ts.result} ${id}=${other.result}` };
  }
  for (const f of VALUE_FIELDS) {
    const a = ts[f];
    const b = other[f];
    if (a === undefined && b === undefined) continue;
    if (a !== b) return { kind: "value", detail: `${f}: ts=${JSON.stringify(a)} ${id}=${JSON.stringify(b)}` };
  }
  // The reason code is compared only when both sides emit one and neither is a
  // harness marker: the marker means one side's public entry point could not be
  // reached with this input at all, which is an API asymmetry, not a divergence.
  if (ts.reason && other.reason && !isHarness(ts.reason) && !isHarness(other.reason) && ts.reason !== other.reason) {
    return { kind: "reason", detail: `reason: ts=${ts.reason} ${id}=${other.reason}` };
  }
  return null;
}

/** Compare every decider against the reference for one case, and return EVERY
 * disagreement rather than the first. Each pair is its own finding: with three
 * implementations, "the witness and the reference disagree" is a different
 * fact from "Go and the reference disagree", and returning only the first
 * would let a Go disagreement mask a witness one on the same case, so the
 * witness pair could go a whole run without ever producing a finding. A
 * decider that does not answer this surface is not absent, it simply was not
 * asked. */
export function compareAll(deciders, decisions, caseId, surface) {
  const reference = decisions.get(REFERENCE)?.get(caseId);
  const out = [];
  for (const d of deciders) {
    if (d.id === REFERENCE) continue;
    if (d.surfaces !== null && !d.surfaces.has(surface)) continue;
    const diff = comparePair(reference, decisions.get(d.id)?.get(caseId), d.id);
    if (diff) out.push({ ...diff, against: d.id });
  }
  return out;
}

/** The disagreement between the reference and one named decider, or null. The
 * caller has already established that this decider answers the surface, so a
 * decider with no record here has failed to answer something it was asked,
 * which is a `missing` divergence and not a case it sat out. */
export function compareOne(decisions, caseId, against) {
  const diff = comparePair(
    decisions.get(REFERENCE)?.get(caseId),
    decisions.get(against)?.get(caseId),
    against,
  );
  return diff ? { ...diff, against } : null;
}
