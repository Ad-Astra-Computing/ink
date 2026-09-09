// What a finding's artifact should say, once minimization has had its turn.
//
// The shrinker matches on the divergence kind, not the exact detail, and it
// searches: the input it returns is the smallest one it saw diverge, which is
// not always one that still does. So nothing is written until the case about to
// be written has been decided again and seen to diverge.

import { compareOne } from "./compare.mjs";

/** Re-decide a finding before it is recorded, and say which case the artifact
 * should carry.
 *
 * The minimized case is preferred, because it is the one worth reading. When it
 * does not reproduce the divergence it was shrunk from, the case it came from
 * is re-decided rather than trusted: a finding whose artifact disagrees with
 * its own claim sends a reader chasing a divergence that is not there, which is
 * worse than no finding at all. When neither reproduces, there is nothing
 * honest to write and the caller is told so.
 *
 * The pair is fixed throughout. A re-decision that diverges against a different
 * decider, or in a different way, is a different finding and does not count as
 * this one reproducing.
 *
 * `decide` is the batch decider, taken as an argument so this can be exercised
 * against a decider that answers on the first pass and changes its mind on the
 * recheck, which is the case that matters here and the one a real decider will
 * not produce on demand.
 *
 * @returns {Promise<{caseId: string, input: unknown, decisions: Map, diff: object}|null>}
 */
export async function reproduce(surface, original, minimized, diff, decide) {
  const attempt = async (caseId, input) => {
    const decisions = await decide([{ caseId, surface: surface.id, input }]);
    const again = compareOne(decisions, caseId, diff.against);
    if (!again || again.kind !== diff.kind) return null;
    return { caseId, input, decisions, diff: again };
  };
  return (await attempt("min", minimized)) ?? (await attempt("orig", original));
}
