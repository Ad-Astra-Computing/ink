/**
 * Runtime probe for the V8 escaped-member-name defect.
 *
 * INK's signed-body gate (`member-name.ts`) removes the defect's precondition
 * from every body INK itself parses, so an application using INK's parse path is
 * covered regardless of what this probe reports. The probe exists for the rest
 * of the application: an adopter's own `JSON.parse` calls, on the same runtime,
 * are still affected, and a wrong member name there is silent.
 *
 * The result is deliberately three-valued in spirit but two-valued in type, with
 * the asymmetry documented rather than hidden: `true` is proof the runtime is
 * affected, `false` is only the absence of proof. Whether the defect fires
 * depends on the isolate's hidden-class transition tables at the moment of the
 * call, which no caller controls. A version list would be the wrong control for
 * the same reason: what matters is the embedded V8, not the Node release, and
 * embedders such as Cloudflare workerd do not track Node's semver at all.
 */

/**
 * Whether this runtime demonstrably returns a wrong object member name from
 * `JSON.parse`.
 *
 * `true` means the defect reproduced here and now: member names written with an
 * escape cannot be trusted anywhere in this process. `false` means it did not
 * reproduce on this call, which is weaker than "unaffected" because the defect
 * is state-dependent. Treat `false` as "no evidence", never as a clean bill of
 * health.
 *
 * The probe is self-contained and allocates two small objects. It does not
 * mutate global state beyond whatever hidden-class transitions the parse itself
 * creates, which is the same thing any `JSON.parse` of the same shape would do.
 */
export function hasEscapedMemberNameDefect(): boolean {
  // The first member plants a transition named `\`; the second is spelled with
  // an escape whose decoded length matches and whose raw text starts with `\`,
  // which is the exact shape that makes V8 adopt the planted name.
  const probe = JSON.parse(String.raw`{"x":{"\\":1},"y":{"\n":2}}`) as {
    y: Record<string, unknown>;
  };
  return !Object.prototype.hasOwnProperty.call(probe.y, "\n");
}
