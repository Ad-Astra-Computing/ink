/**
 * Types for the CLI's self-contained copy of the signed-body text gate.
 *
 * The implementation is plain `.mjs` so it runs from a git checkout with no
 * build step. These declarations exist so `test/bin-gate-parity.test.ts` can
 * import it under `tsc --noEmit` without falling back to `any`, which would
 * hide a signature change in exactly the file the parity test is there to
 * watch.
 */

export type SignedBodyGateReason = "utf8" | "surrogate" | "number-range" | "member-name-escape";

export declare class SignedBodyGateError extends Error {
  readonly reason: SignedBodyGateReason;
  constructor(reason: SignedBodyGateReason, message: string);
}

export declare function containsLoneSurrogateEscape(raw: string): boolean;
export declare function containsOutOfRangeNumberLiteral(raw: string): boolean;
export declare function containsEscapedMemberName(raw: string): boolean;
export declare function parseSignedBodyBytes(bytes: Uint8Array): unknown;
