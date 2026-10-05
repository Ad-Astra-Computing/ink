/**
 * Types for the CLI's self-contained copy of the shared Ed25519 strict
 * verifier.
 *
 * The implementation is plain `.mjs` so it runs from a git checkout with no
 * build step. These declarations exist so `test/bin-ed25519-strict-parity.test.ts`
 * can import it under `tsc --noEmit` without falling back to `any`, which
 * would hide a signature change in exactly the file the parity test is there
 * to watch.
 */

export declare function verifyStrictEd25519(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean>;
