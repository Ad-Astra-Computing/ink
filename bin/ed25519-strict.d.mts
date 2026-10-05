/**
 * Types for the canonical shared Ed25519 strict verifier, implemented in
 * this directory as plain `.mjs` so `bin/` can run from a git checkout with
 * no build step. `src/crypto/ed25519-strict.ts` re-exports the value from
 * here; this file is what lets that re-export, and every test that imports
 * either, type-check without falling back to `any`.
 */

export declare function verifyStrictEd25519(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean>;
