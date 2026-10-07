/**
 * The one shared Ed25519 verifier for the whole package, implemented in
 * `../../bin/ed25519-strict.mjs`.
 *
 * It lives there, not here, because `bin/` must run from a git checkout
 * with no `dist/` built yet and cannot import a compiled copy of this file,
 * while this file CAN import a plain-JS sibling at both source-checkout and
 * published-package depth. Re-exporting rather than duplicating means there
 * is nothing to keep in step and no second copy to drift. See that file for
 * the cofactorless-equation rationale and the RFC 8032 details.
 *
 * Every call site in this package MUST go through this function instead of
 * calling `ed.verifyAsync` (or `ed.verify`) directly.
 */
export { verifyStrictEd25519 } from "../../bin/ed25519-strict.mjs";
